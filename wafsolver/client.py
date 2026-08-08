"""Driving the AWS WAF challenge exchange end to end.

A protected site answers non-browser clients with ``x-amzn-waf-action:
challenge`` and a stub page carrying ``window.gokuProps`` and a
``challenge.js`` URL. The token endpoint lives at that URL's directory: fetch
``/inputs``, solve what it returns, post the envelope to ``/verify`` or
``/mp_verify``, and receive an ``aws-waf-token``.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from curl_cffi import requests

from . import fingerprint
from .challenge import select_solver
from .errors import ChallengePageError, TokenRequestError

if TYPE_CHECKING:
    from collections.abc import Mapping

    from curl_cffi.requests.impersonate import BrowserTypeLiteral

#: Cookie the WAF checks on subsequent requests.
TOKEN_COOKIE = "aws-waf-token"  # noqa: S105 - a cookie name, not a secret

#: Header the WAF sets when it intercepts a request.
ACTION_HEADER = "x-amzn-waf-action"

_GOKU_MARKER = "window.gokuProps = "
_SCRIPT_MARKER = 'src="https://'
_CHALLENGE_MARKER = "/challenge.js"


def is_challenged(headers: Mapping[str, str]) -> bool:
    """Report whether a response is a WAF challenge rather than real content.

    Args:
        headers (Mapping[str, str]): The response headers.

    Returns:
        bool: True if the WAF intercepted the request with a challenge.
    """
    return headers.get(ACTION_HEADER) == "challenge"


def parse_challenge_page(html: str) -> tuple[dict[str, Any], str]:
    """Extract the challenge parameters from a WAF stub page.

    Args:
        html (str): The challenge page body.

    Raises:
        ChallengePageError: If the page is not a WAF challenge page.

    Returns:
        tuple[dict[str, Any], str]: The ``gokuProps`` object and the token
            endpoint (host plus path prefix, without a scheme).
    """
    try:
        props = html.split(_GOKU_MARKER)[1].split(";", maxsplit=1)[0]
        goku_props = json.loads(props)
        endpoint = html.split(_SCRIPT_MARKER)[1].split(_CHALLENGE_MARKER, maxsplit=1)[0]
    except (IndexError, ValueError) as err:
        msg = "Could not parse the AWS WAF challenge page."
        raise ChallengePageError(msg) from err
    return goku_props, endpoint


class WafSolver:
    """Solves AWS WAF challenges for a domain.

    Args:
        domain (str): The domain the token will be used for.
        user_agent (str): The user agent to present, which must match the
            one the fingerprint reports. Defaults to a recent Chrome.
        impersonate (BrowserTypeLiteral): The TLS fingerprint ``curl_cffi``
            should imitate.
    """

    def __init__(
        self,
        domain: str,
        user_agent: str = fingerprint.USER_AGENT,
        impersonate: BrowserTypeLiteral = "chrome",
    ) -> None:
        """Initialize the solver."""
        self.domain = domain
        self.user_agent = user_agent
        self.session = requests.Session(impersonate=impersonate)
        self.session.headers.update(
            {
                "user-agent": user_agent,
                "accept": "*/*",
                "accept-language": "en-US,en;q=0.9",
                "sec-fetch-site": "cross-site",
                "sec-fetch-mode": "cors",
                "sec-fetch-dest": "empty",
            }
        )

    def fetch_inputs(self, endpoint: str) -> dict[str, Any]:
        """Fetch a fresh challenge from the token endpoint.

        Args:
            endpoint (str): The token endpoint, without a scheme.

        Returns:
            dict[str, Any]: The challenge inputs.
        """
        res = self.session.get(f"https://{endpoint}/inputs?client=browser")
        return dict(res.json())

    def build_envelope(
        self,
        inputs: Mapping[str, Any],
        goku_props: Mapping[str, Any],
        existing_token: str | None = None,
    ) -> dict[str, Any]:
        """Solve the challenge and build the envelope to post.

        Args:
            inputs (Mapping[str, Any]): The challenge inputs.
            goku_props (Mapping[str, Any]): The props from the challenge page.
            existing_token (str | None): A token to refresh, if any.

        Returns:
            dict[str, Any]: The envelope, carrying a ``_mode`` key naming the
                endpoint it must be posted to.
        """
        mode, solver = select_solver(str(inputs["challenge_type"]))
        checksum, encrypted_fp = fingerprint.build(self.user_agent)
        solution = solver(dict(inputs), checksum)
        return {
            "_mode": mode,
            "challenge": inputs["challenge"],
            "solution": solution,
            "signals": [{"name": "Zoey", "value": {"Present": encrypted_fp}}],
            "checksum": checksum,
            "existing_token": existing_token,
            "client": "Browser",
            "domain": self.domain,
            "metrics": fingerprint.build_metrics(),
            "goku_props": dict(goku_props),
        }

    def submit(self, endpoint: str, envelope: Mapping[str, Any]) -> str:
        """Post a solved envelope and return the token.

        Args:
            endpoint (str): The token endpoint, without a scheme.
            envelope (Mapping[str, Any]): The envelope from
                :meth:`build_envelope`.

        Raises:
            TokenRequestError: If the endpoint rejects the solution or returns
                no token.

        Returns:
            str: The acquired token.
        """
        body = dict(envelope)
        mode = body.pop("_mode")
        url = f"https://{endpoint}/{mode}"

        if mode == "mp_verify":
            # challenge.js moves the payload out of the JSON and posts it as a
            # separate multipart field, leaving `solution` null in the metadata.
            solution = body["solution"]
            metadata = dict(body, solution=None)
            res = self.session.post(
                url,
                files={
                    "solution_metadata": (None, json.dumps(metadata)),
                    "solution_data": (None, solution),
                },
            )
        else:
            res = self.session.post(
                url,
                json=body,
                headers={"content-type": "text/plain;charset=UTF-8"},
            )

        if not res.ok:
            msg = f"{url} returned HTTP {res.status_code}: {res.text[:200]}"
            raise TokenRequestError(msg)
        token = res.json().get("token")
        if not token:
            msg = f"{url} did not return a token."
            raise TokenRequestError(msg)
        return str(token)

    def solve(self, challenge_html: str, existing_token: str | None = None) -> str:
        """Solve a challenge page and return an ``aws-waf-token``.

        Args:
            challenge_html (str): The challenge page body served by the WAF.
            existing_token (str | None): A token to refresh, if any.

        Returns:
            str: The acquired token.
        """
        goku_props, endpoint = parse_challenge_page(challenge_html)
        inputs = self.fetch_inputs(endpoint)
        envelope = self.build_envelope(inputs, goku_props, existing_token)
        return self.submit(endpoint, envelope)


def solve_challenge(
    domain: str,
    challenge_html: str,
    user_agent: str = fingerprint.USER_AGENT,
) -> str:
    """Solve a challenge page in one call.

    Args:
        domain (str): The domain the token will be used for.
        challenge_html (str): The challenge page body served by the WAF.
        user_agent (str): The user agent to present.

    Returns:
        str: The acquired ``aws-waf-token``.
    """
    return WafSolver(domain, user_agent=user_agent).solve(challenge_html)


__all__ = (
    "ACTION_HEADER",
    "TOKEN_COOKIE",
    "WafSolver",
    "is_challenged",
    "parse_challenge_page",
    "solve_challenge",
)
