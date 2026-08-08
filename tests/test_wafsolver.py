from __future__ import annotations

import base64
import hashlib
import json
import zlib
from typing import Any
from unittest.mock import Mock, patch

import pytest

from wafsolver import __version__
from wafsolver.challenge import (
    BANDWIDTH_CHALLENGE,
    BANDWIDTH_SIZES,
    SCRYPT_CHALLENGE,
    SHA256_CHALLENGE,
    has_leading_zero_bits,
    select_solver,
    solve_bandwidth,
    solve_scrypt,
    solve_sha256,
)
from wafsolver.client import (
    WafSolver,
    is_challenged,
    parse_challenge_page,
)
from wafsolver.errors import (
    ChallengePageError,
    InvalidDifficultyError,
    TokenRequestError,
    UnsupportedChallengeError,
)
from wafsolver.fingerprint import FP_KEY, build, build_metrics, decrypt, encrypt

CHALLENGE_PAGE = (
    "<html><head>"
    '<script>window.gokuProps = {"key":"k","iv":"i","context":"c"};</script>'
    '<script src="https://abc.def.eu-west-1.token.awswaf.com/a/b/c/challenge.js">'
    "</script></head><body></body></html>"
)
ENDPOINT = "abc.def.eu-west-1.token.awswaf.com/a/b/c"


@pytest.fixture
def solver() -> tuple[WafSolver, Mock]:
    session = Mock()
    with patch("wafsolver.client.requests.Session", return_value=session):
        return WafSolver("example.com"), session


def test_version() -> None:
    assert isinstance(__version__, str)
    assert len(__version__) > 0


def test_is_challenged() -> None:
    assert is_challenged({"x-amzn-waf-action": "challenge"})
    assert not is_challenged({"x-amzn-waf-action": "captcha"})
    assert not is_challenged({})


def test_parse_challenge_page() -> None:
    goku, endpoint = parse_challenge_page(CHALLENGE_PAGE)
    assert goku == {"key": "k", "iv": "i", "context": "c"}
    assert endpoint == ENDPOINT


def test_parse_challenge_page_rejects_other_pages() -> None:
    with pytest.raises(ChallengePageError, match="Could not parse"):
        parse_challenge_page("<html>not a challenge</html>")


def test_has_leading_zero_bits() -> None:
    assert has_leading_zero_bits(b"\x00\x00\xff", 16)
    assert has_leading_zero_bits(b"\x00\x0f", 12)
    assert not has_leading_zero_bits(b"\x00\x1f", 12)
    assert not has_leading_zero_bits(b"\x01", 8)


def test_solve_sha256_meets_difficulty() -> None:
    difficulty = 12
    nonce = solve_sha256("input", "CHECKSUM", difficulty)
    digest = hashlib.sha256(f"inputCHECKSUM{nonce}".encode()).digest()
    assert has_leading_zero_bits(digest, difficulty)


def test_solve_scrypt_meets_difficulty() -> None:
    difficulty = 8
    nonce = solve_scrypt("input", "CHECKSUM", difficulty)
    digest = hashlib.scrypt(
        f"inputCHECKSUM{nonce}".encode(),
        salt=b"CHECKSUM",
        n=128,
        r=8,
        p=1,
        dklen=16,
    )
    assert has_leading_zero_bits(digest, difficulty)


def test_solve_bandwidth_returns_base64_zeros() -> None:
    for difficulty, size in BANDWIDTH_SIZES.items():
        payload = solve_bandwidth(difficulty)
        assert base64.b64decode(payload) == b"\x00" * size


def test_solve_bandwidth_rejects_unknown_difficulty() -> None:
    with pytest.raises(InvalidDifficultyError, match="Invalid difficulty 99"):
        solve_bandwidth(99)


def test_select_solver_modes() -> None:
    assert select_solver(BANDWIDTH_CHALLENGE)[0] == "mp_verify"
    assert select_solver(SHA256_CHALLENGE)[0] == "verify"
    assert select_solver(SCRYPT_CHALLENGE)[0] == "verify"


def test_select_solver_rejects_unknown_type() -> None:
    with pytest.raises(UnsupportedChallengeError, match="hdeadbeef"):
        select_solver("hdeadbeef")


def test_select_solver_bandwidth_ignores_checksum() -> None:
    _, solve = select_solver(BANDWIDTH_CHALLENGE)
    payload = solve({"difficulty": 1}, "unused")
    assert base64.b64decode(payload) == b"\x00" * BANDWIDTH_SIZES[1]


def test_encrypt_decrypt_round_trip() -> None:
    assert decrypt(encrypt(b"payload")) == b"payload"


def test_fingerprint_build_round_trips() -> None:
    checksum, encrypted = build("test-agent")
    plaintext = decrypt(encrypted, FP_KEY)

    prefix, _, payload = plaintext.partition(b"#")
    assert prefix.decode() == checksum
    assert f"{zlib.crc32(payload) & 0xFFFFFFFF:08x}".upper() == checksum
    assert json.loads(payload)["userAgent"] == "test-agent"


def test_build_metrics_shape() -> None:
    metrics = build_metrics()
    assert len(metrics) == 23  # noqa: PLR2004
    assert all({"name", "value", "unit"} == set(m) for m in metrics)


def _inputs(challenge_type: str, difficulty: int = 1) -> dict[str, Any]:
    return {
        "challenge_type": challenge_type,
        "difficulty": difficulty,
        "challenge": {"input": "abc"},
    }


def test_build_envelope_bandwidth(solver: tuple[WafSolver, Mock]) -> None:
    waf, _ = solver
    envelope = waf.build_envelope(_inputs(BANDWIDTH_CHALLENGE), {"key": "k"})

    assert envelope["_mode"] == "mp_verify"
    assert envelope["client"] == "Browser"
    assert envelope["domain"] == "example.com"
    assert envelope["existing_token"] is None
    assert envelope["goku_props"] == {"key": "k"}
    assert envelope["signals"][0]["name"] == "Zoey"
    assert base64.b64decode(envelope["solution"]) == b"\x00" * BANDWIDTH_SIZES[1]


def test_build_envelope_carries_existing_token(
    solver: tuple[WafSolver, Mock],
) -> None:
    waf, _ = solver
    envelope = waf.build_envelope(
        _inputs(BANDWIDTH_CHALLENGE),
        {},
        existing_token="old",
    )
    assert envelope["existing_token"] == "old"


def test_submit_bandwidth_posts_multipart(solver: tuple[WafSolver, Mock]) -> None:
    waf, session = solver
    session.post.return_value = Mock(ok=True, json=lambda: {"token": "tok"})
    envelope = waf.build_envelope(_inputs(BANDWIDTH_CHALLENGE), {})
    solution = envelope["solution"]

    assert waf.submit(ENDPOINT, envelope) == "tok"

    args, kwargs = session.post.call_args
    assert args[0] == f"https://{ENDPOINT}/mp_verify"

    files = kwargs["files"]
    assert list(files) == ["solution_metadata", "solution_data"]
    assert files["solution_data"] == (None, solution)
    # the payload is moved out of the JSON, leaving `solution` null behind
    metadata = json.loads(files["solution_metadata"][1])
    assert metadata["solution"] is None
    assert "_mode" not in metadata
    assert metadata["checksum"] == envelope["checksum"]


def test_submit_proof_of_work_posts_json(solver: tuple[WafSolver, Mock]) -> None:
    waf, session = solver
    session.post.return_value = Mock(ok=True, json=lambda: {"token": "tok"})
    envelope = waf.build_envelope(_inputs(SHA256_CHALLENGE, difficulty=4), {})

    assert waf.submit(ENDPOINT, envelope) == "tok"

    args, kwargs = session.post.call_args
    assert args[0] == f"https://{ENDPOINT}/verify"
    assert "files" not in kwargs
    assert kwargs["json"]["solution"] == envelope["solution"]
    assert "_mode" not in kwargs["json"]


def test_submit_raises_on_error_status(solver: tuple[WafSolver, Mock]) -> None:
    waf, session = solver
    session.post.return_value = Mock(ok=False, status_code=403, text="denied")
    envelope = waf.build_envelope(_inputs(BANDWIDTH_CHALLENGE), {})

    with pytest.raises(TokenRequestError, match="HTTP 403"):
        waf.submit(ENDPOINT, envelope)


def test_submit_raises_without_token(solver: tuple[WafSolver, Mock]) -> None:
    waf, session = solver
    session.post.return_value = Mock(ok=True, json=dict)
    envelope = waf.build_envelope(_inputs(BANDWIDTH_CHALLENGE), {})

    with pytest.raises(TokenRequestError, match="did not return a token"):
        waf.submit(ENDPOINT, envelope)


def test_solve_runs_the_whole_exchange(solver: tuple[WafSolver, Mock]) -> None:
    waf, session = solver
    session.get.return_value = Mock(
        json=lambda: _inputs(BANDWIDTH_CHALLENGE),
    )
    session.post.return_value = Mock(ok=True, json=lambda: {"token": "tok"})

    assert waf.solve(CHALLENGE_PAGE) == "tok"

    args, _ = session.get.call_args
    assert args[0] == f"https://{ENDPOINT}/inputs?client=browser"
