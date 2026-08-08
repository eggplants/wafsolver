"""The challenge types AWS WAF serves, and how to solve each one.

``challenge.js`` dispatches on a challenge type identifier. Two types are
proof-of-work: hash ``input + checksum + nonce`` repeatedly, with SHA-256 or
scrypt, until the digest starts with ``difficulty`` zero bits. The third is a
bandwidth challenge with no work at all -- the client uploads a fixed number of
zero bytes, base64 encoded, and posts it to a different endpoint.
"""

from __future__ import annotations

import base64
import hashlib
import itertools
from typing import TYPE_CHECKING, Any, Literal

from .errors import InvalidDifficultyError, UnsupportedChallengeError

if TYPE_CHECKING:
    from collections.abc import Callable

#: Endpoint the solution is posted to, which depends on the challenge type.
ChallengeMode = Literal["verify", "mp_verify"]

#: SHA-256 proof of work.
SHA256_CHALLENGE = "h7b0c470f0cfe3a80a9e26526ad185f484f6817d0832712a4a37a908786a6a67f"
#: scrypt proof of work.
SCRYPT_CHALLENGE = "h72f957df656e80ba55f5d8ce2e8c7ccb59687dba3bfb273d54b08a261b2f3002"
#: Bandwidth challenge, posted as multipart form data to ``/mp_verify``.
BANDWIDTH_CHALLENGE = (
    "ha9faaffd31b4d5ede2a2e19d2d7fd525f66fee61911511960dcbb52d3c48ce25"
)

#: Bandwidth challenge: difficulty selects how many zero bytes to upload.
BANDWIDTH_SIZES: dict[int, int] = {
    1: 0x400,
    2: 0x2800,
    3: 0x19000,
    4: 0x100000,
    5: 0xA00000,
}

# scrypt parameters challenge.js uses.
_SCRYPT_N = 128
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 16


def has_leading_zero_bits(digest: bytes, difficulty: int) -> bool:
    """Check whether a digest starts with ``difficulty`` zero bits.

    Args:
        digest (bytes): The digest to test.
        difficulty (int): Required number of leading zero bits.

    Returns:
        bool: True if the digest satisfies the difficulty.
    """
    full, rem = divmod(difficulty, 8)
    if digest[:full] != b"\x00" * full:
        return False
    return not (rem and (digest[full] >> (8 - rem)))


def solve_sha256(challenge_input: str, checksum: str, difficulty: int) -> str:
    """Find a nonce whose SHA-256 digest meets the difficulty.

    Args:
        challenge_input (str): The challenge input string.
        checksum (str): The fingerprint checksum.
        difficulty (int): Required number of leading zero bits.

    Returns:
        str: The winning nonce.
    """
    base = (challenge_input + checksum).encode()
    for nonce in itertools.count():
        digest = hashlib.sha256(base + str(nonce).encode()).digest()
        if has_leading_zero_bits(digest, difficulty):
            return str(nonce)
    raise AssertionError  # pragma: no cover - unreachable


def solve_scrypt(challenge_input: str, checksum: str, difficulty: int) -> str:
    """Find a nonce whose scrypt digest meets the difficulty.

    Args:
        challenge_input (str): The challenge input string.
        checksum (str): The fingerprint checksum, also used as the salt.
        difficulty (int): Required number of leading zero bits.

    Returns:
        str: The winning nonce.
    """
    base = challenge_input + checksum
    salt = checksum.encode()
    for nonce in itertools.count():
        digest = hashlib.scrypt(
            f"{base}{nonce}".encode(),
            salt=salt,
            n=_SCRYPT_N,
            r=_SCRYPT_R,
            p=_SCRYPT_P,
            dklen=_SCRYPT_DKLEN,
        )
        if has_leading_zero_bits(digest, difficulty):
            return str(nonce)
    raise AssertionError  # pragma: no cover - unreachable


def solve_bandwidth(difficulty: int) -> str:
    """Build the bandwidth challenge payload.

    There is no work to do here: ``challenge.js`` allocates a zero-filled
    buffer whose size depends on the difficulty and returns it base64 encoded.

    Args:
        difficulty (int): The challenge difficulty, selecting the payload size.

    Raises:
        InvalidDifficultyError: If the difficulty has no known payload size.

    Returns:
        str: The base64 encoded payload.
    """
    size = BANDWIDTH_SIZES.get(difficulty)
    if size is None:
        raise InvalidDifficultyError(difficulty)
    return base64.b64encode(b"\x00" * size).decode()


def select_solver(
    challenge_type: str,
) -> tuple[ChallengeMode, Callable[[dict[str, Any], str], str]]:
    """Pick the endpoint mode and solver for a challenge type.

    Args:
        challenge_type (str): The challenge type identifier.

    Raises:
        UnsupportedChallengeError: If the challenge type is not recognised.

    Returns:
        tuple[ChallengeMode, Callable[[dict[str, Any], str], str]]: The
            endpoint mode and a solver taking the challenge inputs and the
            fingerprint checksum.
    """
    if challenge_type == BANDWIDTH_CHALLENGE:
        return "mp_verify", lambda inputs, _: solve_bandwidth(inputs["difficulty"])
    if challenge_type == SHA256_CHALLENGE:
        return "verify", lambda inputs, checksum: solve_sha256(
            inputs["challenge"]["input"],
            checksum,
            inputs["difficulty"],
        )
    if challenge_type == SCRYPT_CHALLENGE:
        return "verify", lambda inputs, checksum: solve_scrypt(
            inputs["challenge"]["input"],
            checksum,
            inputs["difficulty"],
        )
    raise UnsupportedChallengeError(challenge_type)


__all__ = (
    "BANDWIDTH_CHALLENGE",
    "BANDWIDTH_SIZES",
    "SCRYPT_CHALLENGE",
    "SHA256_CHALLENGE",
    "ChallengeMode",
    "has_leading_zero_bits",
    "select_solver",
    "solve_bandwidth",
    "solve_scrypt",
    "solve_sha256",
)
