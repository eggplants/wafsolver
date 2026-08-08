""".. include:: ../README.md"""  # noqa: D415

import importlib.metadata

from .challenge import (
    BANDWIDTH_CHALLENGE,
    BANDWIDTH_SIZES,
    SCRYPT_CHALLENGE,
    SHA256_CHALLENGE,
    select_solver,
    solve_bandwidth,
    solve_scrypt,
    solve_sha256,
)
from .client import (
    ACTION_HEADER,
    TOKEN_COOKIE,
    WafSolver,
    is_challenged,
    parse_challenge_page,
    solve_challenge,
)
from .errors import (
    ChallengePageError,
    InvalidDifficultyError,
    TokenRequestError,
    UnsupportedChallengeError,
    WafSolveError,
)

try:
    __version__ = importlib.metadata.version(__name__)
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.0.0"

__all__ = (
    "ACTION_HEADER",
    "BANDWIDTH_CHALLENGE",
    "BANDWIDTH_SIZES",
    "SCRYPT_CHALLENGE",
    "SHA256_CHALLENGE",
    "TOKEN_COOKIE",
    "ChallengePageError",
    "InvalidDifficultyError",
    "TokenRequestError",
    "UnsupportedChallengeError",
    "WafSolveError",
    "WafSolver",
    "__version__",
    "is_challenged",
    "parse_challenge_page",
    "select_solver",
    "solve_bandwidth",
    "solve_challenge",
    "solve_scrypt",
    "solve_sha256",
)
