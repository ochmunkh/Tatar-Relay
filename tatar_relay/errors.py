"""Error taxonomy — Frozen Contract #4.

Every failure inside the engine is surfaced as a RelayError (or subclass) with a
stable ``category`` string. Frontends never crash the proxy; they catch these,
log them, and pass the original message through untouched.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional


# Stable category vocabulary. Adding a value is a MINOR change; renaming or
# removing one is a BREAKING change (contract is versioned).
CATEGORIES = (
    "padding",           # CBC unpad failed (wrong key / corrupt data)
    "tag_mismatch",      # GCM/AEAD auth tag invalid
    "wrong_key_size",    # key length not valid for the cipher
    "signature_invalid", # HMAC / signature check failed
    "type_mismatch",     # a step received the wrong DataType
    "locate_failed",     # no envelope locate strategy matched
    "extraction_failed", # a variable could not be extracted
    "scope_violation",   # host/path outside the profile's authorized scope
    "profile_invalid",   # the profile itself failed validation
    "hook_error",        # a user Python hook raised
    "config_error",      # a step was mis-configured in the profile
    "internal",          # anything unclassified
)


class RelayError(Exception):
    """Base class for all Tatar Relay errors."""


@dataclass
class DecryptError(RelayError):
    """Structured, catchable pipeline failure.

    Attributes mirror the Frozen Contract #4 shape so frontends and logs can
    render a consistent diagnostic.
    """

    category: str
    message: str
    step: Optional[str] = None
    direction: Optional[str] = None   # "forward" | "backward"
    channel: Optional[str] = None     # "request" | "response"
    detail: dict = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.category not in CATEGORIES:
            # Never let a typo silently create a new category.
            raise ValueError(f"unknown error category: {self.category!r}")
        super().__init__(self.message)

    def __str__(self) -> str:  # pragma: no cover - cosmetic
        loc = ".".join(x for x in (self.channel, self.direction, self.step) if x)
        return f"[{self.category}] {self.message}" + (f" ({loc})" if loc else "")

    def as_dict(self) -> dict:
        return {
            "category": self.category,
            "message": self.message,
            "step": self.step,
            "direction": self.direction,
            "channel": self.channel,
            "detail": self.detail,
        }


class ScopeViolation(RelayError):
    """Raised (fail-closed) when a profile is used outside its authorized scope."""


class ProfileError(RelayError):
    """Raised when a profile fails to load or validate."""
