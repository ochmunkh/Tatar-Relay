"""Tatar Relay — Application-Layer Protocol Adaptation Layer.

Turn encrypted APIs into editable HTTP for security testing.
Authorized testing only.
"""
from . import steps  # noqa: F401  (registers built-in steps)
from .context import Context, HttpMessage
from .engine import Engine, ChannelPipeline
from .errors import DecryptError, RelayError, ProfileError, ScopeViolation
from .profile import Profile
from .variables import VarStore

__version__ = "0.1.0"

__all__ = [
    "Context", "HttpMessage", "Engine", "ChannelPipeline",
    "DecryptError", "RelayError", "ProfileError", "ScopeViolation",
    "Profile", "VarStore", "__version__",
]
