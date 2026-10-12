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

# THE single source of truth for the version. pyproject.toml reads this
# attribute (dynamic version) and cli.py's --version formats it, so a release
# bumps exactly one literal. tests/test_version.py pins it to CHANGELOG.md.
__version__ = "0.6.1"

__all__ = [
    "Context", "HttpMessage", "Engine", "ChannelPipeline",
    "DecryptError", "RelayError", "ProfileError", "ScopeViolation",
    "Profile", "VarStore", "__version__",
]
