"""One source of truth for the version.

`relay --version` is the one string a user pastes into a bug report, and it used
to say 0.1.0 at tag v0.6.1 because pyproject.toml and tatar_relay/__init__.py
were two hand-maintained copies. __init__.py is now the only literal; pyproject
reads it via a dynamic version. These tests keep the three places that quote a
version — the module, the package metadata and the changelog — from drifting
apart again.
"""
import re
from pathlib import Path

import tatar_relay

ROOT = Path(__file__).resolve().parent.parent


def test_pyproject_reads_the_version_from_the_package():
    """pyproject must declare the version dynamic, never restate the number."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert 'version = { attr = "tatar_relay.__version__" }' in text
    # a second literal is exactly what drifted before
    assert not re.search(r'(?m)^version\s*=\s*"', text), \
        "pyproject.toml restates the version; it must read __version__ instead"


def test_changelog_newest_entry_matches_the_package_version():
    """The top `## [x.y.z]` heading is what shipped, so it is what we report."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"(?m)^## \[(\d+\.\d+(?:\.\d+)?)\]", text)
    assert headings, "CHANGELOG.md has no '## [x.y.z]' release heading"
    assert headings[0] == tatar_relay.__version__, (
        f"CHANGELOG.md documents {headings[0]} as the newest release but "
        f"tatar_relay.__version__ is {tatar_relay.__version__}"
    )


def test_cli_version_flag_reports_the_package_version():
    from tatar_relay.cli import build_parser
    action = next(a for a in build_parser()._actions
                  if "--version" in (a.option_strings or []))
    assert tatar_relay.__version__ in action.version
