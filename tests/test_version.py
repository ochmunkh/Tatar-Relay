"""One source of truth for the version.

`relay --version` is the one string a user pastes into a bug report, and it used
to say 0.1.0 at tag v0.6.1 because pyproject.toml and tatar_relay/__init__.py
were two hand-maintained copies. __init__.py is now the only literal; pyproject
reads it via a dynamic version. These tests keep the places that quote a
version — the module, the package metadata, the CLI and the changelog — from
drifting apart again, and keep CONTRIBUTING.md honest about which file wins.
"""
import re
from pathlib import Path

import pytest

import tatar_relay

ROOT = Path(__file__).resolve().parent.parent

# The one file allowed to state the number.
SOURCE_OF_TRUTH = "tatar_relay/__init__.py"


def test_pyproject_reads_the_version_from_the_package():
    """pyproject must declare the version dynamic, never restate the number."""
    text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'dynamic = ["version"]' in text
    assert 'version = { attr = "tatar_relay.__version__" }' in text
    # a second literal is exactly what drifted before
    assert not re.search(r'(?m)^version\s*=\s*"', text), \
        "pyproject.toml restates the version; it must read __version__ instead"


def test_the_source_of_truth_holds_a_plain_release_number():
    """A literal the changelog heading and the tag can both match verbatim.

    `0.6.1.dev0` or `v0.6.1` would still import fine and would still satisfy
    the checks below only by accident, so pin the shape here rather than
    discover it through a confusing changelog mismatch.
    """
    assert re.fullmatch(r"\d+\.\d+(\.\d+)?", tatar_relay.__version__), (
        f"tatar_relay.__version__ is {tatar_relay.__version__!r}; the single "
        f"source of truth holds a bare x.y.z, matching the CHANGELOG heading"
    )


def test_changelog_newest_entry_matches_the_package_version():
    """The top `## [x.y.z]` heading is what shipped, so it is what we report."""
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    headings = re.findall(r"(?m)^## \[(\d+\.\d+(?:\.\d+)?)\]", text)
    assert headings, "CHANGELOG.md has no '## [x.y.z]' release heading"
    assert headings[0] == tatar_relay.__version__, (
        f"CHANGELOG.md documents {headings[0]} as the newest release but "
        f"tatar_relay.__version__ is {tatar_relay.__version__}"
    )


def test_cli_version_flag_prints_the_package_version(capsys):
    """Assert on what argparse actually prints, not on the action's attribute.

    `--version` exits the process, so the string a user sees is only ever
    produced by this path; checking `action.version` would still pass if the
    parser stopped wiring the action up at all.
    """
    from tatar_relay.cli import build_parser
    with pytest.raises(SystemExit) as exit_info:
        build_parser().parse_args(["--version"])
    assert exit_info.value.code == 0
    printed = capsys.readouterr().out.strip()
    assert printed == f"tatar-relay {tatar_relay.__version__}", \
        f"`relay --version` printed {printed!r}"


def test_installed_distribution_metadata_matches_the_package():
    """The dynamic version must actually resolve when the package is built.

    This is the half `test_pyproject_reads_the_version_from_the_package` cannot
    see: pyproject can be spelled correctly and still produce the wrong number
    if the attr path is stale. Skipped on a bare source checkout, where there is
    no installed distribution to ask; CI installs with `pip install -e .[dev]`
    and so does run it.
    """
    from importlib.metadata import PackageNotFoundError, version
    try:
        installed = version("tatar-relay")
    except PackageNotFoundError:
        pytest.skip("tatar-relay is not installed; run `pip install -e .[dev]`")
    assert installed == tatar_relay.__version__, (
        f"the installed tatar-relay distribution reports {installed} but "
        f"tatar_relay.__version__ is {tatar_relay.__version__} — reinstall, or "
        f"pyproject's dynamic version no longer resolves"
    )


def test_contributing_names_the_single_source_of_truth():
    """A rule nobody wrote down is a rule that gets broken on the next release."""
    contributing = ROOT / "CONTRIBUTING.md"
    assert contributing.exists(), \
        "CONTRIBUTING.md is missing; it documents which file owns the version"
    text = contributing.read_text(encoding="utf-8")
    assert SOURCE_OF_TRUTH in text, (
        f"CONTRIBUTING.md must name {SOURCE_OF_TRUTH} as the version's single "
        f"source of truth"
    )
