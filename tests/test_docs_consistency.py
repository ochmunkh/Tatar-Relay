"""Guards against documentation drift, which is the recurring cost in this repo.

Three cheap, offline checks:

  1. Every "NNN tests" / "NNN тест" claim matches what pytest actually collects.
     Both halves of the README and the newest changelog entry claimed 125
     against 124 collected.
  2. The bilingual README's two halves stay structurally level — same number
     of `###` sections, fenced code blocks and table rows. The Mongolian half
     was missing `### Development` and `### Roadmap`, so a Mongolian-speaking
     contributor reading their half never learned `pip install -e .[dev]` or
     `pytest`. The bilingual README is a deliberate product decision, so the
     guard keeps the halves level — it never argues for dropping one. The
     comparison itself lives in `tools/readme_parity.py` so CI can run it on
     its own; this only asserts that it finds nothing.
  3. Every ``[`file`](path)`` link in the docs points at something on disk.

The collected count comes from conftest.py's `full_suite_test_count` fixture,
which skips rather than lies when only part of the suite was run.
"""
import importlib.util
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent

# Files whose test-count claims must stay true.
COUNT_SOURCES = ("README.md",)

# Markdown files whose links must resolve.
LINK_SOURCES = ["README.md", "CONTRACTS.md", "CHANGELOG.md", "CONTRIBUTING.md"] + [
    f"docs/{p.name}" for p in sorted((ROOT / "docs").glob("*.md"))
]

# Two shapes of claim:
#   prose  "232 tests", "232 тест"        -> digits BEFORE the word
#   badge  "badge/tests-232-brightgreen"  -> digits AFTER it
# The badge form arrived with the CI/release commit from origin/main carrying a
# stale 125, and the prose-only pattern did not see it.
_COUNT_CLAIM = re.compile(
    r"(?:(\d+)\s*(?:tests|test|тест)\b"
    r"|(?:tests|test|тест)-(\d+)(?:-|\b))"
)
_LINK = re.compile(r"\[`([^`]+)`\]\(([^)]+)\)")


def _newest_changelog_entry() -> str:
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    parts = re.split(r"(?m)^## \[", text)
    # parts[0] is the preamble; parts[1] is the newest release section
    return parts[1] if len(parts) > 1 else text


# ---- 1. test-count claims ------------------------------------------------

def test_test_count_claims_match_what_pytest_collects(full_suite_test_count):
    actual = full_suite_test_count
    wrong = []
    sources = [(name, (ROOT / name).read_text(encoding="utf-8"))
               for name in COUNT_SOURCES]
    # only the newest changelog entry: older entries are a historical record
    sources.append(("CHANGELOG.md (newest entry)", _newest_changelog_entry()))
    for name, text in sources:
        for before, after in _COUNT_CLAIM.findall(text):
            claimed = before or after
            if int(claimed) != actual:
                wrong.append(f"{name}: claims {claimed}")
    assert not wrong, (
        f"pytest collects {actual} tests, but: {'; '.join(wrong)}"
    )


# ---- 2. the bilingual README's halves stay level -------------------------

def _readme_parity():
    """Load tools/readme_parity.py, the script CI runs, without installing it."""
    path = ROOT / "tools" / "readme_parity.py"
    assert path.exists(), f"{path} is missing; CI runs it as its own step"
    spec = importlib.util.spec_from_file_location("readme_parity", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _readme_halves():
    parity = _readme_parity()
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    return parity.analyse(text)


def test_the_readme_halves_match_structurally():
    parity = _readme_parity()
    text = (ROOT / "README.md").read_text(encoding="utf-8")
    problems = parity.compare(text)
    assert not problems, (
        "the README halves have drifted apart:\n  "
        + "\n  ".join(problems)
    )


def test_neither_readme_half_is_empty():
    english, mongolian = _readme_halves()
    assert english["headings"] and mongolian["headings"]


# ---- 3. links resolve ----------------------------------------------------

@pytest.mark.parametrize("name", LINK_SOURCES)
def test_document_links_exist_on_disk(name):
    path = ROOT / name
    broken = []
    for label, target in _LINK.findall(path.read_text(encoding="utf-8")):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        target = target.split("#", 1)[0]
        if not target:
            continue
        if not (path.parent / target).exists():
            broken.append(f"[`{label}`]({target})")
    assert not broken, f"{name} links to missing paths: {broken}"
