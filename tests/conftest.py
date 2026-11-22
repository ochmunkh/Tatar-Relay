"""Shared pytest wiring.

Records how many tests the suite collects so tests/test_docs_consistency.py can
check the README's "NNN tests" claim without shelling out to a second pytest
(the suite runs in well under a second; a subprocess would dominate it).
"""
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent

_collection: dict = {}


def _is_local_only(name: str) -> bool:
    """``tests/test_*_local.py`` is the gitignored convention for an operator's
    private tests. They never reach CI, so they must not count toward the
    documented total — otherwise a local run and CI disagree by one file's
    worth of tests and the docs check fails in one place or the other."""
    return name.startswith("test_") and name.endswith("_local.py")


def pytest_collection_modifyitems(session, config, items):
    shared = [i for i in items if not _is_local_only(Path(str(i.fspath)).name)]
    _collection["count"] = len(shared)
    _collection["files"] = {Path(str(i.fspath)).name for i in shared}


@pytest.fixture
def full_suite_test_count() -> int:
    """Tests collected by the FULL suite, or skip when this is a partial run.

    Running a single file collects a handful of tests, which says nothing about
    whether the README's total is right — so only assert on a complete run.
    Local-only test files are excluded on both sides of the comparison.
    """
    on_disk = {p.name for p in TESTS_DIR.glob("test_*.py") if not _is_local_only(p.name)}
    if _collection.get("files") != on_disk:
        missing = sorted(on_disk - _collection.get("files", set()))
        pytest.skip(f"partial run (not collected: {missing}); the documented "
                    f"test count is only checked on a full run")
    return _collection["count"]
