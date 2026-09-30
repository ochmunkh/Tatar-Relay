"""Shared pytest wiring.

Records how many tests the suite collects so tests/test_docs_consistency.py can
check the README's "NNN tests" claim without shelling out to a second pytest
(the suite runs in well under a second; a subprocess would dominate it).
"""
from pathlib import Path

import pytest

TESTS_DIR = Path(__file__).resolve().parent

_collection: dict = {}


def pytest_collection_modifyitems(session, config, items):
    _collection["count"] = len(items)
    _collection["files"] = {Path(str(item.fspath)).name for item in items}


@pytest.fixture
def full_suite_test_count() -> int:
    """Tests collected by the FULL suite, or skip when this is a partial run.

    Running a single file collects a handful of tests, which says nothing about
    whether the README's total is right — so only assert on a complete run.
    """
    on_disk = {p.name for p in TESTS_DIR.glob("test_*.py")}
    if _collection.get("files") != on_disk:
        missing = sorted(on_disk - _collection.get("files", set()))
        pytest.skip(f"partial run (not collected: {missing}); the documented "
                    f"test count is only checked on a full run")
    return _collection["count"]
