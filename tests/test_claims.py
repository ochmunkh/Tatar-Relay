"""The claim <-> test gate (tools/claims_check.py), and a meta-test that it
actually catches a threat model drifting away from the code."""
import importlib.util
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("claims_check", ROOT / "tools" / "claims_check.py")
claims = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(claims)


def _clone(tmp_path):
    dst = tmp_path / "repo"
    shutil.copytree(ROOT / "tatar_relay", dst / "tatar_relay")
    shutil.copytree(ROOT / "tools", dst / "tools")
    shutil.copytree(ROOT / "tests", dst / "tests",
                    ignore=shutil.ignore_patterns("__pycache__", "*_local.py"))
    shutil.copytree(ROOT / ".github", dst / ".github")
    shutil.copy(ROOT / "THREAT_MODEL.md", dst / "THREAT_MODEL.md")
    return dst


def test_real_threat_model_is_consistent():
    assert claims.check(ROOT) == []


def test_clone_is_clean_baseline(tmp_path):
    assert claims.check(_clone(tmp_path)) == []


def test_missing_cited_test_is_caught(tmp_path):
    repo = _clone(tmp_path)
    (repo / "tests" / "test_scope_gate.py").unlink()
    out = claims.check(repo)
    assert any("test_scope_gate.py does not exist" in f for f in out)


def test_test_without_functions_is_caught(tmp_path):
    repo = _clone(tmp_path)
    (repo / "tests" / "test_schema_version.py").write_text("# emptied\n")
    assert any("contains no test function" in f for f in claims.check(repo))


def test_uncited_security_test_is_caught(tmp_path):
    repo = _clone(tmp_path)
    (repo / "tests" / "test_new_hardening.py").write_text("def test_x():\n    pass\n")
    assert any("test_new_hardening.py: security test not cited" in f
               for f in claims.check(repo))


def test_renamed_symbol_is_caught(tmp_path):
    repo = _clone(tmp_path)
    for p in (repo / "tatar_relay").rglob("*.py"):
        s = p.read_text(encoding="utf-8")
        if "require_safe_bind" in s:
            p.write_text(s.replace("require_safe_bind", "renamed_guard"), encoding="utf-8")
    assert any("require_safe_bind" in f and "not found" in f for f in claims.check(repo))


def test_claim_without_evidence_and_id_gap_are_caught(tmp_path):
    repo = _clone(tmp_path)
    tm = repo / "THREAT_MODEL.md"
    tm.write_text(tm.read_text(encoding="utf-8")
                  + "| T16 | x | y | claim with no evidence | nothing |\n", encoding="utf-8")
    out = claims.check(repo)
    assert any("T16: cites no test" in f for f in out)
    assert any("contiguous" in f for f in out)
