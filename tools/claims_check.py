#!/usr/bin/env python3
"""Claim <-> test gate for THREAT_MODEL.md.

Every threat row (``| T<n> | ...``) is a claim about the tool. A claim that
cites a test or code location that no longer exists is a silent lie, and a
security test that no claim cites is an unexplained guarantee. This gate fails
on both, so the threat model cannot drift away from the code.

Checks (exit 1 with one line per finding):
  1. threat ids are T1..Tn, contiguous and unique;
  2. every row cites at least one test file, workflow or tool;
  3. every cited tests/test_*.py exists and contains a test function;
  4. every cited workflow / tool / source path exists;
  5. every cited code symbol (last column) still appears in the source;
  6. every security-relevant test file is cited by some claim.

Usage:  python tools/claims_check.py [--root DIR]
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

DEFAULT_ROOT = Path(__file__).resolve().parent.parent

ROW = re.compile(r"^\|\s*T(\d+)\s*\|(.*)\|\s*$")
TICK = re.compile(r"`([^`]+)`")
IDENT = re.compile(r"^[A-Za-z_][\w.]*$")

# A test file whose name matches is a security test and must back a claim.
SECURITY_TEST = re.compile(
    r"hardening|scope_gate|policy|schema_version|capture_exposure|timeout|fuzz|"
    r"hostile|hook_contract|reseal_and_bridge_auth|unsupported_cipher|"
    r"hmac_verify|explain")


def _rows(text: str):
    for line in text.splitlines():
        m = ROW.match(line.strip())
        if m:
            cells = [c.strip() for c in m.group(2).split("|")]
            yield int(m.group(1)), cells


def _source_text(root: Path) -> str:
    parts = []
    for d in ("tatar_relay", "tools"):
        for p in sorted((root / d).rglob("*.py")):
            parts.append(p.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(parts)


def check(root: Path = DEFAULT_ROOT) -> list[str]:
    root = Path(root)
    findings: list[str] = []
    tm = root / "THREAT_MODEL.md"
    if not tm.is_file():
        return ["THREAT_MODEL.md: missing"]
    rows = list(_rows(tm.read_text(encoding="utf-8")))
    if not rows:
        return ["THREAT_MODEL.md: no threat rows (| T<n> | ...) found"]

    ids = [n for n, _ in rows]
    if ids != list(range(1, len(ids) + 1)):
        findings.append(f"THREAT_MODEL.md: threat ids must be T1..T{len(ids)} "
                        f"contiguous and unique, got {ids}")

    src = _source_text(root)
    cited_tests: set[str] = set()

    for n, cells in rows:
        where = cells[-1] if cells else ""
        row_text = " ".join(cells)
        tests = set(re.findall(r"test_\w+\.py", row_text))
        flows = set(re.findall(r"\.github/workflows/[\w.-]+\.yml", row_text))
        tools = set(re.findall(r"tools/[\w.-]+\.py", row_text))
        if not (tests or flows or tools):
            findings.append(f"T{n}: cites no test, workflow or tool")

        for t in sorted(tests):
            f = root / "tests" / t
            if not f.is_file():
                findings.append(f"T{n}: cited test {t} does not exist")
            elif not re.search(r"^def test_\w+|^\s+def test_\w+",
                               f.read_text(encoding="utf-8"), re.M):
                findings.append(f"T{n}: cited test {t} contains no test function")
            cited_tests.add(t)
        for p in sorted(flows | tools):
            if not (root / p).is_file():
                findings.append(f"T{n}: cited path {p} does not exist")

        for tok in TICK.findall(where):
            tok = tok.strip()
            if tok.endswith(".py") or tok.endswith(".yml") or "/" in tok:
                continue                       # files handled above / by name
            if not IDENT.match(tok):
                continue
            last = tok.split(".")[-1]
            if not re.search(r"\b" + re.escape(last) + r"\b", src):
                findings.append(f"T{n}: cited symbol `{tok}` not found in the source")
        for tok in TICK.findall(where):
            tok = tok.strip()
            if tok.endswith(".py") and "/" not in tok and not tok.startswith("test_"):
                if not list((root / "tatar_relay").rglob(tok)):
                    findings.append(f"T{n}: cited module {tok} not found under tatar_relay/")
            elif tok.startswith(("steps/",)) and tok.endswith(".py"):
                if not (root / "tatar_relay" / tok).is_file():
                    findings.append(f"T{n}: cited module {tok} does not exist")

    tdir = root / "tests"
    if tdir.is_dir():
        for f in sorted(tdir.glob("test_*.py")):
            if f.name.endswith("_local.py"):
                continue
            if SECURITY_TEST.search(f.stem) and f.name not in cited_tests:
                findings.append(f"tests/{f.name}: security test not cited by any threat claim")
    return findings


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--root", default=str(DEFAULT_ROOT))
    args = ap.parse_args(argv)
    findings = check(Path(args.root))
    for f in findings:
        print("FAIL  " + f)
    if findings:
        print(f"\n{len(findings)} claim/test problem(s)")
        return 1
    print("claims OK: every threat cites live tests/code, every security test is cited")
    return 0


if __name__ == "__main__":
    sys.exit(main())
