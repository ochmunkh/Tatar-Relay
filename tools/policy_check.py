#!/usr/bin/env python3
"""Repository policy guard — keeps disallowed names out of the public repo.

Project rule: the public repository must never contain specific organisation /
product names, company names, or AI-tool attribution. Crypto is described by
algorithm name only.

The disallowed tokens are stored here ONLY as SHA-256 digests, so this file
does not itself publish the names it guards against. Output never prints a
matched token either — only the file/line and a short digest prefix — so CI
logs stay clean too.

Usage:
    python tools/policy_check.py            # scan tracked files (HEAD tree)
    python tools/policy_check.py commits    # scan every commit message + author

Exit status 0 = clean, 1 = findings.
"""
from __future__ import annotations

import hashlib
import io
import re
import subprocess
import sys
import zipfile
from pathlib import Path
from typing import Iterable, Iterator, List, Set, Tuple

ROOT = Path(__file__).resolve().parent.parent

# sha256(lowercase token). Edit with care: add a digest, never a plain name.
DISALLOWED: Set[str] = {
    "2d35fcfe45d5b37278f7010b09307f53bc93d4ed299663165465e2385cdc4a6c",
    "a00725d436f6420d594c88c94a3bcc1fa2c1806da9d5d6f578a065fd1e5e142f",
    "1b2455e9fef29158f799dcf9076248a8e13cc42199514a13638ef3a18f43244d",
    "6b347fbd1d8c2eae4cebc3923b86187ac7f7afea91da4929777fd58688cec5f2",
    "724ec1a3f9b8f747b32cd757444071a2ea9338c2b64bc319ec0f85b635f52b21",
    "1ef393f2c0772064cae9403f23e7f8fc6d49bb2939f463f23c4e637231e84da4",
    "f7ee2caecd9fa24aa89d26def1c0e20f75c1e5ebea4316c655f6967502571a50",
    "ac17a9cb6ec242a67263a248f8d5ffa7e2b026acf110517bfccf2ba60a435f0d",
    "766111729f7ab532e056f8738d5abee1fc8b609812c7565267ef7dd21119bde7",
    "fd28b6e8bdc03aa125e8e9336dbbbc7f6319b2b45486dc48546ace54fac0da03",
    "3da9dd9babe178f1426a7ef54c2eab406978f8be157070ec4bea6b38a19354d4",
    "8f3aa6dc3ef013603d97b89bb62a487fbb704c6d5b7b65047bb9408f82a12a58",
    "39cadfc09c25a64652039810e09994854656c7e578f82fdb76585ea9b1f5bdc8",
    "58020fe0349e63f42d77742edbf1664af38a89cb880a6dcf0b6e087970cad29a",
    "c70eca6b0f88f44d81a41311647e50fda1ac454ec04ffd442b0eb4743a993131",
    "c857d09db23e6822e3600bc06ad8d58f92ed62bc8efd81c753f77048662cb97d",
    "0002dabb0f9d5511113d9e95ddc1cac604f88624339fc5358e579a7420a6585b",
}

# Commit authors that must never appear (automation would land in Contributors).
BOT_AUTHOR = re.compile(r"\[bot\]|dependabot|renovate", re.I)

_TOKEN = re.compile(rb"[a-z0-9]+")
_PRINTABLE = re.compile(rb"[\x20-\x7e]{4,}")
_ZIP_EXT = {".pptx", ".docx", ".xlsx", ".zip", ".jar", ".odt", ".odp"}
_SKIP = {"tools/policy_check.py"}


def _digest(tok: bytes) -> str:
    return hashlib.sha256(tok).hexdigest()


def find_tokens(data: bytes, digests: Set[str] = DISALLOWED) -> Iterator[Tuple[int, str]]:
    """Yield (line_no, digest) for each disallowed token in ``data``."""
    for no, line in enumerate(data.lower().splitlines(), 1):
        for tok in _TOKEN.findall(line):
            d = _digest(tok)
            if d in digests:
                yield no, d


def _binary_text(data: bytes) -> bytes:
    """Printable runs from a binary file (catches embedded metadata)."""
    return b"\n".join(_PRINTABLE.findall(data))


def scan_blob(name: str, data: bytes, digests: Set[str] = DISALLOWED) -> List[str]:
    out: List[str] = []
    suffix = Path(name).suffix.lower()
    if suffix in _ZIP_EXT:
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for member in z.namelist():
                    for line in scan_blob(f"{name}!{member}", z.read(member), digests):
                        out.append(line)
            return out
        except zipfile.BadZipFile:
            pass
    text = data if b"\x00" not in data[:8192] else _binary_text(data)
    for no, d in find_tokens(text, digests):
        out.append(f"{name}:{no}: disallowed token (sha256 {d[:12]}…)")
    return out


def tracked_files() -> List[str]:
    try:
        res = subprocess.run(["git", "ls-files", "-z"], cwd=ROOT, check=True,
                             capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        return []
    return [p for p in res.stdout.decode("utf-8", "replace").split("\0") if p]


def scan_tree(files: Iterable[str] | None = None) -> List[str]:
    findings: List[str] = []
    for rel in files if files is not None else tracked_files():
        if rel in _SKIP:
            continue
        path = ROOT / rel
        if not path.is_file():
            continue
        findings.extend(scan_blob(rel, path.read_bytes()))
    return findings


def check_commit(message: str, author: str, sha: str = "?",
                 digests: Set[str] = DISALLOWED) -> List[str]:
    out = [f"commit {sha[:10]}: message line {no}: disallowed token (sha256 {d[:12]}…)"
           for no, d in find_tokens(message.encode("utf-8"), digests)]
    if BOT_AUTHOR.search(author):
        out.append(f"commit {sha[:10]}: automated author not allowed ({author})")
    return out


def scan_commits(rev: str = "HEAD") -> List[str]:
    fmt = "%H%x1f%an <%ae>%x1f%B%x1e"
    res = subprocess.run(["git", "log", rev, f"--format={fmt}"], cwd=ROOT,
                         check=True, capture_output=True)
    findings: List[str] = []
    for rec in res.stdout.decode("utf-8", "replace").split("\x1e"):
        rec = rec.strip("\n")
        if not rec:
            continue
        sha, author, msg = (rec.split("\x1f") + ["", ""])[:3]
        findings.extend(check_commit(msg, author, sha))
    return findings


def main(argv: List[str]) -> int:
    mode = argv[1] if len(argv) > 1 else "tree"
    findings = scan_commits() if mode == "commits" else scan_tree()
    for f in findings:
        print(f)
    label = "commit history" if mode == "commits" else "tracked files"
    print(f"policy_check: {len(findings)} finding(s) in {label}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
