#!/usr/bin/env python3
"""Structural parity check for the bilingual README.

README.md carries an English half (``## English``) and a Mongolian half
(``## Монгол``). Both halves are a product decision: a Mongolian-speaking
reader is meant to get the same document, not a summary of it. What actually
happens is that a change lands in one half and is forgotten in the other, and
the halves drift — the Mongolian half was once missing ``### Development``
entirely, so a Mongolian-speaking contributor never learned about ``pytest``.

A script cannot judge a translation, so this judges *structure* — the part
that is language-independent and that drift shows up in first:

  * ``###``-and-deeper section headings (count, plus both lists in the message)
  * fenced code blocks
  * table rows

Anything inside a fenced block is skipped, so a ``#`` line in a sample or a
pipe-delimited line in an ASCII diagram is not mistaken for structure.

Usage::

    python3 tools/readme_parity.py [README.md]

Exit status: 0 when the halves match, 1 when they have drifted, 2 when the
README is not shaped the way this check expects (missing/mis-ordered heading,
unclosed code fence) — that is a broken check, not a drift report, and it is
reported separately so CI does not mistake one for the other.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_README = ROOT / "README.md"

ENGLISH_HEADING = "## English"
MONGOLIAN_HEADING = "## Монгол"

_HEADING = re.compile(r"^#{3,6} +(.+?)\s*$")


class ReadmeShapeError(RuntimeError):
    """The README is not shaped the way this check expects."""


def split_halves(text: str) -> tuple[list[str], list[str]]:
    """Return (english_lines, mongolian_lines).

    The Mongolian half runs to the end of the file: it is deliberately last so
    that neither half needs a terminator nobody remembers to move.
    """
    lines = text.split("\n")
    for marker in (ENGLISH_HEADING, MONGOLIAN_HEADING):
        if marker not in lines:
            raise ReadmeShapeError(
                f"no {marker!r} heading — the bilingual README must keep both "
                f"halves; do not drop one to make this check pass"
            )
    english_at = lines.index(ENGLISH_HEADING)
    mongolian_at = lines.index(MONGOLIAN_HEADING)
    if mongolian_at < english_at:
        raise ReadmeShapeError(
            f"{MONGOLIAN_HEADING!r} (line {mongolian_at + 1}) comes before "
            f"{ENGLISH_HEADING!r} (line {english_at + 1}); this check assumes "
            f"English first, Монгол last"
        )
    return lines[english_at:mongolian_at], lines[mongolian_at:]


def measure(lines: list[str], half: str) -> dict:
    """Count the structural features of one half."""
    headings: list[str] = []
    fence_lines = 0
    table_rows = 0
    in_fence = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("```"):
            in_fence = not in_fence
            fence_lines += 1
            continue
        if in_fence:
            continue
        match = _HEADING.match(line)
        if match:
            headings.append(match.group(1))
        elif stripped.startswith("|") and stripped.endswith("|") and len(stripped) > 1:
            table_rows += 1
    if in_fence:
        raise ReadmeShapeError(f"the {half} half has an unclosed ``` code fence")
    return {
        "headings": headings,
        "code_blocks": fence_lines // 2,
        "table_rows": table_rows,
    }


def analyse(text: str) -> tuple[dict, dict]:
    """Measure both halves of the README in one pass."""
    english_lines, mongolian_lines = split_halves(text)
    return (measure(english_lines, "English"),
            measure(mongolian_lines, "Монгол"))


def compare(text: str) -> list[str]:
    """Return one message per structural mismatch; empty means the halves match."""
    return problems(*analyse(text))


def problems(english: dict, mongolian: dict) -> list[str]:
    """The mismatches between two already-measured halves."""
    found: list[str] = []
    if len(english["headings"]) != len(mongolian["headings"]):
        found.append(
            "section headings: English has {}, Монгол has {}\n"
            "      English: {}\n"
            "      Монгол : {}\n"
            "      Add the missing section to the shorter half — never remove "
            "one from the longer.".format(
                len(english["headings"]), len(mongolian["headings"]),
                english["headings"], mongolian["headings"],
            )
        )
    if english["code_blocks"] != mongolian["code_blocks"]:
        found.append(
            "fenced code blocks: English has {}, Монгол has {} — a command a "
            "reader of one half can copy and a reader of the other cannot"
            .format(english["code_blocks"], mongolian["code_blocks"])
        )
    if english["table_rows"] != mongolian["table_rows"]:
        found.append(
            "table rows: English has {}, Монгол has {} — a row was added to or "
            "removed from one table only".format(
                english["table_rows"], mongolian["table_rows"])
        )
    return found


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    path = Path(argv[0]) if argv else DEFAULT_README
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"README parity: cannot read {path}: {exc}", file=sys.stderr)
        return 2
    try:
        english, mongolian = analyse(text)
        mismatches = problems(english, mongolian)
    except ReadmeShapeError as exc:
        print(f"README parity: {path} is malformed: {exc}", file=sys.stderr)
        return 2

    counts = (
        f"headings {len(english['headings'])}/{len(mongolian['headings'])}, "
        f"code blocks {english['code_blocks']}/{mongolian['code_blocks']}, "
        f"table rows {english['table_rows']}/{mongolian['table_rows']}"
        "  (English/Монгол)"
    )
    if not mismatches:
        print(f"README parity OK: {path} — {counts}")
        return 0

    print(f"README PARITY FAILED: {path} — {counts}", file=sys.stderr)
    print("The two halves of the bilingual README have drifted apart:",
          file=sys.stderr)
    for mismatch in mismatches:
        print(f"  * {mismatch}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
