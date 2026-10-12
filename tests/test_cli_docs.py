"""The user guide's CLI chapter must actually parse.

docs/user-guide.md section 8 documented a `tatar-relay` binary that does not
exist (pyproject declares `relay`), gave `run` a `--port` it does not have and
`inspect` a `--profile`/`--request` pair it does not have, and named 3 of the
9 subcommands. Every command in the chapter failed. This test feeds each line of
that chapter to the real parser, so a renamed flag fails the suite instead of
rotting in the prose.

Placeholders like `<profile.yaml>` are fine: argparse never touches the
filesystem, it only checks that the flags and arity exist.
"""
import re
import shlex
from pathlib import Path

import pytest

from tatar_relay.cli import build_parser

GUIDE = Path(__file__).resolve().parent.parent / "docs" / "user-guide.md"
SECTION = re.compile(r"^## 8\. ", re.M)


def _cli_lines():
    """Every `relay ...` invocation inside section 8's bash blocks."""
    text = GUIDE.read_text(encoding="utf-8")
    start = SECTION.search(text)
    assert start, "docs/user-guide.md has no '## 8.' CLI section"
    rest = text[start.end():]
    end = re.search(r"^## 9\. ", rest, re.M)
    body = rest[: end.start()] if end else rest

    out = []
    for block in re.findall(r"```bash\n(.*?)```", body, re.S):
        for raw in block.splitlines():
            line = raw.split("#", 1)[0].strip()
            if line.startswith("relay "):
                out.append(line)
    assert out, "section 8 contains no `relay ...` command lines"
    return out


CLI_LINES = _cli_lines()


def test_the_guide_never_invokes_a_binary_that_does_not_exist():
    """`tatar-relay` is the PyPI package name, never a command to run."""
    text = GUIDE.read_text(encoding="utf-8")
    bad = [line for block in re.findall(r"```bash\n(.*?)```", text, re.S)
           for line in block.splitlines()
           if line.strip().startswith("tatar-relay ")]
    assert not bad, (
        f"the entry point is `relay` (pyproject.toml [project.scripts]); "
        f"there is no `tatar-relay` binary, but the guide runs: {bad}"
    )


@pytest.mark.parametrize("line", CLI_LINES, ids=lambda s: s[:40])
def test_documented_command_parses(line):
    argv = shlex.split(line)
    assert argv[0] == "relay"
    build_parser().parse_args(argv[1:])


def test_every_subcommand_is_documented():
    """A new subcommand must be added to the chapter, not just to the parser."""
    sub = next(a for a in build_parser()._actions if a.dest == "cmd")
    documented = {shlex.split(l)[1] for l in CLI_LINES}
    missing = set(sub.choices) - documented
    assert not missing, f"section 8 does not document: {sorted(missing)}"


def test_preview_leads_the_chapter():
    """`preview` is the step-by-step debugging view; a reader should meet it first."""
    assert shlex.split(CLI_LINES[0])[1] == "preview"
