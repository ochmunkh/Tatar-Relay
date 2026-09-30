# Contributing to Tatar Relay

> **Translation wanted.** This file is English-only for now. The project's
> README and quickstart are bilingual on purpose (see *Documentation* below);
> a Mongolian counterpart to this guide is welcome and should be written by a
> Mongolian speaker, not machine-translated.

## Getting set up

```bash
git clone https://github.com/ochmunkh/Tatar-Relay
cd Tatar-Relay
pip install -e ".[dev]"
pytest -q
```

`[dev]` pulls in pytest; `[mitmproxy]` pulls in the proxy frontend. The test
suite is offline and takes well under a second — run it before every commit.

## The version has exactly one source of truth

**`tatar_relay/__init__.py` — the `__version__` literal. Nothing else.**

A release bumps that one line. Everything else derives from it or is checked
against it:

| Place | How it gets the version |
| --- | --- |
| `pyproject.toml` | `dynamic = ["version"]` + `version = { attr = "tatar_relay.__version__" }` — setuptools reads the attribute, so the number is never restated here |
| `relay --version` | `tatar_relay/cli.py` formats `__version__` |
| installed metadata (`pip show tatar-relay`) | comes from `pyproject.toml`, so from `__version__` |
| `CHANGELOG.md` | the newest `## [x.y.z]` heading must equal `__version__` — this one is not derived, it is *checked* |

This is not a style preference. `relay --version` printed `0.1.0` at tag
`v0.6.1` because `pyproject.toml` and `__init__.py` were two hand-maintained
copies, and the one string a user pastes into a bug report was the wrong one.

[`tests/test_version.py`](tests/test_version.py) fails the build if any of
those four disagree, and also fails if someone reintroduces a second literal in
`pyproject.toml`.

### Cutting a release

1. Edit `__version__` in `tatar_relay/__init__.py`.
2. Rename the `## [Unreleased]` heading in `CHANGELOG.md` to `## [x.y.z] — YYYY-MM-DD`
   and open a fresh `## [Unreleased]` above it.
3. `pytest -q` — `tests/test_version.py` confirms the four places agree.
4. Tag `vx.y.z`.

Nothing else needs touching. In particular, do **not** add a `version = "..."`
line to `pyproject.toml`; the test rejects it.

The Burp extension in [`burp/`](burp/) carries its own, independent version
(`burp/build.gradle`) because it ships as a separate `.jar`. It is deliberately
not tied to the Python package version.

## Documentation

- **`README.md` is bilingual and stays bilingual.** It has an English half
  (`## English`) and a Mongolian half (`## Монгол`). Both halves are a product
  decision for a Mongolian-speaking audience — never delete one, and never
  machine-translate one into the other. If you add a section to one half and
  cannot write idiomatic technical Mongolian, say so in your pull request so a
  Mongolian speaker can write the counterpart.
- [`tools/readme_parity.py`](tools/readme_parity.py) compares the two halves
  structurally — heading count, fenced code-block count, table row count — and
  fails with the specific mismatch. CI runs it as its own step, and
  `tests/test_docs_consistency.py` runs the same comparison:

  ```bash
  python3 tools/readme_parity.py
  ```

- `tests/test_docs_consistency.py` also checks that every documented test count
  matches what pytest collects, and that every backticked file link in the
  top-level docs resolves on disk. If you add or remove tests, update the counts
  in **both** README halves and in the newest `CHANGELOG.md` entry.
- The five frozen contracts in [`CONTRACTS.md`](CONTRACTS.md) are frozen:
  additive changes only, never a breaking one.

## The Burp extension

Building it needs a JDK, not Gradle — see [`burp/BUILD.md`](burp/BUILD.md) for
the exact commands.

## CI

[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs on every push and
pull request: install with the `dev` extra, a scoped `ruff` pass (only the
rules that flag real errors — syntax, undefined names, broken asserts), the
README parity check, then `pytest -q`. It does not build the Burp extension.

## Scope of a change

- Python hooks are arbitrary code execution, so untrusted profiles stay
  declarative-only and scope stays fail-closed. Do not relax either default.
- Transform steps must stay reversible: `decrypt(encrypt(x)) == x` is enforced
  by the suite.
- Add a test with every fix. Never weaken or delete a test to go green.

## Licence

MIT. By contributing you agree your contribution is licensed under it.
