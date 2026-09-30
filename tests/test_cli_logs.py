"""A hook's `ctx.log()` breadcrumbs must reach the CLI operator on FAILURE.

`Engine._attach_logs` collects them into `DecryptError.detail['logs']` so the
bridge can return them, but `DecryptError.__str__` omits `detail` and cli.main
printed only `f"✗ {e}"` — so on the command line the logs were gathered and then
dropped, which is the one moment they exist for. `_drain_logs` only runs after a
step that *succeeds*, so the failing step's own breadcrumbs were never shown
either way.

`relay preview` had a second gap: it calls `step.forward` directly and so never
goes through `Engine._run`, meaning nothing attached the logs to the error at
all.
"""
import pytest

from tatar_relay.cli import main

HOOK = '''\
def noisy_ok(data, ctx):
    ctx.log("step one ok")
    return bytes(data)


def noisy_fail(data, ctx):
    ctx.log(f"hook saw {len(data)} bytes")
    ctx.log("about to fail", "warn")
    raise ValueError("boom")


def quiet_ok(data, ctx):
    return bytes(data)
'''

PROFILE = """
name: logs-demo
security: {{ allow_python_hooks: true }}
scope: {{ hosts: [ "api.example.com" ] }}
request:
  envelope: {{ locate: [ {{ in: raw }} ] }}
  transform:
{steps}
"""

_STEP = ('    - python: {{ file: "hooks/h.py", forward: "{fn}", '
         'backward: "{fn}" }}')


@pytest.fixture
def setup(tmp_path):
    def _mk(*fns: str):
        (tmp_path / "hooks").mkdir(exist_ok=True)
        (tmp_path / "hooks" / "h.py").write_text(HOOK, encoding="utf-8")
        prof = tmp_path / "p.yaml"
        prof.write_text(
            PROFILE.format(steps="\n".join(_STEP.format(fn=f) for f in fns)),
            encoding="utf-8")
        wire = tmp_path / "wire.bin"
        wire.write_bytes(b"abcdef")
        return str(prof), str(wire)
    return _mk


def test_run_shows_the_logs_of_the_step_that_failed(setup, capsys):
    prof, wire = setup("noisy_fail")
    assert main(["run", prof, "-i", wire]) == 2
    err = capsys.readouterr().err
    assert "[hook_error]" in err
    assert "· info: hook saw 6 bytes" in err
    assert "· warn: about to fail" in err


def test_preview_shows_the_logs_of_the_step_that_failed(setup, capsys):
    """preview bypasses Engine._run, so it has to attach them itself."""
    prof, wire = setup("noisy_fail")
    assert main(["preview", prof, "-i", wire]) == 2
    err = capsys.readouterr().err
    assert "[hook_error]" in err
    assert "· info: hook saw 6 bytes" in err
    assert "· warn: about to fail" in err


def test_preview_does_not_repeat_logs_it_already_printed(setup, capsys):
    """The `since` slice: a successful step's logs print once, on stdout."""
    prof, wire = setup("noisy_ok", "noisy_fail")
    assert main(["preview", prof, "-i", wire]) == 2
    out, err = capsys.readouterr()
    assert "· info: step one ok" in out          # drained when step one passed
    assert "step one ok" not in err              # and NOT attached to the error
    assert "· warn: about to fail" in err


def test_a_clean_run_adds_no_log_noise(setup, capsys):
    prof, wire = setup("quiet_ok")
    assert main(["run", prof, "-i", wire]) == 0
    assert capsys.readouterr().err == ""


def test_an_error_with_no_logs_prints_no_bullet(setup, capsys):
    """A failure that logged nothing must not grow an empty bullet list."""
    prof, wire = setup("quiet_ok")
    assert main(["run", prof, "-i", wire, "--host", "evil.attacker.example"]) == 2
    err = capsys.readouterr().err
    assert "scope" in err.lower() and " · " not in err
