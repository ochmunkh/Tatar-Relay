"""`relay explain` — static, secret-free pipeline view."""
from tatar_relay import cli

PROF = '''name: explain-demo
scope: { hosts: ["api.example.com"] }
request:
  envelope: { locate: [ { in: json_field, field: "data" } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: gcm, key: "deadbeefdeadbeefdeadbeefdeadbeef" }
    - as_json
'''


def test_explain_shows_pipeline_types_and_schema(tmp_path, capsys):
    p = tmp_path / "p.yaml"
    p.write_text(PROF, encoding="utf-8")
    rc = cli.main(["explain", str(p)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "aes_decrypt" in out
    assert "bytes -> json" in out
    assert "schema v1" in out
    assert "json_field 'data'" in out


def test_explain_redacts_literal_key(tmp_path, capsys):
    p = tmp_path / "p.yaml"
    p.write_text(PROF, encoding="utf-8")
    cli.main(["explain", str(p)])
    out = capsys.readouterr().out
    # a literal (non-template) key must never be printed
    assert "deadbeef" not in out
    assert "<redacted>" in out
