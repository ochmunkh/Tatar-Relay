import base64
import json
import os

from tatar_relay.inspect import fingerprint, analyze, draft_profile


def test_fingerprint_json_envelope():
    body = json.dumps({
        "data": base64.b64encode(os.urandom(48)).decode(),
        "iv": os.urandom(12).hex(),
        "sig": os.urandom(32).hex(),
    }).encode()
    fp = fingerprint(body)
    assert fp.is_json
    assert fp.cipher_field == "data"
    assert fp.json_fields.get("iv") == "iv"
    assert fp.json_fields.get("sig") == "sig"


def test_fingerprint_aead_blob():
    blob = base64.b64encode(os.urandom(12 + 40 + 16)).decode().encode()  # non-block length
    fp = fingerprint(blob)
    assert fp.outer_encoding == "base64"
    assert fp.cipher_guess == "aead"


def test_fingerprint_cbc_blob():
    blob = base64.b64encode(os.urandom(48)).decode().encode()  # multiple of 16
    fp = fingerprint(blob)
    assert fp.cipher_guess in ("aes-cbc", "aes-ecb")


def test_analyze_backcompat():
    guesses, pipeline = analyze(base64.b64encode(os.urandom(64)).decode().encode())
    assert any(g.name == "base64" for g in guesses)
    assert "as_json" in pipeline[-1]


def test_draft_profile_uses_observation():
    blob = base64.b64encode(os.urandom(60)).decode().encode()
    obs = [{"lib": "WebCrypto", "api": "encrypt", "algorithm": "AES-GCM",
            "mode": "GCM", "keyLen": 32, "ivLen": 12}]
    y = draft_profile(blob, name="acme", observations=obs)
    assert "mode: gcm" in y
    assert "length: 12" in y
    assert "from JS observation" in y
    assert "name: \"acme\"" in y


def test_draft_profile_json_field_and_sig():
    body = json.dumps({"payload": base64.b64encode(os.urandom(48)).decode(),
                       "mac": os.urandom(32).hex()}).encode()
    y = draft_profile(body, name="t")
    assert "json_field, field: \"payload\"" in y
    assert "into: mac" in y  # sign step targets the detected signature field
