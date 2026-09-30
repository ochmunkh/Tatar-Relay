"""Reseal signing, serialize modes, and bridge token auth.

Named for its subjects, not for the release that happened to introduce them
(it was `test_v011_fixes.py`, a version that appears nowhere else in the repo) —
so that the next person adding a sign-algorithm or serialize-mode test finds it.

Three subjects, 8 test functions:

  1. reseal `sign` — the algorithm table (hmac_sha256/512/1) and its key
     coercion. This is the ONLY coverage of `hmac_sha512`/`hmac_sha1` anywhere
     in the suite, so do not thin it.
  2. serialize `preserve` vs `compact` — `preserve` is spaced JSON, and nothing
     else asserts on the difference (other files only use it inside a profile).
  3. `BridgeService.authorize` — likewise the only coverage of bridge auth.
"""
import hashlib
import hmac as _hmac

import pytest

from tatar_relay import Profile, Engine, Context, HttpMessage
from tatar_relay.variables import VarStore
from tatar_relay.reseal import Reseal
from tatar_relay.errors import DecryptError
from tatar_relay.bridge import BridgeService


def _ctx(key=b"k" * 32):
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore(); vs.set("session_key", key)
    c.vars = vs
    c.channel = "request"
    return c


# ---- Fix 1: sign algorithms ------------------------------------------------

@pytest.mark.parametrize("algo,hashfn", [
    ("hmac_sha256", hashlib.sha256),
    ("hmac_sha512", hashlib.sha512),
    ("hmac_sha1", hashlib.sha1),
])
def test_sign_supports_algo(algo, hashfn):
    key = b"k" * 32
    payload = b'{"amount":100}'
    reseal = Reseal([
        {"sign": {"algo": algo, "key": "${session_key}",
                  "input": "${payload}", "into": "sig"}},
        {"serialize": {"mode": "compact"}},
    ])
    out = reseal.apply({"data": "x"}, payload, _ctx(key))
    import json
    got = json.loads(out)["sig"]
    expected = _hmac.new(key, payload, hashfn).hexdigest()
    assert got == expected


def test_sign_rejects_unknown_algo():
    reseal = Reseal([
        {"sign": {"algo": "hmac_md5", "key": "${session_key}",
                  "input": "${payload}", "into": "sig"}},
    ])
    with pytest.raises(DecryptError) as e:
        reseal.apply({"data": "x"}, b"body", _ctx())
    assert e.value.category == "config_error"


def test_sign_reads_a_hex_string_key_the_same_way_hmac_verify_does():
    """A hex *string* key must sign with the same bytes hmac_verify checks with.

    `hmac_verify` and reseal `sign` are the two ends of one round-trip. They had
    two different coercion rules, so a profile that extracted `session_key` from
    a JSON handshake field without `transform: [ base64_decode ]` got a str:
    hmac_verify validated with 32 hex-decoded bytes while sign re-signed with 64
    UTF-8 ones. The operator saw `signature_invalid` or a server 401 with no hint
    that the key had been read two different ways. Both now go through
    variables.coerce_key, so this asserts they agree.
    """
    import json
    from tatar_relay.steps.auth import _to_bytes

    key_hex = bytes(range(32)).hex()          # 64 chars of clean hex
    payload = b'{"amount":100}'

    def sig(key):
        out = Reseal([
            {"sign": {"algo": "hmac_sha256", "key": "${session_key}",
                      "input": "${payload}", "into": "sig"}},
            {"serialize": {"mode": "compact"}},
        ]).apply({"data": "x"}, payload, _ctx(key))
        return json.loads(out)["sig"]

    # the string and its decoded bytes must produce one MAC, not two
    assert sig(key_hex) == sig(bytes.fromhex(key_hex))
    # ...and that MAC is the one hmac_verify's own key rule produces
    assert sig(key_hex) == _hmac.new(_to_bytes(key_hex), payload,
                                     hashlib.sha256).hexdigest()


def test_sha512_differs_from_sha256():
    key = b"k" * 32
    payload = b'{"amount":100}'
    def sig(algo):
        import json
        out = Reseal([
            {"sign": {"algo": algo, "key": "${session_key}",
                      "input": "${payload}", "into": "sig"}},
            {"serialize": {"mode": "compact"}},
        ]).apply({"data": "x"}, payload, _ctx(key))
        return json.loads(out)["sig"]
    assert sig("hmac_sha256") != sig("hmac_sha512")


# ---- Fix 2: preserve vs compact --------------------------------------------

def test_preserve_is_spaced_and_distinct_from_compact():
    carrier = {"b": 1, "a": 2}
    pres = Reseal([{"serialize": {"mode": "preserve"}}]).apply(dict(carrier), b"", _ctx())
    comp = Reseal([{"serialize": {"mode": "compact"}}]).apply(dict(carrier), b"", _ctx())
    assert pres == b'{"b": 1, "a": 2}'      # standard spacing, insertion order
    assert comp == b'{"b":1,"a":2}'         # no spacing
    assert pres != comp


def test_preserve_roundtrips():
    PROFILE = """
name: preserve-rt
scope: { hosts: [ "api.example.com" ] }
request:
  envelope: { locate: [ { in: json_field, field: "data" } ] }
  transform:
    - base64_decode
    - aes_decrypt: { mode: cbc, key: "${session_key}", iv: { source: prefix, length: 16 } }
    - as_json
  reseal:
    - serialize: { mode: preserve }
"""
    eng = Engine(Profile.loads(PROFILE))
    ctx = _ctx(bytes(range(32)))
    plain = {"z": 1, "a": {"nested": [1, 2, 3]}}
    wire = eng.encrypt("request", plain, ctx)
    assert eng.decrypt("request", wire, ctx) == plain


# ---- Fix 3: bridge auth ----------------------------------------------------

def test_authorize_off_by_default():
    svc = BridgeService()
    assert svc.authorize(None) is True
    assert svc.authorize("anything") is True


def test_authorize_enforced_when_token_set():
    svc = BridgeService(token="s3cret")
    assert svc.authorize("s3cret") is True
    assert svc.authorize("wrong") is False
    assert svc.authorize(None) is False
    assert svc.authorize("") is False
