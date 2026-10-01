"""What bytes a cipher step's ``key`` resolves to — pinned, not incidental.

Unifying `aes_decrypt` / `chacha20_decrypt` onto `variables.coerce_key` changed
behaviour rather than merely deduplicating it: the old private `_resolve_key`
copies did `val.encode("utf-8")` for *any* str, while `coerce_key(bare="auto")`
hex-decodes a bare string that parses as hex. That change is KEPT deliberately,
and this file is the record of why plus the guard on both edges of it.

Why keep it:

  * One var, one meaning. The shipped `examples/acme-bank-mobile.yaml` feeds the
    same `${session_key}` to `aes_decrypt` (line 26) and to reseal `sign`
    (line 31). Before the unification a 64-hex-char session_key reached the
    cipher as 64 UTF-8 bytes and the signer as 32 hex-decoded bytes — the same
    var, different bytes, inside one profile. `test_one_var_one_meaning` pins
    that they now agree.
  * It is right on the forms keys actually take. 32/48/64 hex characters is how
    an AES key is normally written down, and all three were wrong before — and
    32 was wrong *silently*, because 32 UTF-8 bytes is itself a valid AES-256
    length, so the size check passed and the wrong key was used.
  * It matches what the rest of the tool already documents: `--var` and the
    bridge's `vars` read a bare value as hex (`bare="hex"`), and `hmac_verify`
    read it as auto-hex before this change.

What it costs, and why that is acceptable: a bare key of even length made only
of hex digits and *intended* as UTF-8 text is now halved. Every realistic text
password contains a non-hex character or has odd length and so still reads as
UTF-8 (`test_bare_text_key_stays_utf8`). The pathological case fails loudly in
every cipher rather than returning plausible garbage
(`test_the_regressed_case_fails_loudly_never_silently`), the reading is named in
the diagnostics (`test_the_hex_reading_is_reported`), and `str:` restores the old
behaviour exactly (`test_str_prefix_restores_the_old_utf8_reading`).
"""
import os

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.padding import PKCS7

from tatar_relay import Context, HttpMessage
from tatar_relay.errors import DecryptError
from tatar_relay.steps.base import build_step
from tatar_relay.variables import VarStore

PLAIN = b'{"amount": 100}'

# 32 chars, every one a hex digit: the only shape whose reading changed.
AMBIGUOUS = "0123456789abcdef0123456789abcdef"
# The same 32 bytes the old code would have produced from it.
AMBIGUOUS_UTF8 = AMBIGUOUS.encode("utf-8")
# 64 hex chars: how an AES-256 key is normally written down.
HEX64 = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"


def _ctx(**vars_) -> Context:
    c = Context(request=HttpMessage(host="api.example.com"))
    vs = VarStore()
    for k, v in vars_.items():
        vs.set(k, v)
    c.vars = vs
    return c


def _cbc(key: bytes, plain: bytes = PLAIN) -> bytes:
    iv = os.urandom(16)
    padder = PKCS7(128).padder()
    body = padder.update(plain) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return iv + enc.update(body) + enc.finalize()


def _gcm(key: bytes, plain: bytes = PLAIN) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(key).encrypt(nonce, plain, None)


def _chacha(key: bytes, plain: bytes = PLAIN) -> bytes:
    nonce = os.urandom(12)
    return nonce + ChaCha20Poly1305(key).encrypt(nonce, plain, None)


CBC = {"aes_decrypt": {"mode": "cbc", "key": "${k}",
                       "iv": {"source": "prefix", "length": 16}}}
GCM = {"aes_decrypt": {"mode": "gcm", "key": "${k}"}}
CC20 = {"chacha20_decrypt": {"key": "${k}"}}


# ── the kept behaviour ────────────────────────────────────────────────────

def test_bare_hex_string_key_is_hex_decoded():
    """A 64-hex-char key var is 32 bytes, not 64. This used to be a size error."""
    raw = bytes.fromhex(HEX64)
    assert build_step(GCM).forward(_gcm(raw), _ctx(k=HEX64)) == PLAIN
    assert build_step(CBC).forward(_cbc(raw), _ctx(k=HEX64)) == PLAIN
    assert build_step(CC20).forward(_chacha(raw), _ctx(k=HEX64)) == PLAIN


def test_hex_prefix_is_equivalent_to_the_bare_form():
    raw = bytes.fromhex(HEX64)
    assert build_step(GCM).forward(_gcm(raw), _ctx(k="hex:" + HEX64)) == PLAIN


def test_b64_prefix_decodes_base64():
    import base64
    raw = os.urandom(32)
    key = "b64:" + base64.b64encode(raw).decode()
    assert build_step(GCM).forward(_gcm(raw), _ctx(k=key)) == PLAIN


def test_bytes_key_is_untouched():
    """The common path — `--var`/bridge already hand the step bytes."""
    raw = os.urandom(32)
    assert build_step(GCM).forward(_gcm(raw), _ctx(k=raw)) == PLAIN


def test_bare_text_key_stays_utf8():
    """Backward compatibility for every realistic text key.

    One non-hex character anywhere and the value still reads as UTF-8, exactly
    as it did before the unification. That is the whole protection for text
    keys: a valid AES/ChaCha length is always even, so "odd length cannot be
    hex" never rescues a key that would otherwise be accepted.
    """
    for text in ("correct-horse-battery-staple-xyz",   # 32, has -,o,r,s,t,x,y,z
                 "hunter2hunter2hunter2hunter2hunt",   # 32, has h,u,n,t,r
                 "P@ssw0rd!P@ssw0rd!P@ssw0rd!P@ss0",   # 32, punctuation
                 "s3cret-passphrase-ok!!!!"):          # 24, mixed
        key = text.encode("utf-8")
        assert len(key) in (16, 24, 32), f"bad fixture: {text!r} ({len(key)})"
        assert build_step(GCM).forward(_gcm(key), _ctx(k=text)) == PLAIN, text


def test_odd_length_hex_digits_still_read_as_utf8():
    """Pinned at the coercion, where it is observable.

    `bytes.fromhex` rejects an odd-length string, so it falls through to UTF-8.
    It is untestable through a cipher step (no valid key length is odd) but it
    is the boundary of the auto-hex rule, so it is pinned here.
    """
    from tatar_relay.variables import coerce_key
    assert coerce_key("0123456789abcde", "aes") == b"0123456789abcde"


def test_one_var_one_meaning():
    """The property the unification bought: same var -> same bytes everywhere.

    Before this, `${session_key}` = 64 hex chars reached `aes_decrypt` as 64
    UTF-8 bytes and `hmac_verify`/reseal `sign` as 32 hex-decoded bytes, and
    acme-bank-mobile.yaml uses one var for both.
    """
    from tatar_relay.steps.auth import _to_bytes
    from tatar_relay.steps.base import resolve_key
    from tatar_relay.variables import coerce_key

    for value in (HEX64, AMBIGUOUS, "correct-horse-battery-staple-xyz",
                  "str:" + AMBIGUOUS, "hex:" + HEX64, os.urandom(32)):
        sizes = (16, 24, 32)
        via_cipher = resolve_key({"key": "${k}"}, _ctx(k=value),
                                 sizes=sizes, label="aes")
        via_hmac = _to_bytes(value)                    # hmac_verify
        via_sign = coerce_key(value, "sign")           # reseal sign
        assert via_cipher == via_hmac == via_sign, f"drifted on {value!r}"


def test_chacha_and_aes_read_a_key_identically():
    from tatar_relay.steps.chacha import _resolve_key as cc_key
    from tatar_relay.steps.crypto import _resolve_key as aes_key
    for value in (HEX64, "hex:" + HEX64, "str:" + AMBIGUOUS):
        ctx = _ctx(k=value)
        assert aes_key({"key": "${k}"}, ctx) == cc_key({"key": "${k}"}, ctx)


# ── the escape hatch and the cost ─────────────────────────────────────────

def test_str_prefix_restores_the_old_utf8_reading():
    """`str:` is the documented way back to the pre-unification behaviour."""
    key = "str:" + AMBIGUOUS
    assert build_step(GCM).forward(_gcm(AMBIGUOUS_UTF8), _ctx(k=key)) == PLAIN
    assert build_step(CBC).forward(_cbc(AMBIGUOUS_UTF8), _ctx(k=key)) == PLAIN
    assert build_step(CC20).forward(_chacha(AMBIGUOUS_UTF8), _ctx(k=key)) == PLAIN


@pytest.mark.parametrize("spec,mk,expected", [
    (CBC, _cbc, "padding"),
    (GCM, _gcm, "tag_mismatch"),
    (CC20, _chacha, "wrong_key_size"),
])
def test_the_regressed_case_fails_loudly_never_silently(spec, mk, expected):
    """The cost of the change, bounded.

    A bare all-hex-digit *text* key is now halved. Every cipher rejects the
    result: CBC on the PKCS7 check, GCM and ChaCha20-Poly1305 on the AEAD tag,
    and ChaCha20 on the length before it even tries. No plausible-looking
    plaintext is ever returned, which is what makes the change safe to keep.
    """
    with pytest.raises(DecryptError) as ei:
        build_step(spec).forward(mk(AMBIGUOUS_UTF8), _ctx(k=AMBIGUOUS))
    assert ei.value.category == expected


def test_the_hex_reading_is_reported():
    """A halved key must not be diagnosed as a cipher problem in silence.

    Contract #2 logs carry the reading that was chosen; `relay preview` prints
    them and the bridge attaches them to `DecryptError.detail['logs']`.
    """
    ctx = _ctx(k=AMBIGUOUS)
    with pytest.raises(DecryptError):
        build_step(GCM).forward(_gcm(AMBIGUOUS_UTF8), ctx)
    note = " ".join(m for _, m in ctx.logs)
    assert "read as hex" in note and "str:" in note

    # ...and a bytes key says nothing, so the note only appears when it matters.
    quiet = _ctx(k=os.urandom(32))
    build_step(GCM).forward(_gcm(quiet.vars.get("k")), quiet)
    assert quiet.logs == []


def test_the_size_error_names_the_hex_reading():
    """`got 8` alone would send the operator looking at the wrong thing."""
    ctx = _ctx(k="0123456789abcdef")          # 16 hex chars -> 8 bytes
    with pytest.raises(DecryptError) as ei:
        build_step(GCM).forward(b"x" * 40, ctx)
    assert ei.value.category == "wrong_key_size"
    assert "got 8" in ei.value.message
    assert "read as hex" in ei.value.message and "str:" in ei.value.message


def test_the_size_error_is_unchanged_for_a_bytes_key():
    """The base message stays byte-for-byte; only the ambiguous case adds a clause."""
    ctx = _ctx(k=os.urandom(17))
    with pytest.raises(DecryptError) as ei:
        build_step(GCM).forward(b"x" * 40, ctx)
    assert ei.value.message == "aes: key must be 16/24/32 bytes, got 17"

    ctx = _ctx(k=os.urandom(17))
    with pytest.raises(DecryptError) as ei:
        build_step(CC20).forward(b"x" * 40, ctx)
    assert ei.value.message == "chacha20-poly1305: key must be 32 bytes, got 17"


def test_evp_aes_passphrase_is_not_affected():
    """`evp_aes_decrypt` takes a passphrase (text by contract), not a key var."""
    import inspect

    from tatar_relay.steps import kdf
    src = inspect.getsource(kdf)
    assert "coerce_key" not in src and "resolve_key" not in src


def test_the_breadcrumb_agrees_with_what_coerce_key_actually_did():
    """`_read_as_bare_hex` re-derives the branch `coerce_key` took.

    They are separate functions, so a future edit to either could desync them
    and make the breadcrumb claim a hex reading that did not happen (or stay
    silent about one that did). This pins them together.
    """
    from tatar_relay.steps.base import _read_as_bare_hex
    from tatar_relay.variables import coerce_key

    values = [
        HEX64, AMBIGUOUS, "0123456789abcdef", "0123456789abcde",
        "01 23 45 67 89 ab cd ef",            # fromhex skips whitespace
        "", "correct-horse-battery-staple-xyz", "hello world",
        "str:" + AMBIGUOUS, "hex:" + HEX64, "b64:aGk=",
        b"\x00" * 32, bytearray(b"\x01" * 16),
    ]
    for v in values:
        got = coerce_key(v, "aes")
        claims_hex = _read_as_bare_hex(v)
        if claims_hex:
            assert got == bytes.fromhex(v), f"claimed hex but was not: {v!r}"
        elif isinstance(v, str) and not v.startswith(("str:", "hex:", "b64:")):
            assert got == v.encode("utf-8"), f"silently hex-decoded: {v!r}"
