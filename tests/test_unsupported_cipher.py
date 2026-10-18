"""Graceful handling of ciphers the engine has no native step for."""
import pytest

from tatar_relay.steps.base import build_step
from tatar_relay.errors import DecryptError
from tatar_relay.inspect import draft_profile


def test_unsupported_aes_mode_is_actionable():
    with pytest.raises(DecryptError) as e:
        build_step({"aes_decrypt": {"mode": "ctr", "key": "${k}"}})
    assert e.value.category == "unsupported_cipher"
    assert "cbc, gcm" in e.value.message


def test_supported_modes_still_build():
    build_step({"aes_decrypt": {"mode": "gcm", "key": "${k}"}})
    build_step({"aes_decrypt": {"mode": "cbc", "key": "${k}"}})


def test_draft_flags_unsupported_observed_cipher():
    blob = b'{"data":"' + b"A" * 40 + b'"}'
    obs = [{"algorithm": "RSA-OAEP", "ivLen": 0, "keyLen": 256}]
    draft = draft_profile(blob, name="t", observations=obs)
    assert "UNSUPPORTED cipher observed" in draft
    assert "RSA-OAEP" in draft
