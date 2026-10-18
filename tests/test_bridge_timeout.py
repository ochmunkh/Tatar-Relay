"""Bridge per-request execution timeout — fail-closed, portable."""
import time

import pytest

from tatar_relay.bridge import BridgeService, _call_with_timeout, DEFAULT_TIMEOUT


def test_default_timeout_is_set():
    assert BridgeService().timeout == DEFAULT_TIMEOUT


def test_call_with_timeout_fast_returns():
    assert _call_with_timeout(lambda: 42, 1.0) == 42


def test_call_with_timeout_slow_raises():
    with pytest.raises(TimeoutError):
        _call_with_timeout(lambda: time.sleep(0.5), 0.05)


def test_call_with_timeout_propagates_inner_error():
    def boom():
        raise ValueError("inner")
    with pytest.raises(ValueError):
        _call_with_timeout(boom, 1.0)


def test_handle_timed_returns_structured_timeout():
    svc = BridgeService(timeout=0.05)
    svc.handle = lambda msg: (time.sleep(0.5), {"ok": True})[1]
    resp = svc.handle_timed({"method": "decrypt"})
    assert resp["ok"] is False
    assert resp["error"]["category"] == "timeout"


def test_handle_timed_disabled_runs_inline():
    svc = BridgeService(timeout=0)
    svc.handle = lambda msg: {"ok": True, "hit": True}
    assert svc.handle_timed({})["hit"] is True
