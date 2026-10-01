"""The key-capture sidecar must not hand the session key to any origin.

The sidecar deliberately allows cross-origin requests so the injected page hook
can reach `/key` and `/observe`. But `_send_json` applied
`Access-Control-Allow-Origin: *` to *every* response, and `/status` returned the
live AES session key in its body — so while the tester was logged into the
target, any page in that browser (including the target app) could read the key
out of `/status`, or overwrite it via `/key`.

Fixed three ways, pinned here:
  * `/status` reports readiness only, never the key.
  * CORS is advertised on `/key` and `/observe` alone — on the preflight as
    well as on the response, or the preflight promises what the response
    refuses.
  * `/reset` and `/schemes` honour an optional shared secret.

The `/key` WRITE vector is accepted, not closed: the page hook that posts the
key runs in the target's own origin and cannot carry a secret, so `/key` has to
stay open to any origin (`relay capture --token` says so: "/key and /observe
stay open"). A hostile page can therefore overwrite the captured key; it still
cannot read one back, which is the vector that mattered.

Two servers are started per module rather than one per test: each leaves a
`serve_forever` thread polling twice a second for the rest of the session, and
ten of those measurably slowed every test that followed. Each test therefore
sets up the capture state it needs, so order does not matter.
"""
import json
import socket
import urllib.error
import urllib.request

import pytest

from tatar_relay.capture import KeyCapture, ObservationLog, serve_capture

KEY_HEX = "00" * 32
TOKEN = "s3cret"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _start(token=None):
    port = _free_port()
    cap, obs = KeyCapture(), ObservationLog()
    srv = serve_capture(cap, host="127.0.0.1", port=port, block=False,
                        observations=obs, token=token)
    return f"http://127.0.0.1:{port}", cap, srv


@pytest.fixture(scope="module")
def open_sidecar():
    """A sidecar with no token configured (the default)."""
    base, cap, srv = _start()
    yield base, cap
    # Release the listening socket. No shutdown(): that blocks on
    # serve_forever's 0.5s poll, and the thread is a daemon anyway.
    srv.server_close()


@pytest.fixture(scope="module")
def secured_sidecar():
    """A sidecar started with a capture token."""
    base, cap, srv = _start(token=TOKEN)
    yield base, cap
    srv.server_close()


def _get(url, headers=None):
    req = urllib.request.Request(url, headers=headers or {})
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, dict(r.headers), r.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read().decode()


def _options(url, headers=None):
    """A CORS preflight, which is what a browser sends before a non-simple request."""
    req = urllib.request.Request(url, headers=headers or {}, method="OPTIONS")
    try:
        r = urllib.request.urlopen(req, timeout=5)
        return r.status, dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers)


# ---- /status no longer leaks the key --------------------------------------

def test_status_never_returns_the_key(open_sidecar):
    base, cap = open_sidecar
    assert _get(f"{base}/key?v={KEY_HEX}")[0] == 200
    assert cap.hex() == KEY_HEX                      # the sidecar did capture it

    code, _, body = _get(f"{base}/status", {"Origin": "https://evil.example"})
    assert code == 200
    data = json.loads(body)
    assert data == {"ok": True, "ready": True}
    assert "key" not in data
    assert KEY_HEX not in body


def test_status_reports_not_ready_before_a_key_arrives(open_sidecar):
    base, cap = open_sidecar
    cap.reset()
    assert json.loads(_get(f"{base}/status")[2]) == {"ok": True, "ready": False}


# ---- CORS only where a target page needs it ------------------------------

def test_no_cors_on_status(open_sidecar):
    base, _ = open_sidecar
    _, headers, _ = _get(f"{base}/status", {"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in headers


def test_cors_still_advertised_on_key_so_the_js_hook_works(open_sidecar):
    base, _ = open_sidecar
    _, headers, _ = _get(f"{base}/key?v={KEY_HEX}",
                         {"Origin": "https://target.example"})
    assert headers.get("Access-Control-Allow-Origin") == "*"


@pytest.mark.parametrize("path", ["/key", "/observe"])
def test_preflight_advertises_cors_where_the_hook_needs_it(open_sidecar, path):
    base, _ = open_sidecar
    code, headers = _options(f"{base}{path}", {"Origin": "https://target.example"})
    assert code == 200
    assert headers.get("Access-Control-Allow-Origin") == "*"


@pytest.mark.parametrize("path", ["/status", "/reset", "/schemes", "/nope"])
def test_preflight_denies_cors_everywhere_else(open_sidecar, path):
    """`do_OPTIONS` answered every path with `_cors()`.

    The GET responses correctly carried no ACAO, so this was not exploitable —
    a browser still could not read the bodies — but the preflight advertised
    exactly what the responses refuse, which is the opposite of the claim the
    rest of this file makes.
    """
    base, _ = open_sidecar
    _, headers = _options(f"{base}{path}", {"Origin": "https://evil.example"})
    assert "Access-Control-Allow-Origin" not in headers


# ---- the control paths take a token --------------------------------------

@pytest.mark.parametrize("path", ["/reset", "/schemes"])
def test_control_paths_require_the_token_when_set(secured_sidecar, path):
    base, _ = secured_sidecar
    assert _get(f"{base}{path}")[0] == 401
    assert _get(f"{base}{path}", {"X-Relay-Token": "wrong"})[0] == 401
    assert _get(f"{base}{path}", {"X-Relay-Token": TOKEN})[0] == 200


def test_reset_cannot_clear_the_key_without_the_token(secured_sidecar):
    base, cap = secured_sidecar
    assert _get(f"{base}/key?v={KEY_HEX}")[0] == 200
    assert _get(f"{base}/reset")[0] == 401
    assert cap.hex() == KEY_HEX              # still there
    assert _get(f"{base}/reset", {"X-Relay-Token": TOKEN})[0] == 200
    assert cap.hex() is None


@pytest.mark.parametrize("path", ["/reset", "/schemes"])
def test_control_paths_stay_open_when_no_token_is_configured(open_sidecar, path):
    """Default is unchanged: the documented browser workflow keeps working."""
    base, _ = open_sidecar
    assert _get(f"{base}{path}")[0] == 200


# ---- the guide must not tell people to read the key out of /status -------

def test_the_inject_guide_does_not_document_a_key_field():
    from pathlib import Path
    guide = (Path(__file__).resolve().parent.parent
             / "examples" / "js-hooks" / "BURP_INJECT_GUIDE.md")
    text = guide.read_text(encoding="utf-8")
    assert '"ready":true,"key"' not in text, \
        "the guide still documents /status returning the session key"
