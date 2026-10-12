"""Command-line interface: run · validate · preview · steps · init · inspect.

The CLI lets you exercise the core with no proxy at all — the fastest way to
prove a profile works and to run it in CI.

Authoring mistakes are reported, never raised: a step-name typo, an unreadable
or malformed profile, and a bad ``--var`` each exit with one actionable line
instead of a traceback (``main`` is the backstop for the rest).
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

import yaml

from . import __version__
from .context import Context, HttpMessage
from .errors import DecryptError, ProfileError, RelayError
from .engine import _attach_logs
from .inspect import analyze, fingerprint, draft_profile, load_observations
from .profile import Profile
from .variables import coerce_key


def _build_ctx(profile: Profile, host: str, overrides: list, path: str = "") -> Context:
    if host:
        # --host was given explicitly, so authorize it fail-closed rather than
        # trusting it. The path half is only checked when --path was supplied:
        # defaulting it to "/" would reject every profile with a `paths:` regex,
        # e.g. `relay run examples/acme-bank-mobile.yaml --host api.example.com`.
        profile.authorize(host, path or None)
    ctx = Context(request=HttpMessage(
        host=host or (profile.scope.hosts[0] if profile.scope.hosts else ""),
        path=path))
    vs = profile.new_varstore(ctx)
    for ov in overrides or []:
        name, _, val = ov.partition("=")
        name = name.strip()
        # default HEX; prefix str:/b64:/hex: for passphrases or other encodings
        try:
            vv = coerce_key(val.strip(), f"--var {name}", bare="hex")
        except DecryptError as e:
            raise ProfileError(e.message)
        vs.set(name, vv)
    ctx.vars = vs
    return ctx


def _read(path: str) -> bytes:
    if path == "-":
        return sys.stdin.buffer.read()
    with open(path, "rb") as f:
        return f.read()


def cmd_run(args) -> int:
    profile = Profile.load(args.profile)
    from .engine import Engine
    eng = Engine(profile)
    ctx = _build_ctx(profile, args.host, args.var, args.path)
    wire = _read(args.input)
    plain = eng.decrypt(args.channel, wire, ctx)
    out = json.dumps(plain, indent=2, ensure_ascii=False) if isinstance(plain, (dict, list)) \
        else (plain.decode("utf-8", "replace") if isinstance(plain, bytes) else str(plain))
    print(out)
    if args.roundtrip:
        rewire = eng.encrypt(args.channel, plain, ctx)
        ok = eng.decrypt(args.channel, rewire, ctx) == plain
        print(f"\n# round-trip: {'OK' if ok else 'FAILED'}  ({len(rewire)} bytes)", file=sys.stderr)
    return 0


def cmd_preview(args) -> int:
    """Step-by-step decrypt view (CLI Live Preview)."""
    profile = Profile.load(args.profile)
    pipe = profile.pipeline(args.channel)
    if pipe is None:
        raise ProfileError(
            f"profile '{profile.name}': no '{args.channel}' pipeline to preview "
            f"(this profile defines: {', '.join(profile.pipelines) or 'none'})")
    ctx = _build_ctx(profile, args.host, args.var, args.path)
    ctx.channel = args.channel
    ctx.direction = "forward"
    data = pipe.envelope.locate(_read(args.input), ctx)
    print(f"envelope.locate  -> {_short(data)}")
    seen = _drain_logs(ctx, 0)
    for step in pipe.transform:
        try:
            data = step.forward(data, ctx)
        except DecryptError as e:
            # preview calls steps directly, bypassing Engine._run, so nothing
            # else would carry the failing step's ctx.log() breadcrumbs out to
            # main's handler — which is precisely when they are wanted.
            _attach_logs(e, ctx, seen)
            raise
        print(f"{step.name:<14} -> {_short(data)}")
        seen = _drain_logs(ctx, seen)
    return 0


def _drain_logs(ctx: Context, seen: int) -> int:
    """Print whatever the last step wrote with ``ctx.log()`` (Contract #2)."""
    logs = ctx.logs
    for level, msg in logs[seen:]:
        print(f"{'':<14}    · {level}: {msg}")
    return len(logs)


def cmd_validate(args) -> int:
    try:
        profile = Profile.load(args.profile)
    except RelayError as e:
        print(f"✗ {e}")
        return 1
    print(f"✓ Profile '{profile.name}' valid")
    for ch, pipe in profile.pipelines.items():
        chain = " → ".join(s.name for s in pipe.transform) or "(none)"
        print(f"✓ {ch} pipeline: {chain} (type check passed)")
    print(f"✓ Scope: hosts={profile.scope.hosts}")
    if profile.allow_python_hooks:
        print("⚠ Python hooks enabled (trusted local)")
    if args.sample:
        from .engine import Engine
        eng = Engine(profile)
        ctx = _build_ctx(profile, args.host, args.var, args.path)
        sample = json.loads(_read(args.sample))
        wire = eng.encrypt(args.channel, sample, ctx)
        back = eng.decrypt(args.channel, wire, ctx)
        print(f"✓ Round-trip: {'passed' if back == sample else 'FAILED'}")
    return 0


def cmd_steps(args) -> int:
    """Print the transform vocabulary, so it is discoverable at all."""
    from .steps import known_steps
    names = known_steps()
    print(f"{len(names)} transform steps available for a profile's "
          f"`transform:` list:")
    for name in names:
        print(f"  {name}")
    print("\nUse one as a bare name (`- base64_decode`) or with params "
          "(`- aes_decrypt: { mode: gcm, key: \"${session_key}\" }`).")
    return 0


def cmd_inspect(args) -> int:
    import os
    data = _read(args.input)
    guesses, pipeline = analyze(data)
    fp = fingerprint(data)

    print("Detected:")
    for g in guesses:
        mark = "✓" if g.confidence >= 70 else "?"
        print(f"  {mark} {g.name:<14} {g.confidence}%")
    if fp.is_json and fp.json_fields:
        print("\nJSON fields:")
        for k, role in fp.json_fields.items():
            print(f"  - {k}: {role}")
    print("\nSuggested pipeline:")
    for step in pipeline:
        print(f"  - {step}")

    # Observations (ground truth from the JS observer)
    obs = []
    obs_path = args.observations
    if obs_path is None and os.path.exists("observations.jsonl"):
        obs_path = "observations.jsonl"
    if obs_path:
        obs = load_observations(obs_path)
        if obs:
            print(f"\nObservations ({obs_path}):")
            seen = set()
            for o in obs:
                summ = f"{o.get('algorithm')} · {o.get('ivLen')}B nonce · {o.get('keyLen')}B key"
                if summ not in seen:
                    seen.add(summ); print(f"  · {summ}")

    if args.emit_profile:
        yaml_text = draft_profile(data, name=args.name or "target", observations=obs)
        with open(args.emit_profile, "w", encoding="utf-8") as f:
            f.write(yaml_text)
        print(f"\n✓ draft profile written: {args.emit_profile}  (REVIEW before use)")
    else:
        print("\n(Review; add --emit-profile draft.yaml to scaffold a profile — no blind auto-decrypt.)")
    return 0


def cmd_init(args) -> int:
    """Scaffold a profile that wraps existing decrypt/encrypt scripts as hooks."""
    name = args.name or "my-target"
    prof = f"""# {name}.yaml  (scaffolded by `relay init`)
# NOTE: hooks below wrap your existing scripts. Adjust hardcoded keys/paths
#       inside the hook to read from ctx / ${{vars}} instead.
name: "{name}"
scope:
  hosts: [ "REPLACE.example.com" ]   # REQUIRED (fail-closed)
security:
  allow_python_hooks: true           # trusted local profile

request:
  envelope: {{ locate: [ {{ in: json_field, field: "data" }} ] }}
  transform:
    - python: {{ file: "hooks/{name}.py", forward: decrypt_payload, backward: encrypt_payload }}
    - as_json

view: {{ pretty_json: true, diff_preview: true }}
"""
    hook = f'''"""Hook wrapping existing decrypt/encrypt logic for '{name}'.

TODO: replace hardcoded keys with ctx.vars, remove file/network side effects,
      and keep per-flow state in ctx.session (NOT module globals).
"""

def decrypt_payload(data, ctx):
    # data: bytes located from the envelope
    # return: bytes (plaintext, ready for `as_json`)
    raise NotImplementedError("port your decrypt.py logic here")


def encrypt_payload(data, ctx):
    # data: bytes (the edited plaintext, serialized)
    # return: bytes/str to place back into the envelope
    raise NotImplementedError("port your encrypt.py logic here")
'''
    import os
    with open(f"{name}.yaml", "w", encoding="utf-8") as f:
        f.write(prof)
    os.makedirs("hooks", exist_ok=True)
    hp = f"hooks/{name}.py"
    if not os.path.exists(hp):
        with open(hp, "w", encoding="utf-8") as f:
            f.write(hook)
    print(f"✓ wrote {name}.yaml and {hp}")
    if args.decrypt or args.encrypt:
        print(f"  (reference your logic from: {args.decrypt or '-'} / {args.encrypt or '-'})")
    print("⚠ edit hooks: replace hardcoded key with ${session_key}, drop file/global state")
    return 0


def cmd_decrypt_field(args) -> int:
    """Quick one-shot ECDH-GCM field decryption — no profile or YAML needed.

    Useful for ad-hoc verification after capturing a session key:

        relay decrypt-field \\
            --key 63323666333735363033653266353536 \\
            --field "6dc94b82a7f1e3c0YWJj..."

    The key is the hex string printed by `relay capture`.
    The field value is the raw encrypted field string from Burp.
    """
    import base64
    import binascii
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    try:
        key = bytes.fromhex(args.key.strip())
    except ValueError as e:
        print(f"✗ --key: {e}", file=sys.stderr)
        return 1

    field = args.field.strip()
    if len(field) < 24:
        print("✗ --field: too short (expected ≥24 hex chars for nonce)", file=sys.stderr)
        return 1

    try:
        nonce = binascii.unhexlify(field[:24])
        b64 = field[24:]
        pad = (4 - len(b64) % 4) % 4
        ct_tag = base64.b64decode(b64 + "=" * pad)
        plain = AESGCM(key).decrypt(nonce, ct_tag, None)
    except Exception as e:
        print(f"✗ Decryption failed: {e}", file=sys.stderr)
        print("  Check that --key and --field are from the same session.", file=sys.stderr)
        return 1

    # pretty-print if JSON
    try:
        parsed = json.loads(plain)
        print(json.dumps(parsed, indent=2, ensure_ascii=False))
    except json.JSONDecodeError:
        print(plain.decode("utf-8", errors="replace"))

    return 0


def cmd_bridge(args) -> int:
    """Start the local JSON-RPC bridge that the Burp extension talks to."""
    from .bridge import BridgeService, serve_http
    default_vars = {}
    for ov in args.var or []:
        name, _, val = ov.partition("=")
        default_vars[name.strip()] = val.strip()
    import os
    token = args.token or os.environ.get("TATAR_RELAY_TOKEN") or None
    svc = BridgeService(default_vars=default_vars, token=token)
    for path in args.profile:
        svc.add_profile(Profile.load(path))
    print(f"profiles: {list(svc.profiles)}  default_vars: {list(default_vars)}"
          f"  auth: {'on' if token else 'off'}")
    print("⚠ scope is enforced per request only for frontends that send a "
          '"host"; a message without one is not scope-checked')
    capture_port = args.capture_port if args.capture else None
    serve_http(svc, host=args.host, port=args.port,
               capture_port=capture_port,
               capture_key_var=args.capture_var,
               observe_path=args.observe_file,
               capture_token=args.capture_token)
    return 0


def cmd_capture(args) -> int:
    """Start a standalone key capture server.

    The companion JS hook (examples/js-hooks/session_key_capture.js) sends
    the derived AES session key here.  This command waits for the key, prints
    it, and exits — you can then pass it to `relay bridge --var session_key=…`.

    Typical workflow:
        1.  relay capture --port 9091
        2.  Inject the JS hook into the target page (Burp Match & Replace)
        3.  Log in to the target app in Burp's browser
        4.  Copy the printed key
        5.  relay bridge myprofile.yaml --var session_key=<printed_key>
    """
    import os
    from .capture import KeyCapture, serve_capture

    hook_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "examples", "js-hooks", "session_key_capture.js"
    )

    cap = KeyCapture()
    serve_capture(cap, host=args.host, port=args.port, block=False,
                  token=args.token)

    print(f"[+] Tatar Relay capture server:  http://{args.host}:{args.port}/key")
    if os.path.isfile(hook_path):
        print(f"[+] JS hook:  {hook_path}")
    print()
    print("  Steps:")
    print("    1. In Burp → Proxy → Match and Replace → add rule:")
    print(f"         Type: Response body  |  Match: </head>")
    print(f'         Replace: <script src="data:text/javascript;base64,…"></script></head>')
    print(f"       (base64-encode the hook file and paste it as the src)")
    print()
    print("    Or paste the hook directly into DevTools → Console before logging in.")
    print()
    print(f"[+] Waiting for session key (timeout: {args.timeout}s)…")

    key = cap.wait(timeout=float(args.timeout))

    if key is None:
        print(f"\n✗  Timeout — no key received in {args.timeout}s")
        return 1

    hex_key = key.hex()
    bits = len(key) * 8
    print(f"\n✅  Session key captured ({bits}-bit AES):")
    print(f"    {hex_key}")
    print()
    print("  Use with:")
    print(f"    relay run  <profile.yaml> -i <wire.bin>  --var session_key={hex_key}")
    print(f"    relay bridge <profile.yaml>              --var session_key={hex_key}")
    return 0


def _short(v) -> str:
    if isinstance(v, (bytes, bytearray)):
        return f"<{len(v)} bytes> {v[:24]!r}{'…' if len(v) > 24 else ''}"
    s = json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else str(v)
    return s if len(s) <= 80 else s[:77] + "…"


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="relay", description="Tatar Relay — encrypted APIs as editable HTTP")
    p.add_argument("--version", action="version", version=f"tatar-relay {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    def common(sp):
        sp.add_argument("--channel", default="request", choices=["request", "response"])
        sp.add_argument("--host", default="",
                        help="authorize against the profile's scope as this host "
                             "(default: the profile's first scope host)")
        sp.add_argument("--path", default="",
                        help="also check the scope's paths: regexes against this "
                             "path (default: host-only check)")
        sp.add_argument("--var", action="append", help="name=HEX (e.g. session_key=00112233…)")

    r = sub.add_parser("run", help="decrypt a captured wire body")
    r.add_argument("profile"); r.add_argument("--input", "-i", required=True)
    r.add_argument("--roundtrip", action="store_true"); common(r); r.set_defaults(func=cmd_run)

    pv = sub.add_parser("preview", help="step-by-step decrypt view")
    pv.add_argument("profile"); pv.add_argument("--input", "-i", required=True)
    common(pv); pv.set_defaults(func=cmd_preview)

    v = sub.add_parser("validate", help="validate a profile (+ optional round-trip)")
    v.add_argument("profile"); v.add_argument("--sample", help="plaintext JSON file for round-trip")
    common(v); v.set_defaults(func=cmd_validate)

    st = sub.add_parser("steps", help="list the available transform step names")
    st.set_defaults(func=cmd_steps)

    i = sub.add_parser("inspect", help="fingerprint a captured blob + draft a profile")
    i.add_argument("input")
    i.add_argument("--emit-profile", help="write a draft profile YAML to this path")
    i.add_argument("--observations", help="JSONL of crypto observations to merge "
                                          "(default: ./observations.jsonl if present)")
    i.add_argument("--name", help="profile name for the draft (default: target)")
    i.set_defaults(func=cmd_inspect)

    n = sub.add_parser("init", help="scaffold a profile (optionally wrapping scripts)")
    n.add_argument("--name"); n.add_argument("--decrypt"); n.add_argument("--encrypt")
    n.set_defaults(func=cmd_init)

    df = sub.add_parser("decrypt-field",
                        help="decrypt a single ECDH-GCM field (quick key + field test)")
    df.add_argument("--key", required=True,
                    help="AES key hex from `relay capture`")
    df.add_argument("--field", required=True,
                    help="raw encrypted field value from Burp")
    df.set_defaults(func=cmd_decrypt_field)

    b = sub.add_parser("bridge", help="serve the JSON-RPC bridge for the Burp extension")
    b.add_argument("profile", nargs="+", help="one or more profile.yaml files")
    b.add_argument("--host", default="127.0.0.1")
    b.add_argument("--port", type=int, default=8799)
    b.add_argument("--var", action="append", help="default var name=HEX (e.g. session_key=00…)")
    b.add_argument("--token", default=None,
                   help="require this shared secret in the X-Relay-Token header "
                        "(else reads TATAR_RELAY_TOKEN; default: no auth)")
    b.add_argument("--capture", action="store_true",
                   help="also start the JS key-capture sidecar (see relay capture)")
    b.add_argument("--capture-port", type=int, default=9091, dest="capture_port",
                   help="port for the capture sidecar (default: 9091)")
    b.add_argument("--capture-var", default="session_key", dest="capture_var",
                   help="var name to store the captured key into (default: session_key)")
    b.add_argument("--capture-token", default=None, dest="capture_token",
                   help="require this shared secret in the X-Relay-Token header "
                        "on the sidecar's /reset and /schemes (default: no auth). "
                        "/key and /observe stay open — the injected page hook "
                        "would have to carry the secret to reach them.")
    b.add_argument("--observe-file", default="observations.jsonl", dest="observe_file",
                   help="JSONL file for crypto observations from the JS observer "
                        "(default: observations.jsonl)")
    b.set_defaults(func=cmd_bridge)

    cap = sub.add_parser("capture",
                         help="wait for JS hook to deliver a session key, then print it")
    cap.add_argument("--host", default="127.0.0.1")
    cap.add_argument("--port", type=int, default=9091,
                     help="capture server port (default: 9091)")
    cap.add_argument("--timeout", type=int, default=120,
                     help="seconds to wait for the key (default: 120)")
    cap.add_argument("--token", default=None,
                     help="require this shared secret in the X-Relay-Token "
                          "header on /reset and /schemes (default: no auth)")
    cap.set_defaults(func=cmd_capture)

    return p


def main(argv: Optional[list] = None) -> int:
    # Windows consoles default to cp1252, which can't encode ✓/→/⚠ — force UTF-8
    # so status output doesn't crash with UnicodeEncodeError.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")
        except Exception:  # noqa: BLE001 - older/odd streams; best effort
            pass
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DecryptError as e:
        print(f"✗ {e}", file=sys.stderr)
        # DecryptError.__str__ omits detail, so the hook/step breadcrumbs the
        # engine collected would otherwise be gathered and never shown.
        for line in e.detail.get("logs") or []:
            print(f"  · {line}", file=sys.stderr)
        return 2
    except RelayError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2
    # Backstops: anything the commands touch outside a Profile (an unreadable
    # --input/--sample, a stray YAML) still exits with one line, not a traceback.
    except yaml.YAMLError as e:
        print(f"✗ invalid YAML: {e}", file=sys.stderr)
        return 2
    except OSError as e:
        where = getattr(e, "filename", None)
        print(f"✗ {where + ': ' if where else ''}{e.strerror or e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
