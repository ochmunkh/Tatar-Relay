"""Command-line interface: run · validate · init · inspect · preview.

The CLI lets you exercise the core with no proxy at all — the fastest way to
prove a profile works and to run it in CI.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Optional

from . import __version__
from .context import Context, HttpMessage
from .errors import RelayError, DecryptError
from .inspect import analyze
from .profile import Profile
from .variables import VarStore


def _build_ctx(profile: Profile, host: str, overrides: list) -> Context:
    ctx = Context(request=HttpMessage(host=host or (profile.scope.hosts[0] if profile.scope.hosts else "")))
    vs = profile.new_varstore(ctx)
    for ov in overrides or []:
        name, _, val = ov.partition("=")
        vs.set(name.strip(), bytes.fromhex(val.strip()))
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
    ctx = _build_ctx(profile, args.host, args.var)
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
    ctx = _build_ctx(profile, args.host, args.var)
    ctx.channel = args.channel
    ctx.direction = "forward"
    data = pipe.envelope.locate(_read(args.input), ctx)
    print(f"envelope.locate  -> {_short(data)}")
    for step in pipe.transform:
        data = step.forward(data, ctx)
        print(f"{step.name:<14} -> {_short(data)}")
    return 0


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
        ctx = _build_ctx(profile, args.host, args.var)
        sample = json.loads(_read(args.sample))
        wire = eng.encrypt(args.channel, sample, ctx)
        back = eng.decrypt(args.channel, wire, ctx)
        print(f"✓ Round-trip: {'passed' if back == sample else 'FAILED'}")
    return 0


def cmd_inspect(args) -> int:
    data = _read(args.input)
    guesses, pipeline = analyze(data)
    print("Detected:")
    for g in guesses:
        mark = "✓" if g.confidence >= 70 else "?"
        print(f"  {mark} {g.name:<8} {g.confidence}%")
    print("\nSuggested pipeline:")
    for step in pipeline:
        print(f"  - {step}")
    print("\n(Review and save as profile.yaml — no blind auto-decrypt.)")
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


def cmd_bridge(args) -> int:
    """Start the local JSON-RPC bridge that the Burp extension talks to."""
    from .bridge import BridgeService, serve_http
    default_vars = {}
    for ov in args.var or []:
        name, _, val = ov.partition("=")
        default_vars[name.strip()] = val.strip()
    svc = BridgeService(default_vars=default_vars)
    for path in args.profile:
        svc.add_profile(Profile.load(path))
    print(f"profiles: {list(svc.profiles)}  default_vars: {list(default_vars)}")
    serve_http(svc, host=args.host, port=args.port)
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
        sp.add_argument("--host", default="")
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

    i = sub.add_parser("inspect", help="suggest a pipeline for a captured blob")
    i.add_argument("input"); i.set_defaults(func=cmd_inspect)

    n = sub.add_parser("init", help="scaffold a profile (optionally wrapping scripts)")
    n.add_argument("--name"); n.add_argument("--decrypt"); n.add_argument("--encrypt")
    n.set_defaults(func=cmd_init)

    b = sub.add_parser("bridge", help="serve the JSON-RPC bridge for the Burp extension")
    b.add_argument("profile", nargs="+", help="one or more profile.yaml files")
    b.add_argument("--host", default="127.0.0.1")
    b.add_argument("--port", type=int, default=8799)
    b.add_argument("--var", action="append", help="default var name=HEX (e.g. session_key=00…)")
    b.set_defaults(func=cmd_bridge)
    return p


def main(argv: Optional[list] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DecryptError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2
    except RelayError as e:
        print(f"✗ {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
