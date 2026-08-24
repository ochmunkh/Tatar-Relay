# Frozen Contracts (v1)

These five interfaces are the stable surface of Tatar Relay. Community profiles
and hooks are written against them, so they are **versioned**: additive changes
are minor; renames/removals are breaking.

## #1 — Profile v1 schema
`tatar_relay/profile.py`. YAML with `name`, `scope` (fail-closed `hosts`,
optional `paths`), `vars` (extraction + `live`), and `request`/`response`
pipelines, each `{ envelope, transform, reseal }`. See
`examples/acme-bank-mobile.yaml`.

## #2 — Context API
`tatar_relay/context.py`. The object every step and hook receives:
`direction`, `channel`, `request`, `response`, `matched`, `vars`, `session`,
`log()`, `fail()`. Per-flow state lives in `session`; module globals must not be
used for state.

## #3 — Step interface
`tatar_relay/steps/base.py`. `forward(data, ctx)` (decrypt) and
`backward(data, ctx)` (its exact inverse), plus `in_type`/`out_type` for
load-time type checking. Register with `@register("name")`.

## #4 — Error taxonomy
`tatar_relay/errors.py`. `DecryptError(category, message, step, direction,
channel, detail)`. Categories are a closed vocabulary (`padding`,
`tag_mismatch`, `wrong_key_size`, `signature_invalid`, `type_mismatch`,
`locate_failed`, `extraction_failed`, `scope_violation`, `profile_invalid`,
`hook_error`, `config_error`, `internal`). Frontends catch these; the proxy
never crashes.

## #5 — Bridge (JSON-RPC)
`tatar_relay/bridge.py`. How non-Python frontends (Burp/Java) reach the core.

```jsonc
// Burp → Core
{"method":"decrypt","channel":"request","profile":"acme","wire":"<base64>",
 "flow_id":"a1","vars":{"session_key":"<hex>"}}
// Core → Burp
{"ok":true,"plaintext":<json>,"ctx_token":"t-9f"}
// Burp → Core
{"method":"encrypt","channel":"request","plaintext":<json>,"ctx_token":"t-9f"}
// Core → Burp
{"ok":true,"wire":"<base64>","diff":{"changed_bytes":14}}
```

v0.1 transport is localhost HTTP JSON (easy to debug); a Unix-domain-socket /
Named-Pipe transport is a drop-in optimization for high-volume traffic.
