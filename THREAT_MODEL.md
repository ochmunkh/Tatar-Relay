# Threat model

Tatar Relay decrypts and reseals application-layer encrypted HTTP traffic for
**authorized** security testing. This document lists what it protects, where its
trust boundaries are, the threats at each boundary, and the control that
answers each one — with the code and test that prove it.

## Assets

| Asset | Why it matters |
|-------|----------------|
| Session keys / secrets the operator loads (`--var`, captured, derived) | Whoever holds them can decrypt and forge the target's traffic |
| Decrypted plaintext of the authorized target | Confidential test data |
| The operator's machine | Profiles with Python hooks execute code there |
| Release artifacts (jar, source tarball) | Users install them |

## Actors

| Actor | Trust |
|-------|-------|
| Operator | Trusted |
| Target application (authorized scope) | Semi-trusted — its messages are attacker-shaped input |
| Web pages open in the testing browser | **Untrusted** |
| Other hosts on the network | **Untrusted** |
| Other local users on the same machine | Untrusted (loopback is reachable by them) |
| Community / third-party profiles | **Untrusted** unless the operator wrote or reviewed them |
| Dependencies, CI actions, release pipeline | Supply chain — verified, pinned |

## Trust boundaries

```
 [Burp extension] --HTTP JSON-RPC (loopback)--> [Bridge]  --> [Engine] <-- [Profile YAML]
 [Page in testing browser] --/key,/observe (loopback, CORS)--> [Capture sidecar]
 [Python hook]  ==full trust==>  [Engine]          (only when allow_python_hooks: true)
 [CI]  --> [Release assets + SBOM + provenance]
```

## Threats and controls (STRIDE)

| # | Boundary | Threat | Control | Where (code / test) |
|---|----------|--------|---------|---------------------|
| T1 | Network → bridge | Anyone on the LAN uses the bridge as a decryption / forging oracle (S, I, E) | Non-loopback bind is **refused** without a token (fail-closed); token compared in constant time | `bridge.require_safe_bind`, `BridgeService.authorize` · `test_bridge_hardening.py`, `test_reseal_and_bridge_auth.py` |
| T2 | Browser page → bridge | A page in the testing browser posts to `127.0.0.1` (CSRF) or uses DNS rebinding to read answers (S, I) | Requests carrying an `Origin` header are refused; when bound to loopback the `Host` header must be loopback | `bridge.screen_request` · `test_bridge_hardening.py` (incl. live-server tests) |
| T3 | Any client → bridge | Oversized body / runaway hook / unbounded state exhausts memory or hangs Burp (D) | 16 MiB request cap (413), per-request timeout (fail-closed), LRU-bounded flow store | `MAX_REQUEST_BYTES`, `handle_timed`, `MAX_CTX_ENTRIES` · `test_bridge_hardening.py`, `test_bridge_timeout.py` |
| T4 | Bridge flow tokens | Guessing another flow's `ctx_token` to reseal it (S, T) | 128-bit random tokens | `BridgeService._remember` · `test_bridge_hardening.py` |
| T5 | Network → capture sidecar | Injecting a fake key / observation from the LAN (T) | Sidecar always binds loopback, even if the bridge is network-bound | `bridge.capture_bind_host` · `test_bridge_hardening.py` |
| T6 | Page → capture sidecar | Reading the captured key back (I) | No endpoint returns the key; control endpoints (`/reset`, `/schemes`) can require a token | `capture.py` · `test_capture_exposure.py` |
| T7 | Profile → engine | A community profile runs code (E) | Declarative-only by default: any Python hook (incl. in header sub-pipelines and vars) is rejected unless `allow_python_hooks: true` | `Profile._guard_hooks` · `test_profile.py`, `test_hook_contract.py` |
| T8 | Profile → target | Using a profile against an unauthorized host (E) | Scope is fail-closed: no `hosts` → refuse to load; per-request host/path authorization | `Profile.authorize` · `test_scope_gate.py` |
| T9 | Profile from the future | An older build silently mis-reads a newer profile (T) | `schema_version` newer than supported is refused | `Profile._read_schema_version` · `test_schema_version.py` |
| T10 | Target message → engine | Malformed / hostile input crashes the proxy or leaks partial plaintext (D, I) | Structured `DecryptError` taxonomy, original bytes passed through on failure; decompression caps | `errors.py`, `engine._run`, `codecs` · `test_fuzz.py`, `test_inflate.py`, `test_unsupported_cipher.py`, `test_hostile_plaintext.py` |
| T11 | Logs / CLI output | Keys or secrets printed (I) | Keys never logged; `relay explain` redacts literal keys; capture logs sizes, not values | `cli._params_summary`, `capture.py` · `test_explain.py`, `test_capture_exposure.py` |
| T12 | Crypto misuse | Nonce reuse on encrypt, timing leaks on MAC check (I) | Random nonce/IV per message on encrypt; constant-time MAC comparison | `steps/crypto.py`, `steps/chacha.py`, `steps/auth.py` · `test_crypto.py`, `test_hmac_verify.py` — see [CRYPTO.md](CRYPTO.md) |
| T13 | Supply chain | Vulnerable dependency, leaked secret, moved action tag, tampered release (T) | `pip-audit`, gitleaks (checksum-verified binary), CodeQL, actions pinned by commit SHA, CycloneDX SBOM + signed build provenance on release | `.github/workflows/security.yml`, `release.yml` |
| T14 | Repository content | Disallowed names or tool attribution reaching the public repo (I) | Hash-based policy guard over tracked files, commit messages and authors | `tools/policy_check.py` · `test_policy.py`, CI `policy` job |

## Assumptions and residual risk

- **Python hooks are arbitrary code by design.** Enable `allow_python_hooks` only
  for profiles you wrote or reviewed. A hook is not sandboxed — a partial sandbox
  would give false confidence.
- **Loopback is shared with other local users.** On a multi-user machine set
  `--token` even on `127.0.0.1`.
- **Regular expressions in a profile** can be slow on crafted input. The bridge
  timeout bounds the damage; the CLI has no timeout.
- **Decrypted plaintext is shown in Burp** and wherever the operator copies it;
  handling it is the operator's responsibility. It is treated as hostile data at
  the tool's own boundaries: it round-trips byte-for-byte, never breaks the
  bridge's one-line JSON, undecodable bytes become a classified error, and the
  Burp Comment preview strips control and bidi characters
  (`test_hostile_plaintext.py`, `LogicTest`).
- **Client-side keys:** app-layer encryption whose key lives on the client is
  obfuscation over TLS. The tool works *with* keys the authorized tester already
  holds; it does not recover keys or break cryptography.
- Loopback HTTP is not encrypted; that is acceptable only because it never
  leaves the machine (T1, T5).

## Out of scope

TLS interception (Burp / mitmproxy do that), key recovery, scanning, fuzzing
frameworks, exploit development.

---

## Монгол — товч

Энэ баримт нь Tatar Relay юуг хамгаалдаг (түлхүүр, plaintext, операторын машин,
release), итгэлцлийн хил хаана байгаа (Burp↔bridge, browser↔capture, profile,
hook, CI), хил бүр дээрх аюул ба түүнийг хаадаг хяналтыг **код ба тестийн**
холбоостойгоор жагсаана. Гол хяналтууд: loopback-аас гадуур token-гүй асахгүй,
браузерийн `Origin` болон DNS rebinding-ийг татгалзана, хэмжээ/хугацаа/төлөвийн
хязгаар, capture sidecar үргэлж loopback, declarative-only профайл, fail-closed
scope, supply-chain шалгалтууд.
