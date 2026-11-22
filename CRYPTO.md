# Cryptography

All primitives come from [pyca/cryptography](https://cryptography.io) (and the
Python standard library for HMAC/hashes). Tatar Relay implements **no custom
cryptographic primitives**. Algorithms are named by algorithm only.

## Inventory

| Where | Algorithm | Parameters | Encrypt-direction randomness | Reference |
|-------|-----------|------------|------------------------------|-----------|
| `aes_decrypt` (cbc) | AES-128/192/256-CBC, PKCS#7 | IV 16 B | Random IV per message when `iv.source: prefix`; a fixed IV only when the target's own format dictates it (`iv.source: value`) | NIST SP 800-38A |
| `aes_decrypt` (gcm) | AES-128/192/256-GCM | nonce 12 B (default), tag 16 B | Random nonce per message | NIST SP 800-38D |
| `chacha20_decrypt` | ChaCha20-Poly1305 | key 32 B, nonce 12 B | Random nonce per message | RFC 8439 |
| `evp_aes_decrypt` | OpenSSL `EVP_BytesToKey` (MD5 default, 1 iteration) + AES-256-CBC | salt 8 B | Random salt per message | OpenSSL legacy format |
| `hmac_verify`, reseal `sign` | HMAC-SHA-256 (default), HMAC-SHA-512, HMAC-SHA-1 | — | — | FIPS 198-1 |
| `vars: from: hkdf` | HKDF | SHA-256 (default) / SHA-512 / SHA-1 | — | RFC 5869, NIST SP 800-56C |
| `vars: from: ecdh` | X25519, ECDH P-256 | raw 32 B keys / uncompressed point | — | RFC 7748, NIST SP 800-56A |
| `gunzip`, `inflate` | (not cryptography) gzip / DEFLATE | output capped at 64 MiB by default | — | RFC 1952 / 1950 / 1951 |

Randomness: `os.urandom` / `secrets` (the operating system CSPRNG).

## Legacy algorithms — why they are present

**MD5 and SHA-1 are deprecated** for security use (NIST SP 800-131A). They are
present **only to interoperate with targets whose own message format uses
them** — `EVP_BytesToKey` passphrase envelopes and HMAC-SHA-1 signatures. Tatar
Relay never relies on them to protect anything of its own; removing them would
only make those targets untestable. The defaults are the modern choices
(HMAC-SHA-256, HKDF-SHA-256, AEAD modes).

## Rules the code follows

- **Fresh nonce/IV on every encrypt** (AEAD and CBC-with-prefix). A pentest tool
  does not *enforce* uniqueness on what it decrypts — testers sometimes replay
  on purpose — but it never reuses one itself.
- **Constant-time comparison** for every MAC and for the bridge token
  (`hmac.compare_digest`).
- **Typed key input** (`str:` / `hex:` / `b64:`) so a text key is never silently
  hex-decoded and halved; wrong sizes fail with `wrong_key_size`.
- **Keys stay in memory.** The tool does not write keys to disk; `relay explain`
  redacts literal keys and logs report sizes, not values.
- **Authenticated failures are explicit** (`tag_mismatch`, `padding`,
  `signature_invalid`) and never return partial plaintext.

## Not provided

Key recovery, brute force, padding-oracle tooling, or extracting keys from
binaries. Keys come from the authorized tester.
