# Security Policy

## Scope and intended use

Tatar Relay is a defensive tool for **authorized security testing only** — work
only with systems you own or have explicit written permission to test. The
project does not endorse or support unauthorized use.

## Supported versions

The latest released version receives security fixes. Older tags do not.

| Version | Supported |
|---------|-----------|
| 0.7.x   | ✅        |
| < 0.7   | ❌        |

## Reporting a vulnerability

Please report security issues **privately**, not in public issues or pull
requests.

- Use GitHub's private reporting: the repository's **Security** tab →
  **“Report a vulnerability”** (GitHub Security Advisories).
- Include: affected version/commit, a minimal reproduction, impact, and any
  suggested fix.

What to expect: an acknowledgement, an assessment of impact and affected
versions, a fix on a coordinated timeline, and credit in the release notes if
you want it. Please give a reasonable window to fix before any public
disclosure.

## Security design

- [THREAT_MODEL.md](THREAT_MODEL.md) — assets, trust boundaries, threats and the
  control (code + test) that answers each one.
- [CRYPTO.md](CRYPTO.md) — algorithm inventory, legacy-algorithm rationale and
  the rules the crypto code follows.
- Automated checks on every push: secret scan, dependency audit, static
  analysis, repository policy guard (`.github/workflows/security.yml`). Releases
  ship a CycloneDX SBOM and signed build provenance.

## Out of scope

- Findings that require running **untrusted Python hook profiles** with
  `allow_python_hooks: true`. A profile that enables Python hooks runs arbitrary
  code **by design** — only enable hooks for profiles you wrote or trust. Treat
  community profiles as declarative-only (the default).
