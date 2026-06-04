# Security Policy

credvault stores and brokers other people's credentials. We take its security posture
seriously and ask that you do too when reporting issues.

## Supported versions

This project follows semantic versioning. Security fixes are released for the latest
minor version. Until a `2.0` line exists, the `1.x` series is the supported line.

| Version | Supported          |
| ------- | ------------------ |
| 1.x     | :white_check_mark: |
| < 1.0   | :x:                |

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Instead, report privately through one of:

1. **GitHub Security Advisories** (preferred) — use the
   ["Report a vulnerability"](https://github.com/chamuka-inc/credvault/security/advisories/new)
   button on the repository's *Security* tab. This keeps the report private and lets us
   collaborate on a fix and a CVE in one place.
2. **Email** — `security@chamuka.io` (or `swiftugandan@gmail.com` if that bounces).
   Encrypt sensitive details if you can.

Please include:

- A description of the issue and the impact you believe it has.
- Steps to reproduce, or a proof-of-concept, if available.
- The affected version, commit, or deployment configuration.
- Any suggested remediation.

## What to expect

- **Acknowledgement** within **3 business days**.
- An initial **assessment and severity rating** within **7 business days**.
- Regular updates at least every **7 days** until resolution.
- **Coordinated disclosure**: we will agree on a disclosure timeline with you, typically
  within **90 days** of the report, and credit you in the advisory unless you prefer to
  remain anonymous.

## Scope

In scope:

- The `credvault` library and binaries in this repository.
- The cryptographic handling of credentials at rest (`src/crypto.rs`, `src/secret.rs`).
- Tenant isolation, the OAuth/PKCE flow, signed-state handling, and the refresh path.
- Anything that could lead to credential disclosure, cross-tenant access, token leakage
  in logs, or refresh/lock races.

Out of scope:

- Vulnerabilities in third-party dependencies (report those upstream; we will pick up the
  fix on update). You are still welcome to flag them so we can bump.
- Issues that require a misconfigured deployment explicitly warned against in
  [`DEPLOYMENT.md`](DEPLOYMENT.md) (e.g. `VAULT_ALLOW_INSECURE_HTTP=1` in production).
- Denial of service from unbounded request volume against an unprotected instance —
  credvault is designed to sit behind your platform's own gateway and network policy.

## Hardening guidance

Operators should read [`DEPLOYMENT.md`](DEPLOYMENT.md) for the production hardening
checklist (secret management via `*_FILE` mounts, TLS enforcement, key rotation, and the
service-to-service auth expected in front of the credential endpoints).

Thank you for helping keep credvault and its users safe.
