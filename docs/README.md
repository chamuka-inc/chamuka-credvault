# credvault documentation

Reference docs for operating and understanding credvault — a multi-tenant,
multi-provider credential vault. Start with the [project README](../README.md) for the
overview, the HTTP API, and quickstarts.

| Doc | Covers |
|-----|--------|
| [ARCHITECTURE.md](ARCHITECTURE.md) | The system at depth: the workspace, the security invariants the compiler enforces, the single refresh path, encryption at rest, tenant isolation, and the process model. **Start here to understand the design.** |
| [DEPLOYMENT.md](DEPLOYMENT.md) | Running it in production: the three processes, secret delivery, configuration, key rotation, and hardening. |

Governance and contribution docs live at the repo root: [CONTRIBUTING](../CONTRIBUTING.md),
[SECURITY](../SECURITY.md), [CODE_OF_CONDUCT](../CODE_OF_CONDUCT.md), and the
[CHANGELOG](../CHANGELOG.md). The provider plugin manifest contract is documented in
[plugins/README.md](../plugins/README.md).
