<!--
  Thanks for contributing to credvault. Please read CONTRIBUTING.md first.
  Do NOT include real credentials, tokens, or secrets anywhere in this PR.
-->

## Summary

<!-- What does this change do, and why? Link any related issue (e.g. "Closes #123"). -->

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] New / updated provider (plugin manifest)
- [ ] Documentation
- [ ] Refactor / internal
- [ ] Other:

## How was this verified?

<!-- Commands run, scenarios tested. -->

## Checklist

- [ ] `cargo fmt --all --check` passes
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` passes
- [ ] `cargo test` and `cargo test --features sqlite` pass
- [ ] Tests added or updated for behavior changes
- [ ] Docs updated (README / DEPLOYMENT / .env.example / CHANGELOG) where relevant
- [ ] No new path logs or exposes plaintext secrets
- [ ] Tenant isolation preserved (`tenant_id` still derived server-side, no cross-tenant queries)
- [ ] No new refresh path introduced outside the single locked path
