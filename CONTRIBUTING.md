# Contributing

Thanks for the interest in `@tensorfeed/x402-base-mcp`. This guide covers how to file an issue, what kinds of changes are welcome, and how releases happen.

## Filing issues

- Bug reports: include the version, the tool you called, the input, and the response. Stack traces are gold.
- Feature requests: explain the use case first, then the proposed shape. We are likely to push back on tools that would require holding private keys, since the package is intentionally read-only.
- Security reports: do NOT file a public issue. See SECURITY.md for the private-disclosure flow.

## Pull requests

- One concern per PR. A small, well-scoped change merges faster than a large refactor.
- Tests required. The existing security utilities (`src/security/`) and RPC client (`src/rpc/`) have full test coverage; new code should match.
- Run `npm run typecheck` and `npm test` locally before opening the PR.
- Keep the threat model in mind. New tools must route inputs through `src/security/validate.ts`, return outputs through `src/security/sanitize.ts`, and respect the 50 KB response cap in `src/security/limits.ts`.

## Code style

- TypeScript strict mode. No `any` types in new code.
- Prefer named functions over arrow functions for module exports.
- Comments explain *why*, not *what*. Save the long form for prose; the code should read on its own.
- One-line module-top JSDoc comment explaining what the file is for is encouraged.

## Releases

Versioning follows semver:

- Patch: bug fixes, no schema changes
- Minor: new tools, new optional inputs, no breaking changes
- Major: anything that changes existing tool inputs or outputs

Release flow:

1. PR lands on `main`
2. CI runs typecheck + tests + npm audit
3. Maintainer bumps version in `package.json`, `server.json`, and `manifest.json`, adds a CHANGELOG entry, tags `v<x.y.z>`
4. Tag triggers `.github/workflows/publish.yml` which builds, runs tests, and publishes to npm with provenance via OIDC

## Maintainer

This package is maintained by [TensorFeed.ai](https://tensorfeed.ai). Email: `security@tensorfeed.ai` for security, `evan@tensorfeed.ai` for everything else.
