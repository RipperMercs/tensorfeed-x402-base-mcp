# Changelog

## 0.1.2 - 2026-05-11

Glama directory polish: add MCPB manifest, icon, mcpbignore, and CHANGELOG so the package can be installed via the MCPB bundle workflow and scored properly in third-party MCP catalogs. No runtime behavior changes.

- Add `manifest.json` (MCPB v0.3 format) describing the server, tool generation, runtime constraints, and platform compatibility
- Add `icon.png` (TensorFeed brand mark, 22.7 KB)
- Add `.mcpbignore` excluding source, tests, and CI scaffolding from the bundle
- Add this CHANGELOG
- Clean up `repository.url` format in `package.json` (drop the `git+` prefix and `.git` suffix for consistency with sibling packages)

## 0.1.1 - 2026-05-11

Required for the official MCP registry submission.

- Add top-level `mcpName: "ai.tensorfeed/x402-base-mcp"` to `package.json` so the registry can verify package ownership
- Add `server.json` (MCP registry v0 schema) describing tools, environment variables, and publisher metadata

## 0.1.0 - 2026-05-11

Initial release.

- Eleven read-only tools across three tiers
  - Generic Base reads: `balance`, `usdc_balance`, `block_number`, `get_tx_receipt`, `call`, `recent_transfers`
  - x402-native verification: `verify_x402_settlement`, `parse_x402_manifest`, `usdc_recent_payments_to`
  - TensorFeed flavor: `verify_afta_federation`, `tf_payment_lookup`
- Twelve-point security baseline: input validators, output sanitization, 50 KB response cap, RPC endpoint allowlist (SSRF defense), per-method rate limiting, in-process cache with method-specific TTLs, no bundled secrets, safe-run wrapper for non-echoing errors, external-string origin markers, npm Trusted Publisher OIDC + provenance, minimal dependency surface, CodeQL + Semgrep + npm audit in CI
- 83 tests including live integration against Base mainnet (verifies the TensorFeed first canonical x402 V2 settlement on chain)
