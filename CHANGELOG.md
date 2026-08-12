# Changelog

## Unreleased

Two fixes from a security review prompted by the August 2026 GhostSplice research on splitting instructions across MCP channels. This server was never a vector for that attack (it never requests sampling, its tool descriptions are static literals, and every value that can flow back in as a tool argument is allowlist-validated), but the review surfaced a real problem next door.

- **Chain-identity check before any settlement answer.** `BASE_CHAIN_ID` was declared and never used. The RPC allowlist constrains which host we talk to but not which chain that host serves, and providers like Alchemy, Infura, and dRPC serve every network off the same allowlisted domain, so `base-sepolia.g.alchemy.com` passed every existing check. Because an EVM address is identical on every chain, an RPC pointed at Base Sepolia would confirm a free testnet USDC transfer to the real payment wallet as a genuine mainnet settlement, which is the one thing this server exists to rule out. Every chain-reading tool now calls a memoized `assertBaseChain()` that asks the node for its chain id and refuses to answer unless it is 8453. Verified against a live testnet RPC: `https://base-sepolia.drpc.org` passes the host allowlist and is now rejected with `chain_mismatch` (expected 8453, actual 84532). Costs one `eth_chainId` per process. A mismatch caches the rejection so a misconfigured server fails closed instead of hammering the RPC; a transient network error clears the memo so it can retry.
- **Publisher-controlled payloads are now actually marked.** `externalString()` was imported by `tools/tf.ts` and `tools/x402.ts`, unit-tested, and never called, while `parse_x402_manifest`'s doc comment claimed "External strings carry an `_origin` marker." They did not. `parse_x402_manifest` and `probe_x402_endpoint` both relay entire third-party JSON bodies into the calling agent's context, so those responses now carry `_origin: "external"` and a `content_notice` saying to treat the payload as data rather than instructions. Marking is container-level rather than per string, because rewriting every leaf of a manifest into `{value,_origin}` would destroy the structure the agent needs to read. The stale doc claim is corrected and the unused imports are gone.
- 10 new offline tests (89 offline, 124 passing overall).

## 0.2.1 - 2026-05-27

Positioning update for the Coinbase Base MCP launch (mcp.base.org, May 2026). No code changes; documentation and metadata only.

- README lede rewritten to lead with "read-only verifier for x402 USDC settlements." Adds a new "Relationship to Coinbase Base MCP" section explaining that this package is the verify-side companion (read-only chain visibility) to Coinbase's official transact-side Base MCP (signs and submits via Base Account).
- `Related` section in README now links Coinbase Base MCP first, with the pay + verify loop framing.
- `package.json` `description` rewritten: drops the "x402 ecosystem's canonical chain reader" phrasing (now ambiguous next to Coinbase's official "Base MCP") in favor of "the verify-side companion to Coinbase Base MCP, with AFTA federation helpers."
- `manifest.json` `description` matched to the new framing.
- No tool surface changes. Still 15 read-only tools, 98 tests, same security baseline.

## 0.2.0 - 2026-05-12

Four new tools for agents that want to negotiate x402 payments more intelligently and pick healthy publishers.

- `probe_x402_endpoint(url)`: fetch any https URL and report whether the response looks like canonical x402 (HTTP 402 + JSON body with `accepts[]`). Read-only probe; never pays, never broadcasts. SSRF-hardened (refuses http://, file://, raw IPs, loopback, private network ranges).
- `decode_x402_payment_payload(payload)`: offline decode of a base64 X-PAYMENT header per the Coinbase x402 V2 spec. Returns parsed `scheme`, `network`, `x402Version`, EIP-3009 `authorization`, and `signature`, plus shape-warning flags for non-canonical inputs. Pure offline; no network calls, no signature verification.
- `x402_publisher_health(domain)`: fetches TensorFeed's canonical hourly status snapshot and returns the per-publisher record: current outcome, latency, 24h/7d uptime, recent series. Returns `monitored: false` for domains TF does not yet probe.
- `afta_federation_members()`: static curated list of confirmed AFTA federation members (TensorFeed origin + TerminalFeed). Each entry includes the domain's role, join date, x402 manifest URL, and AFTA cert-check URL.
- New `requireHttpsUrl` and `requireBase64` validators in `src/security/validate.ts`. SSRF guard refuses loopback, private network, link-local, and bare single-label hostnames.
- 98 tests pass (up from 83). Live integration tests skipped under `VITEST_SKIP_LIVE=1`.
- Tool count: 11 → 15. All new tools annotated `readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: true`.

## 0.1.3 - 2026-05-12

Anthropic Connectors Directory readiness: add MCP tool annotations (`readOnlyHint: true`, `destructiveHint: false`, `openWorldHint: true`, plus title) to every tool. The 2026 Connectors Directory submission policy rejects 30% of servers for missing this exact metadata; this release unblocks listing.

- Add `READ_ONLY_ANNOTATIONS` constant and apply to all 11 `server.registerTool` calls
- No tool behavior change; every tool was already read-only by construction

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
