# Security Policy

## Supported Versions

The latest minor version on npm is the only supported release. Older versions do not receive security backports.

## Reporting a Vulnerability

Email **security@tensorfeed.ai** with:

- A description of the issue
- Reproduction steps or a proof of concept
- Your name or handle (for the changelog credit, optional)

Please do not file a public issue, post on social media, or open a CVE for an unfixed vulnerability. We aim to acknowledge reports within 72 hours and to ship a patch within 14 days for high-severity issues. Once a fix is released we will publish a brief advisory and credit the reporter unless asked not to.

## What's in scope

- Code in `src/`
- Default RPC endpoints in `src/rpc/allowlist.ts`
- The `dist/` output published to npm
- GitHub Actions workflows in `.github/workflows/`
- The npm package supply chain (provenance, OIDC publishing)

## What's not in scope

- Bugs in viem, the Model Context Protocol SDK, or other upstream dependencies. Report those to their respective maintainers; we'll bump the version once a patched release ships.
- The user's chosen RPC provider's behavior (rate limits, downtime, data accuracy)
- Issues caused by ignoring documented inputs (e.g. malformed addresses, non-Base chains)
- The behavior of the MCP client (Claude Desktop, etc.) consuming this server's output

## Threat model (summary)

This is a read-only chain-visibility MCP server. There are no signing keys, no write capability, no funds to move. The realistic attack surface is:

1. **Supply chain**: a compromised npm release publishing malicious code. Mitigated by Trusted Publisher OIDC + provenance attestations and minimal dependency surface.
2. **Prompt injection through outputs**: an attacker controls a value returned by an external service (a publisher's `/.well-known/x402.json`, an ENS name, a contract event log) and uses it to manipulate the calling agent's reasoning. Mitigated by output sanitization (control char stripping, length caps) and explicit `_origin: external` markers.
3. **SSRF via tool inputs**: an agent input passes a private/loopback hostname to a fetch tool. Mitigated by domain validators rejecting `localhost`, private IPv4 ranges, and URL-shaped inputs.
4. **RPC provider key exfiltration**: leaked Alchemy/Infura URL drains caller billing. Mitigated by env-only configuration (never bundled), allowlist-checked endpoints, and standardized error messages that do not echo URLs.
5. **Resource exhaustion**: an agent calls a tool in a tight loop and burns RPC budget. Mitigated by in-process caching, per-method token-bucket rate limits, and bounded loop ranges (max `blocks_back = 10000`).
6. **Oversized responses blowing context**: a tool returns a huge payload. Mitigated by a 50 KB hard cap on serialized output; oversize responses collapse to a structured stub.

For the full posture, see the "Threat model" section of the README.
