# @tensorfeed/x402-base-mcp

Read-only MCP server for verifying x402 USDC settlements on Base mainnet. Drop it into any MCP-compatible agent (Claude Desktop, Claude Code, Cursor, ChatGPT) to independently audit x402 payment receipts on-chain, parse publisher `.well-known/x402` manifests, and check AFTA federation status. No private keys, no signing, no broadcasts.

```
npm install -g @tensorfeed/x402-base-mcp
```

## Relationship to Coinbase Base MCP

Coinbase shipped **Base MCP** (the official `mcp.base.org` server, launched May 2026) as the *transact-side* MCP: it connects an agent to a Base Account and lets the agent propose swaps, transfers, and x402 payments that the user approves in-wallet.

This package, `@tensorfeed/x402-base-mcp`, is the *verify-side* MCP. Once an x402 payment has been made (by Base MCP, by a server-side `@coinbase/x402` middleware, or by any other x402 client), this server lets the calling agent independently check the on-chain settlement, parse the publisher's `/.well-known/x402` manifest, and audit the receipt. Read-only chain visibility, no wallet.

The two are complementary, not competing. Use Base MCP to pay. Use this MCP to verify.

## Why a separate verify MCP

x402 is a payment protocol where agents pay merchants in USDC on Base for paid API responses. When an agent receives a payment receipt back, it has two options for confirming that the settlement actually happened the way the receipt claims:

1. Trust the merchant
2. Read the on-chain Transfer event itself

Most existing EVM MCP servers either require a private key (so the agent can also send transactions, which is operationally risky and unnecessary for verification), or are generic multi-chain readers that don't speak x402. This server is the read-only, x402-aware option. Drop it into a Claude Desktop or Claude Code session and any agent can verify x402 payments without operating a wallet.

The TensorFeed-flavor tools (`verify_afta_federation`, `tf_payment_lookup`) compose the same primitives against TF's canonical surfaces and demonstrate the pattern. Use them or ignore them; the generic tools work fine on their own.

## Installation

### Claude Desktop

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "tensorfeed-x402-base": {
      "command": "npx",
      "args": ["-y", "@tensorfeed/x402-base-mcp"]
    }
  }
}
```

### Claude Code

```bash
claude mcp add tensorfeed-x402-base -- npx -y @tensorfeed/x402-base-mcp
```

### Optional: bring your own RPC

The server defaults to the public Base RPC (`https://mainnet.base.org`), which is fine for casual use. For heavier workloads, set an Alchemy or Infura URL via `TENSORFEED_RPC_URL`. The URL must match the allowlist in `src/rpc/allowlist.ts`; anything else falls back to the public endpoint and logs a warning to stderr.

```bash
export TENSORFEED_RPC_URL="https://base-mainnet.g.alchemy.com/v2/YOUR_KEY"
```

Affiliate links if you don't already have an account:
- Alchemy: https://www.alchemy.com/
- Infura: https://www.infura.io/

## Tools

### Generic Base reads

| Tool | Description |
|------|-------------|
| `balance` | Native ETH balance for an address |
| `usdc_balance` | USDC (Circle native bridged) balance for an address |
| `block_number` | Latest Base block number |
| `get_tx_receipt` | Full tx receipt with status, gas, and logs summary |
| `call` | Read-only contract call (eth_call, never broadcasts) |
| `recent_transfers` | USDC Transfer events involving an address over N blocks |

### x402-native verification

| Tool | Description |
|------|-------------|
| `verify_x402_settlement` | Given a tx hash, expected recipient, and expected USDC amount, returns a structured verdict on whether the on-chain Transfer event matches. |
| `parse_x402_manifest` | Fetches `https://{domain}/.well-known/x402.json`, returns the structured manifest. |
| `usdc_recent_payments_to` | USDC transfers TO an address over N blocks; the merchant-side view. |
| `probe_x402_endpoint` | Probes any https URL and reports whether it returns a canonical x402-paid 402 response with `accepts[]`. |
| `decode_x402_payment_payload` | Offline decode of a base64 `X-PAYMENT` header (Coinbase x402 V2): returns scheme, network, version, EIP-3009 authorization, signature. |

### TensorFeed flavor

| Tool | Description |
|------|-------------|
| `verify_afta_federation` | Calls TensorFeed's AFTA certification endpoint for a domain, returns a scored checklist. |
| `tf_payment_lookup` | Checks whether a tx hash is a USDC payment to TensorFeed's canonical wallet on Base. |
| `x402_publisher_health` | Returns current outcome + 24h/7d uptime + recent series for a domain monitored by TensorFeed's hourly x402 status probe. |
| `afta_federation_members` | Returns the canonical curated list of confirmed AFTA federation members (TF origin + federated members). |

## Examples

Verify an x402 settlement (works on TensorFeed's first canonical V2 payment):

```
verify_x402_settlement({
  tx_hash: "0xe20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67",
  expected_recipient: "0x549c82e6bFC54bdaE9A2073744CBC2AF5D1FC6D1",
  expected_amount_usdc: "0.02"
})
// returns { ok: true, verified: true, matches: [...] }
```

Inspect a publisher's x402 manifest:

```
parse_x402_manifest({ domain: "tensorfeed.ai" })
```

Check AFTA certification:

```
verify_afta_federation({ domain: "tensorfeed.ai" })
```

## Threat model

Read-only chain-visibility MCP. The full picture is in `SECURITY.md`; the short version:

- **No private keys**, no signing, no broadcasts. The server cannot move funds.
- **Input validators** on every tool reject malformed inputs (bad checksums, malformed hashes, URL-shaped domains, private/loopback hostnames).
- **Output sanitization** strips C0/C1 control characters and zero-width / direction-override marks from every string returned to the calling agent.
- **External strings** carry an `_origin: "external"` marker so the calling agent knows the value came from a third party.
- **50 KB response cap** on serialized tool output; oversized responses collapse to a structured stub.
- **RPC allowlist** limits self-hosters to known endpoints; arbitrary URLs are rejected and fall back to public Base RPC.
- **No telemetry**, no phone-home, no analytics.
- **Provenance**: npm releases are published via GitHub Actions OIDC with cryptographic provenance attestations. Verify with `npm audit signatures`.

Report security issues to **security@tensorfeed.ai**. Please do not file a public issue or CVE for an unfixed vulnerability.

## License

MIT

## Related

- [Coinbase Base MCP](https://mcp.base.org) - the official transact-side MCP for Base. Pair with this package for a full pay + verify loop: Base MCP signs the x402 payment, this package independently confirms the settlement on-chain.
- [@tensorfeed/mcp-server](https://www.npmjs.com/package/@tensorfeed/mcp-server) - companion package, the TensorFeed data MCP (news, status, models, benchmarks, premium endpoints). Complementary role: this server verifies x402 payments on-chain; mcp-server wraps the TF data API as MCP tools.
- [TensorFeed](https://tensorfeed.ai) - AI ecosystem data layer
- [TensorFeed developers](https://tensorfeed.ai/developers) - free + premium API for AI agents
- [Agent Fair-Trade Agreement (AFTA)](https://tensorfeed.ai/agent-fair-trade) - open standard for honest agent commerce
- [x402 spec](https://github.com/coinbase/x402) - the payment protocol this MCP verifies
