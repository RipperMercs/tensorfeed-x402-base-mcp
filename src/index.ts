#!/usr/bin/env node
/**
 * tensorfeed-x402-base-mcp
 *
 * MCP server exposing read-only Base mainnet chain visibility with
 * x402 payment verification and AFTA federation helpers.
 *
 * Transport: stdio. Wire this server into any MCP-compatible client
 * (Claude Desktop, Claude Code, Continue, etc.) and call the registered
 * tools by name.
 *
 * Security boundary: every tool routes input through src/security/validate
 * before touching RPC or HTTP, and every output is sanitized and capped
 * (50 KB) before being returned. See README's "Threat model" section for
 * the full posture.
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';

import { balance, usdc_balance, block_number, get_tx_receipt, call, recent_transfers } from './tools/generic.js';
import {
  verify_x402_settlement,
  parse_x402_manifest,
  usdc_recent_payments_to,
  probe_x402_endpoint,
  decode_x402_payment_payload,
} from './tools/x402.js';
import {
  verify_afta_federation,
  tf_payment_lookup,
  x402_publisher_health,
  afta_federation_members,
  TF_PAYMENT_WALLET,
} from './tools/tf.js';
import { safeRun } from './security/errors.js';
import { sanitizeValue } from './security/sanitize.js';
import { enforceResponseCap, MAX_RESPONSE_BYTES } from './security/limits.js';

const PACKAGE_VERSION = '0.2.0';

const server = new McpServer({
  name: 'tensorfeed-x402-base-mcp',
  version: PACKAGE_VERSION,
});

/**
 * Every tool in this package is read-only by construction. The package
 * holds no private keys and broadcasts no transactions; every handler
 * is a `view`/`getLogs` / outbound HTTP GET against allowlisted
 * endpoints. These annotations satisfy the Anthropic Connectors
 * Directory policy requirement that every tool carries either
 * readOnlyHint: true OR destructiveHint: true.
 *
 * openWorldHint = true because results depend on external systems
 * (Base mainnet RPC, publisher /.well-known/x402 endpoints, TensorFeed
 * AFTA cert endpoint).
 */
const READ_ONLY_ANNOTATIONS = {
  readOnlyHint: true,
  destructiveHint: false,
  openWorldHint: true,
} as const;

/**
 * Wraps a tool handler in:
 *   1. safeRun (catches throws, returns structured error)
 *   2. sanitizeValue (strips control chars, caps strings)
 *   3. enforceResponseCap (50 KB hard limit on serialized output)
 *
 * Returns the MCP CallToolResult shape: `content` array with one
 * text block containing the JSON payload.
 */
function wrapTool<T extends Record<string, unknown>>(handler: (args: T) => Promise<unknown>) {
  return async (args: T) => {
    const raw = await safeRun(async () => handler(args));
    const sanitized = sanitizeValue(raw);
    const serialized = enforceResponseCap(sanitized, MAX_RESPONSE_BYTES);
    return {
      content: [
        {
          type: 'text' as const,
          text: serialized,
        },
      ],
    };
  };
}

// ---------- generic Base reads ----------

server.registerTool(
  'balance',
  {
    title: 'Get ETH balance',
    description: 'Returns the native ETH balance of an address on Base mainnet.',
    inputSchema: {
      address: z.string().describe('EVM address (0x-prefixed, checksummed)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get ETH balance' },
  },
  wrapTool((args) => balance({ address: args.address })),
);

server.registerTool(
  'usdc_balance',
  {
    title: 'Get USDC balance',
    description: 'Returns the USDC balance of an address on Base mainnet (Circle native bridged USDC).',
    inputSchema: {
      address: z.string().describe('EVM address (0x-prefixed, checksummed)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get USDC balance' },
  },
  wrapTool((args) => usdc_balance({ address: args.address })),
);

server.registerTool(
  'block_number',
  {
    title: 'Get latest Base block number',
    description: 'Returns the latest block number on Base mainnet.',
    inputSchema: {},
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get latest Base block number' },
  },
  wrapTool(() => block_number()),
);

server.registerTool(
  'get_tx_receipt',
  {
    title: 'Get transaction receipt',
    description: 'Returns the receipt for a transaction on Base mainnet, including status, gas used, and a summary of emitted logs.',
    inputSchema: {
      tx_hash: z.string().describe('32-byte tx hash (0x-prefixed)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Get transaction receipt' },
  },
  wrapTool((args) => get_tx_receipt({ tx_hash: args.tx_hash })),
);

server.registerTool(
  'call',
  {
    title: 'Read-only contract call',
    description: 'Performs an eth_call against a contract on Base mainnet. Read-only; never broadcasts a transaction.',
    inputSchema: {
      contract: z.string().describe('Contract address (0x-prefixed)'),
      data: z.string().describe('ABI-encoded calldata (0x-prefixed hex, up to 64 KB)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Read-only contract call' },
  },
  wrapTool((args) => call({ contract: args.contract, data: args.data })),
);

server.registerTool(
  'recent_transfers',
  {
    title: 'Recent USDC transfers touching an address',
    description: 'Returns USDC Transfer events involving the given address over the last N blocks on Base mainnet. Direction filter: in, out, or both.',
    inputSchema: {
      address: z.string().describe('EVM address (0x-prefixed)'),
      blocks_back: z.number().optional().describe('How many blocks back to scan (1-10000, default 1000)'),
      direction: z.enum(['in', 'out', 'both']).optional().describe('Filter to incoming, outgoing, or both (default both)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Recent USDC transfers touching an address' },
  },
  wrapTool((args) => recent_transfers({
    address: args.address,
    blocks_back: args.blocks_back,
    direction: args.direction,
  })),
);

// ---------- x402-native tools ----------

server.registerTool(
  'verify_x402_settlement',
  {
    title: 'Verify an x402 payment settlement on Base',
    description: 'Given a tx hash, expected recipient, and expected USDC amount, returns a structured verdict on whether the on-chain USDC Transfer event actually matches the claimed settlement. Use to independently verify any x402 payment receipt.',
    inputSchema: {
      tx_hash: z.string().describe('32-byte tx hash (0x-prefixed)'),
      expected_recipient: z.string().describe('Expected payTo wallet (0x-prefixed, checksummed)'),
      expected_amount_usdc: z.union([z.string(), z.number()]).describe('Expected USDC amount, e.g. "0.02" or 0.02'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Verify an x402 payment settlement on Base' },
  },
  wrapTool((args) => verify_x402_settlement({
    tx_hash: args.tx_hash,
    expected_recipient: args.expected_recipient,
    expected_amount_usdc: args.expected_amount_usdc,
  })),
);

server.registerTool(
  'parse_x402_manifest',
  {
    title: 'Fetch and parse a publisher\'s x402 manifest',
    description: 'Fetches https://{domain}/.well-known/x402.json (or x402) and returns the structured manifest. Used to discover what an x402-paid publisher accepts (scheme, network, payTo, prices, paid endpoints).',
    inputSchema: {
      domain: z.string().describe('Bare hostname, e.g. "tensorfeed.ai" (no scheme or path)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Fetch and parse a publisher\'s x402 manifest' },
  },
  wrapTool((args) => parse_x402_manifest({ domain: args.domain })),
);

server.registerTool(
  'usdc_recent_payments_to',
  {
    title: 'Recent USDC payments to an address',
    description: 'Returns USDC transfers TO the given address over the last N blocks on Base mainnet. A convenience wrapper for x402 merchants verifying incoming agent payments.',
    inputSchema: {
      address: z.string().describe('Recipient address (0x-prefixed)'),
      blocks_back: z.number().optional().describe('How many blocks back to scan (1-10000, default 1000)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Recent USDC payments to an address' },
  },
  wrapTool((args) => usdc_recent_payments_to({
    address: args.address,
    blocks_back: args.blocks_back,
  })),
);

server.registerTool(
  'probe_x402_endpoint',
  {
    title: 'Probe whether a URL is x402-paid',
    description: 'Performs a GET against an https URL and reports whether the response looks like a canonical x402-paid endpoint (HTTP 402 with a JSON body containing accepts[]). Read-only. Does not pay, does not broadcast.',
    inputSchema: {
      url: z.string().describe('Absolute https:// URL to probe (no http, no file, no IP; rejects localhost/private network targets)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Probe whether a URL is x402-paid' },
  },
  wrapTool((args) => probe_x402_endpoint({ url: args.url })),
);

server.registerTool(
  'decode_x402_payment_payload',
  {
    title: 'Decode an X-PAYMENT header payload',
    description: 'Decodes a base64-encoded X-PAYMENT header payload per the Coinbase x402 V2 spec. Returns the parsed scheme, network, x402Version, EIP-3009 authorization, and signature. Pure offline decode; no signature is verified and no network call is made.',
    inputSchema: {
      payload: z.string().describe('Base64-encoded X-PAYMENT header value (standard or URL-safe). Decoded size capped at 64 KB.'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Decode an X-PAYMENT header payload' },
  },
  wrapTool((args) => decode_x402_payment_payload({ payload: args.payload })),
);

// ---------- TF-flavor tools ----------

server.registerTool(
  'verify_afta_federation',
  {
    title: 'AFTA certification check for a domain',
    description: 'Calls TensorFeed\'s canonical AFTA certification endpoint for a domain. Returns a scored checklist of which Agent Fair-Trade Agreement tenets the domain\'s public surfaces satisfy. Read-only.',
    inputSchema: {
      domain: z.string().describe('Bare hostname, e.g. "tensorfeed.ai"'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'AFTA certification check for a domain' },
  },
  wrapTool((args) => verify_afta_federation({ domain: args.domain })),
);

server.registerTool(
  'tf_payment_lookup',
  {
    title: 'Check if a tx was a USDC payment to TensorFeed',
    description: `On-chain lookup: was this transaction hash a USDC payment to TensorFeed's canonical payment wallet (${TF_PAYMENT_WALLET}) on Base mainnet? Returns structured details if yes. For credit attribution and endpoint mapping, the paying agent should call https://tensorfeed.ai/api/payment/history with its bearer token.`,
    inputSchema: {
      tx_hash: z.string().describe('32-byte tx hash (0x-prefixed)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Check if a tx was a USDC payment to TensorFeed' },
  },
  wrapTool((args) => tf_payment_lookup({ tx_hash: args.tx_hash })),
);

server.registerTool(
  'x402_publisher_health',
  {
    title: 'Health and uptime of an x402 publisher',
    description: 'Returns the latest x402 status snapshot for a given domain from TensorFeed\'s canonical hourly monitor: current outcome, latency, 24h/7d uptime, and the recent series of check results. Useful for agents picking which paid publisher to depend on.',
    inputSchema: {
      domain: z.string().describe('Bare hostname, e.g. "tensorfeed.ai" (no scheme or path)'),
    },
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'Health and uptime of an x402 publisher' },
  },
  wrapTool((args) => x402_publisher_health({ domain: args.domain })),
);

server.registerTool(
  'afta_federation_members',
  {
    title: 'List confirmed AFTA federation members',
    description: 'Returns the canonical list of confirmed Agent Fair-Trade Agreement (AFTA) federation members as of this package version. Static curated list; chain through verify_afta_federation(domain) to confirm live cert posture per member.',
    inputSchema: {},
    annotations: { ...READ_ONLY_ANNOTATIONS, title: 'List confirmed AFTA federation members' },
  },
  wrapTool(() => afta_federation_members()),
);

// ---------- stdio bootstrap ----------

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  // Once connected the SDK takes over stdin/stdout; do not log to stdout.
  // eslint-disable-next-line no-console
  console.error(`[tensorfeed-x402-base-mcp] v${PACKAGE_VERSION} ready on stdio`);
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error('[tensorfeed-x402-base-mcp] fatal:', err);
  process.exit(1);
});
