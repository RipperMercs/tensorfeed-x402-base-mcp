/**
 * x402-native tools.
 *
 * These are the differentiated value-add of this MCP: they let an agent
 * verify x402 payment claims on Base mainnet without trusting a publisher's
 * receipt alone. The pattern: agent receives a payment receipt from some
 * x402-paid API, then calls one of these tools to independently confirm
 * that the on-chain settlement actually matches the claimed parameters.
 *
 * Spec references:
 *   - https://x402.org/ (overview)
 *   - https://github.com/coinbase/x402/blob/main/specs/x402-specification-v2.md
 *   - https://tensorfeed.ai/.well-known/x402.json (canonical V2 example)
 */

import {
  parseEventLogs,
  parseUnits,
  formatUnits,
  type Address,
} from 'viem';
import {
  requireTxHash,
  requireAddress,
  requireDomain,
  requireUint,
} from '../security/validate.js';
import { sanitizeString, sanitizeValue, externalString } from '../security/sanitize.js';
import { getClient, cached, rateLimit, CACHE_TTL } from '../rpc/client.js';
import { USDC_ADDRESS, USDC_DECIMALS, ERC20_ABI, BASE_CAIP2 } from '../chains.js';

const WELL_KNOWN_X402_PATHS = ['/.well-known/x402.json', '/.well-known/x402'];
const FETCH_TIMEOUT_MS = 8_000;

/**
 * verify_x402_settlement
 *
 * Given a tx hash, expected recipient, and expected USDC amount, returns
 * a structured verdict on whether the on-chain settlement actually matches.
 * No trust required of any party but the Base node.
 *
 * The check inspects USDC Transfer events on the tx receipt and looks for
 * one where `to == expected_recipient` and `value == expected_amount`.
 * Multiple transfers in one tx are supported; we look for any matching.
 *
 * Returns ok=true with `verified: true|false` and supporting evidence.
 */
export async function verify_x402_settlement(args: {
  tx_hash: unknown;
  expected_recipient: unknown;
  expected_amount_usdc: unknown;
}) {
  const txHash = requireTxHash(args.tx_hash);
  const expectedRecipient = requireAddress(args.expected_recipient, 'expected_recipient');
  if (typeof args.expected_amount_usdc !== 'string' && typeof args.expected_amount_usdc !== 'number') {
    return {
      ok: false as const,
      error: 'validation_failed',
      details: { field: 'expected_amount_usdc', code: 'must-be-string-or-number' },
    };
  }
  const amountStr = String(args.expected_amount_usdc);
  if (!/^\d+(\.\d{1,6})?$/.test(amountStr)) {
    return {
      ok: false as const,
      error: 'validation_failed',
      details: { field: 'expected_amount_usdc', code: 'not-a-usdc-amount' },
    };
  }
  const expectedRaw = parseUnits(amountStr, USDC_DECIMALS);

  await rateLimit('verify_x402_settlement');
  const receipt = await cached(`receipt:${txHash}`, CACHE_TTL.RECEIPT, async () => {
    try {
      return await getClient().getTransactionReceipt({ hash: txHash });
    } catch {
      return null;
    }
  });

  if (!receipt) {
    return {
      ok: true as const,
      verified: false,
      reason: 'tx_not_found',
      tx_hash: txHash,
      network: BASE_CAIP2,
    };
  }

  if (receipt.status !== 'success') {
    return {
      ok: true as const,
      verified: false,
      reason: 'tx_reverted',
      tx_hash: txHash,
      network: BASE_CAIP2,
      block_number: receipt.blockNumber.toString(),
    };
  }

  const transferEvent = ERC20_ABI.find((x) => x.type === 'event' && x.name === 'Transfer')!;
  const parsedLogs = parseEventLogs({
    abi: ERC20_ABI,
    eventName: 'Transfer',
    logs: receipt.logs.filter(
      (l) => l.address.toLowerCase() === USDC_ADDRESS.toLowerCase(),
    ),
  });

  const matches: Array<{ from: Address; to: Address; amount_raw: string; amount_usdc: string }> = [];
  for (const log of parsedLogs) {
    const { from, to, value } = log.args as { from: Address; to: Address; value: bigint };
    if (to.toLowerCase() === expectedRecipient.toLowerCase() && value === expectedRaw) {
      matches.push({
        from,
        to,
        amount_raw: value.toString(),
        amount_usdc: formatUnits(value, USDC_DECIMALS),
      });
    }
  }

  if (matches.length === 0) {
    // Provide the transfers that DID happen so the caller knows why we
    // failed. This is a verification tool; "we didn't find a match" must
    // come with evidence.
    const observed = parsedLogs.map((log) => {
      const a = log.args as { from: Address; to: Address; value: bigint };
      return {
        from: a.from,
        to: a.to,
        amount_raw: a.value.toString(),
        amount_usdc: formatUnits(a.value, USDC_DECIMALS),
      };
    });
    return {
      ok: true as const,
      verified: false,
      reason: 'no_matching_transfer',
      tx_hash: txHash,
      network: BASE_CAIP2,
      block_number: receipt.blockNumber.toString(),
      expected: {
        recipient: expectedRecipient,
        amount_usdc: amountStr,
        amount_raw: expectedRaw.toString(),
      },
      observed_usdc_transfers: observed,
    };
  }

  return {
    ok: true as const,
    verified: true,
    tx_hash: txHash,
    network: BASE_CAIP2,
    block_number: receipt.blockNumber.toString(),
    asset: 'USDC',
    contract: USDC_ADDRESS,
    matches,
  };
}

/**
 * parse_x402_manifest
 *
 * Fetches and parses a publisher's /.well-known/x402.json. Returns the
 * structured manifest if found. The response is sanitized (control chars
 * stripped, fields capped). External strings carry an _origin marker.
 *
 * Used by agents to discover what an x402-paid publisher accepts.
 */
export async function parse_x402_manifest(args: { domain: unknown }) {
  const domain = requireDomain(args.domain);
  await rateLimit('parse_x402_manifest');

  const cacheKey = `well_known_x402:${domain}`;
  const result = await cached(cacheKey, CACHE_TTL.WELL_KNOWN, async () => {
    for (const path of WELL_KNOWN_X402_PATHS) {
      const url = `https://${domain}${path}`;
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'User-Agent': buildUserAgent(),
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
          redirect: 'manual',
        });
        if (!res.ok) continue;
        const ct = (res.headers.get('content-type') || '').toLowerCase();
        if (!ct.includes('json')) continue;
        const text = await res.text();
        if (text.length > 256 * 1024) {
          // Manifest too large; refuse to parse to avoid memory bloat.
          return { ok: false, error: 'manifest_too_large', source_url: url };
        }
        let data: unknown;
        try {
          data = JSON.parse(text);
        } catch {
          return { ok: false, error: 'manifest_invalid_json', source_url: url };
        }
        return {
          ok: true,
          source_url: url,
          fetched_at: new Date().toISOString(),
          manifest: sanitizeValue(data),
        };
      } catch (e) {
        // Try next path
        continue;
      }
    }
    return { ok: false, error: 'manifest_not_found', domain };
  });

  return result;
}

/**
 * usdc_recent_payments_to
 *
 * Convenience over `recent_transfers` filtered to direction=in. Returns
 * USDC transfers TO the given address over the last N blocks. Useful for
 * any x402 merchant (including TF) to verify a recent agent payment.
 *
 * Default block range: 1000 blocks (~33 minutes on Base at 2s/block).
 */
export async function usdc_recent_payments_to(args: {
  address: unknown;
  blocks_back?: unknown;
}) {
  const address = requireAddress(args.address);
  const blocksBack = requireUint(args.blocks_back ?? 1000, 'blocks_back', 1, 10_000);
  await rateLimit('usdc_recent_payments_to');

  const client = getClient();
  const latest = await cached('block_number', CACHE_TTL.BLOCK_NUMBER, async () => client.getBlockNumber());
  const fromBlock = latest > BigInt(blocksBack) ? latest - BigInt(blocksBack) : 0n;
  const toBlock = latest;

  const transferEvent = ERC20_ABI.find((x) => x.type === 'event' && x.name === 'Transfer')!;
  const logs = await client.getLogs({
    address: USDC_ADDRESS,
    event: transferEvent as any,
    args: { to: address },
    fromBlock,
    toBlock,
  });

  const payments = (logs as Array<any>).slice(0, 100).map((log) => {
    const a = log.args as { from: Address; to: Address; value: bigint };
    return {
      block_number: log.blockNumber.toString(),
      tx_hash: log.transactionHash,
      log_index: log.logIndex,
      from: a.from,
      to: a.to,
      amount_raw: a.value.toString(),
      amount_usdc: formatUnits(a.value, USDC_DECIMALS),
    };
  });
  payments.sort((a, b) => (BigInt(b.block_number) > BigInt(a.block_number) ? 1 : -1));

  return {
    ok: true as const,
    recipient: address,
    asset: 'USDC',
    contract: USDC_ADDRESS,
    network: BASE_CAIP2,
    from_block: fromBlock.toString(),
    to_block: toBlock.toString(),
    payment_count: payments.length,
    payments,
  };
}

function buildUserAgent(): string {
  const suffix = process.env.TENSORFEED_UA_SUFFIX
    ? ` ${sanitizeString(process.env.TENSORFEED_UA_SUFFIX, 64)}`
    : '';
  return `tensorfeed-x402-base-mcp/0.1.0${suffix}`;
}
