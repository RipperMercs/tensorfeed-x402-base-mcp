/**
 * TensorFeed-flavor tools.
 *
 * These tools demonstrate domain authority by composing the generic
 * x402 building blocks against TF-owned canonical surfaces. They are
 * read-only and use only public data (TF's published wallet address,
 * TF's public AFTA certification endpoint).
 *
 * They are intentionally TF-specific rather than generic; that's the
 * point. An agent doing AFTA-aware reasoning gets a one-call shortcut
 * to the canonical answer instead of having to wire up the manifest
 * fetch + on-chain cross-check themselves.
 */

import { formatUnits, parseEventLogs, type Address } from 'viem';
import { requireDomain, requireTxHash } from '../security/validate.js';
import { sanitizeValue, externalString, sanitizeString } from '../security/sanitize.js';
import { getClient, cached, rateLimit, CACHE_TTL } from '../rpc/client.js';
import { USDC_ADDRESS, USDC_DECIMALS, ERC20_ABI, BASE_CAIP2 } from '../chains.js';

// TF's canonical Base mainnet payment wallet. This is the wallet that
// receives all USDC settlements for TF's x402-paid premium endpoints.
// Cross-published at:
//   - https://tensorfeed.ai/.well-known/x402.json
//   - https://tensorfeed.ai/api/payment/info
//   - https://tensorfeed.ai/llms.txt
// If TF rotates this wallet, this constant must be updated and a new
// version of this MCP package must be released.
export const TF_PAYMENT_WALLET: Address = '0x549c82e6bFC54bdaE9A2073744CBC2AF5D1FC6D1';

const TF_AFTA_CERT_ENDPOINT = 'https://tensorfeed.ai/api/afta-certify/check';
const FETCH_TIMEOUT_MS = 10_000;

/**
 * verify_afta_federation
 *
 * Calls TF's canonical AFTA certification endpoint for a given domain.
 * Returns the scored checklist showing which AFTA tenets the domain's
 * public surfaces satisfy. This is the authoritative "is this domain
 * AFTA-aware?" answer.
 *
 * The endpoint itself is read-only and idempotent; it makes outbound
 * fetches against the target domain's /.well-known/* URLs and validates
 * the JSON against the canonical Coinbase x402 V2 + AFTA standards.
 */
export async function verify_afta_federation(args: { domain: unknown }) {
  const domain = requireDomain(args.domain);
  await rateLimit('verify_afta_federation');

  const result = await cached(
    `afta_cert:${domain}`,
    CACHE_TTL.WELL_KNOWN,
    async () => {
      const url = `${TF_AFTA_CERT_ENDPOINT}?domain=${encodeURIComponent(domain)}`;
      try {
        const res = await fetch(url, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'User-Agent': buildUserAgent(),
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
        if (!res.ok) {
          return { ok: false, error: 'cert_endpoint_error', http_status: res.status };
        }
        const data = (await res.json()) as Record<string, unknown>;
        return {
          ok: true,
          domain,
          source: TF_AFTA_CERT_ENDPOINT,
          fetched_at: new Date().toISOString(),
          report: sanitizeValue(data),
        };
      } catch (e) {
        return { ok: false, error: 'cert_endpoint_unreachable' };
      }
    },
  );
  return result;
}

/**
 * tf_payment_lookup
 *
 * On-chain lookup: was this transaction hash a USDC payment to TF's
 * canonical payment wallet on Base mainnet? Returns the matched
 * transfer details if yes, or a structured "not_a_tf_payment" if no.
 *
 * Limitation: this is a wallet-level lookup. It cannot tell you which
 * specific TF endpoint the agent was paying for or how many credits
 * were granted; that mapping lives in TF's bearer-token-scoped payment
 * history (which is not public). For credit attribution the agent
 * already holds its purchase token and can call TF's
 * /api/payment/history with it.
 *
 * Useful for: third parties auditing TF wallet activity, agents
 * confirming a tx hash is in fact a payment to TF (vs the same tx
 * being claimed by some other domain).
 */
export async function tf_payment_lookup(args: { tx_hash: unknown }) {
  const txHash = requireTxHash(args.tx_hash);
  await rateLimit('tf_payment_lookup');

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
      is_tf_payment: false,
      reason: 'tx_not_found',
      tx_hash: txHash,
      network: BASE_CAIP2,
    };
  }

  if (receipt.status !== 'success') {
    return {
      ok: true as const,
      is_tf_payment: false,
      reason: 'tx_reverted',
      tx_hash: txHash,
      network: BASE_CAIP2,
      block_number: receipt.blockNumber.toString(),
    };
  }

  const usdcLogs = receipt.logs.filter(
    (l) => l.address.toLowerCase() === USDC_ADDRESS.toLowerCase(),
  );
  const parsed = parseEventLogs({
    abi: ERC20_ABI,
    eventName: 'Transfer',
    logs: usdcLogs,
  });

  const tfTransfers = parsed
    .map((log) => {
      const a = log.args as { from: Address; to: Address; value: bigint };
      return {
        from: a.from,
        to: a.to,
        amount_raw: a.value.toString(),
        amount_usdc: formatUnits(a.value, USDC_DECIMALS),
      };
    })
    .filter((t) => t.to.toLowerCase() === TF_PAYMENT_WALLET.toLowerCase());

  if (tfTransfers.length === 0) {
    return {
      ok: true as const,
      is_tf_payment: false,
      reason: 'no_transfer_to_tf_wallet',
      tx_hash: txHash,
      network: BASE_CAIP2,
      block_number: receipt.blockNumber.toString(),
      tf_payment_wallet: TF_PAYMENT_WALLET,
      hint: 'This tx executed successfully but did not transfer USDC to TF. If you expected this to be a TF payment, double-check the recipient wallet matches the one published at https://tensorfeed.ai/.well-known/x402.json',
    };
  }

  return {
    ok: true as const,
    is_tf_payment: true,
    tx_hash: txHash,
    network: BASE_CAIP2,
    block_number: receipt.blockNumber.toString(),
    tf_payment_wallet: TF_PAYMENT_WALLET,
    transfers: tfTransfers,
    note: 'On-chain wallet-level match only. For credit attribution and endpoint mapping, the paying agent should call https://tensorfeed.ai/api/payment/history with its bearer token.',
    docs: 'https://tensorfeed.ai/developers/agent-payments',
  };
}

function buildUserAgent(): string {
  const suffix = process.env.TENSORFEED_UA_SUFFIX
    ? ` ${sanitizeString(process.env.TENSORFEED_UA_SUFFIX, 64)}`
    : '';
  return `tensorfeed-x402-base-mcp/0.1.0${suffix}`;
}
