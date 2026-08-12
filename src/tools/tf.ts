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
import { sanitizeValue, sanitizeString } from '../security/sanitize.js';
import { getClient, cached, rateLimit, assertBaseChain, CACHE_TTL } from '../rpc/client.js';
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
const TF_X402_STATUS_ENDPOINT = 'https://tensorfeed.ai/api/x402/status';
const FETCH_TIMEOUT_MS = 10_000;

/**
 * Known AFTA federation members. Hand-maintained list of domains the
 * TensorFeed team has confirmed implement the Agent Fair-Trade Agreement
 * with code-enforced no-charge guarantees and signed receipts.
 *
 * This is intentionally a static list rather than a network call: it is
 * the curated answer to "who has TF actually federated with?" rather
 * than "who has merely shipped /.well-known/x402.json?" Membership grows
 * with package versions; agents that need the live discovery surface
 * should call verify_afta_federation(domain) per-domain instead.
 */
const AFTA_FEDERATION_MEMBERS: ReadonlyArray<{
  domain: string;
  role: 'origin' | 'federated_member';
  joined_at: string;
  x402_manifest: string;
  afta_certify_check: string;
}> = [
  {
    domain: 'tensorfeed.ai',
    role: 'origin',
    joined_at: '2026-04-30',
    x402_manifest: 'https://tensorfeed.ai/.well-known/x402.json',
    afta_certify_check: 'https://tensorfeed.ai/api/afta-certify/check?domain=tensorfeed.ai',
  },
  {
    domain: 'terminalfeed.io',
    role: 'federated_member',
    joined_at: '2026-05-08',
    x402_manifest: 'https://terminalfeed.io/.well-known/x402.json',
    afta_certify_check: 'https://tensorfeed.ai/api/afta-certify/check?domain=terminalfeed.io',
  },
];

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
  await assertBaseChain();

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

/**
 * x402_publisher_health
 *
 * Calls TF's canonical x402 status endpoint and filters to one domain.
 * Returns current outcome, recent series, and uptime stats. Used by
 * agents picking a publisher: "is this x402-paid endpoint healthy
 * enough to depend on right now?"
 *
 * TF runs an hourly cron probe across all known x402 publishers. The
 * series array carries the last several days of checks. Each tick has
 * outcome (ok, manifest_malformed, unreachable, timeout, http_error)
 * and observed latency.
 */
export async function x402_publisher_health(args: { domain: unknown }) {
  const domain = requireDomain(args.domain);
  await rateLimit('x402_publisher_health');

  return cached(
    `x402_health:${domain}`,
    CACHE_TTL.WELL_KNOWN,
    async () => {
      let res: Response;
      try {
        res = await fetch(TF_X402_STATUS_ENDPOINT, {
          method: 'GET',
          headers: {
            Accept: 'application/json',
            'User-Agent': buildUserAgent(),
          },
          signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
        });
      } catch {
        return { ok: false as const, error: 'status_endpoint_unreachable' };
      }
      if (!res.ok) {
        return {
          ok: false as const,
          error: 'status_endpoint_error',
          http_status: res.status,
        };
      }
      let snapshot: unknown;
      try {
        snapshot = await res.json();
      } catch {
        return { ok: false as const, error: 'status_endpoint_bad_json' };
      }
      const snap = snapshot as
        | { publishers?: unknown; generated_at?: unknown }
        | null;
      const publishers = snap && Array.isArray(snap.publishers) ? snap.publishers : null;
      if (!publishers) {
        return { ok: false as const, error: 'status_endpoint_missing_publishers' };
      }
      const match = publishers.find(
        (p) =>
          p &&
          typeof p === 'object' &&
          typeof (p as { domain?: unknown }).domain === 'string' &&
          ((p as { domain: string }).domain as string).toLowerCase() === domain,
      ) as Record<string, unknown> | undefined;
      if (!match) {
        return {
          ok: true as const,
          monitored: false,
          domain,
          note: 'TF does not currently monitor this domain. To request monitoring open an issue at https://github.com/RipperMercs/tensorfeed-x402-base-mcp/issues.',
        };
      }
      return {
        ok: true as const,
        monitored: true,
        domain,
        source: TF_X402_STATUS_ENDPOINT,
        generated_at:
          snap && typeof snap.generated_at === 'string' ? snap.generated_at : null,
        record: sanitizeValue(match),
      };
    },
  );
}

/**
 * afta_federation_members
 *
 * Returns the canonical list of confirmed AFTA federation members. This
 * is a static list maintained in-package; the latest version always
 * reflects the federation as of that package release. Agents that need
 * to verify the live AFTA posture of any of these domains should chain
 * the response through verify_afta_federation(domain).
 */
export async function afta_federation_members() {
  return {
    ok: true as const,
    standard: 'AFTA (Agent Fair-Trade Agreement)',
    standard_url: 'https://tensorfeed.ai/originals/agent-fair-trade-agreement',
    member_count: AFTA_FEDERATION_MEMBERS.length,
    members: AFTA_FEDERATION_MEMBERS.map((m) => ({ ...m })),
    note: 'Static list maintained per package version. To check live cert status of any member, chain through verify_afta_federation(domain).',
    last_updated_in_package: '2026-05-12',
  };
}

function buildUserAgent(): string {
  const suffix = process.env.TENSORFEED_UA_SUFFIX
    ? ` ${sanitizeString(process.env.TENSORFEED_UA_SUFFIX, 64)}`
    : '';
  return `tensorfeed-x402-base-mcp/0.2.0${suffix}`;
}
