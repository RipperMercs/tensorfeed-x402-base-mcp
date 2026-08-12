/**
 * Viem-based public client with response caching and rate limiting.
 *
 * Caching: 30s TTL for most reads (balances, receipts, calls). Block
 * number cache is shorter (3s) so freshness stays acceptable. Cache
 * is in-process memory; a long-running MCP server may eventually want
 * an LRU eviction policy but for v0.1 we cap at 500 entries.
 *
 * Rate limiting: a simple per-method token bucket protects the upstream
 * RPC from a misbehaving agent. We do not enforce a hard global cap
 * (the cap belongs upstream at the provider) but we smooth bursts.
 */

import { createPublicClient, http } from 'viem';
import { BASE_CHAIN, BASE_CHAIN_ID, ChainMismatchError } from '../chains.js';
import { resolveRpcUrl } from './allowlist.js';

function makeClient() {
  const url = resolveRpcUrl(process.env.TENSORFEED_RPC_URL);
  return createPublicClient({
    chain: BASE_CHAIN,
    transport: http(url, {
      timeout: 10_000,
      retryCount: 2,
      retryDelay: 500,
    }),
  });
}

type BaseClient = ReturnType<typeof makeClient>;

let _client: BaseClient | null = null;

export function getClient(): BaseClient {
  if (_client) return _client;
  _client = makeClient();
  return _client;
}

/**
 * Memoized chain-identity check.
 *
 * The RPC allowlist constrains which HOST we will talk to, but not which CHAIN
 * that host serves. Providers like Alchemy and Infura serve every network off
 * the same allowlisted domain, so base-sepolia.g.alchemy.com passes the
 * allowlist exactly as base-mainnet.g.alchemy.com does. Since an EVM address is
 * the same on every chain, a testnet-pointed RPC would let free testnet USDC
 * sent to the real payment wallet verify as a genuine mainnet settlement. Every
 * answer this server gives depends on being on chain 8453, so we ask the node
 * directly and refuse to answer if it is not.
 *
 * Called once per process. The resolved promise is cached, so the extra
 * eth_chainId costs one request for the lifetime of the server.
 *
 * A mismatch caches the REJECTION deliberately: the configuration is wrong and
 * retrying cannot fix it, so every later call fails closed without hammering
 * the RPC. A transient network failure clears the memo so the next call can
 * retry, since that one genuinely might succeed.
 */
let _chainVerified: Promise<void> | null = null;

export function assertBaseChain(): Promise<void> {
  if (!_chainVerified) {
    _chainVerified = (async () => {
      let actual: number;
      try {
        actual = await getClient().getChainId();
      } catch (err) {
        _chainVerified = null;
        throw err;
      }
      if (actual !== BASE_CHAIN_ID) {
        throw new ChainMismatchError(actual);
      }
    })();
  }
  return _chainVerified;
}

/** Reset cached client. Test-only. */
export function _resetClient(): void {
  _client = null;
  _chainVerified = null;
}

// -------- in-memory cache --------

interface CacheEntry {
  value: unknown;
  expiresAt: number;
}

const CACHE = new Map<string, CacheEntry>();
const CACHE_MAX = 500;
const DEFAULT_TTL_MS = 30_000;

export async function cached<T>(
  key: string,
  ttlMs: number,
  loader: () => Promise<T>,
): Promise<T> {
  const now = Date.now();
  const hit = CACHE.get(key);
  if (hit && hit.expiresAt > now) {
    return hit.value as T;
  }
  const value = await loader();
  if (CACHE.size >= CACHE_MAX) {
    // Cheap eviction: drop the oldest entry. For v0.1 this is fine;
    // upgrade to LRU if memory growth becomes a real problem.
    const oldest = CACHE.keys().next().value;
    if (oldest) CACHE.delete(oldest);
  }
  CACHE.set(key, { value, expiresAt: now + ttlMs });
  return value;
}

export const CACHE_TTL = {
  BLOCK_NUMBER: 3_000,
  BALANCE: 30_000,
  RECEIPT: 60_000 * 5, // 5 min, receipts are immutable
  CONTRACT_CALL: 30_000,
  LOGS: 30_000,
  WELL_KNOWN: 5 * 60_000, // 5 min, publishers update infrequently
} as const;

// -------- simple token bucket per logical method --------

interface Bucket {
  tokens: number;
  lastRefill: number;
}

const BUCKETS = new Map<string, Bucket>();
const BUCKET_CAPACITY = 30;
const BUCKET_REFILL_PER_SEC = 10;

export async function rateLimit(method: string): Promise<void> {
  const now = Date.now();
  let b = BUCKETS.get(method);
  if (!b) {
    b = { tokens: BUCKET_CAPACITY, lastRefill: now };
    BUCKETS.set(method, b);
  }
  const elapsedSec = (now - b.lastRefill) / 1000;
  b.tokens = Math.min(BUCKET_CAPACITY, b.tokens + elapsedSec * BUCKET_REFILL_PER_SEC);
  b.lastRefill = now;
  if (b.tokens < 1) {
    const waitMs = Math.ceil(((1 - b.tokens) / BUCKET_REFILL_PER_SEC) * 1000);
    await new Promise((resolve) => setTimeout(resolve, waitMs));
    b.tokens = 0;
  } else {
    b.tokens -= 1;
  }
}

export function _resetCache(): void {
  CACHE.clear();
  BUCKETS.clear();
}

export { DEFAULT_TTL_MS };
