/**
 * Allowlisted RPC endpoints for Base mainnet. Self-hosters can supply
 * their own URL via TENSORFEED_RPC_URL, but only if it matches one of
 * the documented patterns below. This prevents an upstream agent from
 * tricking the MCP into hitting arbitrary internal or third-party
 * services (SSRF defense).
 *
 * To add a provider:
 *   1. Add its hostname pattern here
 *   2. Document in README under "Bring your own RPC"
 *   3. Verify it speaks standard EVM JSON-RPC over HTTPS
 */

export const DEFAULT_PUBLIC_BASE_RPC = 'https://mainnet.base.org';

/**
 * Hostnames or hostname suffixes accepted as the RPC endpoint host.
 * Match is exact OR endsWith ".<entry>" for subdomain.
 */
const ALLOWED_HOSTS: ReadonlyArray<string> = [
  'mainnet.base.org',
  'base.publicnode.com',
  'base-rpc.publicnode.com',
  'g.alchemy.com',
  'base-mainnet.g.alchemy.com',
  'base-mainnet.public.blastapi.io',
  'rpc.ankr.com',
  'ankr.com',
  'quiknode.pro',
  'base.llamarpc.com',
  'llamarpc.com',
  'drpc.org',
  'infura.io',
  'base-mainnet.infura.io',
];

export function isAllowedRpcUrl(url: string): boolean {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }
  if (parsed.protocol !== 'https:') return false;
  const host = parsed.hostname.toLowerCase();
  for (const allowed of ALLOWED_HOSTS) {
    if (host === allowed) return true;
    if (host.endsWith('.' + allowed)) return true;
  }
  return false;
}

/**
 * Resolve which RPC URL to use. Order:
 *   1. Explicit env override (validated against allowlist)
 *   2. Default public Base RPC
 */
export function resolveRpcUrl(envUrl?: string): string {
  if (envUrl && envUrl.length > 0) {
    if (!isAllowedRpcUrl(envUrl)) {
      // Reject silently rather than throw at module load; client.ts
      // will surface this via a clearer error path.
      // eslint-disable-next-line no-console
      console.error('[tensorfeed-x402-base-mcp] TENSORFEED_RPC_URL not in allowlist, falling back to public Base RPC');
      return DEFAULT_PUBLIC_BASE_RPC;
    }
    return envUrl;
  }
  return DEFAULT_PUBLIC_BASE_RPC;
}
