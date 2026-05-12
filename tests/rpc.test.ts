import { describe, it, expect, beforeEach } from 'vitest';
import { isAllowedRpcUrl, resolveRpcUrl, DEFAULT_PUBLIC_BASE_RPC } from '../src/rpc/allowlist.js';
import { cached, rateLimit, _resetCache, CACHE_TTL } from '../src/rpc/client.js';

describe('RPC allowlist', () => {
  it('accepts public Base RPC', () => {
    expect(isAllowedRpcUrl('https://mainnet.base.org')).toBe(true);
  });

  it('accepts Alchemy Base subdomain', () => {
    expect(isAllowedRpcUrl('https://base-mainnet.g.alchemy.com/v2/KEY')).toBe(true);
  });

  it('rejects HTTP (not HTTPS)', () => {
    expect(isAllowedRpcUrl('http://mainnet.base.org')).toBe(false);
  });

  it('rejects unknown host', () => {
    expect(isAllowedRpcUrl('https://evil.example.com')).toBe(false);
  });

  it('rejects malformed URL', () => {
    expect(isAllowedRpcUrl('not a url')).toBe(false);
  });

  it('rejects scheme-stripped host', () => {
    expect(isAllowedRpcUrl('mainnet.base.org')).toBe(false);
  });

  it('resolveRpcUrl falls back to public when env is unset', () => {
    expect(resolveRpcUrl(undefined)).toBe(DEFAULT_PUBLIC_BASE_RPC);
  });

  it('resolveRpcUrl falls back when env URL is not allowlisted', () => {
    expect(resolveRpcUrl('https://malicious.example')).toBe(DEFAULT_PUBLIC_BASE_RPC);
  });

  it('resolveRpcUrl returns allowlisted env URL', () => {
    expect(resolveRpcUrl('https://mainnet.base.org')).toBe('https://mainnet.base.org');
  });
});

describe('cache', () => {
  beforeEach(() => _resetCache());

  it('returns cached value on hit', async () => {
    let calls = 0;
    const loader = async () => ++calls;
    const a = await cached('k1', 10_000, loader);
    const b = await cached('k1', 10_000, loader);
    expect(a).toBe(1);
    expect(b).toBe(1);
    expect(calls).toBe(1);
  });

  it('expires after TTL', async () => {
    let calls = 0;
    const loader = async () => ++calls;
    await cached('k2', 1, loader);
    await new Promise((r) => setTimeout(r, 10));
    await cached('k2', 1, loader);
    expect(calls).toBe(2);
  });

  it('different keys are independent', async () => {
    const a = await cached('a', 10_000, async () => 'A');
    const b = await cached('b', 10_000, async () => 'B');
    expect(a).toBe('A');
    expect(b).toBe('B');
  });

  it('TTL constants are sane', () => {
    expect(CACHE_TTL.BLOCK_NUMBER).toBeLessThan(CACHE_TTL.BALANCE);
    expect(CACHE_TTL.BALANCE).toBeLessThan(CACHE_TTL.RECEIPT);
  });
});

describe('rate limiter', () => {
  beforeEach(() => _resetCache());

  it('allows initial burst', async () => {
    const start = Date.now();
    for (let i = 0; i < 10; i++) await rateLimit('test');
    const elapsed = Date.now() - start;
    expect(elapsed).toBeLessThan(100);
  });
});
