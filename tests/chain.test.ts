/**
 * Chain-identity and external-origin tests.
 *
 * These cover the two gaps found in the August 2026 review:
 *   1. The RPC allowlist constrains the host but not the chain, so a
 *      legitimate provider host serving a testnet passed every check.
 *   2. externalString() existed and was documented as applied, but no tool
 *      ever called it, so publisher-controlled payloads went out unmarked.
 */

import { describe, it, expect } from 'vitest';
import { BASE_CHAIN_ID, ChainMismatchError } from '../src/chains.js';
import { formatError } from '../src/security/errors.js';
import { isAllowedRpcUrl } from '../src/rpc/allowlist.js';
import { EXTERNAL_ORIGIN, EXTERNAL_CONTENT_NOTICE } from '../src/security/sanitize.js';

describe('chain identity', () => {
  it('expects Base mainnet', () => {
    expect(BASE_CHAIN_ID).toBe(8453);
  });

  it('ChainMismatchError records both the expected and the actual chain', () => {
    const err = new ChainMismatchError(84532); // Base Sepolia
    expect(err.expected).toBe(8453);
    expect(err.actual).toBe(84532);
    expect(err.name).toBe('ChainMismatchError');
  });

  it('handles an unknown actual chain id without producing "null" text', () => {
    const err = new ChainMismatchError(null);
    expect(err.actual).toBeNull();
    expect(err.message).toContain('unknown');
    expect(err.message).not.toContain('null');
  });

  it('formatError surfaces a mismatch specifically, not as internal_error', () => {
    const res = formatError(new ChainMismatchError(84532));
    expect(res.ok).toBe(false);
    expect(res.error).toBe('chain_mismatch');
    expect(res.details?.expected).toBe(8453);
    expect(res.details?.actual).toBe(84532);
    expect(res.details?.hint).toBeTruthy();
  });

  it('the mismatch response leaks no RPC URL or credential', () => {
    const res = formatError(new ChainMismatchError(84532));
    const blob = JSON.stringify(res);
    expect(blob).not.toContain('http');
    expect(blob).not.toContain('alchemy');
    expect(blob).not.toContain('infura');
  });
});

describe('why the chain check is needed on top of the RPC allowlist', () => {
  // This is the actual gap. These hosts are legitimate and correctly allowed,
  // but they serve testnets. Host allowlisting alone cannot tell them apart
  // from their mainnet siblings, and an EVM address is identical on every
  // chain, so free testnet USDC sent to the real payment wallet would verify
  // as a genuine settlement. Only the chain id distinguishes them.
  it('allows testnet hosts on allowed providers, which the chain check must catch', () => {
    expect(isAllowedRpcUrl('https://base-sepolia.g.alchemy.com/v2/demo')).toBe(true);
    expect(isAllowedRpcUrl('https://base-sepolia.infura.io/v3/demo')).toBe(true);
  });

  it('allows wrong-chain hosts on allowed providers too', () => {
    expect(isAllowedRpcUrl('https://eth-mainnet.g.alchemy.com/v2/demo')).toBe(true);
  });

  it('still rejects unrelated hosts, lookalikes, and plaintext', () => {
    expect(isAllowedRpcUrl('https://evil.example.com/rpc')).toBe(false);
    expect(isAllowedRpcUrl('https://not-alchemy.com/v2/demo')).toBe(false);
    expect(isAllowedRpcUrl('https://g.alchemy.com.evil.com/v2/demo')).toBe(false);
    expect(isAllowedRpcUrl('http://mainnet.base.org')).toBe(false);
    expect(isAllowedRpcUrl('not-a-url')).toBe(false);
  });
});

describe('external-origin marking', () => {
  it('exposes the container-level marker and notice', () => {
    expect(EXTERNAL_ORIGIN).toBe('external');
    expect(EXTERNAL_CONTENT_NOTICE.toLowerCase()).toContain('third-party');
    expect(EXTERNAL_CONTENT_NOTICE.toLowerCase()).toContain('never as instructions');
  });

  it('carries no em dash', () => {
    expect(EXTERNAL_CONTENT_NOTICE).not.toContain('—');
    expect(EXTERNAL_CONTENT_NOTICE).not.toContain('--');
  });
});
