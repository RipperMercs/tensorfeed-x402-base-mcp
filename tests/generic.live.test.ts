/**
 * Live integration tests against public Base RPC.
 *
 * These tests hit https://mainnet.base.org. They will fail if offline
 * or if the public RPC is rate-limiting us. Skip with VITEST_SKIP_LIVE=1
 * in environments without network access.
 */

import { describe, it, expect } from 'vitest';
import { balance, usdc_balance, block_number, get_tx_receipt } from '../src/tools/generic.js';
import { _resetCache } from '../src/rpc/client.js';

const SKIP_LIVE = process.env.VITEST_SKIP_LIVE === '1';

const TF_X402_FIRST_TX = '0xe20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67';
const ANY_USDC_HOLDER = '0x4200000000000000000000000000000000000006'; // WETH contract on Base, just a known address

describe.skipIf(SKIP_LIVE)('generic tools (live Base RPC)', () => {
  it('block_number returns a positive integer', async () => {
    _resetCache();
    const result = await block_number();
    expect(result.ok).toBe(true);
    expect(BigInt(result.block) > 0n).toBe(true);
  }, 20_000);

  it('balance returns ETH balance for a known address', async () => {
    _resetCache();
    const result = await balance({ address: ANY_USDC_HOLDER });
    expect(result.ok).toBe(true);
    expect(result.asset).toBe('ETH');
    expect(typeof result.wei).toBe('string');
    expect(typeof result.eth).toBe('string');
  }, 20_000);

  it('usdc_balance returns USDC balance', async () => {
    _resetCache();
    const result = await usdc_balance({ address: ANY_USDC_HOLDER });
    expect(result.ok).toBe(true);
    expect(result.asset).toBe('USDC');
    expect(result.contract.toLowerCase()).toBe('0x833589fcd6edb6e08f4c7c32d4f71b54bda02913');
  }, 20_000);

  it('get_tx_receipt returns the TF first canonical x402 settlement', async () => {
    _resetCache();
    const result = await get_tx_receipt({ tx_hash: TF_X402_FIRST_TX });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.status).toBe('success');
      expect(result.log_count).toBeGreaterThan(0);
    }
  }, 20_000);
});

describe('generic tools (input validation)', () => {
  it('balance rejects malformed address', async () => {
    await expect(balance({ address: 'not-an-address' })).rejects.toThrow();
  });

  it('usdc_balance rejects malformed address', async () => {
    await expect(usdc_balance({ address: '0x123' })).rejects.toThrow();
  });

  it('get_tx_receipt rejects malformed tx hash', async () => {
    await expect(get_tx_receipt({ tx_hash: '0xbad' })).rejects.toThrow();
  });
});
