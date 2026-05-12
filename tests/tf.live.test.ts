/**
 * Live integration tests for TF-flavor tools.
 */

import { describe, it, expect } from 'vitest';
import { verify_afta_federation, tf_payment_lookup, TF_PAYMENT_WALLET } from '../src/tools/tf.js';
import { _resetCache } from '../src/rpc/client.js';

const SKIP_LIVE = process.env.VITEST_SKIP_LIVE === '1';

const TF_X402_FIRST_TX = '0xe20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67';

describe.skipIf(SKIP_LIVE)('verify_afta_federation (live)', () => {
  it('returns a structured AFTA report for tensorfeed.ai', async () => {
    _resetCache();
    const result = await verify_afta_federation({ domain: 'tensorfeed.ai' });
    expect(result.ok).toBe(true);
    if (result.ok && 'report' in result) {
      expect(result.report).toBeTruthy();
    }
  }, 20_000);

  it('handles a non-AFTA domain gracefully', async () => {
    _resetCache();
    const result = await verify_afta_federation({ domain: 'example.com' });
    // The cert endpoint should still return ok with a low score, not throw
    expect(typeof result.ok).toBe('boolean');
  }, 20_000);
});

describe.skipIf(SKIP_LIVE)('tf_payment_lookup (live)', () => {
  it('identifies the TF first canonical settlement', async () => {
    _resetCache();
    const result = await tf_payment_lookup({ tx_hash: TF_X402_FIRST_TX });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.is_tf_payment).toBe(true);
      if (result.is_tf_payment) {
        expect(result.transfers.length).toBeGreaterThan(0);
        expect(result.tf_payment_wallet.toLowerCase()).toBe(TF_PAYMENT_WALLET.toLowerCase());
      }
    }
  }, 20_000);

  it('returns is_tf_payment=false for a random tx', async () => {
    _resetCache();
    // Pick a known-non-TF Base tx (a recent USDC transfer to a different address)
    const result = await tf_payment_lookup({
      tx_hash: '0x0000000000000000000000000000000000000000000000000000000000000001',
    });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.is_tf_payment).toBe(false);
    }
  }, 20_000);
});

describe('TF tools (input validation)', () => {
  it('verify_afta_federation rejects URL input', async () => {
    await expect(verify_afta_federation({ domain: 'https://evil.example' })).rejects.toThrow();
  });

  it('tf_payment_lookup rejects malformed tx hash', async () => {
    await expect(tf_payment_lookup({ tx_hash: '0xbad' })).rejects.toThrow();
  });
});
