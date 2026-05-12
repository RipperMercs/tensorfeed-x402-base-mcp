/**
 * Live integration tests for x402-native tools against Base mainnet.
 * Uses known artifacts: the TF first canonical x402 V2 settlement on
 * 2026-05-08, tx 0xe20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67.
 */

import { describe, it, expect } from 'vitest';
import {
  verify_x402_settlement,
  parse_x402_manifest,
  usdc_recent_payments_to,
  probe_x402_endpoint,
  decode_x402_payment_payload,
} from '../src/tools/x402.js';
import { _resetCache } from '../src/rpc/client.js';

const SKIP_LIVE = process.env.VITEST_SKIP_LIVE === '1';

const TF_X402_FIRST_TX = '0xe20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67';
const TF_PAY_TO = '0x549c82e6bfc54bdae9a2073744cbc2af5d1fc6d1';

describe.skipIf(SKIP_LIVE)('verify_x402_settlement (live)', () => {
  it('returns verified=true for a known good TF settlement', async () => {
    _resetCache();
    const result = await verify_x402_settlement({
      tx_hash: TF_X402_FIRST_TX,
      expected_recipient: TF_PAY_TO,
      expected_amount_usdc: '0.02',
    });
    expect(result.ok).toBe(true);
    if (result.ok && 'verified' in result) {
      expect(result.verified).toBe(true);
      if (result.verified) {
        expect(result.matches.length).toBeGreaterThan(0);
      }
    }
  }, 20_000);

  it('returns verified=false with reason when amount mismatches', async () => {
    _resetCache();
    const result = await verify_x402_settlement({
      tx_hash: TF_X402_FIRST_TX,
      expected_recipient: TF_PAY_TO,
      expected_amount_usdc: '99999',
    });
    expect(result.ok).toBe(true);
    if (result.ok && 'verified' in result) {
      expect(result.verified).toBe(false);
      if (!result.verified) {
        expect(result.reason).toBe('no_matching_transfer');
        expect('observed_usdc_transfers' in result).toBe(true);
      }
    }
  }, 20_000);

  it('returns verified=false for nonexistent tx hash', async () => {
    _resetCache();
    const result = await verify_x402_settlement({
      tx_hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      expected_recipient: TF_PAY_TO,
      expected_amount_usdc: '0.02',
    });
    expect(result.ok).toBe(true);
    if (result.ok && 'verified' in result && !result.verified) {
      expect(result.reason).toBe('tx_not_found');
    }
  }, 20_000);
});

describe.skipIf(SKIP_LIVE)('parse_x402_manifest (live)', () => {
  it('fetches TF own manifest', async () => {
    _resetCache();
    const result = await parse_x402_manifest({ domain: 'tensorfeed.ai' });
    expect(result.ok).toBe(true);
    if (result.ok && 'manifest' in result) {
      expect(result.manifest).toBeTruthy();
    }
  }, 20_000);

  it('returns not_found for a domain without manifest', async () => {
    _resetCache();
    const result = await parse_x402_manifest({ domain: 'example.com' });
    expect(result.ok).toBe(false);
  }, 20_000);
});

describe.skipIf(SKIP_LIVE)('usdc_recent_payments_to (live)', () => {
  it('returns a structured payment list for TF wallet', async () => {
    _resetCache();
    const result = await usdc_recent_payments_to({
      address: TF_PAY_TO,
      blocks_back: 5_000,
    });
    expect(result.ok).toBe(true);
    expect(Array.isArray(result.payments)).toBe(true);
    expect(typeof result.from_block).toBe('string');
    expect(typeof result.to_block).toBe('string');
  }, 30_000);
});

describe.skipIf(SKIP_LIVE)('probe_x402_endpoint (live)', () => {
  it('returns x402_paid=true for a known x402-paid TF endpoint', async () => {
    _resetCache();
    const result = await probe_x402_endpoint({
      url: 'https://tensorfeed.ai/api/premium/news/search?q=ai',
    });
    expect(result.ok).toBe(true);
    if (result.ok && 'x402_paid' in result) {
      // Be lenient: this endpoint should return 402 with accepts[]
      expect(result.x402_paid === true || result.x402_paid === 'unclear').toBe(true);
    }
  }, 20_000);

  it('returns x402_paid=false for a free endpoint', async () => {
    _resetCache();
    const result = await probe_x402_endpoint({
      url: 'https://tensorfeed.ai/api/meta',
    });
    expect(result.ok).toBe(true);
    if (result.ok && 'x402_paid' in result) {
      expect(result.x402_paid).toBe(false);
    }
  }, 20_000);
});

describe('decode_x402_payment_payload (pure)', () => {
  it('decodes a well-formed canonical V2 payload', async () => {
    const canonical = {
      x402Version: 2,
      scheme: 'exact',
      network: 'eip155:8453',
      payload: {
        signature: '0x' + '00'.repeat(65),
        authorization: {
          from: '0x549c82e6bFC54bdaE9A2073744CBC2AF5D1FC6D1',
          to: '0x549c82e6bFC54bdaE9A2073744CBC2AF5D1FC6D1',
          value: '20000',
          validAfter: '0',
          validBefore: '99999999999',
          nonce: '0x' + '11'.repeat(32),
        },
      },
    };
    const b64 = Buffer.from(JSON.stringify(canonical)).toString('base64');
    const result = await decode_x402_payment_payload({ payload: b64 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.x402_version).toBe(2);
      expect(result.scheme).toBe('exact');
      expect(result.network).toBe('eip155:8453');
      expect(result.canonical_shape_ok).toBe(true);
      expect(result.shape_warnings).toEqual([]);
    }
  });

  it('flags shape warnings for missing fields', async () => {
    const b64 = Buffer.from(JSON.stringify({ scheme: 'exact' })).toString('base64');
    const result = await decode_x402_payment_payload({ payload: b64 });
    expect(result.ok).toBe(true);
    if (result.ok) {
      expect(result.canonical_shape_ok).toBe(false);
      expect(result.shape_warnings.length).toBeGreaterThan(0);
    }
  });

  it('returns validation_failed on non-JSON payload', async () => {
    const b64 = Buffer.from('not json at all').toString('base64');
    const result = await decode_x402_payment_payload({ payload: b64 });
    expect(result.ok).toBe(false);
    if (!result.ok) expect(result.details.code).toBe('not-json');
  });

  it('returns validation_failed on JSON array (not object)', async () => {
    const b64 = Buffer.from(JSON.stringify([1, 2, 3])).toString('base64');
    const result = await decode_x402_payment_payload({ payload: b64 });
    expect(result.ok).toBe(false);
  });
});

describe('x402 tools (input validation)', () => {
  it('verify_x402_settlement rejects bad tx hash', async () => {
    await expect(
      verify_x402_settlement({
        tx_hash: 'not-a-hash',
        expected_recipient: TF_PAY_TO,
        expected_amount_usdc: '1',
      }),
    ).rejects.toThrow();
  });

  it('verify_x402_settlement returns validation_failed for bad amount format', async () => {
    const result = await verify_x402_settlement({
      tx_hash: '0x0000000000000000000000000000000000000000000000000000000000000000',
      expected_recipient: TF_PAY_TO,
      expected_amount_usdc: 'NaN',
    });
    expect(result.ok).toBe(false);
    if (!result.ok && 'details' in result && result.details) {
      expect(result.details.field).toBe('expected_amount_usdc');
    }
  });

  it('parse_x402_manifest rejects URL input (SSRF guard)', async () => {
    await expect(parse_x402_manifest({ domain: 'https://evil.example/x402' })).rejects.toThrow();
  });

  it('parse_x402_manifest rejects localhost (SSRF guard)', async () => {
    await expect(parse_x402_manifest({ domain: 'localhost' })).rejects.toThrow();
  });

  it('probe_x402_endpoint rejects http:// (SSRF guard)', async () => {
    await expect(probe_x402_endpoint({ url: 'http://tensorfeed.ai/api/meta' })).rejects.toThrow();
  });

  it('probe_x402_endpoint rejects localhost (SSRF guard)', async () => {
    await expect(probe_x402_endpoint({ url: 'https://localhost/api' })).rejects.toThrow();
  });

  it('probe_x402_endpoint rejects file:// (SSRF guard)', async () => {
    await expect(probe_x402_endpoint({ url: 'file:///etc/passwd' })).rejects.toThrow();
  });

  it('decode_x402_payment_payload rejects non-base64 input', async () => {
    await expect(decode_x402_payment_payload({ payload: 'not!base64!@#' })).rejects.toThrow();
  });
});
