import { describe, it, expect } from 'vitest';
import {
  requireAddress,
  requireTxHash,
  requireHexCalldata,
  requireDomain,
  requireUint,
  requireHttpsUrl,
  requireBase64,
  ValidationError,
} from '../src/security/validate.js';
import { sanitizeString, sanitizeValue, externalString } from '../src/security/sanitize.js';
import {
  enforceResponseCap,
  assertResponseCap,
  ResponseTooLargeError,
  MAX_RESPONSE_BYTES,
} from '../src/security/limits.js';
import { formatError, safeRun } from '../src/security/errors.js';

describe('requireAddress', () => {
  it('accepts a valid checksummed address', () => {
    const a = requireAddress('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
    expect(a).toBe('0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913');
  });

  it('rejects wrong checksum', () => {
    expect(() => requireAddress('0x833589FCD6EDB6E08F4C7C32D4F71B54BDA02913'))
      .toThrowError(ValidationError);
  });

  it('rejects non-string', () => {
    expect(() => requireAddress(42)).toThrow();
  });

  it('rejects empty string', () => {
    expect(() => requireAddress('')).toThrow();
  });

  it('rejects bad length', () => {
    expect(() => requireAddress('0x123')).toThrow();
  });

  it('does not echo input in error message', () => {
    try {
      requireAddress('<script>alert(1)</script>');
      throw new Error('expected throw');
    } catch (e) {
      expect(String((e as Error).message)).not.toContain('<script>');
    }
  });
});

describe('requireTxHash', () => {
  it('accepts and lowercases a 32-byte hash', () => {
    const h = requireTxHash('0xE20C57D8AA6DF63F75CE7A4E4C0CAB492EB7FA672A23CD8FD59967EB6B66BD67');
    expect(h).toBe('0xe20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67');
  });

  it('rejects wrong length', () => {
    expect(() => requireTxHash('0x1234')).toThrow();
  });

  it('rejects missing 0x prefix', () => {
    expect(() => requireTxHash('e20c57d8aa6df63f75ce7a4e4c0cab492eb7fa672a23cd8fd59967eb6b66bd67'))
      .toThrow();
  });
});

describe('requireHexCalldata', () => {
  it('accepts valid hex calldata', () => {
    expect(requireHexCalldata('0xa9059cbb')).toBe('0xa9059cbb');
  });

  it('rejects non-hex', () => {
    expect(() => requireHexCalldata('0xnothex')).toThrow();
  });

  it('rejects oversized calldata', () => {
    const big = '0x' + 'a'.repeat(2 * 70_000);
    expect(() => requireHexCalldata(big)).toThrow();
  });
});

describe('requireDomain', () => {
  it('accepts a normal domain', () => {
    expect(requireDomain('tensorfeed.ai')).toBe('tensorfeed.ai');
  });

  it('accepts subdomains', () => {
    expect(requireDomain('api.tensorfeed.ai')).toBe('api.tensorfeed.ai');
  });

  it('lowercases input', () => {
    expect(requireDomain('TensorFeed.AI')).toBe('tensorfeed.ai');
  });

  it('rejects URLs', () => {
    expect(() => requireDomain('https://tensorfeed.ai/path')).toThrow();
  });

  it('rejects localhost (SSRF)', () => {
    expect(() => requireDomain('localhost')).toThrow();
  });

  it('rejects 127.0.0.1 (SSRF)', () => {
    expect(() => requireDomain('127.0.0.1')).toThrow();
  });

  it('rejects 10.x private (SSRF)', () => {
    expect(() => requireDomain('10.0.0.1')).toThrow();
  });

  it('rejects whitespace/control chars', () => {
    expect(() => requireDomain('tensor\nfeed.ai')).toThrow();
  });
});

describe('requireUint', () => {
  it('accepts integer in range', () => {
    expect(requireUint(100, 'blocks', 0, 1000)).toBe(100);
  });

  it('accepts numeric string', () => {
    expect(requireUint('100', 'blocks', 0, 1000)).toBe(100);
  });

  it('rejects negative', () => {
    expect(() => requireUint(-1, 'blocks', 0, 1000)).toThrow();
  });

  it('rejects above max', () => {
    expect(() => requireUint(2000, 'blocks', 0, 1000)).toThrow();
  });

  it('rejects non-integer', () => {
    expect(() => requireUint(1.5, 'blocks')).toThrow();
  });
});

describe('requireHttpsUrl', () => {
  it('accepts a plain https URL', () => {
    expect(requireHttpsUrl('https://tensorfeed.ai/api/x402/status')).toBe(
      'https://tensorfeed.ai/api/x402/status',
    );
  });

  it('strips fragment', () => {
    expect(requireHttpsUrl('https://tensorfeed.ai/x402#section')).toBe(
      'https://tensorfeed.ai/x402',
    );
  });

  it('rejects http://', () => {
    expect(() => requireHttpsUrl('http://tensorfeed.ai')).toThrowError(ValidationError);
  });

  it('rejects file://', () => {
    expect(() => requireHttpsUrl('file:///etc/passwd')).toThrow();
  });

  it('rejects javascript:', () => {
    expect(() => requireHttpsUrl('javascript:alert(1)')).toThrow();
  });

  it('rejects localhost (SSRF)', () => {
    expect(() => requireHttpsUrl('https://localhost/api')).toThrow();
  });

  it('rejects 127.0.0.1 (SSRF)', () => {
    expect(() => requireHttpsUrl('https://127.0.0.1/api')).toThrow();
  });

  it('rejects 10.x private (SSRF)', () => {
    expect(() => requireHttpsUrl('https://10.0.0.1/api')).toThrow();
  });

  it('rejects 192.168.x private (SSRF)', () => {
    expect(() => requireHttpsUrl('https://192.168.1.5/api')).toThrow();
  });

  it('rejects 172.16-31.x private (SSRF)', () => {
    expect(() => requireHttpsUrl('https://172.20.0.1/api')).toThrow();
  });

  it('rejects 169.254.x link-local (SSRF)', () => {
    expect(() => requireHttpsUrl('https://169.254.169.254/latest/meta-data')).toThrow();
  });

  it('rejects raw single-label host', () => {
    expect(() => requireHttpsUrl('https://internal/api')).toThrow();
  });

  it('rejects empty string', () => {
    expect(() => requireHttpsUrl('')).toThrow();
  });

  it('rejects huge URL', () => {
    expect(() => requireHttpsUrl('https://x.com/' + 'a'.repeat(3000))).toThrow();
  });
});

describe('requireBase64', () => {
  it('decodes standard base64', () => {
    const buf = requireBase64(Buffer.from('hello world').toString('base64'));
    expect(buf.toString('utf8')).toBe('hello world');
  });

  it('decodes URL-safe base64', () => {
    const url = Buffer.from('hi?>').toString('base64')
      .replace(/\+/g, '-').replace(/\//g, '_');
    const buf = requireBase64(url);
    expect(buf.toString('utf8')).toBe('hi?>');
  });

  it('rejects empty', () => {
    expect(() => requireBase64('')).toThrowError(ValidationError);
  });

  it('rejects non-base64', () => {
    expect(() => requireBase64('not!base64!@#')).toThrow();
  });

  it('rejects oversized decoded payload', () => {
    const huge = Buffer.alloc(200 * 1024, 0x41).toString('base64');
    expect(() => requireBase64(huge, 'payload', 64 * 1024)).toThrow();
  });
});

describe('sanitizeString', () => {
  it('strips null bytes', () => {
    expect(sanitizeString('hello\x00world')).toBe('helloworld');
  });

  it('strips DEL', () => {
    expect(sanitizeString('hello\x7Fworld')).toBe('helloworld');
  });

  it('preserves tab/newline/cr', () => {
    expect(sanitizeString('a\tb\nc\rd')).toBe('a\tb\nc\rd');
  });

  it('strips zero-width space', () => {
    expect(sanitizeString('he​llo')).toBe('hello');
  });

  it('strips RLM (right-to-left mark)', () => {
    expect(sanitizeString('he‏llo')).toBe('hello');
  });

  it('strips BOM in middle of string', () => {
    expect(sanitizeString('he﻿llo')).toBe('hello');
  });

  it('truncates very long strings', () => {
    const long = 'x'.repeat(5000);
    const out = sanitizeString(long, 100);
    expect(out.length).toBeLessThanOrEqual(100);
    expect(out.endsWith('[truncated]')).toBe(true);
  });
});

describe('sanitizeValue', () => {
  it('handles bigints', () => {
    expect(sanitizeValue(123n)).toBe('123');
  });

  it('walks nested objects', () => {
    const out = sanitizeValue({ a: 'he\x00llo', b: { c: 1n } });
    expect(out).toEqual({ a: 'hello', b: { c: '1' } });
  });

  it('handles arrays', () => {
    expect(sanitizeValue([1, 'a\x00b', 3])).toEqual([1, 'ab', 3]);
  });

  it('caps deep recursion', () => {
    let nested: any = 'leaf';
    for (let i = 0; i < 40; i++) nested = { x: nested };
    const result = JSON.stringify(sanitizeValue(nested));
    expect(result).toContain('max-depth-exceeded');
  });

  it('caps large arrays', () => {
    const arr = Array(2000).fill('item');
    const out = sanitizeValue(arr) as unknown[];
    expect(out.length).toBe(1000);
  });
});

describe('externalString', () => {
  it('marks external origin', () => {
    expect(externalString('user input')).toEqual({
      value: 'user input',
      _origin: 'external',
    });
  });
});

describe('limits', () => {
  it('returns original when under cap', () => {
    const out = enforceResponseCap({ a: 1 });
    expect(JSON.parse(out)).toEqual({ a: 1 });
  });

  it('substitutes stub when over cap', () => {
    const big = { data: 'x'.repeat(100_000) };
    const out = enforceResponseCap(big);
    const parsed = JSON.parse(out);
    expect(parsed.ok).toBe(false);
    expect(parsed.error).toBe('response_too_large');
  });

  it('assertResponseCap throws on oversize', () => {
    expect(() => assertResponseCap({ data: 'x'.repeat(100_000) })).toThrowError(ResponseTooLargeError);
  });

  it('default cap matches constant', () => {
    expect(MAX_RESPONSE_BYTES).toBe(50_000);
  });
});

describe('errors', () => {
  it('formats validation error without echoing input', () => {
    try {
      requireAddress('0xinvalid<script>');
    } catch (e) {
      const safe = formatError(e);
      expect(safe.ok).toBe(false);
      expect(safe.error).toBe('validation_failed');
      expect(JSON.stringify(safe)).not.toContain('<script>');
    }
  });

  it('collapses unknown errors to internal_error', () => {
    const safe = formatError(new Error('something with secret xyz'));
    expect(safe.error).toBe('internal_error');
    expect(JSON.stringify(safe)).not.toContain('secret');
  });

  it('safeRun wraps thrown errors', async () => {
    const out = await safeRun(async () => {
      throw new Error('boom');
    });
    expect((out as { ok: false }).ok).toBe(false);
  });

  it('safeRun returns success value', async () => {
    const out = await safeRun(async () => ({ ok: true, value: 42 }));
    expect(out).toEqual({ ok: true, value: 42 });
  });
});
