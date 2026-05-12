/**
 * Input validators. All MCP tool inputs flow through here before touching
 * RPC, HTTP, or any external system. Validation failures must produce
 * non-echoing errors (see errors.ts) so a malformed input from a compromised
 * upstream agent cannot be used to inject content into our outputs.
 */

import { getAddress, isAddress, isHex } from 'viem';
import { z } from 'zod';

const HEX64 = /^0x[0-9a-fA-F]{64}$/;
const DOMAIN_RE = /^[a-z0-9.-]+\.[a-z]{2,}$/;
const ENS_RE = /^[a-z0-9-]+(\.[a-z0-9-]+)*\.eth$/;

export class ValidationError extends Error {
  readonly field: string;
  readonly code: string;
  constructor(field: string, code: string) {
    super(`invalid ${field}: ${code}`);
    this.field = field;
    this.code = code;
    this.name = 'ValidationError';
  }
}

/**
 * Returns a checksummed address. Rejects anything that isn't a valid
 * EVM address. We deliberately don't return the original input - this
 * prevents echoing attacker-controlled strings back through error paths.
 */
export function requireAddress(input: unknown, field = 'address'): `0x${string}` {
  if (typeof input !== 'string') {
    throw new ValidationError(field, 'must-be-string');
  }
  if (input.length > 42 || input.length < 42) {
    throw new ValidationError(field, 'bad-length');
  }
  if (!isAddress(input)) {
    throw new ValidationError(field, 'not-an-address');
  }
  // getAddress normalizes to checksummed form. If the input was a wrong
  // checksum (mixed case that doesn't match), viem throws.
  try {
    return getAddress(input);
  } catch {
    throw new ValidationError(field, 'bad-checksum');
  }
}

/**
 * Returns a normalized lowercase 0x-prefixed 32-byte hash. Rejects anything
 * else. We don't accept upper-case to avoid duplicate cache keys for the
 * same logical tx.
 */
export function requireTxHash(input: unknown, field = 'tx_hash'): `0x${string}` {
  if (typeof input !== 'string') {
    throw new ValidationError(field, 'must-be-string');
  }
  if (!HEX64.test(input)) {
    throw new ValidationError(field, 'not-a-tx-hash');
  }
  return input.toLowerCase() as `0x${string}`;
}

/**
 * Validates 0x-prefixed hex calldata. Caps at 64KB to prevent unbounded
 * input from being passed to an RPC.
 */
export function requireHexCalldata(input: unknown, field = 'data'): `0x${string}` {
  if (typeof input !== 'string') {
    throw new ValidationError(field, 'must-be-string');
  }
  if (!isHex(input)) {
    throw new ValidationError(field, 'not-hex');
  }
  if (input.length > 2 + 65536 * 2) {
    throw new ValidationError(field, 'calldata-too-large');
  }
  return input.toLowerCase() as `0x${string}`;
}

/**
 * Validates a domain name. Rejects URLs, schemes, paths, and anything that
 * doesn't look like a bare hostname. Used for AFTA federation lookups and
 * /.well-known/x402 fetches.
 */
export function requireDomain(input: unknown, field = 'domain'): string {
  if (typeof input !== 'string') {
    throw new ValidationError(field, 'must-be-string');
  }
  const trimmed = input.trim().toLowerCase();
  if (trimmed.length === 0 || trimmed.length > 253) {
    throw new ValidationError(field, 'bad-length');
  }
  // Reject anything containing scheme, slashes, or whitespace
  if (/[/\s@?#]/.test(trimmed) || trimmed.includes('://')) {
    throw new ValidationError(field, 'must-be-bare-hostname');
  }
  if (!DOMAIN_RE.test(trimmed)) {
    throw new ValidationError(field, 'malformed');
  }
  // Reject localhost/loopback/private to avoid SSRF
  if (
    trimmed === 'localhost' ||
    trimmed.endsWith('.localhost') ||
    trimmed === '127.0.0.1' ||
    trimmed.startsWith('192.168.') ||
    trimmed.startsWith('10.') ||
    trimmed.startsWith('172.16.') ||
    trimmed === '0.0.0.0'
  ) {
    throw new ValidationError(field, 'private-or-loopback-blocked');
  }
  return trimmed;
}

/**
 * Validates a positive integer within bounds. Used for block ranges.
 */
export function requireUint(input: unknown, field: string, min = 0, max = 1_000_000): number {
  let n: number;
  if (typeof input === 'number') {
    n = input;
  } else if (typeof input === 'string' && /^[0-9]+$/.test(input)) {
    n = Number(input);
  } else {
    throw new ValidationError(field, 'must-be-uint');
  }
  if (!Number.isInteger(n) || n < min || n > max) {
    throw new ValidationError(field, `out-of-range[${min},${max}]`);
  }
  return n;
}

// Convenience zod schemas for tools that prefer schema-first parsing.
export const AddressSchema = z.string().refine((s) => isAddress(s), {
  message: 'not-an-address',
});
export const TxHashSchema = z.string().regex(HEX64, 'not-a-tx-hash');
export const DomainSchema = z.string().refine((s) => {
  try {
    requireDomain(s);
    return true;
  } catch {
    return false;
  }
}, { message: 'malformed-domain' });
