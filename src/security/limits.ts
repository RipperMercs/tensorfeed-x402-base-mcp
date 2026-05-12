/**
 * Response size enforcement. Tool outputs are capped before being returned
 * to the MCP client so that:
 *   - A malicious upstream cannot return a giant payload that fills the
 *     calling agent's context window
 *   - We do not accidentally ship a 10MB log dump to a model and burn
 *     a fortune on tokens
 *
 * The cap operates on the serialized JSON length, since that is what
 * the MCP transport actually sends.
 */

export const MAX_RESPONSE_BYTES = 50_000;

export class ResponseTooLargeError extends Error {
  readonly actualBytes: number;
  readonly limit: number;
  constructor(actualBytes: number, limit: number) {
    super(`response exceeds ${limit} byte cap (was ${actualBytes})`);
    this.name = 'ResponseTooLargeError';
    this.actualBytes = actualBytes;
    this.limit = limit;
  }
}

/**
 * Returns a JSON-stringified version of `value`. If serialized length
 * exceeds limit, returns a truncated structured stub explaining the
 * cap rather than the original data. The stub is small and explicit
 * so a calling agent can decide whether to narrow the request.
 */
export function enforceResponseCap(
  value: unknown,
  limit: number = MAX_RESPONSE_BYTES,
): string {
  const serialized = JSON.stringify(value);
  if (serialized.length <= limit) {
    return serialized;
  }
  const stub = {
    ok: false,
    error: 'response_too_large',
    limit_bytes: limit,
    actual_bytes: serialized.length,
    hint: 'Narrow the request (smaller block range, fewer items, more specific filter).',
  };
  return JSON.stringify(stub);
}

/**
 * Variant that throws instead of substituting a stub. Useful in code
 * paths where the caller wants to decide how to react.
 */
export function assertResponseCap(value: unknown, limit: number = MAX_RESPONSE_BYTES): void {
  const len = JSON.stringify(value).length;
  if (len > limit) {
    throw new ResponseTooLargeError(len, limit);
  }
}
