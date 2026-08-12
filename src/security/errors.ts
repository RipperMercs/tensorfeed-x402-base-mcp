/**
 * Safe error formatting. The error messages our tools return to the MCP
 * client must NOT echo attacker-controlled input back. If a caller passes
 * a malformed address like "0xBADBEEF<script>...", our error must say
 * "invalid address: bad-checksum" not "invalid address: 0xBADBEEF<script>".
 *
 * The reason: a calling LLM may render or quote our error text into its
 * own reasoning. Echoing arbitrary input is a prompt-injection vector.
 *
 * Use formatError() to convert any thrown Error into a safe MCP tool
 * response. ValidationError + ResponseTooLargeError are recognized;
 * everything else collapses to a generic "internal_error" without
 * leaking stack traces or messages.
 */

import { ValidationError } from './validate.js';
import { ResponseTooLargeError } from './limits.js';
import { ChainMismatchError } from '../chains.js';

export interface SafeErrorResponse {
  ok: false;
  error: string;
  details?: {
    field?: string;
    code?: string;
    limit?: number;
    actual?: number;
    expected?: number;
    hint?: string;
  };
}

/**
 * Convert any thrown value into a structured, non-echoing error
 * suitable to return from an MCP tool.
 */
export function formatError(err: unknown): SafeErrorResponse {
  // Surfaced explicitly rather than collapsed into internal_error. A chain
  // mismatch means every settlement answer this server could give would be
  // read off the wrong ledger, so the caller needs to know that specifically,
  // and the operator needs to know their RPC config is wrong. The chain ids
  // are our own constants and the node's reported id, not caller input, so
  // there is nothing attacker-controlled to echo here.
  if (err instanceof ChainMismatchError) {
    return {
      ok: false,
      error: 'chain_mismatch',
      details: {
        expected: err.expected,
        actual: err.actual ?? undefined,
        hint: 'TENSORFEED_RPC_URL points at a node that is not Base mainnet. Settlement verification is refused until it does.',
      },
    };
  }
  if (err instanceof ValidationError) {
    return {
      ok: false,
      error: 'validation_failed',
      details: { field: err.field, code: err.code },
    };
  }
  if (err instanceof ResponseTooLargeError) {
    return {
      ok: false,
      error: 'response_too_large',
      details: { limit: err.limit, actual: err.actualBytes },
    };
  }
  // For unknown errors we deliberately do not include err.message,
  // since it may contain unsafe content from libraries or upstream
  // services. Operators can correlate via logs (stderr below).
  if (err instanceof Error) {
    // eslint-disable-next-line no-console
    console.error('[tensorfeed-x402-base-mcp] internal_error:', err.name, err.message);
  } else {
    // eslint-disable-next-line no-console
    console.error('[tensorfeed-x402-base-mcp] internal_error:', String(err));
  }
  return { ok: false, error: 'internal_error' };
}

/**
 * Wrap a tool handler so any thrown error becomes a safe response.
 * Returns the handler's value on success or a SafeErrorResponse on
 * failure. Use this at the boundary of every MCP tool registration.
 */
export async function safeRun<T>(fn: () => Promise<T>): Promise<T | SafeErrorResponse> {
  try {
    return await fn();
  } catch (e) {
    return formatError(e);
  }
}
