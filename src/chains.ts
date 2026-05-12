/**
 * Network and contract constants. Base mainnet only at v0.1.
 * Adding networks requires extending the allowlist in rpc/allowlist.ts
 * and any address constants below.
 */

import { base } from 'viem/chains';
import type { Address } from 'viem';

export const BASE_CHAIN = base;
export const BASE_CHAIN_ID = 8453;
export const BASE_CAIP2 = 'eip155:8453';

/**
 * USDC contract on Base mainnet (Circle, native bridged USDC).
 * Reference: https://developers.circle.com/stablecoins/docs/usdc-on-test-networks
 */
export const USDC_ADDRESS: Address = '0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913';
export const USDC_DECIMALS = 6;

/**
 * Standard ERC-20 ABI fragments we need. Inlined to avoid pulling in
 * a heavier ABI library and to make the dependency surface auditable.
 */
export const ERC20_ABI = [
  {
    type: 'function',
    name: 'balanceOf',
    stateMutability: 'view',
    inputs: [{ name: 'account', type: 'address' }],
    outputs: [{ name: '', type: 'uint256' }],
  },
  {
    type: 'function',
    name: 'decimals',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'uint8' }],
  },
  {
    type: 'function',
    name: 'symbol',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'string' }],
  },
  {
    type: 'event',
    name: 'Transfer',
    inputs: [
      { name: 'from', type: 'address', indexed: true },
      { name: 'to', type: 'address', indexed: true },
      { name: 'value', type: 'uint256', indexed: false },
    ],
  },
] as const;
