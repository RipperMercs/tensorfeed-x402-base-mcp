/**
 * Generic Base read tools. These are the traffic-magnet primitives:
 * any agent doing chain inspection on Base benefits from them. Each
 * tool routes inputs through security.validate, calls the cached RPC
 * wrapper, and returns sanitized output.
 *
 * Inputs/outputs are JSON-serializable. Bigints (balances, gas, etc.)
 * are stringified to preserve precision across MCP transport.
 */

import { formatUnits, type Address } from 'viem';
import {
  requireAddress,
  requireTxHash,
  requireHexCalldata,
  requireUint,
} from '../security/validate.js';
import { sanitizeValue } from '../security/sanitize.js';
import { getClient, cached, rateLimit, CACHE_TTL } from '../rpc/client.js';
import { USDC_ADDRESS, USDC_DECIMALS, ERC20_ABI } from '../chains.js';

// ----- balance (native ETH) -----

export interface BalanceResult {
  ok: true;
  address: Address;
  network: 'base-mainnet';
  asset: 'ETH';
  wei: string;
  eth: string;
}

export async function balance(args: { address: unknown }): Promise<BalanceResult> {
  const address = requireAddress(args.address);
  await rateLimit('balance');
  const wei = await cached(`balance:${address}`, CACHE_TTL.BALANCE, async () => {
    return getClient().getBalance({ address });
  });
  return {
    ok: true,
    address,
    network: 'base-mainnet',
    asset: 'ETH',
    wei: wei.toString(),
    eth: formatUnits(wei, 18),
  };
}

// ----- usdc_balance -----

export interface UsdcBalanceResult {
  ok: true;
  address: Address;
  network: 'base-mainnet';
  asset: 'USDC';
  contract: Address;
  raw: string;
  usdc: string;
}

export async function usdc_balance(args: { address: unknown }): Promise<UsdcBalanceResult> {
  const address = requireAddress(args.address);
  await rateLimit('usdc_balance');
  const raw = await cached(`usdc_balance:${address}`, CACHE_TTL.BALANCE, async () => {
    return getClient().readContract({
      address: USDC_ADDRESS,
      abi: ERC20_ABI,
      functionName: 'balanceOf',
      args: [address],
    }) as Promise<bigint>;
  });
  return {
    ok: true,
    address,
    network: 'base-mainnet',
    asset: 'USDC',
    contract: USDC_ADDRESS,
    raw: raw.toString(),
    usdc: formatUnits(raw, USDC_DECIMALS),
  };
}

// ----- block_number -----

export async function block_number(): Promise<{ ok: true; network: 'base-mainnet'; block: string }> {
  await rateLimit('block_number');
  const bn = await cached('block_number', CACHE_TTL.BLOCK_NUMBER, async () => {
    return getClient().getBlockNumber();
  });
  return { ok: true, network: 'base-mainnet', block: bn.toString() };
}

// ----- get_tx_receipt -----

export async function get_tx_receipt(args: { tx_hash: unknown }) {
  const hash = requireTxHash(args.tx_hash);
  await rateLimit('get_tx_receipt');
  const receipt = await cached(`receipt:${hash}`, CACHE_TTL.RECEIPT, async () => {
    try {
      return await getClient().getTransactionReceipt({ hash });
    } catch (e) {
      return null;
    }
  });
  if (!receipt) {
    return { ok: false as const, error: 'tx_not_found', tx_hash: hash };
  }
  return {
    ok: true as const,
    network: 'base-mainnet' as const,
    tx_hash: hash,
    status: receipt.status,
    block_number: receipt.blockNumber.toString(),
    block_hash: receipt.blockHash,
    from: receipt.from,
    to: receipt.to,
    gas_used: receipt.gasUsed.toString(),
    effective_gas_price: receipt.effectiveGasPrice.toString(),
    contract_address: receipt.contractAddress,
    log_count: receipt.logs.length,
    logs_summary: sanitizeValue(
      receipt.logs.slice(0, 20).map((l) => ({
        address: l.address,
        topics: l.topics,
        data: l.data,
        log_index: l.logIndex,
      })),
    ),
  };
}

// ----- call (read-only contract call) -----

export async function call(args: { contract: unknown; data: unknown }) {
  const contract = requireAddress(args.contract, 'contract');
  const data = requireHexCalldata(args.data, 'data');
  await rateLimit('call');
  const result = await cached(`call:${contract}:${data}`, CACHE_TTL.CONTRACT_CALL, async () => {
    return getClient().call({ to: contract, data });
  });
  return {
    ok: true as const,
    network: 'base-mainnet' as const,
    contract,
    data,
    result: result.data ?? '0x',
  };
}

// ----- recent_transfers (USDC Transfer events touching `address`) -----

export interface TransferEvent {
  block_number: string;
  tx_hash: `0x${string}`;
  log_index: number;
  from: Address;
  to: Address;
  amount_raw: string;
  amount_usdc: string;
}

export async function recent_transfers(args: {
  address: unknown;
  blocks_back?: unknown;
  direction?: unknown;
}): Promise<{ ok: true; address: Address; from_block: string; to_block: string; events: TransferEvent[] }> {
  const address = requireAddress(args.address);
  const blocksBack = requireUint(args.blocks_back ?? 1000, 'blocks_back', 1, 10_000);
  const direction =
    typeof args.direction === 'string' && ['in', 'out', 'both'].includes(args.direction)
      ? (args.direction as 'in' | 'out' | 'both')
      : 'both';
  await rateLimit('recent_transfers');

  const client = getClient();
  const latest = await cached('block_number', CACHE_TTL.BLOCK_NUMBER, async () => client.getBlockNumber());
  const fromBlock = latest > BigInt(blocksBack) ? latest - BigInt(blocksBack) : 0n;
  const toBlock = latest;

  const transferEvent = ERC20_ABI.find((x) => x.type === 'event' && x.name === 'Transfer')!;

  const tasks: Promise<unknown>[] = [];
  if (direction === 'in' || direction === 'both') {
    tasks.push(
      client.getLogs({
        address: USDC_ADDRESS,
        event: transferEvent as any,
        args: { to: address },
        fromBlock,
        toBlock,
      }),
    );
  }
  if (direction === 'out' || direction === 'both') {
    tasks.push(
      client.getLogs({
        address: USDC_ADDRESS,
        event: transferEvent as any,
        args: { from: address },
        fromBlock,
        toBlock,
      }),
    );
  }

  const results = await Promise.all(tasks);
  const merged: any[] = ([] as any[]).concat(...(results as any[]));
  // Dedupe in case both directions caught the same self-transfer
  const seen = new Set<string>();
  const events: TransferEvent[] = [];
  for (const log of merged) {
    const key = `${log.transactionHash}:${log.logIndex}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const a = log.args as { from: Address; to: Address; value: bigint };
    events.push({
      block_number: log.blockNumber.toString(),
      tx_hash: log.transactionHash,
      log_index: log.logIndex,
      from: a.from,
      to: a.to,
      amount_raw: a.value.toString(),
      amount_usdc: formatUnits(a.value, USDC_DECIMALS),
    });
    if (events.length >= 100) break;
  }
  events.sort((a, b) => (BigInt(b.block_number) > BigInt(a.block_number) ? 1 : -1));

  return {
    ok: true,
    address,
    from_block: fromBlock.toString(),
    to_block: toBlock.toString(),
    events,
  };
}
