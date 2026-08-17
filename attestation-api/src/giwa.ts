import type { SubjectRole } from './types.js';

export const GIWA_CHAIN_ID = 91_342n;
export const RECEIVABLE_FINANCE_ADDRESS = '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315' as const;
export const DEFAULT_GIWA_RPC_URL = 'https://sepolia-rpc.giwa.io' as const;

const GET_RECEIVABLE_SELECTOR = 'a94c9f7d';
const RECEIVABLE_NOT_FOUND_SELECTOR = '0f5b1cf9';
const UINT256_MAX = (1n << 256n) - 1n;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000';
const RPC_TIMEOUT_MS = 10_000;

export interface GiwaReceivable {
  id: bigint;
  seller: string;
  buyer: string;
}

export interface GiwaReceivableResolver {
  resolve(receivableId: bigint): Promise<GiwaReceivable>;
}

export class GiwaReceivableNotFoundError extends Error {
  constructor() {
    super('GIWA receivable was not found');
    this.name = 'GiwaReceivableNotFoundError';
  }
}

export class GiwaRpcError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GiwaRpcError';
  }
}

type JsonRpcResponse = {
  result?: unknown;
  error?: unknown;
};

class JsonRpcCallError extends GiwaRpcError {
  constructor(readonly rpcError: unknown) {
    super('GIWA RPC call failed');
    this.name = 'JsonRpcCallError';
  }
}

function normalizeAddress(value: string): string {
  if (!ADDRESS_PATTERN.test(value)) {
    throw new GiwaRpcError('GIWA RPC returned an invalid address');
  }
  return value.toLowerCase();
}

function parseRpcHex(value: unknown, fieldName: string): bigint {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]+$/.test(value)) {
    throw new GiwaRpcError(`GIWA RPC returned an invalid ${fieldName}`);
  }
  return BigInt(value);
}

function encodeGetReceivableCall(receivableId: bigint): string {
  if (receivableId <= 0n || receivableId > UINT256_MAX) {
    throw new GiwaReceivableNotFoundError();
  }
  return `0x${GET_RECEIVABLE_SELECTOR}${receivableId.toString(16).padStart(64, '0')}`;
}

function decodeAddressWord(word: string): string {
  if (!/^[0-9a-fA-F]{64}$/.test(word) || !/^0{24}[0-9a-fA-F]{40}$/.test(word)) {
    throw new GiwaRpcError('GIWA RPC returned malformed receivable data');
  }
  return normalizeAddress(`0x${word.slice(24)}`);
}

export function decodeReceivableResult(value: unknown): GiwaReceivable {
  if (typeof value !== 'string' || !/^0x[0-9a-fA-F]*$/.test(value)) {
    throw new GiwaRpcError('GIWA RPC returned malformed receivable data');
  }

  const payload = value.slice(2);
  const expectedWordCount = 11;
  if (payload.length !== expectedWordCount * 64) {
    throw new GiwaRpcError('GIWA RPC returned malformed receivable data');
  }

  const words = Array.from({ length: expectedWordCount }, (_, index) =>
    payload.slice(index * 64, (index + 1) * 64),
  );
  const id = BigInt(`0x${words[0]}`);
  const seller = decodeAddressWord(words[1]);
  const buyer = decodeAddressWord(words[2]);

  if (id === 0n || seller === ZERO_ADDRESS || buyer === ZERO_ADDRESS) {
    throw new GiwaReceivableNotFoundError();
  }

  return { id, seller, buyer };
}

async function rpcCall(rpcUrl: string, method: string, params: unknown[]): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(rpcUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
      signal: AbortSignal.timeout(RPC_TIMEOUT_MS),
    });
  } catch {
    throw new GiwaRpcError('GIWA RPC request failed');
  }

  if (!response.ok) {
    throw new GiwaRpcError('GIWA RPC request failed');
  }

  let body: JsonRpcResponse;
  try {
    body = (await response.json()) as JsonRpcResponse;
  } catch {
    throw new GiwaRpcError('GIWA RPC returned invalid JSON');
  }

  if (body.error !== undefined) {
    throw new JsonRpcCallError(body.error);
  }
  if (body.result === undefined) {
    throw new GiwaRpcError('GIWA RPC returned no result');
  }
  return body.result;
}

function isReceivableNotFound(error: unknown): boolean {
  if (!(error instanceof JsonRpcCallError)) {
    return false;
  }
  try {
    return JSON.stringify(error.rpcError).toLowerCase().includes(`0x${RECEIVABLE_NOT_FOUND_SELECTOR}`);
  } catch {
    return false;
  }
}

export function createGiwaSepoliaReceivableResolver(
  rpcUrl: string = process.env.GIWA_RPC_URL?.trim() || DEFAULT_GIWA_RPC_URL,
): GiwaReceivableResolver {
  let verifiedChain = false;

  return {
    async resolve(receivableId: bigint): Promise<GiwaReceivable> {
      if (!verifiedChain) {
        const chainId = parseRpcHex(await rpcCall(rpcUrl, 'eth_chainId', []), 'chain ID');
        if (chainId !== GIWA_CHAIN_ID) {
          throw new GiwaRpcError('Configured RPC is not GIWA Sepolia');
        }
        verifiedChain = true;
      }

      let encoded: unknown;
      try {
        encoded = await rpcCall(rpcUrl, 'eth_call', [
          {
            to: RECEIVABLE_FINANCE_ADDRESS,
            data: encodeGetReceivableCall(receivableId),
          },
          'latest',
        ]);
      } catch (error: unknown) {
        if (error instanceof GiwaReceivableNotFoundError) {
          throw error;
        }
        if (isReceivableNotFound(error)) {
          throw new GiwaReceivableNotFoundError();
        }
        throw new GiwaRpcError('Unable to resolve the GIWA receivable');
      }

      const receivable = decodeReceivableResult(encoded);
      if (receivable.id !== receivableId) {
        throw new GiwaRpcError('GIWA RPC returned a different receivable');
      }
      return receivable;
    },
  };
}

export function walletForRole(receivable: GiwaReceivable, role: SubjectRole): string {
  return role === 'SELLER' ? receivable.seller : receivable.buyer;
}
