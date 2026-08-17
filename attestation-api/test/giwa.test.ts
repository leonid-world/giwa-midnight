import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createGiwaSepoliaReceivableResolver,
  decodeReceivableResult,
  GiwaReceivableNotFoundError,
  GiwaRpcError,
  RECEIVABLE_FINANCE_ADDRESS,
} from '../src/giwa.js';

const seller = '0x1111111111111111111111111111111111111111';
const buyer = '0x2222222222222222222222222222222222222222';

function uintWord(value: bigint): string {
  return value.toString(16).padStart(64, '0');
}

function addressWord(value: string): string {
  return value.slice(2).padStart(64, '0');
}

function encodeReceivable(id: bigint): string {
  return `0x${[
    uintWord(id),
    addressWord(seller),
    addressWord(buyer),
    addressWord('0x0000000000000000000000000000000000000000'),
    uintWord(1_000n),
    uintWord(900n),
    uintWord(1n),
    uintWord(2n),
    'ab'.repeat(32),
    uintWord(3n),
    uintWord(1n),
  ].join('')}`;
}

function rpcResponse(result: unknown): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, result }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

function rpcError(error: unknown): Response {
  return new Response(JSON.stringify({ jsonrpc: '2.0', id: 1, error }), {
    status: 200,
    headers: { 'Content-Type': 'application/json' },
  });
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe('GIWA Sepolia receivable resolver', () => {
  it('decodes the full uint256 ID and canonical seller/buyer addresses', () => {
    const id = (1n << 256n) - 1n;
    expect(decodeReceivableResult(encodeReceivable(id))).toEqual({ id, seller, buyer });
  });

  it('checks GIWA chain ID before reading the fixed ReceivableFinance contract', async () => {
    const id = (1n << 200n) + 9n;
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(rpcResponse('0x164ce'))
      .mockResolvedValueOnce(rpcResponse(encodeReceivable(id)));
    vi.stubGlobal('fetch', fetchMock);

    const resolver = createGiwaSepoliaReceivableResolver('https://example.invalid/giwa');
    await expect(resolver.resolve(id)).resolves.toEqual({ id, seller, buyer });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [, callOptions] = fetchMock.mock.calls[1];
    const request = JSON.parse(String(callOptions.body));
    expect(request.method).toBe('eth_call');
    expect(request.params[0].to).toBe(RECEIVABLE_FINANCE_ADDRESS);
    expect(request.params[0].data).toBe(`0xa94c9f7d${id.toString(16).padStart(64, '0')}`);
  });

  it('rejects a configured RPC on the wrong chain before eth_call', async () => {
    const fetchMock = vi.fn().mockResolvedValueOnce(rpcResponse('0x1'));
    vi.stubGlobal('fetch', fetchMock);
    const resolver = createGiwaSepoliaReceivableResolver('https://example.invalid/wrong-chain');

    await expect(resolver.resolve(1n)).rejects.toBeInstanceOf(GiwaRpcError);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('maps the ReceivableNotFound custom error to a safe not-found result', async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(rpcResponse('0x164ce'))
      .mockResolvedValueOnce(
        rpcError({ code: 3, message: 'execution reverted', data: `0x0f5b1cf9${uintWord(99n)}` }),
      );
    vi.stubGlobal('fetch', fetchMock);
    const resolver = createGiwaSepoliaReceivableResolver('https://example.invalid/giwa');

    await expect(resolver.resolve(99n)).rejects.toBeInstanceOf(GiwaReceivableNotFoundError);
  });

  it('rejects malformed or missing receivable results without inventing a party wallet', () => {
    expect(() => decodeReceivableResult('0x')).toThrow(GiwaRpcError);
    expect(() => decodeReceivableResult(encodeReceivable(0n))).toThrow(GiwaReceivableNotFoundError);
  });
});
