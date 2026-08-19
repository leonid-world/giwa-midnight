// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { Logger } from 'pino';
import * as api from '../api.js';
import {
  PINNED_MIDNIGHT_CONTRACT_ADDRESS,
  fetchProviderInfo,
  generatePseudonymNonce,
  parseProviderInfo,
  preflightContractAndProvider,
  requireExistingPinnedPrivateState,
  validateLocalPreflight,
} from '../proof-bridge/local-runtime.js';
import { fixedHexToBytes } from '../giwa.js';
import type { GasokEligibilityProviders } from '../common-types.js';

afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});

const providerInfoJson = {
  providerId: 2,
  publicKey: { x: '123', y: '456' },
  approvedMidnightContractAddress: PINNED_MIDNIGHT_CONTRACT_ADDRESS,
  attestationType: 'mock',
  authorizationProtocol: 'eip712-role-wallet-v2',
};

function ledger(overrides: Record<string, unknown> = {}) {
  return {
    giwaChainId: 91_342n,
    receivableFinanceAddress: fixedHexToBytes('0x0f264334f98ba0d22f7fc6bb901a5fa36158a315', 20, 'ReceivableFinance', {
      requirePrefix: true,
    }),
    providers: {
      member: () => true,
      lookup: () => ({ x: 123n, y: 456n }),
    },
    ...overrides,
  };
}

describe('local Proof Bridge preflight', () => {
  it('derives the full Uint16 pseudonym nonce from two CSPRNG bytes', () => {
    expect(generatePseudonymNonce(() => Buffer.from([0x12, 0x34]))).toBe(0x1234n);
    expect(() => generatePseudonymNonce(() => Buffer.alloc(1))).toThrow('invalid value');
  });
  it('strictly parses the pinned mock Provider 2 identity', () => {
    expect(parseProviderInfo(providerInfoJson)).toEqual({
      providerId: 2,
      publicKey: { x: 123n, y: 456n },
      approvedMidnightContractAddress: PINNED_MIDNIGHT_CONTRACT_ADDRESS,
    });
    expect(() => parseProviderInfo({ ...providerInfoJson, extra: true })).toThrow('invalid');
    expect(() => parseProviderInfo({ ...providerInfoJson, providerId: 1 })).toThrow('invalid');
    expect(() =>
      parseProviderInfo({
        ...providerInfoJson,
        approvedMidnightContractAddress: '1'.repeat(64),
      }),
    ).toThrow('invalid');
  });

  it('accepts only the sealed GIWA configuration and matching registered Provider 2 key', () => {
    const provider = parseProviderInfo(providerInfoJson);
    expect(validateLocalPreflight(ledger(), provider)).toEqual({
      chainId: 91_342n,
      receivableFinanceAddress: fixedHexToBytes(
        '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315',
        20,
        'ReceivableFinance',
        { requirePrefix: true },
      ),
    });
    expect(() => validateLocalPreflight(null, provider)).toThrow('registration is unavailable');
    expect(() => validateLocalPreflight(ledger({ giwaChainId: 1n }), provider)).toThrow('registration is unavailable');
    expect(() =>
      validateLocalPreflight(
        ledger({
          providers: { member: () => false, lookup: () => ({ x: 123n, y: 456n }) },
        }),
        provider,
      ),
    ).toThrow('registration is unavailable');
    expect(() =>
      validateLocalPreflight(
        ledger({
          providers: { member: () => true, lookup: () => ({ x: 999n, y: 456n }) },
        }),
        provider,
      ),
    ).toThrow('does not match Provider 2');
  });

  it('fails before joining when the pinned contract has no existing private state', async () => {
    const privateStateProvider = {
      setContractAddress: () => undefined,
      get: async () => null,
    };
    const providers = { privateStateProvider } as unknown as GasokEligibilityProviders;

    await expect(requireExistingPinnedPrivateState(providers)).rejects.toThrow('No existing private state');
  });

  it('caps a chunked Provider identity response while streaming it', async () => {
    const oversizedBody = new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(new Uint8Array(3_000));
        controller.enqueue(new Uint8Array(3_000));
        controller.close();
      },
    });
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(oversizedBody, {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      }),
    );

    await expect(fetchProviderInfo()).rejects.toThrow('response is too large');
  });

  it('fails startup within the configured deadline when the SDK Indexer query never settles', async () => {
    vi.useFakeTimers();
    api.setLogger({ info: vi.fn(), warn: vi.fn(), error: vi.fn() } as unknown as Logger);
    const queryContractState = vi.fn(() => new Promise<never>(() => undefined));
    const providers = {
      publicDataProvider: { queryContractState },
    } as unknown as GasokEligibilityProviders;
    const fetchSpy = vi.spyOn(globalThis, 'fetch');

    const pending = preflightContractAndProvider(providers, PINNED_MIDNIGHT_CONTRACT_ADDRESS, 25);
    const rejected = expect(pending).rejects.toThrow('Indexer preflight timed out');
    await vi.advanceTimersByTimeAsync(25);
    await rejected;

    expect(queryContractState).toHaveBeenCalledOnce();
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
