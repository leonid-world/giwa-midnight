import { describe, expect, it, vi } from 'vitest';
import {
  GIWA_CHAIN_ID,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from '../config.js';
import { createEligibilityReader } from '../eligibility.js';

const ADDRESS = 'a'.repeat(64);
const LOOKUP_KEY = Uint8Array.from(Buffer.from('ab'.repeat(32), 'hex'));
const FINANCE_ADDRESS = Uint8Array.from(
  Buffer.from(GIWA_RECEIVABLE_FINANCE_ADDRESS.slice(2), 'hex'),
);

function configuredLedger(overrides: Record<string, unknown> = {}) {
  return {
    giwaChainId: GIWA_CHAIN_ID,
    receivableFinanceAddress: FINANCE_ADDRESS,
    eligibilityResults: {
      member: vi.fn(() => true),
      lookup: vi.fn(() => ({ eligible: true, providerId: 1n, policyVersion: 1n })),
    },
    ...overrides,
  };
}

describe('exact eligibility reader', () => {
  it('looks up one exact key without enumerating public results', async () => {
    const queryContractState = vi.fn().mockResolvedValue({ data: Symbol('public-state') });
    const ledger = configuredLedger();
    const decodeLedger = vi.fn().mockReturnValue(ledger);
    const read = createEligibilityReader({ queryContractState, decodeLedger });

    await expect(read(ADDRESS, LOOKUP_KEY)).resolves.toEqual({
      eligible: true,
      providerId: '1',
      policyVersion: '1',
    });
    expect(queryContractState).toHaveBeenCalledWith(ADDRESS);
    expect(ledger.eligibilityResults.member).toHaveBeenCalledWith(LOOKUP_KEY);
    expect(ledger.eligibilityResults.lookup).toHaveBeenCalledWith(LOOKUP_KEY);
    expect(Symbol.iterator in ledger.eligibilityResults).toBe(false);
  });

  it('maps a missing exact result to a public 404 error', async () => {
    const ledger = configuredLedger({
      eligibilityResults: {
        member: vi.fn(() => false),
        lookup: vi.fn(),
      },
    });
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockResolvedValue({ data: {} }),
      decodeLedger: vi.fn().mockReturnValue(ledger),
    });

    await expect(read(ADDRESS, LOOKUP_KEY)).rejects.toMatchObject({
      status: 404,
      code: 'ELIGIBILITY_RESULT_NOT_FOUND',
    });
    expect(ledger.eligibilityResults.lookup).not.toHaveBeenCalled();
  });

  it('maps a missing contract to a public 404 error', async () => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockResolvedValue(null),
    });

    await expect(read(ADDRESS, LOOKUP_KEY)).rejects.toMatchObject({
      status: 404,
      code: 'CONTRACT_NOT_FOUND',
    });
  });

  it('does not expose upstream errors', async () => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockRejectedValue(new Error('secret upstream detail')),
    });

    await expect(read(ADDRESS, LOOKUP_KEY)).rejects.toMatchObject({
      status: 502,
      code: 'MIDNIGHT_INDEXER_UNAVAILABLE',
      publicMessage: 'The local Midnight Indexer could not be queried.',
    });
  });

  it.each([
    ['chain ID', { giwaChainId: 1n }],
    ['ReceivableFinance', { receivableFinanceAddress: Uint8Array.from({ length: 20 }, () => 0) }],
  ])('rejects a decoded ledger with the wrong pinned %s', async (_label, override) => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockResolvedValue({ data: {} }),
      decodeLedger: vi.fn().mockReturnValue(configuredLedger(override)),
    });

    await expect(read(ADDRESS, LOOKUP_KEY)).rejects.toMatchObject({
      status: 502,
      code: 'INVALID_CONTRACT_STATE',
    });
  });

  it('maps an incompatible ledger state to a safe decode error', async () => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockResolvedValue({ data: {} }),
      decodeLedger: vi.fn(() => {
        throw new Error('decoder internals');
      }),
    });

    await expect(read(ADDRESS, LOOKUP_KEY)).rejects.toMatchObject({
      status: 502,
      code: 'INVALID_CONTRACT_STATE',
    });
  });
});
