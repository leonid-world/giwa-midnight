import { describe, expect, it, vi } from 'vitest';
import { createEligibilityReader } from '../eligibility.js';

const ADDRESS = 'a'.repeat(64);

describe('eligibility reader', () => {
  it('returns only sorted public eligibility fields with JSON-safe integers', async () => {
    const queryContractState = vi.fn().mockResolvedValue({ data: Symbol('public-state') });
    const decodeLedger = vi.fn().mockReturnValue({
      eligibilityResults: [
        [Uint8Array.of(0xff), { eligible: false, providerId: 2n, policyVersion: 10n }],
        [Uint8Array.of(0x01, 0x0a), { eligible: true, providerId: 1n, policyVersion: 1n }],
      ],
    });
    const read = createEligibilityReader({ queryContractState, decodeLedger });

    await expect(read(ADDRESS)).resolves.toEqual({
      networkId: 'undeployed',
      contractAddress: ADDRESS,
      results: [
        { commitment: '010a', eligible: true, providerId: '1', policyVersion: '1' },
        { commitment: 'ff', eligible: false, providerId: '2', policyVersion: '10' },
      ],
    });
    expect(queryContractState).toHaveBeenCalledWith(ADDRESS);
    expect(decodeLedger).toHaveBeenCalledOnce();
  });

  it('maps a missing contract to a public 404 error', async () => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockResolvedValue(null),
    });

    await expect(read(ADDRESS)).rejects.toMatchObject({
      status: 404,
      code: 'CONTRACT_NOT_FOUND',
    });
  });

  it('does not expose upstream errors', async () => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockRejectedValue(new Error('secret upstream detail')),
    });

    await expect(read(ADDRESS)).rejects.toMatchObject({
      status: 502,
      code: 'MIDNIGHT_INDEXER_UNAVAILABLE',
      publicMessage: 'The local Midnight Indexer could not be queried.',
    });
  });

  it('maps an incompatible ledger state to a safe decode error', async () => {
    const read = createEligibilityReader({
      queryContractState: vi.fn().mockResolvedValue({ data: {} }),
      decodeLedger: vi.fn(() => {
        throw new Error('decoder internals');
      }),
    });

    await expect(read(ADDRESS)).rejects.toMatchObject({
      status: 502,
      code: 'INVALID_CONTRACT_STATE',
    });
  });
});
