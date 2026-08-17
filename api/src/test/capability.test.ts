import { describe, expect, it } from 'vitest';
import {
  DEFAULT_GASOK_CONTRACT_ADDRESS,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from '../config.js';
import { verifyProofCapability } from '../capability.js';
import { createValidCapability } from './fixture.js';

describe('proof capability v1', () => {
  it('recomputes and accepts the exact lookup key while normalizing public context', () => {
    const input = createValidCapability({
      midnightContractAddress: DEFAULT_GASOK_CONTRACT_ADDRESS.toUpperCase(),
      companyCommitment: createValidCapability().companyCommitment.toUpperCase().replace('0X', '0x'),
      lookupKey: createValidCapability().lookupKey.toUpperCase().replace('0X', '0x'),
      receivableFinanceAddress: GIWA_RECEIVABLE_FINANCE_ADDRESS.toUpperCase().replace('0X', '0x'),
      partyWallet: createValidCapability().partyWallet.toUpperCase().replace('0X', '0x'),
    });

    const verified = verifyProofCapability(input, DEFAULT_GASOK_CONTRACT_ADDRESS);

    expect(verified.capability).toEqual(createValidCapability());
    expect(Buffer.from(verified.lookupKeyBytes).toString('hex')).toBe(
      createValidCapability().lookupKey.slice(2),
    );
  });

  it('rejects a lookup key that does not match the capability fields', () => {
    expect(() => verifyProofCapability(
      createValidCapability({ lookupKey: `0x${'ff'.repeat(32)}` }),
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code: 'CAPABILITY_LOOKUP_MISMATCH' }));
  });

  it.each([
    ['company commitment', { companyCommitment: `0x${'33'.repeat(32)}` }],
    ['receivable ID', { onchainReceivableId: '8' }],
    ['subject role', { subjectRole: 'BUYER' }],
    ['party wallet', { partyWallet: `0x${'44'.repeat(20)}` }],
  ] as const)('rejects reuse after changing the bound %s', (_label, override) => {
    expect(() => verifyProofCapability(
      createValidCapability(override),
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code: 'CAPABILITY_LOOKUP_MISMATCH' }));
  });

  it.each([
    ['Midnight contract', { midnightContractAddress: 'f'.repeat(64) }, 'UNAPPROVED_CONTRACT_ADDRESS'],
    ['GIWA chain', { giwaChainId: '1' }, 'UNAPPROVED_GIWA_CONTEXT'],
    ['ReceivableFinance', { receivableFinanceAddress: `0x${'ff'.repeat(20)}` }, 'UNAPPROVED_GIWA_CONTEXT'],
  ])('rejects an unapproved %s', (_label, override, code) => {
    expect(() => verifyProofCapability(
      createValidCapability(override),
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code }));
  });

  it.each([
    ['version', { version: 2 }],
    ['zero ID', { onchainReceivableId: '0' }],
    ['non-canonical ID', { onchainReceivableId: '07' }],
    ['invalid role', { subjectRole: 'FUNDER' }],
    ['unprefixed lookup key', { lookupKey: 'aa'.repeat(32) }],
    ['unprefixed company commitment', { companyCommitment: 'aa'.repeat(32) }],
    ['unprefixed party wallet', { partyWallet: 'aa'.repeat(20) }],
  ])('rejects invalid schema: %s', (_label, override) => {
    expect(() => verifyProofCapability(
      createValidCapability(override as never),
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code: 'INVALID_PROOF_CAPABILITY' }));
  });

  it('rejects extra fields so raw financial values cannot enter this API', () => {
    const capability = {
      ...createValidCapability(),
      annualRevenueKrw: '500000000',
    };

    expect(() => verifyProofCapability(
      capability,
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code: 'INVALID_PROOF_CAPABILITY' }));
  });
});
