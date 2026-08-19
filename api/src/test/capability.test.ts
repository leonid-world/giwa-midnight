import { describe, expect, it } from 'vitest';
import { DEFAULT_GASOK_CONTRACT_ADDRESS } from '../config.js';
import { verifyProofCapability } from '../capability.js';
import { createValidCapability } from './fixture.js';

describe('proof capability v2', () => {
  it('recomputes and accepts the exact policy and lookup hashes', () => {
    const input = createValidCapability();
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
    ['request ID', { requestId: `0x${'55'.repeat(32)}` }],
    ['intended Funder', { intendedFunderWallet: `0x${'55'.repeat(20)}` }],
    ['minimum revenue', { minAnnualRevenueKrw: '500000001' }],
    ['maximum debt ratio', { maxDebtRatioBps: '19999' }],
    ['maximum overdue count', { maxOverdueCount: '0' }],
    ['valid-until', { validUntil: '4000000001' }],
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
    ['version', { version: 1 }],
    ['zero ID', { onchainReceivableId: '0' }],
    ['non-canonical ID', { onchainReceivableId: '07' }],
    ['invalid role', { subjectRole: 'FUNDER' }],
    ['unprefixed lookup key', { lookupKey: 'aa'.repeat(32) }],
    ['unprefixed company commitment', { companyCommitment: 'aa'.repeat(32) }],
    ['unprefixed party wallet', { partyWallet: 'aa'.repeat(20) }],
    ['uppercase request ID', { requestId: `0x${'AA'.repeat(32)}` }],
    ['zero intended Funder', { intendedFunderWallet: `0x${'00'.repeat(20)}` }],
    ['inverted freshness', { profileAsOf: '4000000001' }],
    ['zero Midnight contract', { midnightContractAddress: '0'.repeat(64) }],
  ])('rejects invalid schema: %s', (_label, override) => {
    expect(() => verifyProofCapability(
      createValidCapability(override as never),
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code: 'INVALID_PROOF_CAPABILITY' }));
  });

  it.each([
    ['annual revenue', { annualRevenueKrw: '500000000' }],
    ['debt ratio', { debtRatioBps: '20000' }],
    ['overdue count', { overdueCount: '1' }],
    ['pseudonym nonce', { pseudonymNonce: '1234' }],
    ['provider signature', { signature: 'must-not-enter-the-read-api' }],
  ])('rejects extra %s fields so private proof material cannot enter this API', (_label, extra) => {
    const capability = {
      ...createValidCapability(),
      ...extra,
    };

    expect(() => verifyProofCapability(
      capability,
      DEFAULT_GASOK_CONTRACT_ADDRESS,
    )).toThrow(expect.objectContaining({ code: 'INVALID_PROOF_CAPABILITY' }));
  });
});
