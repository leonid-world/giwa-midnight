import { describe, expect, it } from 'vitest';
import { TypedDataEncoder, Wallet } from 'ethers';
import {
  AUTHORIZATION_DOMAIN,
  AUTHORIZATION_FIELDS,
  AUTHORIZATION_PRIMARY_TYPE,
  AUTHORIZATION_TYPES,
  AuthorizationCapacityError,
  AuthorizationChallengeStore,
  AuthorizationGenerationError,
  AuthorizationValidationError,
  PolicyRequestExpiredError,
  RoleWalletMismatchError,
  buildAttestationRequestCommitment,
  buildAuthorizationChallengeResponse,
  buildAuthorizationMessage,
  hashAuthorizationMessage,
  requireNonZeroAttestationRequestCommitment,
  verifyAuthorizationSignature,
} from '../src/authorization.js';
import type { ParsedAttestationRequest } from '../src/types.js';

const midnightContractAddress = '12caaf76aef1de1c584b67462018810f6e4e7eb2535e136f560cb621e24a3f36';
const wallet = new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');

function request(overrides: Partial<ParsedAttestationRequest> = {}): ParsedAttestationRequest {
  return {
    annualRevenueKrw: 500_000_000n,
    debtRatioBps: 20_000n,
    overdueCount: 1n,
    companyCommitmentHash: 12_345_678_901_234_567_890n,
    authorizationSalt: `0x${'aa'.repeat(32)}`,
    midnightContractAddress,
    onchainReceivableId: 7n,
    subjectRole: 'SELLER',
    policyRequest: {
      requestId: `0x${'33'.repeat(32)}`,
      intendedFunderWallet: '0x4444444444444444444444444444444444444444',
      minAnnualRevenueKrw: 500_000_000n,
      maxDebtRatioBps: 20_000n,
      maxOverdueCount: 1n,
      validUntil: 4_000_000_000n,
    },
    ...overrides,
  };
}

describe('EIP-712 role-wallet authorization protocol', () => {
  it('publishes the exact agreed domain and ordered primary type only', () => {
    expect(AUTHORIZATION_DOMAIN).toEqual({
      name: 'GASOK Mock Attestation',
      version: '2',
      chainId: '91342',
    });
    expect(Object.keys(AUTHORIZATION_TYPES)).toEqual([AUTHORIZATION_PRIMARY_TYPE]);
    expect(AUTHORIZATION_FIELDS).toEqual([
      { name: 'purpose', type: 'string' },
      { name: 'authorizationId', type: 'bytes32' },
      { name: 'midnightContractAddress', type: 'bytes32' },
      { name: 'receivableFinanceAddress', type: 'address' },
      { name: 'onchainReceivableId', type: 'uint256' },
      { name: 'subjectRole', type: 'string' },
      { name: 'partyWallet', type: 'address' },
      { name: 'requestId', type: 'bytes32' },
      { name: 'intendedFunderWallet', type: 'address' },
      { name: 'minAnnualRevenueKrw', type: 'uint64' },
      { name: 'maxDebtRatioBps', type: 'uint32' },
      { name: 'maxOverdueCount', type: 'uint16' },
      { name: 'attestationRequestCommitment', type: 'bytes32' },
      { name: 'providerId', type: 'uint16' },
      { name: 'evaluationVersion', type: 'uint16' },
      { name: 'profileAsOf', type: 'uint64' },
      { name: 'policyValidUntil', type: 'uint64' },
      { name: 'issuedAt', type: 'uint64' },
      { name: 'expiresAt', type: 'uint64' },
    ]);
  });

  it('derives the fixed domain-separated ABI commitment vector', () => {
    expect(buildAttestationRequestCommitment(
      request(),
      '0x1111111111111111111111111111111111111111',
      '1700000000',
    )).toMatch(/^0x[0-9a-f]{64}$/);
  });

  it('rejects a calculated zero attestation request commitment', () => {
    expect(() => requireNonZeroAttestationRequestCommitment(`0x${'0'.repeat(64)}`))
      .toThrow(AuthorizationGenerationError);
  });

  it.each([
    ['annual revenue', { annualRevenueKrw: 500_000_001n }, wallet.address],
    ['debt ratio', { debtRatioBps: 19_999n }, wallet.address],
    ['overdue count', { overdueCount: 0n }, wallet.address],
    ['company commitment', { companyCommitmentHash: 99n }, wallet.address],
    ['authorization salt', { authorizationSalt: `0x${'bb'.repeat(32)}` }, wallet.address],
    ['Midnight deployment', { midnightContractAddress: 'bb'.repeat(32) }, wallet.address],
    ['receivable ID', { onchainReceivableId: 8n }, wallet.address],
    ['subject role', { subjectRole: 'BUYER' as const }, wallet.address],
    ['party wallet', {}, '0x2222222222222222222222222222222222222222'],
    ['policy request ID', {
      policyRequest: { ...request().policyRequest, requestId: `0x${'44'.repeat(32)}` },
    }, wallet.address],
    ['policy audience', {
      policyRequest: {
        ...request().policyRequest,
        intendedFunderWallet: '0x5555555555555555555555555555555555555555',
      },
    }, wallet.address],
    ['policy thresholds', {
      policyRequest: { ...request().policyRequest, minAnnualRevenueKrw: 500_000_001n },
    }, wallet.address],
    ['policy expiry', {
      policyRequest: { ...request().policyRequest, validUntil: 4_000_000_001n },
    }, wallet.address],
  ])('binds the %s into the hidden request commitment', (_label, overrides, partyWallet) => {
    const original = buildAttestationRequestCommitment(request(), wallet.address, '1700000000');
    const changed = buildAttestationRequestCommitment(request(overrides), partyWallet, '1700000000');
    expect(changed).not.toBe(original);
  });

  it('returns no raw financial field or hidden authorization salt', () => {
    const store = new AuthorizationChallengeStore({
      now: () => 1_700_000_000,
      randomId: () => `0x${'11'.repeat(32)}`,
    });
    const record = store.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt));
    const response = buildAuthorizationChallengeResponse(record);
    const serialized = JSON.stringify(response);

    expect(Object.keys(response)).toEqual(['version', 'domain', 'primaryType', 'types', 'message']);
    expect(serialized).not.toContain('annualRevenueKrw');
    expect(serialized).not.toContain('debtRatioBps');
    expect(serialized).not.toContain('overdueCount');
    expect(serialized).not.toContain('companyCommitmentHash');
    expect(serialized).not.toContain('authorizationSalt');
    expect(serialized).not.toContain('aa'.repeat(32));
  });

  it.each([
    ['normal 120-second window', 2_000n, '1120', 120n],
    ['119-second policy remainder', 1_119n, '1119', 119n],
    ['one-second policy remainder', 1_001n, '1001', 1n],
  ])('bounds the %s by the earlier authorization or policy expiry', (
    _label,
    validUntil,
    expectedExpiresAt,
    expectedTtl,
  ) => {
    const policyBoundRequest = request({
      policyRequest: { ...request().policyRequest, validUntil },
    });
    const message = buildAuthorizationMessage(
      policyBoundRequest,
      wallet.address,
      `0x${'11'.repeat(32)}`,
      '1000',
      '1120',
    );

    expect(message.expiresAt).toBe(expectedExpiresAt);
    expect(BigInt(message.expiresAt) - BigInt(message.issuedAt)).toBe(expectedTtl);
  });

  it('rejects an already-expired policy and authorization TTLs outside 1..120 seconds', () => {
    const expiredRequest = request({
      policyRequest: { ...request().policyRequest, validUntil: 1_000n },
    });
    expect(() => buildAuthorizationMessage(
      expiredRequest,
      wallet.address,
      `0x${'11'.repeat(32)}`,
      '1000',
      '1120',
    )).toThrow(PolicyRequestExpiredError);
    expect(() => new AuthorizationChallengeStore({ ttlSeconds: 0 })).toThrow(RangeError);
    expect(() => new AuthorizationChallengeStore({ ttlSeconds: 121 })).toThrow(RangeError);
  });

  it('hashes and verifies an exact ethers v6 EIP-712 signature', async () => {
    const message = buildAuthorizationMessage(
      request(),
      wallet.address,
      `0x${'11'.repeat(32)}`,
      '1700000000',
      '1700000120',
    );
    const signature = await wallet.signTypedData(AUTHORIZATION_DOMAIN, AUTHORIZATION_TYPES, message);
    const typedDataHash = TypedDataEncoder.hash(AUTHORIZATION_DOMAIN, AUTHORIZATION_TYPES, message);

    expect(hashAuthorizationMessage(message)).toBe(typedDataHash);
    expect(() => verifyAuthorizationSignature(message, {
      version: 2,
      authorizationId: message.authorizationId,
      typedDataHash,
      signer: wallet.address,
      signature,
    }, wallet.address)).not.toThrow();
  });

  it('keeps malformed authorization material in the generic validation error class', async () => {
    const message = buildAuthorizationMessage(
      request(),
      wallet.address,
      `0x${'11'.repeat(32)}`,
      '1700000000',
      '1700000120',
    );
    const signature = await wallet.signTypedData(AUTHORIZATION_DOMAIN, AUTHORIZATION_TYPES, message);
    const validProof = {
      version: 2 as const,
      authorizationId: message.authorizationId,
      typedDataHash: hashAuthorizationMessage(message),
      signer: wallet.address,
      signature,
    };

    for (const proof of [
      { ...validProof, typedDataHash: `0x${'ff'.repeat(32)}` },
      { ...validProof, signature: '0x1234' },
      { ...validProof, signature: `0x${'00'.repeat(65)}` },
      { ...validProof, authorizationId: `0x${'22'.repeat(32)}` },
    ]) {
      let thrown: unknown;
      try {
        verifyAuthorizationSignature(message, proof, wallet.address);
      } catch (error: unknown) {
        thrown = error;
      }
      expect(thrown).toBeInstanceOf(AuthorizationValidationError);
      expect(thrown).not.toBeInstanceOf(RoleWalletMismatchError);
    }
  });

  it('distinguishes only valid recoverable signer identities that differ from the role wallet', async () => {
    const other = new Wallet('0x8b3a350cf5c34c9194ca3a545dbe4035957f353df9e4cb8a3173f8a2f1a7e682');
    const message = buildAuthorizationMessage(
      request(),
      wallet.address,
      `0x${'11'.repeat(32)}`,
      '1700000000',
      '1700000120',
    );
    const typedDataHash = hashAuthorizationMessage(message);
    const canonicalSignature = await wallet.signTypedData(AUTHORIZATION_DOMAIN, AUTHORIZATION_TYPES, message);
    const otherSignature = await other.signTypedData(AUTHORIZATION_DOMAIN, AUTHORIZATION_TYPES, message);

    expect(() => verifyAuthorizationSignature(message, {
      version: 2,
      authorizationId: message.authorizationId,
      typedDataHash,
      signer: wallet.address,
      signature: otherSignature,
    }, wallet.address)).toThrow(RoleWalletMismatchError);

    expect(() => verifyAuthorizationSignature(message, {
      version: 2,
      authorizationId: message.authorizationId,
      typedDataHash,
      signer: other.address,
      signature: canonicalSignature,
    }, wallet.address)).toThrow(RoleWalletMismatchError);
  });

  it('takes a challenge exactly once', () => {
    const store = new AuthorizationChallengeStore({
      now: () => 100,
      randomId: () => `0x${'11'.repeat(32)}`,
    });
    const record = store.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt));

    expect(store.take(record.message.authorizationId)).toBe(record);
    expect(() => store.take(record.message.authorizationId)).toThrow(AuthorizationValidationError);
  });

  it('expires and prunes challenges while enforcing the configured capacity', () => {
    let now = 100;
    let nextId = 1;
    const store = new AuthorizationChallengeStore({
      now: () => now,
      ttlSeconds: 2,
      maxEntries: 1,
      randomId: () => `0x${(nextId++).toString(16).padStart(64, '0')}`,
    });
    const first = store.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt));
    expect(() => store.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt)))
      .toThrow(AuthorizationCapacityError);

    now = 102;
    expect(store.size).toBe(0);
    expect(() => store.take(first.message.authorizationId)).toThrow(AuthorizationValidationError);
    expect(() => store.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt)))
      .not.toThrow();
  });

  it('bounds repeated zero or colliding generated authorization IDs', () => {
    const zeroStore = new AuthorizationChallengeStore({
      randomId: () => `0x${'0'.repeat(64)}`,
    });
    expect(() => zeroStore.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt)))
      .toThrow(AuthorizationGenerationError);

    const repeatedId = `0x${'11'.repeat(32)}`;
    const collisionStore = new AuthorizationChallengeStore({
      maxEntries: 2,
      randomId: () => repeatedId,
    });
    collisionStore.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt));
    expect(() => collisionStore.issue((authorizationId, issuedAt, expiresAt) =>
      buildAuthorizationMessage(request(), wallet.address, authorizationId, issuedAt, expiresAt)))
      .toThrow(AuthorizationGenerationError);
  });
});
