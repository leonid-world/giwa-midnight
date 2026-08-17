// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import { Wallet } from 'ethers';
import * as api from '../api';
import {
  AUTHORIZATION_DOMAIN,
  AUTHORIZATION_FIELDS,
  AUTHORIZATION_PRIMARY_TYPE,
  AUTHORIZATION_PURPOSE,
  AUTHORIZATION_TTL_SECONDS,
  buildAttestationRequestCommitment,
  createAuthorizationChallengeRequest,
  generateAuthorizationSalt,
  hashAuthorizationChallenge,
  parseAuthorizationChallenge,
  parseAuthorizationProofJson,
  validateAuthorizationProof,
  type AuthorizationChallengeRequest,
  type AuthorizationExpectedContext,
} from '../authorization';
import { getDefaultGiwaDeploymentConfig } from '../giwa';

const now = 1_700_000_000n;
const midnightContractAddress = '7e3ea9d741ce0f5862db6f46d0ad720be2586cd7d0405ec77e4a0478aa50f4fb';
const expected: AuthorizationExpectedContext = {
  midnightContractAddress,
  onchainReceivableId: 7n,
  subjectRole: 'SELLER',
  giwa: getDefaultGiwaDeploymentConfig(),
};
const request = createAuthorizationChallengeRequest(
  500_000_000n,
  20_000n,
  1n,
  12_345_678_901_234_567_890n,
  expected,
  `0x${'aa'.repeat(32)}`,
);
const signingTypes = {
  [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS.map((field) => ({ ...field })),
};

function rawChallenge(partyWallet: string, challengeRequest: AuthorizationChallengeRequest = request) {
  return {
    version: 1,
    domain: { ...AUTHORIZATION_DOMAIN },
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    types: {
      [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS.map((field) => ({ ...field })),
    },
    message: {
      purpose: AUTHORIZATION_PURPOSE,
      authorizationId: `0x${'11'.repeat(32)}`,
      midnightContractAddress: `0x${challengeRequest.midnightContractAddress}`,
      receivableFinanceAddress: '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315',
      onchainReceivableId: challengeRequest.onchainReceivableId,
      subjectRole: challengeRequest.subjectRole,
      partyWallet: partyWallet.toLowerCase(),
      attestationRequestCommitment: buildAttestationRequestCommitment(challengeRequest, partyWallet),
      providerId: '2',
      policyVersion: '1',
      issuedAt: now.toString(),
      expiresAt: (now + AUTHORIZATION_TTL_SECONDS).toString(),
    },
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('CLI EIP-712 role-wallet authorization', () => {
  it('uses a fresh non-zero 32-byte CSPRNG salt and the exact challenge request schema', () => {
    const first = generateAuthorizationSalt();
    const second = generateAuthorizationSalt();

    expect(first).toMatch(/^0x[0-9a-f]{64}$/);
    expect(first).not.toBe(`0x${'0'.repeat(64)}`);
    expect(second).not.toBe(first);
    expect(Object.keys(request)).toEqual([
      'version',
      'annualRevenueKrw',
      'debtRatioBps',
      'overdueCount',
      'companyCommitmentHash',
      'authorizationSalt',
      'midnightContractAddress',
      'onchainReceivableId',
      'subjectRole',
    ]);
  });

  it('independently reproduces the provider ABI/keccak commitment vector', () => {
    expect(buildAttestationRequestCommitment(
      request,
      '0x1111111111111111111111111111111111111111',
    )).toBe('0xafe5640e5716c74ac0b70cce451e0f4fd7779d7c8a9847a91c7d00f114e8ab9d');
  });

  it.each([
    ['annual revenue', { annualRevenueKrw: '500000001' }],
    ['debt ratio', { debtRatioBps: '19999' }],
    ['overdue count', { overdueCount: '0' }],
    ['company commitment', { companyCommitmentHash: '99' }],
    ['authorization salt', { authorizationSalt: `0x${'bb'.repeat(32)}` }],
    ['Midnight deployment', { midnightContractAddress: 'bb'.repeat(32) }],
    ['receivable ID', { onchainReceivableId: '8' }],
    ['subject role', { subjectRole: 'BUYER' as const }],
  ])('binds the %s into the hidden request commitment', (_label, overrides) => {
    const changedRequest = { ...request, ...overrides } as AuthorizationChallengeRequest;
    expect(buildAttestationRequestCommitment(changedRequest, '0x1111111111111111111111111111111111111111'))
      .not.toBe(buildAttestationRequestCommitment(request, '0x1111111111111111111111111111111111111111'));
  });

  it('strictly accepts the exact primary type and context without exposing hidden inputs', () => {
    const wallet = Wallet.createRandom();
    const untrusted = rawChallenge(wallet.address);
    const challenge = parseAuthorizationChallenge(untrusted, request, expected, now);
    const serialized = JSON.stringify(challenge);

    expect(challenge.domain).toEqual({
      name: 'GASOK Mock Attestation',
      version: '1',
      chainId: '91342',
    });
    expect(Object.keys(challenge.types)).toEqual([AUTHORIZATION_PRIMARY_TYPE]);
    expect(challenge.types[AUTHORIZATION_PRIMARY_TYPE]).toEqual(AUTHORIZATION_FIELDS);
    expect(challenge.message.partyWallet).toBe(wallet.address.toLowerCase());
    for (const hiddenField of [
      'annualRevenueKrw',
      'debtRatioBps',
      'overdueCount',
      'companyCommitmentHash',
      'authorizationSalt',
      'aa'.repeat(32),
    ]) {
      expect(serialized).not.toContain(hiddenField);
    }
  });

  it.each([
    ['extra top-level key', (value: any) => { value.extra = true; }],
    ['EIP712Domain type', (value: any) => { value.types.EIP712Domain = []; }],
    ['field order', (value: any) => { value.types[AUTHORIZATION_PRIMARY_TYPE].reverse(); }],
    ['domain chain', (value: any) => { value.domain.chainId = '1'; }],
    ['purpose', (value: any) => { value.message.purpose = 'other'; }],
    ['Midnight deployment', (value: any) => { value.message.midnightContractAddress = `0x${'22'.repeat(32)}`; }],
    ['ReceivableFinance address', (value: any) => { value.message.receivableFinanceAddress = `0x${'22'.repeat(20)}`; }],
    ['receivable ID', (value: any) => { value.message.onchainReceivableId = '8'; }],
    ['role', (value: any) => { value.message.subjectRole = 'BUYER'; }],
    ['party wallet', (value: any) => { value.message.partyWallet = `0x${'22'.repeat(20)}`; }],
    ['request commitment', (value: any) => { value.message.attestationRequestCommitment = `0x${'22'.repeat(32)}`; }],
    ['provider', (value: any) => { value.message.providerId = '3'; }],
    ['policy', (value: any) => { value.message.policyVersion = '2'; }],
    ['future issue time', (value: any) => { value.message.issuedAt = (now + 1n).toString(); }],
    ['overlong TTL', (value: any) => { value.message.expiresAt = (now + 121n).toString(); }],
  ])('rejects a challenge with tampered %s', (_label, mutate) => {
    const value = rawChallenge(Wallet.createRandom().address);
    mutate(value);
    expect(() => parseAuthorizationChallenge(value, request, expected, now)).toThrow(
      'invalid role authorization challenge',
    );
  });

  it('rejects zero identifiers/salts and a challenge expiring at the current second', () => {
    expect(() => createAuthorizationChallengeRequest(
      1n,
      1n,
      0n,
      1n,
      expected,
      `0x${'0'.repeat(64)}`,
    )).toThrow('authorization salt');

    const zeroId = rawChallenge(Wallet.createRandom().address);
    zeroId.message.authorizationId = `0x${'0'.repeat(64)}`;
    expect(() => parseAuthorizationChallenge(zeroId, request, expected, now)).toThrow();

    const zeroCommitment = rawChallenge(Wallet.createRandom().address);
    zeroCommitment.message.attestationRequestCommitment = `0x${'0'.repeat(64)}`;
    expect(() => parseAuthorizationChallenge(zeroCommitment, request, expected, now)).toThrow();

    const expired = rawChallenge(Wallet.createRandom().address);
    expired.message.expiresAt = now.toString();
    expect(() => parseAuthorizationChallenge(expired, request, expected, now)).toThrow();
  });

  it('verifies exact MetaMask-style JSON against its hash, recovered signer, and current challenge', async () => {
    const wallet = Wallet.createRandom();
    const challenge = parseAuthorizationChallenge(rawChallenge(wallet.address), request, expected, now);
    const signature = await wallet.signTypedData(challenge.domain, signingTypes, challenge.message);
    const proof = {
      version: 1,
      authorizationId: challenge.message.authorizationId,
      typedDataHash: hashAuthorizationChallenge(challenge),
      signer: wallet.address,
      signature,
    };

    expect(parseAuthorizationProofJson(JSON.stringify(proof), challenge, now)).toEqual({
      ...proof,
      signer: wallet.address.toLowerCase(),
      signature: signature.toLowerCase(),
    });
  });

  it('rejects a replay/tamper proof for another hash, ID, signer, signature, schema, or expired challenge', async () => {
    const wallet = Wallet.createRandom();
    const other = Wallet.createRandom();
    const challenge = parseAuthorizationChallenge(rawChallenge(wallet.address), request, expected, now);
    const proof = {
      version: 1,
      authorizationId: challenge.message.authorizationId,
      typedDataHash: hashAuthorizationChallenge(challenge),
      signer: wallet.address,
      signature: await wallet.signTypedData(challenge.domain, signingTypes, challenge.message),
    };
    const cases: unknown[] = [
      { ...proof, authorizationId: `0x${'22'.repeat(32)}` },
      { ...proof, typedDataHash: `0x${'22'.repeat(32)}` },
      { ...proof, typedDataHash: `0x${'0'.repeat(64)}` },
      { ...proof, signer: other.address },
      { ...proof, signature: await other.signTypedData(challenge.domain, signingTypes, challenge.message) },
      { ...proof, privateKey: 'must-never-be-accepted' },
    ];

    for (const candidate of cases) {
      expect(() => validateAuthorizationProof(candidate, challenge, now)).toThrow('wallet authorization response');
    }
    expect(() => validateAuthorizationProof(proof, challenge, now + AUTHORIZATION_TTL_SECONDS)).toThrow(
      'wallet authorization response',
    );
    expect(() => parseAuthorizationProofJson(`${JSON.stringify(proof)}\n`, challenge, now)).toThrow();
    expect(() => parseAuthorizationProofJson('x'.repeat(4_097), challenge, now)).toThrow();
  });

  it('rejects replay of a valid Seller proof against a Buyer request context', async () => {
    const wallet = Wallet.createRandom();
    const sellerChallenge = parseAuthorizationChallenge(rawChallenge(wallet.address), request, expected, now);
    const sellerProof = {
      version: 1,
      authorizationId: sellerChallenge.message.authorizationId,
      typedDataHash: hashAuthorizationChallenge(sellerChallenge),
      signer: wallet.address,
      signature: await wallet.signTypedData(AUTHORIZATION_DOMAIN, signingTypes, sellerChallenge.message),
    };
    const buyerExpected: AuthorizationExpectedContext = {
      ...expected,
      subjectRole: 'BUYER',
    };
    const buyerRequest = createAuthorizationChallengeRequest(
      500_000_000n,
      20_000n,
      1n,
      12_345_678_901_234_567_890n,
      buyerExpected,
      request.authorizationSalt,
    );
    const buyerChallenge = parseAuthorizationChallenge(
      rawChallenge(wallet.address, buyerRequest),
      buyerRequest,
      buyerExpected,
      now,
    );

    expect(() => validateAuthorizationProof(sellerProof, buyerChallenge, now)).toThrow(
      'wallet authorization response',
    );
  });

  it('POSTs the exact request to the loopback challenge endpoint and validates the response', async () => {
    vi.spyOn(Date, 'now').mockReturnValue(Number(now * 1_000n));
    const wallet = Wallet.createRandom();
    const responseBody = rawChallenge(wallet.address);
    const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(JSON.stringify(responseBody), { status: 201 }),
    );

    const challenge = await api.fetchAuthorizationChallenge('http://localhost:4000', request, expected);

    expect(challenge.message.partyWallet).toBe(wallet.address.toLowerCase());
    expect(fetchMock).toHaveBeenCalledOnce();
    const [endpoint, options] = fetchMock.mock.calls[0];
    expect(String(endpoint)).toBe('http://localhost:4000/authorization-challenges');
    expect(options?.redirect).toBe('error');
    expect(options?.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.parse(String(options?.body))).toEqual(request);
  });

  it('bounds and times out the challenge response without echoing its body or transport error', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
      new Response('x'.repeat(api.MAX_ATTESTATION_RESPONSE_BYTES + 1), { status: 201 }),
    );
    await expect(
      api.fetchAuthorizationChallenge('http://localhost:4000', request, expected),
    ).rejects.toThrow(`exceeds ${api.MAX_ATTESTATION_RESPONSE_BYTES} bytes`);

    const marker = 'challenge-transport-secret';
    const controller = new AbortController();
    vi.spyOn(AbortSignal, 'timeout').mockReturnValue(controller.signal);
    vi.spyOn(globalThis, 'fetch').mockImplementationOnce(
      async (_input, init) => await new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error(marker)), { once: true });
      }),
    );
    const pending = api.fetchAuthorizationChallenge('http://localhost:4000', request, expected);
    const assertion = expect(pending).rejects.toThrow('Mock Attestation API request timed out.');
    controller.abort();
    await assertion;
    await expect(pending).rejects.not.toThrow(marker);
  });
});
