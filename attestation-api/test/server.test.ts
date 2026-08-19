import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { TypedDataEncoder, Wallet } from 'ethers';
import {
  AUTHORIZATION_PROTOCOL,
  AUTHORIZATION_TTL_SECONDS,
  AuthorizationChallengeStore,
  PROVIDER_ID,
} from '../src/authorization.js';
import {
  HEADERS_TIMEOUT_MS,
  MAX_ATTESTATION_BODY_BYTES,
  REQUEST_TIMEOUT_MS,
  createServer,
} from '../src/server.js';
import { JUBJUB_ORDER, generateKeyPair } from '../src/signing.js';
import { DEFAULT_APPROVED_MIDNIGHT_CONTRACT_ADDRESS } from '../src/context.js';
import {
  GiwaReceivableNotFoundError,
  GiwaRpcError,
  type GiwaReceivableResolver,
} from '../src/giwa.js';
import type {
  AuthorizationChallengeRequest,
  AuthorizationChallengeResponse,
  AuthorizationProof,
} from '../src/types.js';
import type restify from 'restify';

setNetworkId('undeployed');

const sellerWallet = new Wallet('0x59c6995e998f97a5a0044966f0945389dc9e86dae88c7a8412f4603b6b78690d');
const buyerWallet = new Wallet('0x8b3a350cf5c34c9194ca3a545dbe4035957f353df9e4cb8a3173f8a2f1a7e682');
const replacementWallet = new Wallet('0x0dbbe8f54b5f35db3d10c3a87a55b7b750be7f78f50f4e83478b07a65d6e1b29');

describe('Attestation API EIP-712 issuance gate', () => {
  let server: restify.Server;
  let baseUrl: string;
  const { sk, pk } = generateKeyPair();
  const midnightContractAddress = DEFAULT_APPROVED_MIDNIGHT_CONTRACT_ADDRESS;
  let seller = sellerWallet.address.toLowerCase();
  let buyer = buyerWallet.address.toLowerCase();
  const resolveReceivable = vi.fn(async (receivableId: bigint) => {
    if (receivableId === 404n) {
      throw new GiwaReceivableNotFoundError();
    }
    if (receivableId === 503n) {
      throw new GiwaRpcError('test RPC failure details must not leak');
    }
    return { id: receivableId, seller, buyer };
  });
  const resolver: GiwaReceivableResolver = { resolve: resolveReceivable };

  const validRequest: AuthorizationChallengeRequest = {
    version: 2,
    annualRevenueKrw: '500000000',
    debtRatioBps: '20000',
    overdueCount: '1',
    companyCommitmentHash: '12345678901234567890',
    authorizationSalt: `0x${'aa'.repeat(32)}`,
    midnightContractAddress,
    onchainReceivableId: '7',
    subjectRole: 'SELLER',
    policyRequest: {
      requestId: `0x${'33'.repeat(32)}`,
      intendedFunderWallet: '0x4444444444444444444444444444444444444444',
      minAnnualRevenueKrw: '500000000',
      maxDebtRatioBps: '20000',
      maxOverdueCount: '1',
      validUntil: '4000000000',
    },
  };

  beforeAll(async () => {
    server = createServer(sk, {
      receivableResolver: resolver,
      approvedMidnightContractAddress: midnightContractAddress,
    });
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const address = server.address();
        const port = typeof address === 'string' ? address : address?.port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  beforeEach(() => {
    seller = sellerWallet.address.toLowerCase();
    buyer = buyerWallet.address.toLowerCase();
    resolveReceivable.mockClear();
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  async function post(path: string, body: unknown, headers = { 'Content-Type': 'application/json' }): Promise<Response> {
    return fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers,
      body: JSON.stringify(body),
    });
  }

  async function issueChallenge(
    overrides: Partial<AuthorizationChallengeRequest> = {},
  ): Promise<AuthorizationChallengeResponse> {
    const response = await post('/authorization-challenges', { ...validRequest, ...overrides });
    expect(response.status).toBe(201);
    return response.json() as Promise<AuthorizationChallengeResponse>;
  }

  async function signChallenge(
    challenge: AuthorizationChallengeResponse,
    signer: Wallet,
    overrides: Partial<AuthorizationProof> = {},
  ): Promise<AuthorizationProof> {
    const signature = await signer.signTypedData(challenge.domain, challenge.types, challenge.message);
    return {
      version: 2,
      authorizationId: challenge.message.authorizationId,
      typedDataHash: TypedDataEncoder.hash(challenge.domain, challenge.types, challenge.message),
      signer: signer.address,
      signature,
      ...overrides,
    };
  }

  async function attest(
    challenge: AuthorizationChallengeResponse,
    signer: Wallet = sellerWallet,
    requestOverrides: Partial<AuthorizationChallengeRequest> = {},
    proofOverrides: Partial<AuthorizationProof> = {},
  ): Promise<Response> {
    return post('/attest', {
      ...validRequest,
      ...requestOverrides,
      authorization: await signChallenge(challenge, signer, proofOverrides),
    });
  }

  it('advertises fixed Provider 2 and the EIP-712 protocol', async () => {
    for (const path of ['/health', '/provider-info']) {
      const response = await fetch(`${baseUrl}${path}`);
      expect(response.status).toBe(200);
      expect(response.headers.get('cache-control')).toBe('no-store');
      expect(response.headers.get('access-control-allow-origin')).toBeNull();
      const body = await response.json();
      expect(body.providerId).toBe(PROVIDER_ID);
      expect(body.authorizationProtocol).toBe(AUTHORIZATION_PROTOCOL);
      expect(body.approvedMidnightContractAddress).toBe(midnightContractAddress);
      expect(body.attestationType).toBe('mock');
      if (path === '/provider-info') {
        expect(body.publicKey).toEqual({ x: pk.x.toString(), y: pk.y.toString() });
      }
    }
  });

  it('configures bounded request, header, and keep-alive timeouts', () => {
    const nodeServer = (server as unknown as {
      server: { requestTimeout: number; headersTimeout: number; keepAliveTimeout: number };
    }).server;
    expect(nodeServer.requestTimeout).toBe(REQUEST_TIMEOUT_MS);
    expect(nodeServer.headersTimeout).toBe(HEADERS_TIMEOUT_MS);
    expect(nodeServer.keepAliveTimeout).toBe(HEADERS_TIMEOUT_MS);
  });

  it.each([0n, JUBJUB_ORDER])('rejects invalid provider secret key %s', (invalidKey) => {
    expect(() => createServer(invalidKey, {
      receivableResolver: resolver,
      approvedMidnightContractAddress: midnightContractAddress,
    })).toThrow('Provider secret key must be between 1 and the Jubjub order minus 1');
  });

  it('returns the exact challenge wire schema without raw values or salt', async () => {
    const before = Math.floor(Date.now() / 1_000);
    const response = await post('/authorization-challenges', validRequest);
    const after = Math.floor(Date.now() / 1_000);
    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json() as AuthorizationChallengeResponse;

    expect(Object.keys(body)).toEqual(['version', 'domain', 'primaryType', 'types', 'message']);
    expect(body.version).toBe(2);
    expect(body.domain).toEqual({ name: 'GASOK Mock Attestation', version: '2', chainId: '91342' });
    expect(body.primaryType).toBe('GASOKRoleAttestationAuthorization');
    expect(Object.keys(body.types)).toEqual(['GASOKRoleAttestationAuthorization']);
    expect(body.message.providerId).toBe('2');
    expect(body.message.evaluationVersion).toBe('2');
    expect(body.message.requestId).toBe(validRequest.policyRequest.requestId);
    expect(body.message.intendedFunderWallet).toBe(validRequest.policyRequest.intendedFunderWallet);
    expect(body.message.policyValidUntil).toBe(validRequest.policyRequest.validUntil);
    expect(body.message.partyWallet).toBe(seller);
    expect(Number(body.message.issuedAt)).toBeGreaterThanOrEqual(before);
    expect(Number(body.message.issuedAt)).toBeLessThanOrEqual(after);
    expect(BigInt(body.message.expiresAt) - BigInt(body.message.issuedAt)).toBe(BigInt(AUTHORIZATION_TTL_SECONDS));
    expect(body.message.authorizationId).toMatch(/^0x[0-9a-f]{64}$/);
    expect(body.message.attestationRequestCommitment).toMatch(/^0x[0-9a-f]{64}$/);
    expect(body.message.midnightContractAddress).toBe(`0x${midnightContractAddress}`);

    const serialized = JSON.stringify(body);
    for (const hidden of [
      'annualRevenueKrw',
      'debtRatioBps',
      'overdueCount',
      'companyCommitmentHash',
      'authorizationSalt',
      '12345678901234567890',
      'aa'.repeat(32),
    ]) {
      expect(serialized).not.toContain(hidden);
    }
  });

  it.each([
    ['SELLER', sellerWallet] as const,
    ['BUYER', buyerWallet] as const,
  ])('authorizes and attests the canonical %s wallet', async (subjectRole, roleWallet) => {
    const challenge = await issueChallenge({ subjectRole });
    const response = await attest(challenge, roleWallet, { subjectRole });
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.providerId).toBe(2);
    expect(body.evaluationVersion).toBe(2);
    expect(body.policyRequestHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(body.profileAsOf).toBe(challenge.message.profileAsOf);
    expect(body.validUntil).toBe(validRequest.policyRequest.validUntil);
    expect(body.authorizationProtocol).toBe(AUTHORIZATION_PROTOCOL);
    expect(body.binding).toEqual({
      giwaChainId: '91342',
      receivableFinanceAddress: '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315',
      onchainReceivableId: '7',
      subjectRole,
      partyWallet: roleWallet.address.toLowerCase(),
    });
    expect(body.signature.announcement.x).toMatch(/^\d+$/);
    expect(body.signature.announcement.y).toMatch(/^\d+$/);
    expect(body.signature.response).toMatch(/^\d+$/);

    const serialized = JSON.stringify(body);
    for (const hidden of [
      'annualRevenueKrw',
      'debtRatioBps',
      'overdueCount',
      'companyCommitmentHash',
      'authorizationSalt',
      'authorizationId',
      'typedDataHash',
    ]) {
      expect(serialized).not.toContain(hidden);
    }
  });

  it('clamps challenge expiry to the policy boundary and rejects an already-expired policy', async () => {
    let now = 1_000;
    const authorizationStore = new AuthorizationChallengeStore({ now: () => now });
    const boundaryServer = createServer(sk, {
      authorizationStore,
      receivableResolver: resolver,
      approvedMidnightContractAddress: midnightContractAddress,
    });
    let boundaryBaseUrl = '';
    await new Promise<void>((resolve) => {
      boundaryServer.listen(0, '127.0.0.1', () => {
        const address = boundaryServer.address();
        const port = typeof address === 'string' ? address : address?.port;
        boundaryBaseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });

    try {
      const issueAtBoundary = async (validUntil: string): Promise<Response> => fetch(
        `${boundaryBaseUrl}/authorization-challenges`,
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            ...validRequest,
            policyRequest: { ...validRequest.policyRequest, validUntil },
          }),
        },
      );

      for (const [validUntil, expectedExpiresAt, expectedTtl] of [
        ['2000', '1120', 120n],
        ['1119', '1119', 119n],
        ['1001', '1001', 1n],
      ] as const) {
        const response = await issueAtBoundary(validUntil);
        expect(response.status).toBe(201);
        const challenge = await response.json() as AuthorizationChallengeResponse;
        expect(challenge.message.expiresAt).toBe(expectedExpiresAt);
        expect(BigInt(challenge.message.expiresAt) - BigInt(challenge.message.issuedAt)).toBe(expectedTtl);
      }

      const expired = await issueAtBoundary('1000');
      expect(expired.status).toBe(409);
      expect(await expired.json()).toEqual({
        error: {
          code: 'POLICY_REQUEST_EXPIRED',
          message: 'The Funder policy request has expired.',
        },
      });
    } finally {
      await new Promise<void>((resolve) => boundaryServer.close(() => resolve()));
    }
  });

  it('preserves a uint256 maximum receivable ID', async () => {
    const onchainReceivableId = ((1n << 256n) - 1n).toString();
    const challenge = await issueChallenge({ onchainReceivableId });
    const response = await attest(challenge, sellerWallet, { onchainReceivableId });
    expect(response.status).toBe(200);
    expect((await response.json()).binding.onchainReceivableId).toBe(onchainReceivableId);
  });

  it('keeps a malformed signature generic and consumes its challenge', async () => {
    const challenge = await issueChallenge();
    const invalid = await attest(challenge, sellerWallet, {}, {
      signature: `0x${'00'.repeat(65)}`,
    });
    expect(invalid.status).toBe(401);
    expect(await invalid.json()).toEqual({
      error: {
        code: 'AUTHORIZATION_INVALID',
        message: 'The wallet authorization is invalid or no longer available.',
      },
    });

    const replay = await attest(challenge, sellerWallet);
    expect(replay.status).toBe(401);
    expect((await replay.json()).error.code).toBe('AUTHORIZATION_INVALID');
  });

  it('returns only a fixed 403 when a valid recoverable signer is not the canonical role wallet', async () => {
    const challenge = await issueChallenge();
    const wrongProof = await signChallenge(challenge, buyerWallet);
    const invalid = await post('/attest', {
      ...validRequest,
      authorization: wrongProof,
    });
    expect(invalid.status).toBe(403);
    const serialized = await invalid.text();
    expect(JSON.parse(serialized)).toEqual({
      error: {
        code: 'ROLE_WALLET_MISMATCH',
        message: 'The wallet authorization does not match the current GIWA role wallet.',
      },
    });
    expect(serialized).not.toContain(sellerWallet.address);
    expect(serialized).not.toContain(buyerWallet.address);
    expect(serialized).not.toContain(challenge.message.partyWallet);
    expect(serialized).not.toContain(wrongProof.signature);
    expect(serialized).not.toContain(wrongProof.authorizationId);

    const replay = await attest(challenge, sellerWallet);
    expect(replay.status).toBe(401);
    expect((await replay.json()).error.code).toBe('AUTHORIZATION_INVALID');
  });

  it.each([
    ['financial value', { annualRevenueKrw: '500000001' }],
    ['company commitment', { companyCommitmentHash: '999' }],
    ['authorization salt', { authorizationSalt: `0x${'bb'.repeat(32)}` }],
    ['Midnight deployment', { midnightContractAddress: 'bb'.repeat(32) }],
    ['receivable ID', { onchainReceivableId: '8' }],
    ['subject role', { subjectRole: 'BUYER' as const }],
    ['policy request ID', {
      policyRequest: { ...validRequest.policyRequest, requestId: `0x${'55'.repeat(32)}` },
    }],
    ['policy audience', {
      policyRequest: {
        ...validRequest.policyRequest,
        intendedFunderWallet: '0x6666666666666666666666666666666666666666',
      },
    }],
    ['policy threshold', {
      policyRequest: { ...validRequest.policyRequest, maxDebtRatioBps: '19999' },
    }],
    ['policy expiry', {
      policyRequest: { ...validRequest.policyRequest, validUntil: '4000000001' },
    }],
  ])('rejects and consumes a challenge when the %s changes', async (_label, overrides) => {
    const challenge = await issueChallenge();
    const response = await attest(challenge, sellerWallet, overrides);
    expect([400, 401]).toContain(response.status);

    const replay = await attest(challenge, sellerWallet);
    expect(replay.status).toBe(401);
  });

  it('keeps a bad typed-data hash generic but distinguishes a valid wrong declared signer', async () => {
    const hashChallenge = await issueChallenge();
    const badHash = await attest(hashChallenge, sellerWallet, {}, {
      typedDataHash: `0x${'ff'.repeat(32)}`,
    });
    expect(badHash.status).toBe(401);

    const signerChallenge = await issueChallenge();
    const badSigner = await attest(signerChallenge, sellerWallet, {}, {
      signer: buyerWallet.address,
    });
    expect(badSigner.status).toBe(403);
    expect(await badSigner.json()).toEqual({
      error: {
        code: 'ROLE_WALLET_MISMATCH',
        message: 'The wallet authorization does not match the current GIWA role wallet.',
      },
    });
  });

  it('re-resolves GIWA and rejects a role-wallet change after challenge issuance', async () => {
    const challenge = await issueChallenge();
    seller = replacementWallet.address.toLowerCase();
    const response = await attest(challenge, sellerWallet);
    expect(response.status).toBe(403);
    const serialized = await response.text();
    expect(JSON.parse(serialized)).toEqual({
      error: {
        code: 'ROLE_WALLET_MISMATCH',
        message: 'The wallet authorization does not match the current GIWA role wallet.',
      },
    });
    expect(serialized).not.toContain(sellerWallet.address);
    expect(serialized).not.toContain(replacementWallet.address);
    expect(resolveReceivable).toHaveBeenCalledTimes(2);
  });

  it('requires exact challenge, attestation, and authorization key sets', async () => {
    const extraChallenge = await post('/authorization-challenges', { ...validRequest, extra: true });
    expect(extraChallenge.status).toBe(400);
    expect(resolveReceivable).not.toHaveBeenCalled();

    const challengeForTopLevel = await issueChallenge();
    const proofForTopLevel = await signChallenge(challengeForTopLevel, sellerWallet);
    const extraTopLevel = await post('/attest', {
      ...validRequest,
      authorization: proofForTopLevel,
      extra: true,
    });
    expect(extraTopLevel.status).toBe(400);

    const challengeForProof = await issueChallenge();
    const proof = await signChallenge(challengeForProof, sellerWallet);
    const extraProof = await post('/attest', {
      ...validRequest,
      authorization: { ...proof, extra: true },
    });
    expect(extraProof.status).toBe(400);
  });

  it.each([
    ['zero ID', { onchainReceivableId: '0' }],
    ['negative ID', { onchainReceivableId: '-1' }],
    ['uint256 overflow', { onchainReceivableId: (1n << 256n).toString() }],
    ['invalid role', { subjectRole: 'FUNDER' as never }],
    ['invalid version', { version: 1 as never }],
    ['invalid salt', { authorizationSalt: '0x1234' }],
    ['zero salt', { authorizationSalt: `0x${'0'.repeat(64)}` }],
    ['numeric revenue', { annualRevenueKrw: 500000000 as never }],
  ])('rejects %s before GIWA lookup', async (_label, overrides) => {
    const response = await post('/authorization-challenges', { ...validRequest, ...overrides });
    expect(response.status).toBe(400);
    expect((await response.json()).error.code).toBe('INVALID_REQUEST');
    expect(resolveReceivable).not.toHaveBeenCalled();
  });

  it('rejects an unapproved deployment before GIWA lookup', async () => {
    const response = await post('/authorization-challenges', {
      ...validRequest,
      midnightContractAddress: 'bb'.repeat(32),
    });
    expect(response.status).toBe(400);
    expect((await response.json()).error.code).toBe('UNAPPROVED_MIDNIGHT_CONTRACT');
    expect(resolveReceivable).not.toHaveBeenCalled();
  });

  it('maps missing receivables and RPC failures to safe errors', async () => {
    const missing = await post('/authorization-challenges', {
      ...validRequest,
      onchainReceivableId: '404',
    });
    expect(missing.status).toBe(404);
    expect((await missing.json()).error.code).toBe('GIWA_RECEIVABLE_NOT_FOUND');

    const unavailable = await post('/authorization-challenges', {
      ...validRequest,
      onchainReceivableId: '503',
    });
    expect(unavailable.status).toBe(502);
    const serialized = JSON.stringify(await unavailable.json());
    expect(serialized).toContain('GIWA_RPC_UNAVAILABLE');
    expect(serialized).not.toContain('test RPC failure details');
  });

  it.each(['/authorization-challenges', '/attest'])('requires uncompressed JSON at %s', async (path) => {
    const contentType = await post(path, validRequest, { 'Content-Type': 'text/plain' });
    expect(contentType.status).toBe(415);
    expect((await contentType.json()).error.code).toBe('JSON_BODY_REQUIRED');

    const compressed = await fetch(`${baseUrl}${path}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Encoding': 'gzip',
      },
      body: JSON.stringify(validRequest),
    });
    expect(compressed.status).toBe(415);
    expect((await compressed.json()).error.code).toBe('UNSUPPORTED_CONTENT_ENCODING');
  });

  it('rejects oversized bodies before GIWA lookup', async () => {
    const response = await post('/authorization-challenges', {
      ...validRequest,
      padding: 'x'.repeat(MAX_ATTESTATION_BODY_BYTES),
    });
    expect(response.status).toBe(413);
    expect(await response.json()).toEqual({
      error: {
        code: 'PAYLOAD_TOO_LARGE',
        message: 'The request body is too large.',
      },
    });
    expect(resolveReceivable).not.toHaveBeenCalled();
  });

  it('returns a safe structured error for malformed JSON without reflecting the body', async () => {
    const response = await fetch(`${baseUrl}/authorization-challenges`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{"authorizationSalt":"must-not-be-reflected",',
    });
    expect(response.status).toBe(400);
    const serialized = await response.text();
    expect(JSON.parse(serialized)).toEqual({
      error: {
        code: 'INVALID_JSON',
        message: 'The JSON request body is invalid.',
      },
    });
    expect(serialized).not.toContain('must-not-be-reflected');
    expect(resolveReceivable).not.toHaveBeenCalled();
  });

  it('rejects the legacy direct /attest request without an authorization', async () => {
    const response = await post('/attest', validRequest);
    expect(response.status).toBe(400);
    expect((await response.json()).error.code).toBe('INVALID_REQUEST');
    expect(resolveReceivable).not.toHaveBeenCalled();
  });
});
