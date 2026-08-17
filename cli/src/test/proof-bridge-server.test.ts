// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import * as http from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AuthorizationChallenge } from '../authorization.js';
import type { ProofBridgeController } from '../proof-bridge/runtime.js';
import { createProofBridgeServer } from '../proof-bridge/server.js';

const SESSION_ID = `0x${'1'.repeat(64)}`;
const challenge = {
  version: 1,
  domain: { name: 'GASOK Mock Attestation', version: '1', chainId: '91342' },
  primaryType: 'GASOKRoleAttestationAuthorization',
  types: { GASOKRoleAttestationAuthorization: [] },
  message: {
    purpose: 'Authorize GASOK local mock financial attestation',
    authorizationId: `0x${'2'.repeat(64)}`,
    midnightContractAddress: `0x${'3'.repeat(64)}`,
    receivableFinanceAddress: `0x${'4'.repeat(40)}`,
    onchainReceivableId: '1',
    subjectRole: 'SELLER',
    partyWallet: `0x${'5'.repeat(40)}`,
    attestationRequestCommitment: `0x${'6'.repeat(64)}`,
    providerId: '2',
    policyVersion: '1',
    issuedAt: '1000',
    expiresAt: '1002',
  },
} as AuthorizationChallenge;

const challengeBody = {
  version: 1,
  onchainReceivableId: '1',
  subjectRole: 'SELLER',
  annualRevenueKrw: '500000000',
  debtRatioBps: '20000',
  overdueCount: '1',
  secretPin: '1234',
};
const authorization = {
  version: 1,
  authorizationId: challenge.message.authorizationId,
  typedDataHash: `0x${'7'.repeat(64)}`,
  signer: challenge.message.partyWallet,
  signature: `0x${'8'.repeat(130)}`,
};

const servers: http.Server[] = [];

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map(
      (server) =>
        new Promise<void>((resolve) => {
          if (!server.listening) {
            resolve();
            return;
          }
          server.closeAllConnections();
          server.close(() => resolve());
        }),
    ),
  );
});

async function startServer(controllerOverrides: Partial<ProofBridgeController> = {}) {
  const controller: ProofBridgeController = {
    createChallenge: vi.fn(async () => ({
      version: 1 as const,
      sessionId: SESSION_ID,
      expiresAt: '1002',
      authorizationRequest: challenge,
    })),
    startProof: vi.fn(() => ({ version: 1 as const, sessionId: SESSION_ID, status: 'attesting' as const })),
    getStatus: vi.fn(() => ({
      version: 1 as const,
      sessionId: SESSION_ID,
      status: 'awaiting_authorization' as const,
    })),
    cancel: vi.fn(() => ({ version: 1 as const, sessionId: SESSION_ID, status: 'cancelled' as const })),
    ...controllerOverrides,
  };
  const allowedHosts = new Set<string>();
  const server = createProofBridgeServer({
    controller,
    allowedOrigins: new Set(['http://127.0.0.1:5173']),
    allowedHosts,
  });
  servers.push(server);
  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error) => reject(error);
    server.once('error', onError);
    server.listen(0, '127.0.0.1', () => {
      server.off('error', onError);
      resolve();
    });
  });
  const address = server.address();
  if (address === null || typeof address === 'string') {
    throw new Error('Test server did not bind to a TCP port.');
  }
  const host = `127.0.0.1:${address.port}`;
  allowedHosts.add(host);
  return { controller, origin: `http://${host}` };
}

function protectedHeaders(): Record<string, string> {
  return {
    'Content-Type': 'application/json',
    Origin: 'http://127.0.0.1:5173',
    'Sec-Fetch-Site': 'same-origin',
    'X-GASOK-MIDNIGHT-UI': '1',
  };
}

describe('Proof Bridge HTTP boundary', () => {
  it('accepts an exact challenge request and returns no-store security headers without CORS', async () => {
    const { controller, origin } = await startServer();
    const response = await fetch(`${origin}/v1/proof-sessions/challenge`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify(challengeBody),
    });

    expect(response.status).toBe(201);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('pragma')).toBe('no-cache');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    expect(response.headers.get('referrer-policy')).toBe('no-referrer');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(await response.json()).toEqual({
      version: 1,
      sessionId: SESSION_ID,
      expiresAt: '1002',
      authorizationRequest: challenge,
    });
    expect(controller.createChallenge).toHaveBeenCalledWith({
      onchainReceivableId: 1n,
      subjectRole: 'SELLER',
      annualRevenueKrw: 500_000_000n,
      debtRatioBps: 20_000n,
      overdueCount: 1n,
      secretPin: 1234n,
    });
  });

  it.each([
    ['missing UI header', { ...protectedHeaders(), 'X-GASOK-MIDNIGHT-UI': '' }, 403],
    ['foreign origin', { ...protectedHeaders(), Origin: 'https://example.com' }, 403],
    ['cross-site context', { ...protectedHeaders(), 'Sec-Fetch-Site': 'cross-site' }, 403],
    ['wrong content type', { ...protectedHeaders(), 'Content-Type': 'text/plain' }, 415],
    ['compressed body', { ...protectedHeaders(), 'Content-Encoding': 'gzip' }, 415],
  ])('rejects %s', async (_label, headers, expectedStatus) => {
    const { origin } = await startServer();
    const response = await fetch(`${origin}/v1/proof-sessions/challenge`, {
      method: 'POST',
      headers,
      body: JSON.stringify(challengeBody),
    });
    expect(response.status).toBe(expectedStatus);
  });

  it('rejects a forged Host header', async () => {
    const { origin } = await startServer();
    const endpoint = new URL('/v1/proof-sessions/challenge', origin);
    const body = JSON.stringify(challengeBody);
    const status = await new Promise<number>((resolve, reject) => {
      const request = http.request(
        {
          hostname: endpoint.hostname,
          port: endpoint.port,
          path: endpoint.pathname,
          method: 'POST',
          headers: {
            ...protectedHeaders(),
            Host: 'evil.example',
            'Content-Length': Buffer.byteLength(body),
          },
        },
        (response) => {
          response.resume();
          response.on('end', () => resolve(response.statusCode ?? 0));
        },
      );
      request.on('error', reject);
      request.end(body);
    });
    expect(status).toBe(403);
  });

  it('rejects extra fields, query strings, wrong methods, and oversized bodies', async () => {
    const { origin } = await startServer();
    const extra = await fetch(`${origin}/v1/proof-sessions/challenge`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ ...challengeBody, unexpected: true }),
    });
    expect(extra.status).toBe(400);

    const query = await fetch(`${origin}/v1/proof-sessions/status?sessionId=${SESSION_ID}`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ version: 1, sessionId: SESSION_ID }),
    });
    expect(query.status).toBe(404);

    const method = await fetch(`${origin}/v1/proof-sessions/status`, {
      method: 'GET',
      headers: protectedHeaders(),
    });
    expect(method.status).toBe(405);

    const oversized = await fetch(`${origin}/v1/proof-sessions/challenge`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ data: 'x'.repeat(4_096) }),
    });
    expect(oversized.status).toBe(413);
  });

  it('does not reflect controller errors that may contain financial values', async () => {
    const { origin } = await startServer({
      createChallenge: async () => {
        throw new Error('annualRevenueKrw=500000000 secretPin=1234');
      },
    });
    const response = await fetch(`${origin}/v1/proof-sessions/challenge`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify(challengeBody),
    });
    const text = await response.text();

    expect(response.status).toBe(502);
    expect(text).toContain('PROOF_BRIDGE_UNAVAILABLE');
    expect(text).not.toContain('500000000');
    expect(text).not.toContain('1234');
  });

  it('accepts only exact prove, status, and cancel schemas', async () => {
    const { controller, origin } = await startServer();
    const prove = await fetch(`${origin}/v1/proof-sessions/prove`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ version: 1, sessionId: SESSION_ID, authorization }),
    });
    expect(prove.status).toBe(202);
    expect(await prove.json()).toEqual({ version: 1, sessionId: SESSION_ID, status: 'attesting' });
    expect(controller.startProof).toHaveBeenCalledWith(SESSION_ID, authorization);

    const status = await fetch(`${origin}/v1/proof-sessions/status`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ version: 1, sessionId: SESSION_ID }),
    });
    expect(status.status).toBe(200);
    expect(controller.getStatus).toHaveBeenCalledWith(SESSION_ID);

    const cancel = await fetch(`${origin}/v1/proof-sessions/cancel`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ version: 1, sessionId: SESSION_ID }),
    });
    expect(cancel.status).toBe(200);
    expect(await cancel.json()).toEqual({ version: 1, sessionId: SESSION_ID, status: 'cancelled' });
    expect(controller.cancel).toHaveBeenCalledWith(SESSION_ID);

    const malformedSession = await fetch(`${origin}/v1/proof-sessions/status`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ version: 1, sessionId: `0x${'A'.repeat(64)}` }),
    });
    expect(malformedSession.status).toBe(400);

    const extraAuthorizationKey = await fetch(`${origin}/v1/proof-sessions/prove`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({
        version: 1,
        sessionId: SESSION_ID,
        authorization: { ...authorization, privateKey: 'must-never-be-accepted' },
      }),
    });
    expect(extraAuthorizationKey.status).toBe(400);

    const extraSessionKey = await fetch(`${origin}/v1/proof-sessions/cancel`, {
      method: 'POST',
      headers: protectedHeaders(),
      body: JSON.stringify({ version: 1, sessionId: SESSION_ID, retry: true }),
    });
    expect(extraSessionKey.status).toBe(400);
  });
});
