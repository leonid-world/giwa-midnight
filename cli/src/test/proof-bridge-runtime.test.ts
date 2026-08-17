// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import type { AuthorizationChallenge, AuthorizationProof } from '../authorization.js';
import type { ProofCapability } from '../api.js';
import { ProofBridgeRuntime } from '../proof-bridge/runtime.js';
import { ProofSessionStore } from '../proof-bridge/session-store.js';

const SESSION_ID = `0x${'1'.repeat(64)}`;
const PARTY = `0x${'2'.repeat(40)}`;
const challenge = {
  version: 1,
  domain: { name: 'GASOK Mock Attestation', version: '1', chainId: '91342' },
  primaryType: 'GASOKRoleAttestationAuthorization',
  types: { GASOKRoleAttestationAuthorization: [] },
  message: {
    purpose: 'Authorize GASOK local mock financial attestation',
    authorizationId: `0x${'3'.repeat(64)}`,
    midnightContractAddress: `0x${'4'.repeat(64)}`,
    receivableFinanceAddress: `0x${'5'.repeat(40)}`,
    onchainReceivableId: '1',
    subjectRole: 'SELLER',
    partyWallet: PARTY,
    attestationRequestCommitment: `0x${'6'.repeat(64)}`,
    providerId: '2',
    policyVersion: '1',
    issuedAt: '1000',
    expiresAt: '1002',
  },
} as AuthorizationChallenge;
const authorization = {
  version: 1,
  authorizationId: challenge.message.authorizationId,
  typedDataHash: `0x${'7'.repeat(64)}`,
  signer: PARTY,
  signature: `0x${'8'.repeat(130)}`,
} as AuthorizationProof;
const capability: ProofCapability = {
  version: 1,
  midnightContractAddress: '4'.repeat(64),
  companyCommitment: `0x${'9'.repeat(64)}`,
  lookupKey: `0x${'a'.repeat(64)}`,
  giwaChainId: '91342',
  receivableFinanceAddress: `0x${'5'.repeat(40)}`,
  onchainReceivableId: '1',
  subjectRole: 'SELLER',
  partyWallet: PARTY,
};
const input = {
  onchainReceivableId: 1n,
  subjectRole: 'SELLER' as const,
  annualRevenueKrw: 500_000_000n,
  debtRatioBps: 20_000n,
  overdueCount: 1n,
  secretPin: 1234n,
};

const flush = async () => {
  await new Promise((resolve) => setTimeout(resolve, 0));
};

describe('ProofBridgeRuntime', () => {
  it('returns the capability as soon as the Midnight transaction finalizes', async () => {
    const complete = vi.fn(async (_prepared, _authorization, onStage) => {
      onStage('attesting');
      onStage('proving_and_submitting');
      return capability;
    });
    const sessions = new ProofSessionStore<{ marker: string }>({
      now: () => 1_000_000,
      createSessionId: () => SESSION_ID,
    });
    const runtime = new ProofBridgeRuntime({
      sessions,
      operations: {
        prepare: async () => ({ prepared: { marker: 'private' }, authorizationRequest: challenge }),
        complete,
      },
    });

    await expect(runtime.createChallenge(input)).resolves.toEqual({
      version: 1,
      sessionId: SESSION_ID,
      expiresAt: '1002',
      authorizationRequest: challenge,
    });
    expect(runtime.startProof(SESSION_ID, authorization).status).toBe('attesting');
    expect(() => runtime.startProof(SESSION_ID, authorization)).toThrow(/cannot be replayed/);
    await flush();
    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 1,
      sessionId: SESSION_ID,
      status: 'complete',
      proofCapability: capability,
    });
    await runtime.shutdown();
  });

  it('does not reflect an operation exception into the public failure response', async () => {
    const runtime = new ProofBridgeRuntime({
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async () => {
          throw new Error('secretPin=1234 annualRevenue=500000000');
        },
      },
    });
    await runtime.createChallenge(input);
    runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 1,
      sessionId: SESSION_ID,
      status: 'failed',
      error: {
        code: 'PROOF_FAILED',
        message: 'The local mock-attested Midnight proof could not be completed.',
      },
    });
    await runtime.shutdown();
  });

  it('keeps submission one-shot while finalization is pending and never waits for Indexer confirmation', async () => {
    let releaseFinalization: (() => void) | undefined;
    const finalization = new Promise<void>((resolve) => {
      releaseFinalization = resolve;
    });
    const complete = vi.fn(async (_prepared, _authorization, onStage) => {
      onStage('attesting');
      onStage('proving_and_submitting');
      await finalization;
      return capability;
    });
    const runtime = new ProofBridgeRuntime({
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete,
      },
    });

    await runtime.createChallenge(input);
    runtime.startProof(SESSION_ID, authorization);
    await flush();
    expect(runtime.getStatus(SESSION_ID).status).toBe('proving_and_submitting');
    expect(() => runtime.startProof(SESSION_ID, authorization)).toThrow(/cannot be replayed/);

    releaseFinalization?.();
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 1,
      sessionId: SESSION_ID,
      status: 'complete',
      proofCapability: capability,
    });
    expect(complete).toHaveBeenCalledOnce();
    expect(() => runtime.startProof(SESSION_ID, authorization)).toThrow(/cannot be replayed/);
    await runtime.shutdown();
  });
});
