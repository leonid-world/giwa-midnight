// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it, vi } from 'vitest';
import type { AuthorizationChallenge, AuthorizationProof } from '../authorization.js';
import type { ProofCapability } from '../api.js';
import { ProofBridgeRuntime } from '../proof-bridge/runtime.js';
import { ProofSessionStore } from '../proof-bridge/session-store.js';
import {
  LocalAttestationApiError,
  type LocalAttestationErrorCode,
} from '../attestation-errors.js';
import {
  ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE,
  ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE,
  EligibilityResultAlreadyExistsError,
} from '../proof-errors.js';
import {
  CapabilityOutboxError,
  type ProofCapabilityOutbox,
} from '../proof-bridge/capability-outbox.js';

const SESSION_ID = `0x${'1'.repeat(64)}`;
const PARTY = `0x${'2'.repeat(40)}`;
const challenge = {
  version: 2,
  domain: { name: 'GASOK Mock Attestation', version: '2', chainId: '91342' },
  primaryType: 'GASOKRoleAttestationAuthorization',
  types: { GASOKRoleAttestationAuthorization: [] },
  message: {
    purpose: 'Authorize GASOK local mock financial attestation for a Funder policy request',
    authorizationId: `0x${'3'.repeat(64)}`,
    midnightContractAddress: `0x${'4'.repeat(64)}`,
    receivableFinanceAddress: `0x${'5'.repeat(40)}`,
    onchainReceivableId: '1',
    subjectRole: 'SELLER',
    partyWallet: PARTY,
    requestId: `0x${'b'.repeat(64)}`,
    intendedFunderWallet: `0x${'c'.repeat(40)}`,
    minAnnualRevenueKrw: '500000000',
    maxDebtRatioBps: '20000',
    maxOverdueCount: '1',
    attestationRequestCommitment: `0x${'6'.repeat(64)}`,
    providerId: '2',
    evaluationVersion: '2',
    profileAsOf: '1000',
    policyValidUntil: '2000',
    issuedAt: '1000',
    expiresAt: '1002',
  },
} as unknown as AuthorizationChallenge;
const authorization = {
  version: 2,
  authorizationId: challenge.message.authorizationId,
  typedDataHash: `0x${'7'.repeat(64)}`,
  signer: PARTY,
  signature: `0x${'8'.repeat(130)}`,
} as AuthorizationProof;
const capability: ProofCapability = {
  version: 2,
  evaluationVersion: 2,
  midnightContractAddress: '4'.repeat(64),
  companyCommitment: `0x${'9'.repeat(64)}`,
  lookupKey: `0x${'a'.repeat(64)}`,
  giwaChainId: '91342',
  receivableFinanceAddress: `0x${'5'.repeat(40)}`,
  onchainReceivableId: '1',
  subjectRole: 'SELLER',
  partyWallet: PARTY,
  requestId: `0x${'b'.repeat(64)}`,
  intendedFunderWallet: `0x${'c'.repeat(40)}`,
  minAnnualRevenueKrw: '500000000',
  maxDebtRatioBps: '20000',
  maxOverdueCount: '1',
  policyRequestHash: `0x${'d'.repeat(64)}`,
  profileAsOf: '1000',
  validUntil: '2000',
};
const input = {
  onchainReceivableId: 1n,
  subjectRole: 'SELLER' as const,
  annualRevenueKrw: 500_000_000n,
  debtRatioBps: 20_000n,
  overdueCount: 1n,
  policyRequest: {
    requestId: `0x${'b'.repeat(64)}`,
    intendedFunderWallet: `0x${'c'.repeat(40)}`,
    minAnnualRevenueKrw: 500000000n,
    maxDebtRatioBps: 20000n,
    maxOverdueCount: 1n,
    validUntil: 2000n,
  },
};

const flush = async () => {
  await new Promise((resolve) => setTimeout(resolve, 0));
};

function memoryOutbox(overrides: Partial<ProofCapabilityOutbox> = {}): ProofCapabilityOutbox {
  let stored: { sessionId: string; capability: ProofCapability } | null = null;
  return {
    assertRequestAvailable: vi.fn(),
    reserve: vi.fn(async () => undefined),
    markProving: vi.fn(async () => undefined),
    releaseAwaiting: vi.fn(async () => undefined),
    persist: vi.fn(async (sessionId, proofCapability) => {
      stored = { sessionId, capability: proofCapability };
    }),
    recoverByRequest: vi.fn((requestId) => {
      if (stored === null || stored.capability.requestId !== requestId) throw new Error('not found');
      return { version: 2 as const, sessionId: stored.sessionId, status: 'complete' as const, proofCapability: stored.capability };
    }),
    recoverBySession: vi.fn((sessionId) => {
      if (stored === null || stored.sessionId !== sessionId) throw new Error('not found');
      return { version: 2 as const, sessionId: stored.sessionId, status: 'complete' as const, proofCapability: stored.capability };
    }),
    acknowledge: vi.fn(async (sessionId, requestId) => {
      const current = stored;
      if (current !== null && current.sessionId === sessionId && current.capability.requestId === requestId) {
        stored = null;
      }
    }),
    close: vi.fn(),
    ...overrides,
  };
}

describe('ProofBridgeRuntime', () => {
  it('returns the capability as soon as the Midnight transaction finalizes', async () => {
    const complete = vi.fn(async (_prepared, _authorization, onStage) => {
      await onStage('attesting');
      await onStage('proving_and_submitting');
      return capability;
    });
    const sessions = new ProofSessionStore<{ marker: string }>({
      now: () => 1_000_000,
      createSessionId: () => SESSION_ID,
    });
    const runtime = new ProofBridgeRuntime({
      outbox: memoryOutbox(),
      sessions,
      operations: {
        prepare: async () => ({ prepared: { marker: 'private' }, authorizationRequest: challenge }),
        complete,
      },
    });

    await expect(runtime.createChallenge(input)).resolves.toEqual({
      version: 2,
      sessionId: SESSION_ID,
      expiresAt: '1002',
      authorizationRequest: challenge,
    });
    expect((await runtime.startProof(SESSION_ID, authorization)).status).toBe('attesting');
    await expect(runtime.startProof(SESSION_ID, authorization)).rejects.toThrow(/cannot be replayed/);
    await flush();
    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'complete',
      proofCapability: capability,
    });
    await runtime.shutdown();
  });

  it('does not reflect an operation exception into the public failure response', async () => {
    const warn = vi.fn();
    const runtime = new ProofBridgeRuntime({
      outbox: memoryOutbox(),
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      logger: { info: vi.fn(), warn },
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async () => {
          throw new Error('secretPin=1234 annualRevenue=500000000');
        },
      },
    });
    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'failed',
      error: {
        code: 'PROOF_FAILED',
        message: 'The local mock-attested Midnight proof could not be completed.',
      },
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn).toHaveBeenCalledWith({ code: 'PROOF_FAILED' }, 'A local GASOK Midnight proof session failed.');
    expect(JSON.stringify(warn.mock.calls)).not.toContain('secretPin');
    expect(JSON.stringify(warn.mock.calls)).not.toContain('annualRevenue');
    await runtime.shutdown();
  });

  it('preserves the fixed duplicate-result code and message without logging the original error', async () => {
    const warn = vi.fn();
    const runtime = new ProofBridgeRuntime({
      outbox: memoryOutbox(),
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      logger: { info: vi.fn(), warn },
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async () => {
          throw new EligibilityResultAlreadyExistsError();
        },
      },
    });
    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'failed',
      error: {
        code: ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE,
        message: ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE,
      },
    });
    expect(warn).toHaveBeenCalledOnce();
    expect(warn).toHaveBeenCalledWith(
      { code: ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE },
      'A local GASOK Midnight proof session failed.',
    );
    await runtime.shutdown();
  });

  it.each([
    'GIWA_RECEIVABLE_NOT_FOUND',
    'GIWA_RPC_UNAVAILABLE',
    'POLICY_REQUEST_EXPIRED',
    'ROLE_WALLET_MISMATCH',
  ] as const)('preserves the safe %s Provider failure in session status', async (code: LocalAttestationErrorCode) => {
    const typedError = new LocalAttestationApiError(code);
    const warn = vi.fn();
    const runtime = new ProofBridgeRuntime({
      outbox: memoryOutbox(),
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      logger: { info: vi.fn(), warn },
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async () => {
          throw typedError;
        },
      },
    });
    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'failed',
      error: { code, message: typedError.publicMessage },
    });
    expect(warn).toHaveBeenCalledWith({ code }, 'A local GASOK Midnight proof session failed.');
    await runtime.shutdown();
  });

  it('keeps submission one-shot while finalization is pending and never waits for Indexer confirmation', async () => {
    let releaseFinalization: (() => void) | undefined;
    const finalization = new Promise<void>((resolve) => {
      releaseFinalization = resolve;
    });
    const complete = vi.fn(async (_prepared, _authorization, onStage) => {
      await onStage('attesting');
      await onStage('proving_and_submitting');
      await finalization;
      return capability;
    });
    const runtime = new ProofBridgeRuntime({
      outbox: memoryOutbox(),
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete,
      },
    });

    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();
    expect(runtime.getStatus(SESSION_ID).status).toBe('proving_and_submitting');
    await expect(runtime.startProof(SESSION_ID, authorization)).rejects.toThrow(/cannot be replayed/);

    releaseFinalization?.();
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'complete',
      proofCapability: capability,
    });
    expect(complete).toHaveBeenCalledOnce();
    await expect(runtime.startProof(SESSION_ID, authorization)).rejects.toThrow(/cannot be replayed/);
    await runtime.shutdown();
  });

  it('does not expose complete until encrypted outbox persistence succeeds', async () => {
    let releasePersistence: (() => void) | undefined;
    const persistence = new Promise<void>((resolve) => {
      releasePersistence = resolve;
    });
    const outbox = memoryOutbox({ persist: vi.fn(async () => await persistence) });
    const runtime = new ProofBridgeRuntime({
      outbox,
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async (_prepared, _authorization, onStage) => {
          await onStage('attesting');
          await onStage('proving_and_submitting');
          return capability;
        },
      },
    });
    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.getStatus(SESSION_ID).status).toBe('proving_and_submitting');
    releasePersistence?.();
    await flush();
    expect(runtime.getStatus(SESSION_ID).status).toBe('complete');
    await runtime.shutdown();
  });

  it('recovers restart status from the durable outbox and removes RAM capability after ACK', async () => {
    const outbox = memoryOutbox();
    const runtime = new ProofBridgeRuntime({
      outbox,
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async (_prepared, _authorization, onStage) => {
          await onStage('attesting');
          await onStage('proving_and_submitting');
          return capability;
        },
      },
    });
    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.recover(capability.requestId).proofCapability).toEqual(capability);
    await expect(runtime.acknowledge(SESSION_ID, capability.requestId)).resolves.toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'acknowledged',
    });
    expect(() => runtime.getStatus(SESSION_ID)).toThrow(/not found/);
    await runtime.shutdown();

    const restartOutbox = memoryOutbox({
      recoverBySession: vi.fn(() => ({
        version: 2 as const,
        sessionId: SESSION_ID,
        status: 'complete' as const,
        proofCapability: capability,
      })),
    });
    const restarted = new ProofBridgeRuntime({
      outbox: restartOutbox,
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async () => capability,
      },
    });
    expect(restarted.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'complete',
      proofCapability: capability,
    });
    await restarted.shutdown();
  });

  it('fails closed with a fixed code when durable persistence fails after finalization', async () => {
    const runtime = new ProofBridgeRuntime({
      outbox: memoryOutbox({
        persist: vi.fn(async () => {
          throw new CapabilityOutboxError(
            'CAPABILITY_OUTBOX_UNAVAILABLE',
            'The encrypted local proof result outbox is unavailable.',
          );
        }),
      }),
      sessions: new ProofSessionStore({ now: () => 1_000_000, createSessionId: () => SESSION_ID }),
      operations: {
        prepare: async () => ({ prepared: {}, authorizationRequest: challenge }),
        complete: async (_prepared, _authorization, onStage) => {
          await onStage('attesting');
          await onStage('proving_and_submitting');
          return capability;
        },
      },
    });
    await runtime.createChallenge(input);
    await runtime.startProof(SESSION_ID, authorization);
    await flush();

    expect(runtime.getStatus(SESSION_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'failed',
      error: {
        code: 'CAPABILITY_OUTBOX_UNAVAILABLE',
        message: 'The encrypted local proof result outbox is unavailable.',
      },
    });
    await runtime.shutdown();
  });
});
