// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from 'vitest';
import type { ProofCapability } from '../api.js';
import { ProofSessionStore } from '../proof-bridge/session-store.js';

const SESSION_A = `0x${'1'.repeat(64)}`;
const SESSION_B = `0x${'2'.repeat(64)}`;

const capability: ProofCapability = {
  version: 2,
  evaluationVersion: 2,
  midnightContractAddress: 'a'.repeat(64),
  companyCommitment: `0x${'b'.repeat(64)}`,
  lookupKey: `0x${'c'.repeat(64)}`,
  giwaChainId: '91342',
  receivableFinanceAddress: `0x${'d'.repeat(40)}`,
  onchainReceivableId: '1',
  subjectRole: 'SELLER',
  partyWallet: `0x${'e'.repeat(40)}`,
  requestId: `0x${'1'.repeat(64)}`,
  intendedFunderWallet: `0x${'2'.repeat(40)}`,
  minAnnualRevenueKrw: '500000000',
  maxDebtRatioBps: '20000',
  maxOverdueCount: '1',
  policyRequestHash: `0x${'3'.repeat(64)}`,
  profileAsOf: '1000',
  validUntil: '2000',
};

describe('ProofSessionStore', () => {
  afterEach(() => {
    vi.useRealTimers();
  });

  it('allows one active session, enforces one-shot use, and moves stages only forward', () => {
    let idIndex = 0;
    const ids = [SESSION_A, SESSION_B];
    const store = new ProofSessionStore<{ readonly secret: string }>({
      now: () => 1_000_000,
      createSessionId: () => ids[idIndex++],
    });
    const sessionId = store.reserve();
    store.activate(sessionId, { secret: 'memory-only' }, '1001');
    expect(store.status(sessionId).status).toBe('awaiting_authorization');
    expect(() => store.reserve()).toThrow(/already active/);

    expect(store.beginProof(sessionId)).toEqual({ secret: 'memory-only' });
    expect(() => store.beginProof(sessionId)).toThrow(/cannot be replayed/);
    store.setStage(sessionId, 'proving_and_submitting');
    expect(() => store.setStage(sessionId, 'attesting')).toThrow(/stage is invalid/);
    store.setStage(sessionId, 'indexing');
    store.complete(sessionId, capability);
    expect(store.status(sessionId)).toEqual({
      version: 2,
      sessionId,
      status: 'complete',
      proofCapability: capability,
    });

    expect(store.reserve()).toBe(SESSION_B);
  });

  it('expires an unsigned challenge, purges its prepared value, and frees capacity', () => {
    let now = 1_000_000;
    let idIndex = 0;
    const ids = [SESSION_A, SESSION_B];
    const store = new ProofSessionStore<{ readonly privateValue: string }>({
      now: () => now,
      createSessionId: () => ids[idIndex++],
    });
    store.reserve();
    store.activate(SESSION_A, { privateValue: 'never-public' }, '1001');
    now = 1_001_000;

    expect(store.status(SESSION_A).status).toBe('expired');
    expect(store.reserve()).toBe(SESSION_B);
  });

  it('automatically expires an unsigned challenge without requiring another store request', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    let idIndex = 0;
    const ids = [SESSION_A, SESSION_B];
    const store = new ProofSessionStore<{ readonly privateValue: string }>({
      createSessionId: () => ids[idIndex++],
    });
    store.reserve();
    store.activate(SESSION_A, { privateValue: 'discard-at-expiry' }, '1001');

    await vi.advanceTimersByTimeAsync(1_000);

    expect(store.status(SESSION_A).status).toBe('expired');
    expect(store.reserve()).toBe(SESSION_B);
  });

  it('does not expire a proof after the one-shot session has started', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    const store = new ProofSessionStore<{ readonly privateValue: string }>({
      createSessionId: () => SESSION_A,
    });
    store.reserve();
    store.activate(SESSION_A, { privateValue: 'proof-in-progress' }, '1001');
    store.beginProof(SESSION_A);

    await vi.advanceTimersByTimeAsync(1_000);

    expect(store.status(SESSION_A).status).toBe('attesting');
  });

  it('retains terminal status briefly and purgeAll removes every capability', () => {
    const store = new ProofSessionStore<unknown>({
      now: () => 1_000_000,
      createSessionId: () => SESSION_A,
    });
    store.reserve();
    store.activate(SESSION_A, {}, '1001');
    store.beginProof(SESSION_A);
    store.setStage(SESSION_A, 'proving_and_submitting');
    store.setStage(SESSION_A, 'indexing');
    store.complete(SESSION_A, capability);
    store.purgeAll();

    expect(() => store.status(SESSION_A)).toThrow(/not found/);
  });

  it('removes a retained capability after sixty seconds and refuses cancellation once proof starts', () => {
    let now = 1_000_000;
    const store = new ProofSessionStore<unknown>({
      now: () => now,
      createSessionId: () => SESSION_A,
    });
    store.reserve();
    store.activate(SESSION_A, {}, '1001');
    store.beginProof(SESSION_A);
    expect(() => store.cancel(SESSION_A)).toThrow(/cannot be cancelled/);
    store.setStage(SESSION_A, 'proving_and_submitting');
    store.setStage(SESSION_A, 'indexing');
    store.complete(SESSION_A, capability);

    now += 60_001;
    expect(() => store.status(SESSION_A)).toThrow(/not found/);
  });

  it('automatically purges a terminal capability after its retention window', async () => {
    vi.useFakeTimers();
    vi.setSystemTime(1_000_000);
    const store = new ProofSessionStore<unknown>({
      createSessionId: () => SESSION_A,
      terminalRetentionMs: 1_000,
    });
    store.reserve();
    store.activate(SESSION_A, {}, '1001');
    store.beginProof(SESSION_A);
    store.setStage(SESSION_A, 'proving_and_submitting');
    store.setStage(SESSION_A, 'indexing');
    store.complete(SESSION_A, capability);
    expect(vi.getTimerCount()).toBe(1);

    await vi.advanceTimersByTimeAsync(1_000);

    expect(vi.getTimerCount()).toBe(0);
    expect(() => store.status(SESSION_A)).toThrow(/not found/);
  });
});
