// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { randomBytes } from 'node:crypto';
import type { ProofCapability } from '../api.js';
import { PROOF_BRIDGE_VERSION, type ProofSessionResponse, type ProofSessionStatus } from './types.js';

const SESSION_ID_PATTERN = /^0x[0-9a-f]{64}$/;
const ZERO_SESSION_ID = `0x${'0'.repeat(64)}`;

export class ProofSessionStoreError extends Error {
  constructor(
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'ProofSessionStoreError';
  }
}

interface SessionRecord<Prepared> {
  readonly sessionId: string;
  status: ProofSessionStatus | 'creating';
  expiresAt: bigint | null;
  prepared?: Prepared;
  proofCapability?: ProofCapability;
  error?: { readonly code: string; readonly message: string };
  terminalAtMs?: number;
  expiryTimer?: NodeJS.Timeout;
  terminalPurgeTimer?: NodeJS.Timeout;
}

export interface ProofSessionStoreOptions {
  readonly now?: () => number;
  readonly createSessionId?: () => string;
  readonly terminalRetentionMs?: number;
  readonly maximumRetainedSessions?: number;
}

export class ProofSessionStore<Prepared> {
  readonly #sessions = new Map<string, SessionRecord<Prepared>>();
  readonly #now: () => number;
  readonly #createSessionId: () => string;
  readonly #terminalRetentionMs: number;
  readonly #maximumRetainedSessions: number;
  #activeSessionId: string | null = null;

  constructor(options: ProofSessionStoreOptions = {}) {
    this.#now = options.now ?? Date.now;
    this.#createSessionId = options.createSessionId ?? generateSessionId;
    this.#terminalRetentionMs = options.terminalRetentionMs ?? 60_000;
    this.#maximumRetainedSessions = options.maximumRetainedSessions ?? 16;
  }

  reserve(): string {
    this.#sweep();
    if (this.#activeSessionId !== null) {
      throw new ProofSessionStoreError('PROOF_SESSION_BUSY', 'Another local proof session is already active.');
    }
    let sessionId = '';
    for (let attempt = 0; attempt < 8; attempt += 1) {
      const candidate = this.#createSessionId();
      if (SESSION_ID_PATTERN.test(candidate) && candidate !== ZERO_SESSION_ID && !this.#sessions.has(candidate)) {
        sessionId = candidate;
        break;
      }
    }
    if (sessionId === '') {
      throw new ProofSessionStoreError('SESSION_ID_UNAVAILABLE', 'Could not create a local proof session.');
    }
    this.#sessions.set(sessionId, {
      sessionId,
      status: 'creating',
      expiresAt: null,
    });
    this.#activeSessionId = sessionId;
    return sessionId;
  }

  abandonReservation(sessionId: string): void {
    const session = this.#sessions.get(sessionId);
    if (session?.status === 'creating') {
      this.#sessions.delete(sessionId);
      if (this.#activeSessionId === sessionId) {
        this.#activeSessionId = null;
      }
    }
  }

  activate(sessionId: string, prepared: Prepared, expiresAt: string): void {
    const session = this.#sessions.get(sessionId);
    if (session?.status !== 'creating' || !/^(0|[1-9][0-9]*)$/.test(expiresAt)) {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session is invalid.');
    }
    const parsedExpiry = BigInt(expiresAt);
    if (parsedExpiry <= this.#nowSeconds()) {
      this.#markTerminal(session, 'expired');
      throw new ProofSessionStoreError('PROOF_SESSION_EXPIRED', 'The wallet authorization request expired.');
    }
    session.prepared = prepared;
    session.expiresAt = parsedExpiry;
    session.status = 'awaiting_authorization';
    this.#scheduleExpiry(session);
  }

  beginProof(sessionId: string): Prepared {
    this.#sweep();
    const session = this.#require(sessionId);
    if (session.status === 'expired') {
      throw new ProofSessionStoreError('PROOF_SESSION_EXPIRED', 'The wallet authorization request expired.');
    }
    if (session.status !== 'awaiting_authorization' || session.prepared === undefined) {
      throw new ProofSessionStoreError('PROOF_SESSION_ALREADY_USED', 'The local proof session cannot be replayed.');
    }
    this.#clearExpiryTimer(session);
    session.status = 'attesting';
    return session.prepared;
  }

  setStage(sessionId: string, status: 'attesting' | 'proving_and_submitting' | 'indexing'): void {
    const session = this.#require(sessionId);
    if (status === 'attesting' && session.status !== 'attesting') {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session stage is invalid.');
    }
    if (
      status === 'proving_and_submitting' &&
      session.status !== 'attesting' &&
      session.status !== 'proving_and_submitting'
    ) {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session stage is invalid.');
    }
    if (status === 'indexing' && session.status !== 'proving_and_submitting' && session.status !== 'indexing') {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session stage is invalid.');
    }
    session.status = status;
  }

  complete(sessionId: string, proofCapability: ProofCapability): void {
    const session = this.#require(sessionId);
    if (session.status !== 'indexing') {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session stage is invalid.');
    }
    session.proofCapability = proofCapability;
    this.#markTerminal(session, 'complete');
  }

  fail(sessionId: string, code: string, message: string): void {
    const session = this.#require(sessionId);
    if (
      session.status !== 'attesting' &&
      session.status !== 'proving_and_submitting' &&
      session.status !== 'indexing'
    ) {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session stage is invalid.');
    }
    session.error = Object.freeze({ code, message });
    this.#markTerminal(session, 'failed');
  }

  cancel(sessionId: string): ProofSessionResponse {
    this.#sweep();
    const session = this.#require(sessionId);
    if (session.status === 'awaiting_authorization') {
      this.#markTerminal(session, 'cancelled');
      return this.#toResponse(session);
    }
    if (session.status === 'cancelled') {
      return this.#toResponse(session);
    }
    throw new ProofSessionStoreError(
      'PROOF_SESSION_NOT_CANCELLABLE',
      'A proof already in progress cannot be cancelled safely.',
    );
  }

  purgeAll(): void {
    for (const session of this.#sessions.values()) {
      this.#clearExpiryTimer(session);
      this.#clearTerminalPurgeTimer(session);
      session.prepared = undefined;
      session.proofCapability = undefined;
      session.error = undefined;
    }
    this.#sessions.clear();
    this.#activeSessionId = null;
  }

  status(sessionId: string): ProofSessionResponse {
    this.#sweep();
    return this.#toResponse(this.#require(sessionId));
  }

  forgetAcknowledgedCapability(sessionId: string, requestId: string): void {
    this.#sweep();
    const session = this.#sessions.get(sessionId);
    if (session === undefined) {
      return;
    }
    if (
      session.status !== 'complete' ||
      session.proofCapability === undefined ||
      session.proofCapability.requestId !== requestId
    ) {
      throw new ProofSessionStoreError(
        'PROOF_RESULT_BINDING_MISMATCH',
        'The proof result acknowledgement does not match the finalized request and session.',
      );
    }
    this.#removeSession(sessionId);
  }

  #require(sessionId: string): SessionRecord<Prepared> {
    if (!SESSION_ID_PATTERN.test(sessionId)) {
      throw new ProofSessionStoreError('PROOF_SESSION_NOT_FOUND', 'The local proof session was not found.');
    }
    const session = this.#sessions.get(sessionId);
    if (session === undefined || session.status === 'creating') {
      throw new ProofSessionStoreError('PROOF_SESSION_NOT_FOUND', 'The local proof session was not found.');
    }
    return session;
  }

  #markTerminal(
    session: SessionRecord<Prepared>,
    status: Extract<ProofSessionStatus, 'complete' | 'failed' | 'expired' | 'cancelled'>,
  ): void {
    this.#clearExpiryTimer(session);
    session.status = status;
    session.prepared = undefined;
    session.expiresAt = null;
    session.terminalAtMs = this.#now();
    if (this.#activeSessionId === session.sessionId) {
      this.#activeSessionId = null;
    }
    this.#scheduleTerminalPurge(session);
    this.#pruneTerminalCapacity();
  }

  #sweep(): void {
    const nowSeconds = this.#nowSeconds();
    if (this.#activeSessionId !== null) {
      const active = this.#sessions.get(this.#activeSessionId);
      if (active?.status === 'awaiting_authorization' && active.expiresAt !== null && active.expiresAt <= nowSeconds) {
        this.#markTerminal(active, 'expired');
      }
    }
    const cutoff = this.#now() - this.#terminalRetentionMs;
    for (const [sessionId, session] of this.#sessions) {
      if (session.terminalAtMs !== undefined && session.terminalAtMs < cutoff) {
        this.#removeSession(sessionId);
      }
    }
  }

  #pruneTerminalCapacity(): void {
    const terminal = [...this.#sessions.values()]
      .filter((session) => session.terminalAtMs !== undefined)
      .sort((left, right) => (left.terminalAtMs ?? 0) - (right.terminalAtMs ?? 0));
    while (terminal.length > this.#maximumRetainedSessions) {
      const oldest = terminal.shift();
      if (oldest !== undefined) {
        this.#removeSession(oldest.sessionId);
      }
    }
  }

  #scheduleTerminalPurge(session: SessionRecord<Prepared>): void {
    this.#clearTerminalPurgeTimer(session);
    if (session.terminalAtMs === undefined) {
      return;
    }
    const remainingMs = session.terminalAtMs + this.#terminalRetentionMs - this.#now();
    const delayMs = Math.min(Math.max(remainingMs, 0), 2_147_483_647);
    const timer = setTimeout(() => {
      session.terminalPurgeTimer = undefined;
      if (this.#sessions.get(session.sessionId) !== session || session.terminalAtMs === undefined) {
        return;
      }
      if (this.#now() - session.terminalAtMs >= this.#terminalRetentionMs) {
        this.#removeSession(session.sessionId);
      } else {
        this.#scheduleTerminalPurge(session);
      }
    }, delayMs);
    timer.unref();
    session.terminalPurgeTimer = timer;
  }

  #scheduleExpiry(session: SessionRecord<Prepared>): void {
    this.#clearExpiryTimer(session);
    if (session.status !== 'awaiting_authorization' || session.expiresAt === null) {
      return;
    }

    const remainingMs = session.expiresAt * 1_000n - BigInt(this.#now());
    const maximumTimerDelayMs = 2_147_483_647n;
    const boundedRemainingMs =
      remainingMs <= 0n ? 0n : remainingMs > maximumTimerDelayMs ? maximumTimerDelayMs : remainingMs;
    const delayMs = Number(boundedRemainingMs);
    const timer = setTimeout(() => {
      session.expiryTimer = undefined;
      if (session.status !== 'awaiting_authorization' || session.expiresAt === null) {
        return;
      }
      if (session.expiresAt <= this.#nowSeconds()) {
        this.#markTerminal(session, 'expired');
      } else {
        // Wall-clock changes and the platform timer ceiling can wake this timer
        // before the authorization deadline. Reschedule without extending it.
        this.#scheduleExpiry(session);
      }
    }, delayMs);
    timer.unref();
    session.expiryTimer = timer;
  }

  #clearExpiryTimer(session: SessionRecord<Prepared>): void {
    if (session.expiryTimer !== undefined) {
      clearTimeout(session.expiryTimer);
      session.expiryTimer = undefined;
    }
  }

  #clearTerminalPurgeTimer(session: SessionRecord<Prepared>): void {
    if (session.terminalPurgeTimer !== undefined) {
      clearTimeout(session.terminalPurgeTimer);
      session.terminalPurgeTimer = undefined;
    }
  }

  #removeSession(sessionId: string): void {
    const session = this.#sessions.get(sessionId);
    if (session === undefined) {
      return;
    }
    this.#clearExpiryTimer(session);
    this.#clearTerminalPurgeTimer(session);
    session.prepared = undefined;
    session.proofCapability = undefined;
    session.error = undefined;
    this.#sessions.delete(sessionId);
  }

  #nowSeconds(): bigint {
    return BigInt(Math.floor(this.#now() / 1_000));
  }

  #toResponse(session: SessionRecord<Prepared>): ProofSessionResponse {
    if (session.status === 'creating') {
      throw new ProofSessionStoreError('PROOF_SESSION_NOT_FOUND', 'The local proof session was not found.');
    }
    if (session.status === 'complete' && session.proofCapability !== undefined) {
      return Object.freeze({
        version: PROOF_BRIDGE_VERSION,
        sessionId: session.sessionId,
        status: 'complete',
        proofCapability: session.proofCapability,
      });
    }
    if (session.status === 'failed' && session.error !== undefined) {
      return Object.freeze({
        version: PROOF_BRIDGE_VERSION,
        sessionId: session.sessionId,
        status: 'failed',
        error: session.error,
      });
    }
    const pendingStatus = session.status as Exclude<ProofSessionStatus, 'complete' | 'failed'>;
    return Object.freeze({
      version: PROOF_BRIDGE_VERSION,
      sessionId: session.sessionId,
      status: pendingStatus,
    });
  }
}

export function generateSessionId(): string {
  return `0x${randomBytes(32).toString('hex')}`;
}
