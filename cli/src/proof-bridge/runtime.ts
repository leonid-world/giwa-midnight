// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from 'pino';
import type { AuthorizationProof } from '../authorization.js';
import { LocalAttestationApiError } from '../attestation-errors.js';
import { EligibilityResultAlreadyExistsError } from '../proof-errors.js';
import type { EligibilityProofStage, PreparedEligibilityVerification, ProofCapability } from '../api.js';
import type { ParsedProofChallengeInput, ProofChallengeResponse, ProofSessionResponse } from './types.js';
import type { ProofAcknowledgementResponse, ProofSessionCompleteResponse } from './types.js';
import { PROOF_BRIDGE_VERSION } from './types.js';
import { ProofSessionStore, ProofSessionStoreError } from './session-store.js';
import {
  CapabilityOutboxError,
  type CapabilityBinding,
  type ProofCapabilityOutbox,
} from './capability-outbox.js';

export interface PreparedProofChallenge<Prepared> {
  readonly prepared: Prepared;
  readonly authorizationRequest: PreparedEligibilityVerification['authorizationChallenge'];
}

export interface ProofBridgeOperations<Prepared> {
  prepare(input: ParsedProofChallengeInput): Promise<PreparedProofChallenge<Prepared>>;
  complete(
    prepared: Prepared,
    authorization: AuthorizationProof,
    onStage: (stage: EligibilityProofStage) => void | Promise<void>,
  ): Promise<ProofCapability>;
}

export interface ProofBridgeController {
  createChallenge(input: ParsedProofChallengeInput): Promise<ProofChallengeResponse>;
  startProof(sessionId: string, authorization: AuthorizationProof): Promise<ProofSessionResponse>;
  getStatus(sessionId: string): ProofSessionResponse;
  cancel(sessionId: string): Promise<ProofSessionResponse>;
  recover(requestId: string): ProofSessionCompleteResponse;
  acknowledge(sessionId: string, requestId: string): Promise<ProofAcknowledgementResponse>;
  shutdown?(): Promise<void>;
}

export interface ProofBridgeRuntimeOptions<Prepared> {
  readonly operations: ProofBridgeOperations<Prepared>;
  readonly outbox: ProofCapabilityOutbox;
  readonly sessions?: ProofSessionStore<Prepared>;
  readonly logger?: Pick<Logger, 'info' | 'warn'>;
}

export class ProofBridgeRuntime<Prepared> implements ProofBridgeController {
  readonly #operations: ProofBridgeOperations<Prepared>;
  readonly #outbox: ProofCapabilityOutbox;
  readonly #sessions: ProofSessionStore<Prepared>;
  readonly #logger?: Pick<Logger, 'info' | 'warn'>;
  readonly #jobs = new Set<Promise<void>>();
  readonly #requestIdsBySession = new Map<string, string>();

  constructor(options: ProofBridgeRuntimeOptions<Prepared>) {
    this.#operations = options.operations;
    this.#outbox = options.outbox;
    this.#sessions = options.sessions ?? new ProofSessionStore<Prepared>();
    this.#logger = options.logger;
  }

  async createChallenge(input: ParsedProofChallengeInput): Promise<ProofChallengeResponse> {
    this.#outbox.assertRequestAvailable(input.policyRequest.requestId);
    const sessionId = this.#sessions.reserve();
    let durableReservation = false;
    try {
      const prepared = await this.#operations.prepare(input);
      const expiresAt = prepared.authorizationRequest.message.expiresAt;
      const binding: CapabilityBinding = Object.freeze({
        requestId: input.policyRequest.requestId,
        onchainReceivableId: input.onchainReceivableId.toString(),
        subjectRole: input.subjectRole,
        partyWallet: prepared.authorizationRequest.message.partyWallet,
        intendedFunderWallet: input.policyRequest.intendedFunderWallet,
        minAnnualRevenueKrw: input.policyRequest.minAnnualRevenueKrw.toString(),
        maxDebtRatioBps: input.policyRequest.maxDebtRatioBps.toString(),
        maxOverdueCount: input.policyRequest.maxOverdueCount.toString(),
        validUntil: input.policyRequest.validUntil.toString(),
      });
      await this.#outbox.reserve(sessionId, binding, expiresAt);
      durableReservation = true;
      this.#sessions.activate(sessionId, prepared.prepared, expiresAt);
      this.#requestIdsBySession.set(sessionId, input.policyRequest.requestId);
      this.#logger?.info('Created a one-time local proof authorization session.');
      return Object.freeze({
        version: PROOF_BRIDGE_VERSION,
        sessionId,
        expiresAt,
        authorizationRequest: prepared.authorizationRequest,
      });
    } catch (error: unknown) {
      if (durableReservation) {
        await this.#outbox.releaseAwaiting(sessionId, input.policyRequest.requestId).catch(() => undefined);
      }
      this.#sessions.abandonReservation(sessionId);
      throw error;
    }
  }

  async startProof(sessionId: string, authorization: AuthorizationProof): Promise<ProofSessionResponse> {
    const prepared = this.#sessions.beginProof(sessionId);
    const requestId = this.#requestIdsBySession.get(sessionId);
    if (requestId === undefined) {
      throw new ProofSessionStoreError('INVALID_SESSION_STATE', 'The local proof session is invalid.');
    }
    const job = Promise.resolve().then(
      async () => await this.#executeProof(sessionId, requestId, prepared, authorization),
    );
    this.#jobs.add(job);
    void job.finally(() => this.#jobs.delete(job));
    return this.#sessions.status(sessionId);
  }

  getStatus(sessionId: string): ProofSessionResponse {
    try {
      return this.#sessions.status(sessionId);
    } catch (error: unknown) {
      if (!(error instanceof ProofSessionStoreError) || error.code !== 'PROOF_SESSION_NOT_FOUND') {
        throw error;
      }
      try {
        return this.#outbox.recoverBySession(sessionId);
      } catch (outboxError: unknown) {
        if (outboxError instanceof CapabilityOutboxError && outboxError.code === 'PROOF_RESULT_NOT_FOUND') {
          throw error;
        }
        throw outboxError;
      }
    }
  }

  async cancel(sessionId: string): Promise<ProofSessionResponse> {
    const response = this.#sessions.cancel(sessionId);
    const requestId = this.#requestIdsBySession.get(sessionId);
    if (requestId !== undefined) {
      await this.#outbox.releaseAwaiting(sessionId, requestId);
      this.#requestIdsBySession.delete(sessionId);
    }
    return response;
  }

  recover(requestId: string): ProofSessionCompleteResponse {
    return this.#outbox.recoverByRequest(requestId);
  }

  async acknowledge(sessionId: string, requestId: string): Promise<ProofAcknowledgementResponse> {
    await this.#outbox.acknowledge(sessionId, requestId);
    this.#sessions.forgetAcknowledgedCapability(sessionId, requestId);
    return Object.freeze({ version: PROOF_BRIDGE_VERSION, sessionId, status: 'acknowledged' });
  }

  async shutdown(): Promise<void> {
    await Promise.allSettled([...this.#jobs]);
    this.#sessions.purgeAll();
    this.#requestIdsBySession.clear();
    this.#outbox.close();
  }

  async #executeProof(
    sessionId: string,
    requestId: string,
    prepared: Prepared,
    authorization: AuthorizationProof,
  ): Promise<void> {
    try {
      const proofCapability = await this.#operations.complete(prepared, authorization, async (stage) => {
        if (stage === 'proving_and_submitting') {
          // This fail-closed marker is durable before callTx begins. If the
          // process crashes in the submission/finalization window, a reload
          // cannot accidentally create a second result for the same request.
          await this.#outbox.markProving(sessionId, requestId);
        }
        this.#sessions.setStage(sessionId, stage);
      });
      // The encrypted outbox is the durability boundary. Never expose a
      // complete response until the request-bound capability is atomically
      // persisted; Spring acknowledges and deletes it only after SUBMITTED.
      await this.#outbox.persist(sessionId, proofCapability);
      // Returning from complete() means the Midnight transaction is finalized.
      // Do not keep the one-shot submission session open while the asynchronous
      // Indexer catches up: Vue resolves this capability through the independent
      // read adapter and may safely retry only that read.
      this.#sessions.setStage(sessionId, 'indexing');
      this.#sessions.complete(sessionId, proofCapability);
      this.#requestIdsBySession.delete(sessionId);
      this.#logger?.info('Completed a local GASOK Midnight proof session.');
    } catch (error: unknown) {
      await this.#outbox.releaseAwaiting(sessionId, requestId).catch(() => undefined);
      this.#requestIdsBySession.delete(sessionId);
      const code =
        error instanceof ProofSessionStoreError ||
        error instanceof CapabilityOutboxError ||
        error instanceof LocalAttestationApiError ||
        error instanceof EligibilityResultAlreadyExistsError
          ? error.code
          : 'PROOF_FAILED';
      const message =
        error instanceof ProofSessionStoreError
          ? error.message
          : error instanceof CapabilityOutboxError
            ? error.publicMessage
          : error instanceof LocalAttestationApiError || error instanceof EligibilityResultAlreadyExistsError
            ? error.publicMessage
            : 'The local mock-attested Midnight proof could not be completed.';
      try {
        this.#sessions.fail(sessionId, code, message);
      } catch {
        // The session store is authoritative. Do not expose or log the original
        // exception because it may carry values from a rejected provider body.
      }
      this.#logger?.warn({ code }, 'A local GASOK Midnight proof session failed.');
    }
  }
}
