// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from 'pino';
import type { AuthorizationProof } from '../authorization.js';
import type { EligibilityProofStage, PreparedEligibilityVerification, ProofCapability } from '../api.js';
import type { ParsedProofChallengeInput, ProofChallengeResponse, ProofSessionResponse } from './types.js';
import { PROOF_BRIDGE_VERSION } from './types.js';
import { ProofSessionStore, ProofSessionStoreError } from './session-store.js';

export interface PreparedProofChallenge<Prepared> {
  readonly prepared: Prepared;
  readonly authorizationRequest: PreparedEligibilityVerification['authorizationChallenge'];
}

export interface ProofBridgeOperations<Prepared> {
  prepare(input: ParsedProofChallengeInput): Promise<PreparedProofChallenge<Prepared>>;
  complete(
    prepared: Prepared,
    authorization: AuthorizationProof,
    onStage: (stage: EligibilityProofStage) => void,
  ): Promise<ProofCapability>;
}

export interface ProofBridgeController {
  createChallenge(input: ParsedProofChallengeInput): Promise<ProofChallengeResponse>;
  startProof(sessionId: string, authorization: AuthorizationProof): ProofSessionResponse;
  getStatus(sessionId: string): ProofSessionResponse;
  cancel(sessionId: string): ProofSessionResponse;
  shutdown?(): Promise<void>;
}

export interface ProofBridgeRuntimeOptions<Prepared> {
  readonly operations: ProofBridgeOperations<Prepared>;
  readonly sessions?: ProofSessionStore<Prepared>;
  readonly logger?: Pick<Logger, 'info' | 'warn'>;
}

export class ProofBridgeRuntime<Prepared> implements ProofBridgeController {
  readonly #operations: ProofBridgeOperations<Prepared>;
  readonly #sessions: ProofSessionStore<Prepared>;
  readonly #logger?: Pick<Logger, 'info' | 'warn'>;
  readonly #jobs = new Set<Promise<void>>();

  constructor(options: ProofBridgeRuntimeOptions<Prepared>) {
    this.#operations = options.operations;
    this.#sessions = options.sessions ?? new ProofSessionStore<Prepared>();
    this.#logger = options.logger;
  }

  async createChallenge(input: ParsedProofChallengeInput): Promise<ProofChallengeResponse> {
    const sessionId = this.#sessions.reserve();
    try {
      const prepared = await this.#operations.prepare(input);
      const expiresAt = prepared.authorizationRequest.message.expiresAt;
      this.#sessions.activate(sessionId, prepared.prepared, expiresAt);
      this.#logger?.info('Created a one-time local proof authorization session.');
      return Object.freeze({
        version: PROOF_BRIDGE_VERSION,
        sessionId,
        expiresAt,
        authorizationRequest: prepared.authorizationRequest,
      });
    } catch (error: unknown) {
      this.#sessions.abandonReservation(sessionId);
      throw error;
    }
  }

  startProof(sessionId: string, authorization: AuthorizationProof): ProofSessionResponse {
    const prepared = this.#sessions.beginProof(sessionId);
    const job = Promise.resolve().then(async () => await this.#executeProof(sessionId, prepared, authorization));
    this.#jobs.add(job);
    void job.finally(() => this.#jobs.delete(job));
    return this.#sessions.status(sessionId);
  }

  getStatus(sessionId: string): ProofSessionResponse {
    return this.#sessions.status(sessionId);
  }

  cancel(sessionId: string): ProofSessionResponse {
    return this.#sessions.cancel(sessionId);
  }

  async shutdown(): Promise<void> {
    await Promise.allSettled([...this.#jobs]);
    this.#sessions.purgeAll();
  }

  async #executeProof(sessionId: string, prepared: Prepared, authorization: AuthorizationProof): Promise<void> {
    try {
      const proofCapability = await this.#operations.complete(prepared, authorization, (stage) =>
        this.#sessions.setStage(sessionId, stage),
      );
      // Returning from complete() means the Midnight transaction is finalized.
      // Do not keep the one-shot submission session open while the asynchronous
      // Indexer catches up: Vue resolves this capability through the independent
      // read adapter and may safely retry only that read.
      this.#sessions.setStage(sessionId, 'indexing');
      this.#sessions.complete(sessionId, proofCapability);
      this.#logger?.info('Completed a local GASOK Midnight proof session.');
    } catch (error: unknown) {
      const code = error instanceof ProofSessionStoreError ? error.code : 'PROOF_FAILED';
      const message =
        error instanceof ProofSessionStoreError
          ? error.message
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
