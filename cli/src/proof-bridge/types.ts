// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import type { AuthorizationChallenge, AuthorizationProof } from '../authorization.js';
import type { ProofCapability } from '../api.js';
import type { SubjectRole } from '../giwa.js';

export const PROOF_BRIDGE_VERSION = 1 as const;
export const PROOF_BRIDGE_MAX_BODY_BYTES = 4_096;

export type ProofSessionStatus =
  | 'awaiting_authorization'
  | 'attesting'
  | 'proving_and_submitting'
  | 'indexing'
  | 'complete'
  | 'failed'
  | 'expired'
  | 'cancelled';

export interface ProofChallengeRequest {
  readonly version: 1;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly annualRevenueKrw: string;
  readonly debtRatioBps: string;
  readonly overdueCount: string;
  readonly secretPin: string;
}

export interface ParsedProofChallengeInput {
  readonly onchainReceivableId: bigint;
  readonly subjectRole: SubjectRole;
  readonly annualRevenueKrw: bigint;
  readonly debtRatioBps: bigint;
  readonly overdueCount: bigint;
  readonly secretPin: bigint;
}

export interface ProofChallengeResponse {
  readonly version: 1;
  readonly sessionId: string;
  readonly expiresAt: string;
  readonly authorizationRequest: AuthorizationChallenge;
}

export interface ProofSessionRequest {
  readonly version: 1;
  readonly sessionId: string;
}

export interface ProofSubmissionRequest extends ProofSessionRequest {
  readonly authorization: AuthorizationProof;
}

export interface ProofSessionPendingResponse {
  readonly version: 1;
  readonly sessionId: string;
  readonly status: Exclude<ProofSessionStatus, 'complete' | 'failed'>;
}

export interface ProofSessionCompleteResponse {
  readonly version: 1;
  readonly sessionId: string;
  readonly status: 'complete';
  readonly proofCapability: ProofCapability;
}

export interface ProofSessionFailedResponse {
  readonly version: 1;
  readonly sessionId: string;
  readonly status: 'failed';
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}

export type ProofSessionResponse =
  ProofSessionPendingResponse | ProofSessionCompleteResponse | ProofSessionFailedResponse;

export interface ProofBridgeErrorResponse {
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}
