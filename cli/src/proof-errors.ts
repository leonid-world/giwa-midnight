// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

export const ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE = 'ELIGIBILITY_RESULT_ALREADY_EXISTS' as const;
export const ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE =
  'An eligibility result already exists for this exact proof context.';

const ELIGIBILITY_RESULT_ALREADY_EXISTS_ASSERTION = 'Eligibility result already exists';
const COMPACT_ASSERTION_MESSAGE = `failed assert: ${ELIGIBILITY_RESULT_ALREADY_EXISTS_ASSERTION}`;
const MAX_ERROR_CAUSE_DEPTH = 8;

export class EligibilityResultAlreadyExistsError extends Error {
  readonly code = ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE;
  readonly publicMessage = ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE;

  constructor() {
    super(ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE);
    this.name = 'EligibilityResultAlreadyExistsError';
  }
}

function isExactDuplicateAssertion(error: unknown): boolean {
  if (!(error instanceof Error)) {
    return false;
  }
  try {
    return (
      error.message === ELIGIBILITY_RESULT_ALREADY_EXISTS_ASSERTION ||
      error.message === COMPACT_ASSERTION_MESSAGE
    );
  } catch {
    return false;
  }
}

/**
 * Promotes only the one allowlisted Compact assertion emitted while building a
 * call transaction. The SDK wraps Compact errors with `cause`, so inspect only
 * that bounded chain. Never retain or reflect the original error because it may
 * contain private witness values or provider diagnostics.
 */
export function classifyEligibilityCallTxError(error: unknown): EligibilityResultAlreadyExistsError | null {
  const visited = new Set<unknown>();
  let current: unknown = error;

  for (let depth = 0; depth < MAX_ERROR_CAUSE_DEPTH; depth += 1) {
    if (visited.has(current)) {
      return null;
    }
    visited.add(current);

    if (isExactDuplicateAssertion(current)) {
      return new EligibilityResultAlreadyExistsError();
    }
    if (!(current instanceof Error)) {
      return null;
    }
    try {
      current = current.cause;
    } catch {
      return null;
    }
  }

  return null;
}
