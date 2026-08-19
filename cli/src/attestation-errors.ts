// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

export type LocalAttestationPath = '/attest' | '/authorization-challenges';

export type LocalAttestationErrorCode =
  | 'GIWA_RECEIVABLE_NOT_FOUND'
  | 'GIWA_RPC_UNAVAILABLE'
  | 'POLICY_REQUEST_EXPIRED'
  | 'ROLE_WALLET_MISMATCH';

interface LocalAttestationErrorDefinition {
  readonly status: 403 | 404 | 409 | 502;
  readonly publicMessage: string;
  readonly paths: ReadonlySet<LocalAttestationPath>;
}

const BOTH_PROVIDER_PATHS = new Set<LocalAttestationPath>([
  '/attest',
  '/authorization-challenges',
]);

const LOCAL_ATTESTATION_ERRORS: Readonly<
  Record<LocalAttestationErrorCode, LocalAttestationErrorDefinition>
> = Object.freeze({
  GIWA_RECEIVABLE_NOT_FOUND: Object.freeze({
    status: 404,
    publicMessage: 'The GIWA receivable was not found.',
    paths: BOTH_PROVIDER_PATHS,
  }),
  GIWA_RPC_UNAVAILABLE: Object.freeze({
    status: 502,
    publicMessage: 'GIWA receivable verification is unavailable.',
    paths: BOTH_PROVIDER_PATHS,
  }),
  POLICY_REQUEST_EXPIRED: Object.freeze({
    status: 409,
    publicMessage: 'The Funder policy request has expired.',
    paths: new Set<LocalAttestationPath>(['/attest']),
  }),
  ROLE_WALLET_MISMATCH: Object.freeze({
    status: 403,
    publicMessage: 'The wallet authorization does not match the current GIWA role wallet.',
    paths: new Set<LocalAttestationPath>(['/attest']),
  }),
});

export class LocalAttestationApiError extends Error {
  readonly status: 403 | 404 | 409 | 502;
  readonly publicMessage: string;

  constructor(readonly code: LocalAttestationErrorCode) {
    const definition = LOCAL_ATTESTATION_ERRORS[code];
    super(definition.publicMessage);
    this.name = 'LocalAttestationApiError';
    this.status = definition.status;
    this.publicMessage = definition.publicMessage;
  }
}

type JsonRecord = Record<string, unknown>;

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expectedKeys: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function isLocalAttestationErrorCode(value: unknown): value is LocalAttestationErrorCode {
  return typeof value === 'string' && Object.hasOwn(LOCAL_ATTESTATION_ERRORS, value);
}

/**
 * Promotes only the Provider's explicitly allowlisted error code/status/path
 * tuples. The Provider-supplied message is shape-checked but deliberately
 * ignored so private values or upstream diagnostics can never be reflected by
 * the CLI, Proof Bridge, or Vue.
 */
export function parseLocalAttestationApiError(
  path: LocalAttestationPath,
  status: number,
  responseText: string,
): LocalAttestationApiError | null {
  let value: unknown;
  try {
    value = JSON.parse(responseText) as unknown;
  } catch {
    return null;
  }
  if (!isRecord(value) || !hasExactKeys(value, ['error'])) {
    return null;
  }
  const error = value.error;
  if (
    !isRecord(error) ||
    !hasExactKeys(error, ['code', 'message']) ||
    !isLocalAttestationErrorCode(error.code) ||
    typeof error.message !== 'string'
  ) {
    return null;
  }
  const definition = LOCAL_ATTESTATION_ERRORS[error.code];
  if (definition.status !== status || !definition.paths.has(path)) {
    return null;
  }
  return new LocalAttestationApiError(error.code);
}
