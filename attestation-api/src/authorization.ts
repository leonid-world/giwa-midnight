import { randomBytes } from 'node:crypto';
import {
  AbiCoder,
  TypedDataEncoder,
  getAddress,
  id,
  keccak256,
  verifyTypedData,
  type TypedDataDomain,
  type TypedDataField,
} from 'ethers';
import { GIWA_CHAIN_ID, RECEIVABLE_FINANCE_ADDRESS } from './giwa.js';
import type {
  AuthorizationChallengeResponse,
  AuthorizationDomain,
  AuthorizationMessage,
  AuthorizationProof,
  AuthorizationTypes,
  ParsedAttestationRequest,
} from './types.js';

export const PROVIDER_ID = 2;
export const POLICY_VERSION = 1;
export const AUTHORIZATION_PROTOCOL = 'eip712-role-wallet-v1' as const;
export const AUTHORIZATION_VERSION = 1 as const;
export const AUTHORIZATION_TTL_SECONDS = 120;
export const MAX_PENDING_AUTHORIZATIONS = 128;
export const AUTHORIZATION_PRIMARY_TYPE = 'GASOKRoleAttestationAuthorization' as const;
export const AUTHORIZATION_PURPOSE = 'Authorize GASOK local mock financial attestation' as const;

const ATTESTATION_REQUEST_DOMAIN = id('gasok:mock-attestation-request:v1');
const abiCoder = AbiCoder.defaultAbiCoder();
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;

export const AUTHORIZATION_DOMAIN: AuthorizationDomain = Object.freeze({
  name: 'GASOK Mock Attestation',
  version: '1',
  chainId: GIWA_CHAIN_ID.toString(),
});

export const AUTHORIZATION_FIELDS = Object.freeze([
  Object.freeze({ name: 'purpose', type: 'string' }),
  Object.freeze({ name: 'authorizationId', type: 'bytes32' }),
  Object.freeze({ name: 'midnightContractAddress', type: 'bytes32' }),
  Object.freeze({ name: 'receivableFinanceAddress', type: 'address' }),
  Object.freeze({ name: 'onchainReceivableId', type: 'uint256' }),
  Object.freeze({ name: 'subjectRole', type: 'string' }),
  Object.freeze({ name: 'partyWallet', type: 'address' }),
  Object.freeze({ name: 'attestationRequestCommitment', type: 'bytes32' }),
  Object.freeze({ name: 'providerId', type: 'uint16' }),
  Object.freeze({ name: 'policyVersion', type: 'uint16' }),
  Object.freeze({ name: 'issuedAt', type: 'uint64' }),
  Object.freeze({ name: 'expiresAt', type: 'uint64' }),
]);

const ETHERS_AUTHORIZATION_TYPES: Record<string, Array<TypedDataField>> = {
  [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS.map((field) => ({ ...field })),
};

export const AUTHORIZATION_TYPES: AuthorizationTypes = Object.freeze({
  [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS,
});

export interface AuthorizationChallengeRecord {
  readonly message: AuthorizationMessage;
}

export interface AuthorizationChallengeStoreOptions {
  readonly now?: () => number;
  readonly randomId?: () => string;
  readonly ttlSeconds?: number;
  readonly maxEntries?: number;
}

export class AuthorizationCapacityError extends Error {
  constructor() {
    super('The authorization challenge capacity has been reached.');
    this.name = 'AuthorizationCapacityError';
  }
}

export class AuthorizationValidationError extends Error {
  constructor() {
    super('The wallet authorization is invalid or no longer available.');
    this.name = 'AuthorizationValidationError';
  }
}

export class AuthorizationGenerationError extends Error {
  constructor() {
    super('Unable to generate a unique authorization challenge.');
    this.name = 'AuthorizationGenerationError';
  }
}

export function requireNonZeroAttestationRequestCommitment(commitment: string): string {
  if (commitment.toLowerCase() === ZERO_BYTES32) {
    throw new AuthorizationGenerationError();
  }
  return commitment;
}

function normalizeBytes32(value: string): string {
  if (!BYTES32_PATTERN.test(value)) {
    throw new AuthorizationValidationError();
  }
  const normalized = value.toLowerCase();
  if (normalized === ZERO_BYTES32) {
    throw new AuthorizationValidationError();
  }
  return normalized;
}

function defaultRandomAuthorizationId(): string {
  return `0x${randomBytes(32).toString('hex')}`;
}

function unixSeconds(): number {
  return Math.floor(Date.now() / 1_000);
}

export class AuthorizationChallengeStore {
  readonly #records = new Map<string, AuthorizationChallengeRecord>();
  readonly #now: () => number;
  readonly #randomId: () => string;
  readonly #ttlSeconds: number;
  readonly #maxEntries: number;

  constructor(options: AuthorizationChallengeStoreOptions = {}) {
    this.#now = options.now ?? unixSeconds;
    this.#randomId = options.randomId ?? defaultRandomAuthorizationId;
    this.#ttlSeconds = options.ttlSeconds ?? AUTHORIZATION_TTL_SECONDS;
    this.#maxEntries = options.maxEntries ?? MAX_PENDING_AUTHORIZATIONS;

    if (!Number.isSafeInteger(this.#ttlSeconds) || this.#ttlSeconds <= 0) {
      throw new RangeError('Authorization TTL must be a positive integer');
    }
    if (!Number.isSafeInteger(this.#maxEntries) || this.#maxEntries <= 0) {
      throw new RangeError('Authorization capacity must be a positive integer');
    }
  }

  #pruneExpired(now: number): void {
    for (const [authorizationId, record] of this.#records) {
      if (BigInt(record.message.expiresAt) <= BigInt(now)) {
        this.#records.delete(authorizationId);
      }
    }
  }

  issue(createMessage: (authorizationId: string, issuedAt: string, expiresAt: string) => AuthorizationMessage):
    AuthorizationChallengeRecord {
    const now = this.#now();
    if (!Number.isSafeInteger(now) || now < 0) {
      throw new RangeError('Authorization clock must return non-negative Unix seconds');
    }
    this.#pruneExpired(now);
    if (this.#records.size >= this.#maxEntries) {
      throw new AuthorizationCapacityError();
    }

    let authorizationId: string | undefined;
    const maxGenerationAttempts = Math.max(16, this.#maxEntries + 1);
    for (let attempt = 0; attempt < maxGenerationAttempts; attempt += 1) {
      try {
        const candidate = normalizeBytes32(this.#randomId());
        if (!this.#records.has(candidate)) {
          authorizationId = candidate;
          break;
        }
      } catch (error: unknown) {
        if (!(error instanceof AuthorizationValidationError)) {
          throw error;
        }
      }
    }
    if (authorizationId === undefined) {
      throw new AuthorizationGenerationError();
    }

    const message = createMessage(
      authorizationId,
      now.toString(),
      (now + this.#ttlSeconds).toString(),
    );
    const record = Object.freeze({ message: Object.freeze({ ...message }) });
    this.#records.set(authorizationId, record);
    return record;
  }

  take(authorizationIdInput: string): AuthorizationChallengeRecord {
    const authorizationId = normalizeBytes32(authorizationIdInput);
    const now = this.#now();
    this.#pruneExpired(now);
    const record = this.#records.get(authorizationId);
    if (record === undefined) {
      throw new AuthorizationValidationError();
    }

    // Deletion happens before any request, context, hash, or signature check.
    // Every issued challenge therefore permits exactly one verification attempt.
    this.#records.delete(authorizationId);
    if (BigInt(record.message.issuedAt) > BigInt(now) || BigInt(record.message.expiresAt) <= BigInt(now)) {
      throw new AuthorizationValidationError();
    }
    return record;
  }

  get size(): number {
    this.#pruneExpired(this.#now());
    return this.#records.size;
  }
}

export function buildAttestationRequestCommitment(
  request: ParsedAttestationRequest,
  partyWallet: string,
): string {
  const encoded = abiCoder.encode(
    [
      'bytes32',
      'uint64',
      'uint32',
      'uint16',
      'uint256',
      'bytes32',
      'uint64',
      'address',
      'uint256',
      'string',
      'address',
      'uint16',
      'uint16',
      'bytes32',
    ],
    [
      ATTESTATION_REQUEST_DOMAIN,
      request.annualRevenueKrw,
      request.debtRatioBps,
      request.overdueCount,
      request.companyCommitmentHash,
      `0x${request.midnightContractAddress}`,
      GIWA_CHAIN_ID,
      RECEIVABLE_FINANCE_ADDRESS,
      request.onchainReceivableId,
      request.subjectRole,
      partyWallet,
      PROVIDER_ID,
      POLICY_VERSION,
      request.authorizationSalt,
    ],
  );
  return requireNonZeroAttestationRequestCommitment(keccak256(encoded));
}

export function buildAuthorizationMessage(
  request: ParsedAttestationRequest,
  partyWallet: string,
  authorizationId: string,
  issuedAt: string,
  expiresAt: string,
): AuthorizationMessage {
  return Object.freeze({
    purpose: AUTHORIZATION_PURPOSE,
    authorizationId: normalizeBytes32(authorizationId),
    midnightContractAddress: `0x${request.midnightContractAddress}`,
    receivableFinanceAddress: RECEIVABLE_FINANCE_ADDRESS,
    onchainReceivableId: request.onchainReceivableId.toString(),
    subjectRole: request.subjectRole,
    partyWallet: getAddress(partyWallet).toLowerCase(),
    attestationRequestCommitment: buildAttestationRequestCommitment(request, partyWallet),
    providerId: PROVIDER_ID.toString(),
    policyVersion: POLICY_VERSION.toString(),
    issuedAt,
    expiresAt,
  });
}

export function buildAuthorizationChallengeResponse(
  record: AuthorizationChallengeRecord,
): AuthorizationChallengeResponse {
  return {
    version: AUTHORIZATION_VERSION,
    domain: AUTHORIZATION_DOMAIN,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    types: AUTHORIZATION_TYPES,
    message: record.message,
  };
}

export function hashAuthorizationMessage(message: AuthorizationMessage): string {
  return TypedDataEncoder.hash(
    AUTHORIZATION_DOMAIN as TypedDataDomain,
    ETHERS_AUTHORIZATION_TYPES,
    message,
  ).toLowerCase();
}

export function verifyAuthorizationSignature(
  message: AuthorizationMessage,
  proof: AuthorizationProof,
  canonicalPartyWallet: string,
): void {
  if (
    proof.version !== AUTHORIZATION_VERSION ||
    normalizeBytes32(proof.authorizationId) !== message.authorizationId ||
    normalizeBytes32(proof.typedDataHash) !== hashAuthorizationMessage(message) ||
    !SIGNATURE_PATTERN.test(proof.signature)
  ) {
    throw new AuthorizationValidationError();
  }

  let signer: string;
  let recovered: string;
  let canonical: string;
  try {
    signer = getAddress(proof.signer);
    canonical = getAddress(canonicalPartyWallet);
    recovered = getAddress(verifyTypedData(
      AUTHORIZATION_DOMAIN as TypedDataDomain,
      ETHERS_AUTHORIZATION_TYPES,
      message,
      proof.signature,
    ));
  } catch {
    throw new AuthorizationValidationError();
  }

  if (signer !== canonical || recovered !== canonical || recovered !== signer) {
    throw new AuthorizationValidationError();
  }
}
