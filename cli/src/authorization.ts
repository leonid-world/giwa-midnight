// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

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
import { MAX_FIELD } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import {
  GIWA_CHAIN_ID,
  RECEIVABLE_FINANCE_ADDRESS,
  UINT16_MAX,
  UINT32_MAX,
  UINT64_MAX,
  UINT256_MAX,
  bytesToHex,
  fixedHexToBytes,
  isZeroBytes,
  normalizeEvmAddress,
  normalizeMidnightContractAddress,
  type GiwaDeploymentConfig,
  type SubjectRole,
} from './giwa';

export const AUTHORIZATION_VERSION = 1 as const;
export const AUTHORIZATION_PROVIDER_ID = 2 as const;
export const AUTHORIZATION_POLICY_VERSION = 1 as const;
export const AUTHORIZATION_TTL_SECONDS = 120n;
export const AUTHORIZATION_PRIMARY_TYPE = 'GASOKRoleAttestationAuthorization' as const;
export const AUTHORIZATION_PURPOSE = 'Authorize GASOK local mock financial attestation' as const;
export const MAX_AUTHORIZATION_PROOF_JSON_BYTES = 4_096;

const ATTESTATION_REQUEST_DOMAIN = id('gasok:mock-attestation-request:v1');
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const LOWER_BYTES32_PATTERN = /^0x[0-9a-f]{64}$/;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const abiCoder = AbiCoder.defaultAbiCoder();

export const AUTHORIZATION_DOMAIN = Object.freeze({
  name: 'GASOK Mock Attestation' as const,
  version: '1' as const,
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

export interface AuthorizationChallengeRequest {
  readonly version: 1;
  readonly annualRevenueKrw: string;
  readonly debtRatioBps: string;
  readonly overdueCount: string;
  readonly companyCommitmentHash: string;
  readonly authorizationSalt: string;
  readonly midnightContractAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
}

export interface AuthorizationTypeField {
  readonly name: string;
  readonly type: string;
}

export interface AuthorizationMessage {
  readonly purpose: typeof AUTHORIZATION_PURPOSE;
  readonly authorizationId: string;
  readonly midnightContractAddress: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
  readonly attestationRequestCommitment: string;
  readonly providerId: string;
  readonly policyVersion: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface AuthorizationChallenge {
  readonly version: 1;
  readonly domain: typeof AUTHORIZATION_DOMAIN;
  readonly primaryType: typeof AUTHORIZATION_PRIMARY_TYPE;
  readonly types: Readonly<Record<typeof AUTHORIZATION_PRIMARY_TYPE, ReadonlyArray<AuthorizationTypeField>>>;
  readonly message: AuthorizationMessage;
}

export interface AuthorizationProof {
  readonly version: 1;
  readonly authorizationId: string;
  readonly typedDataHash: string;
  readonly signer: string;
  readonly signature: string;
}

export interface AuthorizationExpectedContext {
  readonly midnightContractAddress: string;
  readonly onchainReceivableId: bigint;
  readonly subjectRole: SubjectRole;
  readonly giwa: GiwaDeploymentConfig;
}

export type RoleAuthorizationCallback = (challenge: AuthorizationChallenge) => Promise<unknown>;

type JsonRecord = Record<string, unknown>;

const CHALLENGE_KEYS = ['version', 'domain', 'primaryType', 'types', 'message'] as const;
const DOMAIN_KEYS = ['name', 'version', 'chainId'] as const;
const MESSAGE_KEYS = [
  'purpose',
  'authorizationId',
  'midnightContractAddress',
  'receivableFinanceAddress',
  'onchainReceivableId',
  'subjectRole',
  'partyWallet',
  'attestationRequestCommitment',
  'providerId',
  'policyVersion',
  'issuedAt',
  'expiresAt',
] as const;
const PROOF_KEYS = ['version', 'authorizationId', 'typedDataHash', 'signer', 'signature'] as const;

function invalidChallenge(): Error {
  return new Error('Mock Attestation API returned an invalid role authorization challenge.');
}

function invalidAuthorizationProof(): Error {
  return new Error('The wallet authorization response is invalid, expired, or for a different request.');
}

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expectedKeys: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function requireExactRecord(
  value: unknown,
  expectedKeys: ReadonlyArray<string>,
  errorFactory: () => Error,
): JsonRecord {
  if (!isRecord(value) || !hasExactKeys(value, expectedKeys)) {
    throw errorFactory();
  }
  return value;
}

function parseCanonicalUint(value: unknown, maximum: bigint): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw invalidChallenge();
  }
  const parsed = BigInt(value);
  if (parsed > maximum) {
    throw invalidChallenge();
  }
  return parsed;
}

function parseCanonicalPartyWallet(value: unknown): string {
  if (typeof value !== 'string' || !EVM_ADDRESS_PATTERN.test(value)) {
    throw invalidChallenge();
  }
  const normalized = normalizeEvmAddress(value, 'Authorized GIWA party wallet');
  if (
    value !== normalized ||
    isZeroBytes(fixedHexToBytes(normalized, 20, 'Authorized GIWA party wallet', { requirePrefix: true }))
  ) {
    throw invalidChallenge();
  }
  return normalized;
}

function assertFixedGiwaDeployment(expected: AuthorizationExpectedContext): void {
  if (
    expected.giwa.chainId !== GIWA_CHAIN_ID ||
    bytesToHex(expected.giwa.receivableFinanceAddress) !== RECEIVABLE_FINANCE_ADDRESS
  ) {
    throw new Error('The joined Midnight contract is not bound to the approved GIWA deployment.');
  }
}

export function generateAuthorizationSalt(): string {
  for (let attempt = 0; attempt < 8; attempt += 1) {
    const salt = `0x${randomBytes(32).toString('hex')}`;
    if (salt !== ZERO_BYTES32) {
      return salt;
    }
  }
  throw new Error('Could not generate a non-zero authorization salt.');
}

export function createAuthorizationChallengeRequest(
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  companyCommitmentHash: bigint,
  expected: AuthorizationExpectedContext,
  authorizationSalt: string = generateAuthorizationSalt(),
): AuthorizationChallengeRequest {
  assertFixedGiwaDeployment(expected);
  const midnightContractAddress = normalizeMidnightContractAddress(expected.midnightContractAddress);
  if (
    annualRevenueKrw < 0n || annualRevenueKrw > UINT64_MAX ||
    debtRatioBps < 0n || debtRatioBps > UINT32_MAX ||
    overdueCount < 0n || overdueCount > UINT16_MAX ||
    companyCommitmentHash < 0n || companyCommitmentHash > MAX_FIELD ||
    expected.onchainReceivableId <= 0n || expected.onchainReceivableId > UINT256_MAX
  ) {
    throw new Error('The role authorization request contains an out-of-range value.');
  }
  if (!LOWER_BYTES32_PATTERN.test(authorizationSalt) || authorizationSalt === ZERO_BYTES32) {
    throw new Error('The generated authorization salt is invalid.');
  }

  return Object.freeze({
    version: AUTHORIZATION_VERSION,
    annualRevenueKrw: annualRevenueKrw.toString(),
    debtRatioBps: debtRatioBps.toString(),
    overdueCount: overdueCount.toString(),
    companyCommitmentHash: companyCommitmentHash.toString(),
    authorizationSalt,
    midnightContractAddress,
    onchainReceivableId: expected.onchainReceivableId.toString(),
    subjectRole: expected.subjectRole,
  });
}

export function buildAttestationRequestCommitment(
  request: AuthorizationChallengeRequest,
  partyWalletInput: string,
): string {
  const partyWallet = normalizeEvmAddress(partyWalletInput, 'Authorized GIWA party wallet');
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
      BigInt(request.annualRevenueKrw),
      BigInt(request.debtRatioBps),
      BigInt(request.overdueCount),
      BigInt(request.companyCommitmentHash),
      `0x${normalizeMidnightContractAddress(request.midnightContractAddress)}`,
      GIWA_CHAIN_ID,
      RECEIVABLE_FINANCE_ADDRESS,
      BigInt(request.onchainReceivableId),
      request.subjectRole,
      partyWallet,
      AUTHORIZATION_PROVIDER_ID,
      AUTHORIZATION_POLICY_VERSION,
      request.authorizationSalt,
    ],
  );
  return keccak256(encoded).toLowerCase();
}

function validateAuthorizationTypeSchema(value: unknown): void {
  const types = requireExactRecord(value, [AUTHORIZATION_PRIMARY_TYPE], invalidChallenge);
  const fields = types[AUTHORIZATION_PRIMARY_TYPE];
  if (!Array.isArray(fields) || fields.length !== AUTHORIZATION_FIELDS.length) {
    throw invalidChallenge();
  }
  fields.forEach((field, index) => {
    const parsed = requireExactRecord(field, ['name', 'type'], invalidChallenge);
    if (
      parsed.name !== AUTHORIZATION_FIELDS[index].name ||
      parsed.type !== AUTHORIZATION_FIELDS[index].type
    ) {
      throw invalidChallenge();
    }
  });
}

export function parseAuthorizationChallenge(
  value: unknown,
  request: AuthorizationChallengeRequest,
  expected: AuthorizationExpectedContext,
  nowSeconds: bigint = BigInt(Math.floor(Date.now() / 1_000)),
): AuthorizationChallenge {
  assertFixedGiwaDeployment(expected);
  const challenge = requireExactRecord(value, CHALLENGE_KEYS, invalidChallenge);
  const domain = requireExactRecord(challenge.domain, DOMAIN_KEYS, invalidChallenge);
  const message = requireExactRecord(challenge.message, MESSAGE_KEYS, invalidChallenge);
  validateAuthorizationTypeSchema(challenge.types);

  if (
    challenge.version !== AUTHORIZATION_VERSION ||
    challenge.primaryType !== AUTHORIZATION_PRIMARY_TYPE ||
    domain.name !== AUTHORIZATION_DOMAIN.name ||
    domain.version !== AUTHORIZATION_DOMAIN.version ||
    domain.chainId !== AUTHORIZATION_DOMAIN.chainId ||
    message.purpose !== AUTHORIZATION_PURPOSE ||
    typeof message.authorizationId !== 'string' ||
    !LOWER_BYTES32_PATTERN.test(message.authorizationId) ||
    message.authorizationId === ZERO_BYTES32 ||
    message.midnightContractAddress !== `0x${request.midnightContractAddress}` ||
    message.receivableFinanceAddress !== RECEIVABLE_FINANCE_ADDRESS ||
    message.onchainReceivableId !== request.onchainReceivableId ||
    message.subjectRole !== request.subjectRole ||
    typeof message.attestationRequestCommitment !== 'string' ||
    !LOWER_BYTES32_PATTERN.test(message.attestationRequestCommitment) ||
    message.attestationRequestCommitment === ZERO_BYTES32 ||
    message.providerId !== AUTHORIZATION_PROVIDER_ID.toString() ||
    message.policyVersion !== AUTHORIZATION_POLICY_VERSION.toString()
  ) {
    throw invalidChallenge();
  }

  const expectedContractAddress = normalizeMidnightContractAddress(expected.midnightContractAddress);
  if (
    request.midnightContractAddress !== expectedContractAddress ||
    request.onchainReceivableId !== expected.onchainReceivableId.toString() ||
    request.subjectRole !== expected.subjectRole
  ) {
    throw invalidChallenge();
  }

  const partyWallet = parseCanonicalPartyWallet(message.partyWallet);
  if (message.attestationRequestCommitment !== buildAttestationRequestCommitment(request, partyWallet)) {
    throw invalidChallenge();
  }

  const issuedAt = parseCanonicalUint(message.issuedAt, UINT64_MAX);
  const expiresAt = parseCanonicalUint(message.expiresAt, UINT64_MAX);
  if (
    issuedAt > nowSeconds ||
    expiresAt <= nowSeconds ||
    expiresAt <= issuedAt ||
    expiresAt - issuedAt > AUTHORIZATION_TTL_SECONDS
  ) {
    throw invalidChallenge();
  }

  return Object.freeze({
    version: AUTHORIZATION_VERSION,
    domain: AUTHORIZATION_DOMAIN,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    types: Object.freeze({
      [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS,
    }),
    message: Object.freeze({
      purpose: AUTHORIZATION_PURPOSE,
      authorizationId: message.authorizationId,
      midnightContractAddress: message.midnightContractAddress as string,
      receivableFinanceAddress: message.receivableFinanceAddress as string,
      onchainReceivableId: message.onchainReceivableId as string,
      subjectRole: message.subjectRole as SubjectRole,
      partyWallet,
      attestationRequestCommitment: message.attestationRequestCommitment,
      providerId: message.providerId as string,
      policyVersion: message.policyVersion as string,
      issuedAt: message.issuedAt as string,
      expiresAt: message.expiresAt as string,
    }),
  });
}

export function hashAuthorizationChallenge(challenge: AuthorizationChallenge): string {
  return TypedDataEncoder.hash(
    challenge.domain as TypedDataDomain,
    ETHERS_AUTHORIZATION_TYPES,
    challenge.message,
  ).toLowerCase();
}

export function validateAuthorizationProof(
  value: unknown,
  challenge: AuthorizationChallenge,
  nowSeconds: bigint = BigInt(Math.floor(Date.now() / 1_000)),
): AuthorizationProof {
  const proof = requireExactRecord(value, PROOF_KEYS, invalidAuthorizationProof);
  const expiresAt = parseCanonicalUint(challenge.message.expiresAt, UINT64_MAX);
  if (
    proof.version !== AUTHORIZATION_VERSION ||
    typeof proof.authorizationId !== 'string' ||
    !BYTES32_PATTERN.test(proof.authorizationId) ||
    proof.authorizationId.toLowerCase() === ZERO_BYTES32 ||
    typeof proof.typedDataHash !== 'string' ||
    !BYTES32_PATTERN.test(proof.typedDataHash) ||
    proof.typedDataHash.toLowerCase() === ZERO_BYTES32 ||
    typeof proof.signer !== 'string' ||
    !EVM_ADDRESS_PATTERN.test(proof.signer) ||
    typeof proof.signature !== 'string' ||
    !SIGNATURE_PATTERN.test(proof.signature) ||
    expiresAt <= nowSeconds
  ) {
    throw invalidAuthorizationProof();
  }

  const authorizationId = proof.authorizationId.toLowerCase();
  const typedDataHash = proof.typedDataHash.toLowerCase();
  const signature = proof.signature.toLowerCase();
  const expectedTypedDataHash = hashAuthorizationChallenge(challenge);
  let signer: string;
  let recovered: string;
  try {
    signer = getAddress(proof.signer).toLowerCase();
    recovered = getAddress(
      verifyTypedData(
        challenge.domain as TypedDataDomain,
        ETHERS_AUTHORIZATION_TYPES,
        challenge.message,
        signature,
      ),
    ).toLowerCase();
  } catch {
    throw invalidAuthorizationProof();
  }

  if (
    isZeroBytes(fixedHexToBytes(signer, 20, 'Authorization signer', { requirePrefix: true })) ||
    authorizationId !== challenge.message.authorizationId ||
    typedDataHash !== expectedTypedDataHash ||
    signer !== challenge.message.partyWallet ||
    recovered !== signer
  ) {
    throw invalidAuthorizationProof();
  }

  return Object.freeze({
    version: AUTHORIZATION_VERSION,
    authorizationId,
    typedDataHash,
    signer,
    signature,
  });
}

export function parseAuthorizationProofJson(
  input: string,
  challenge: AuthorizationChallenge,
  nowSeconds?: bigint,
): AuthorizationProof {
  if (
    typeof input !== 'string' ||
    input.includes('\n') ||
    input.includes('\r') ||
    Buffer.byteLength(input, 'utf8') > MAX_AUTHORIZATION_PROOF_JSON_BYTES
  ) {
    throw invalidAuthorizationProof();
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(input) as unknown;
  } catch {
    throw invalidAuthorizationProof();
  }
  return validateAuthorizationProof(parsed, challenge, nowSeconds);
}
