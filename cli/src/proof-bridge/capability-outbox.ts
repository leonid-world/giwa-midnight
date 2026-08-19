// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { constants, type Stats } from 'node:fs';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { createCipheriv, createDecipheriv, randomBytes, scrypt } from 'node:crypto';
import type { ProofCapability } from '../api.js';
import { currentDir } from '../config.js';
import type { ProofSessionCompleteResponse } from './types.js';
import { PROOF_BRIDGE_VERSION } from './types.js';

const OUTBOX_SCHEMA_VERSION = 1 as const;
const OUTBOX_AAD = Buffer.from('gasok-midnight-proof-capability-outbox:v1', 'utf8');
const REQUEST_ID_PATTERN = /^0x[0-9a-f]{64}$/;
const SESSION_ID_PATTERN = /^0x[0-9a-f]{64}$/;
const LOWER_HEX_32_PATTERN = /^0x[0-9a-f]{64}$/;
const CONTRACT_ADDRESS_PATTERN = /^[0-9a-f]{64}$/;
const EVM_ADDRESS_PATTERN = /^0x[0-9a-f]{40}$/;
const CANONICAL_UNSIGNED_PATTERN = /^(0|[1-9][0-9]*)$/;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const MAX_OUTBOX_FILE_BYTES = 256 * 1_024;
const MAX_OUTBOX_RECORDS = 32;
const MAX_ACKNOWLEDGEMENTS = 64;
const SALT_BYTES = 32;
const IV_BYTES = 12;
const TAG_BYTES = 16;
const CAPABILITY_KEYS = [
  'companyCommitment',
  'evaluationVersion',
  'giwaChainId',
  'intendedFunderWallet',
  'lookupKey',
  'maxDebtRatioBps',
  'maxOverdueCount',
  'midnightContractAddress',
  'minAnnualRevenueKrw',
  'onchainReceivableId',
  'partyWallet',
  'policyRequestHash',
  'profileAsOf',
  'receivableFinanceAddress',
  'requestId',
  'subjectRole',
  'validUntil',
  'version',
] as const;
const BINDING_KEYS = [
  'intendedFunderWallet',
  'maxDebtRatioBps',
  'maxOverdueCount',
  'minAnnualRevenueKrw',
  'onchainReceivableId',
  'partyWallet',
  'requestId',
  'subjectRole',
  'validUntil',
] as const;
const RECORD_KEYS = ['binding', 'capability', 'requestId', 'sessionId', 'storedAt', 'version'] as const;
const RESERVATION_KEYS = ['authorizationExpiresAt', 'binding', 'requestId', 'sessionId', 'state', 'version'] as const;
const ACK_KEYS = ['acknowledgedAt', 'expiresAt', 'requestId', 'sessionId', 'version'] as const;
const PLAINTEXT_KEYS = ['acknowledgements', 'records', 'reservations', 'version'] as const;
const ENVELOPE_KEYS = ['ciphertext', 'iv', 'kdf', 'salt', 'tag', 'version'] as const;

export const DEFAULT_CAPABILITY_OUTBOX_DIRECTORY = path.resolve(currentDir, '..', '.gasok-midnight-capability-outbox');
export const DEFAULT_CAPABILITY_OUTBOX_PATH = path.join(DEFAULT_CAPABILITY_OUTBOX_DIRECTORY, 'outbox.enc');

export interface CapabilityBinding {
  readonly requestId: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: 'SELLER' | 'BUYER';
  readonly partyWallet: string;
  readonly intendedFunderWallet: string;
  readonly minAnnualRevenueKrw: string;
  readonly maxDebtRatioBps: string;
  readonly maxOverdueCount: string;
  readonly validUntil: string;
}

interface CapabilityReservation {
  readonly version: 1;
  readonly requestId: string;
  readonly sessionId: string;
  readonly state: 'awaiting_authorization' | 'proving';
  readonly authorizationExpiresAt: string;
  readonly binding: CapabilityBinding;
}

interface CapabilityRecord {
  readonly version: 1;
  readonly requestId: string;
  readonly sessionId: string;
  readonly storedAt: string;
  readonly binding: CapabilityBinding;
  readonly capability: ProofCapability;
}

interface AcknowledgementRecord {
  readonly version: 1;
  readonly requestId: string;
  readonly sessionId: string;
  readonly expiresAt: string;
  readonly acknowledgedAt: string;
}

interface PlaintextOutbox {
  readonly version: 1;
  readonly reservations: CapabilityReservation[];
  readonly records: CapabilityRecord[];
  readonly acknowledgements: AcknowledgementRecord[];
}

interface EncryptedEnvelope {
  readonly version: 1;
  readonly kdf: 'scrypt-v1';
  readonly salt: string;
  readonly iv: string;
  readonly tag: string;
  readonly ciphertext: string;
}

export interface CapabilityOutboxOptions {
  readonly filePath?: string;
  readonly password: string;
  readonly now?: () => number;
  readonly random?: (size: number) => Buffer;
}

export interface ProofCapabilityOutbox {
  assertRequestAvailable(requestId: string): void;
  reserve(sessionId: string, binding: CapabilityBinding, authorizationExpiresAt: string): Promise<void>;
  markProving(sessionId: string, requestId: string): Promise<void>;
  releaseAwaiting(sessionId: string, requestId: string): Promise<void>;
  persist(sessionId: string, capability: ProofCapability): Promise<void>;
  recoverByRequest(requestId: string): ProofSessionCompleteResponse;
  recoverBySession(sessionId: string): ProofSessionCompleteResponse;
  acknowledge(sessionId: string, requestId: string): Promise<void>;
  close(): void;
}

export class CapabilityOutboxError extends Error {
  constructor(
    readonly code: string,
    readonly publicMessage: string,
  ) {
    super(publicMessage);
    this.name = 'CapabilityOutboxError';
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function hasExactKeys(value: Record<string, unknown>, expected: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function invalidOutbox(): CapabilityOutboxError {
  return new CapabilityOutboxError(
    'CAPABILITY_OUTBOX_INVALID',
    'The encrypted local proof result outbox is invalid or cannot be decrypted.',
  );
}

function unavailableOutbox(): CapabilityOutboxError {
  return new CapabilityOutboxError(
    'CAPABILITY_OUTBOX_UNAVAILABLE',
    'The encrypted local proof result outbox is unavailable.',
  );
}

function resultNotFound(): CapabilityOutboxError {
  return new CapabilityOutboxError('PROOF_RESULT_NOT_FOUND', 'No recoverable finalized proof result was found.');
}

function resultAvailable(): CapabilityOutboxError {
  return new CapabilityOutboxError(
    'PROOF_RESULT_AVAILABLE',
    'A finalized proof result already exists for this request. Recover it instead of proving again.',
  );
}

function resultAlreadyDelivered(): CapabilityOutboxError {
  return new CapabilityOutboxError(
    'PROOF_RESULT_ALREADY_DELIVERED',
    'This proof result was already acknowledged after durable delivery.',
  );
}

function resultBindingMismatch(): CapabilityOutboxError {
  return new CapabilityOutboxError(
    'PROOF_RESULT_BINDING_MISMATCH',
    'The proof result acknowledgement does not match the finalized request and session.',
  );
}

function canonicalUnsigned(value: unknown, positive = false): string {
  if (typeof value !== 'string' || !CANONICAL_UNSIGNED_PATTERN.test(value) || (positive && value === '0')) {
    throw invalidOutbox();
  }
  return value;
}

function requestId(value: unknown): string {
  if (typeof value !== 'string' || !REQUEST_ID_PATTERN.test(value) || value === ZERO_BYTES32) {
    throw invalidOutbox();
  }
  return value;
}

function sessionId(value: unknown): string {
  if (typeof value !== 'string' || !SESSION_ID_PATTERN.test(value) || value === ZERO_BYTES32) {
    throw invalidOutbox();
  }
  return value;
}

function address(value: unknown): string {
  if (typeof value !== 'string' || !EVM_ADDRESS_PATTERN.test(value) || value === ZERO_ADDRESS) {
    throw invalidOutbox();
  }
  return value;
}

function bytes32(value: unknown, prefixed = true): string {
  const pattern = prefixed ? LOWER_HEX_32_PATTERN : CONTRACT_ADDRESS_PATTERN;
  if (typeof value !== 'string' || !pattern.test(value) || (prefixed && value === ZERO_BYTES32)) {
    throw invalidOutbox();
  }
  return value;
}

function parseCapability(value: unknown): ProofCapability {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, CAPABILITY_KEYS) ||
    value.version !== 2 ||
    value.evaluationVersion !== 2
  ) {
    throw invalidOutbox();
  }
  if (value.subjectRole !== 'SELLER' && value.subjectRole !== 'BUYER') {
    throw invalidOutbox();
  }
  const parsed: ProofCapability = {
    version: 2,
    evaluationVersion: 2,
    midnightContractAddress: bytes32(value.midnightContractAddress, false),
    companyCommitment: bytes32(value.companyCommitment),
    lookupKey: bytes32(value.lookupKey),
    giwaChainId: canonicalUnsigned(value.giwaChainId, true),
    receivableFinanceAddress: address(value.receivableFinanceAddress),
    onchainReceivableId: canonicalUnsigned(value.onchainReceivableId, true),
    subjectRole: value.subjectRole,
    partyWallet: address(value.partyWallet),
    requestId: requestId(value.requestId),
    intendedFunderWallet: address(value.intendedFunderWallet),
    minAnnualRevenueKrw: canonicalUnsigned(value.minAnnualRevenueKrw),
    maxDebtRatioBps: canonicalUnsigned(value.maxDebtRatioBps),
    maxOverdueCount: canonicalUnsigned(value.maxOverdueCount),
    policyRequestHash: bytes32(value.policyRequestHash),
    profileAsOf: canonicalUnsigned(value.profileAsOf, true),
    validUntil: canonicalUnsigned(value.validUntil, true),
  };
  if (BigInt(parsed.profileAsOf) > BigInt(parsed.validUntil)) {
    throw invalidOutbox();
  }
  return Object.freeze(parsed);
}

function bindingFor(capability: ProofCapability): CapabilityBinding {
  return Object.freeze({
    requestId: capability.requestId,
    onchainReceivableId: capability.onchainReceivableId,
    subjectRole: capability.subjectRole,
    partyWallet: capability.partyWallet,
    intendedFunderWallet: capability.intendedFunderWallet,
    minAnnualRevenueKrw: capability.minAnnualRevenueKrw,
    maxDebtRatioBps: capability.maxDebtRatioBps,
    maxOverdueCount: capability.maxOverdueCount,
    validUntil: capability.validUntil,
  });
}

function parseBinding(value: unknown, expectedCapability?: ProofCapability): CapabilityBinding {
  if (!isRecord(value) || !hasExactKeys(value, BINDING_KEYS)) {
    throw invalidOutbox();
  }
  if (value.subjectRole !== 'SELLER' && value.subjectRole !== 'BUYER') {
    throw invalidOutbox();
  }
  const binding: CapabilityBinding = {
    requestId: requestId(value.requestId),
    onchainReceivableId: canonicalUnsigned(value.onchainReceivableId, true),
    subjectRole: value.subjectRole,
    partyWallet: address(value.partyWallet),
    intendedFunderWallet: address(value.intendedFunderWallet),
    minAnnualRevenueKrw: canonicalUnsigned(value.minAnnualRevenueKrw),
    maxDebtRatioBps: canonicalUnsigned(value.maxDebtRatioBps),
    maxOverdueCount: canonicalUnsigned(value.maxOverdueCount),
    validUntil: canonicalUnsigned(value.validUntil, true),
  };
  const expected = expectedCapability === undefined ? undefined : bindingFor(expectedCapability);
  if (expected !== undefined && BINDING_KEYS.some((key) => binding[key] !== expected[key])) {
    throw invalidOutbox();
  }
  return Object.freeze(binding);
}

function parsePlaintext(value: unknown): PlaintextOutbox {
  if (!isRecord(value) || !hasExactKeys(value, PLAINTEXT_KEYS) || value.version !== 1) {
    throw invalidOutbox();
  }
  if (
    !Array.isArray(value.reservations) ||
    !Array.isArray(value.records) ||
    !Array.isArray(value.acknowledgements) ||
    value.reservations.length > MAX_OUTBOX_RECORDS ||
    value.records.length > MAX_OUTBOX_RECORDS ||
    value.acknowledgements.length > MAX_ACKNOWLEDGEMENTS
  ) {
    throw invalidOutbox();
  }
  const seenRequests = new Set<string>();
  const seenSessions = new Set<string>();
  const reservations = value.reservations.map((candidate): CapabilityReservation => {
    if (
      !isRecord(candidate) ||
      !hasExactKeys(candidate, RESERVATION_KEYS) ||
      candidate.version !== 1 ||
      (candidate.state !== 'awaiting_authorization' && candidate.state !== 'proving')
    ) {
      throw invalidOutbox();
    }
    const parsedRequestId = requestId(candidate.requestId);
    const parsedSessionId = sessionId(candidate.sessionId);
    const binding = parseBinding(candidate.binding);
    if (
      binding.requestId !== parsedRequestId ||
      seenRequests.has(parsedRequestId) ||
      seenSessions.has(parsedSessionId)
    ) {
      throw invalidOutbox();
    }
    seenRequests.add(parsedRequestId);
    seenSessions.add(parsedSessionId);
    return Object.freeze({
      version: 1,
      requestId: parsedRequestId,
      sessionId: parsedSessionId,
      state: candidate.state,
      authorizationExpiresAt: canonicalUnsigned(candidate.authorizationExpiresAt, true),
      binding,
    });
  });
  const records = value.records.map((candidate): CapabilityRecord => {
    if (!isRecord(candidate) || !hasExactKeys(candidate, RECORD_KEYS) || candidate.version !== 1) {
      throw invalidOutbox();
    }
    const capability = parseCapability(candidate.capability);
    const parsedRequestId = requestId(candidate.requestId);
    const parsedSessionId = sessionId(candidate.sessionId);
    const storedAt = canonicalUnsigned(candidate.storedAt, true);
    if (
      parsedRequestId !== capability.requestId ||
      seenRequests.has(parsedRequestId) ||
      seenSessions.has(parsedSessionId)
    ) {
      throw invalidOutbox();
    }
    seenRequests.add(parsedRequestId);
    seenSessions.add(parsedSessionId);
    return Object.freeze({
      version: 1,
      requestId: parsedRequestId,
      sessionId: parsedSessionId,
      storedAt,
      binding: parseBinding(candidate.binding, capability),
      capability,
    });
  });
  const acknowledgements = value.acknowledgements.map((candidate): AcknowledgementRecord => {
    if (!isRecord(candidate) || !hasExactKeys(candidate, ACK_KEYS) || candidate.version !== 1) {
      throw invalidOutbox();
    }
    const parsedRequestId = requestId(candidate.requestId);
    const parsedSessionId = sessionId(candidate.sessionId);
    if (seenRequests.has(parsedRequestId) || seenSessions.has(parsedSessionId)) {
      throw invalidOutbox();
    }
    seenRequests.add(parsedRequestId);
    seenSessions.add(parsedSessionId);
    return Object.freeze({
      version: 1,
      requestId: parsedRequestId,
      sessionId: parsedSessionId,
      expiresAt: canonicalUnsigned(candidate.expiresAt, true),
      acknowledgedAt: canonicalUnsigned(candidate.acknowledgedAt, true),
    });
  });
  return { version: 1, reservations, records, acknowledgements };
}

function parseEnvelope(value: unknown): EncryptedEnvelope {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ENVELOPE_KEYS) ||
    value.version !== 1 ||
    value.kdf !== 'scrypt-v1' ||
    typeof value.salt !== 'string' ||
    typeof value.iv !== 'string' ||
    typeof value.tag !== 'string' ||
    typeof value.ciphertext !== 'string'
  ) {
    throw invalidOutbox();
  }
  let salt: Buffer;
  let iv: Buffer;
  let tag: Buffer;
  let ciphertext: Buffer;
  try {
    salt = Buffer.from(value.salt, 'base64');
    iv = Buffer.from(value.iv, 'base64');
    tag = Buffer.from(value.tag, 'base64');
    ciphertext = Buffer.from(value.ciphertext, 'base64');
  } catch {
    throw invalidOutbox();
  }
  if (
    salt.length !== SALT_BYTES ||
    iv.length !== IV_BYTES ||
    tag.length !== TAG_BYTES ||
    ciphertext.length === 0 ||
    salt.toString('base64') !== value.salt ||
    iv.toString('base64') !== value.iv ||
    tag.toString('base64') !== value.tag ||
    ciphertext.toString('base64') !== value.ciphertext
  ) {
    throw invalidOutbox();
  }
  return value as unknown as EncryptedEnvelope;
}

async function deriveKey(password: string, salt: Buffer): Promise<Buffer> {
  if (password.length === 0) {
    throw unavailableOutbox();
  }
  return await new Promise<Buffer>((resolve, reject) => {
    scrypt(password, salt, 32, { N: 1 << 15, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }, (error, key) => {
      if (error !== null) {
        reject(unavailableOutbox());
        return;
      }
      resolve(key);
    });
  });
}

async function safeExistingFile(filePath: string): Promise<Stats | null> {
  try {
    const stat = await fs.lstat(filePath);
    if (
      !stat.isFile() ||
      stat.isSymbolicLink() ||
      stat.size <= 0 ||
      stat.size > MAX_OUTBOX_FILE_BYTES ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    ) {
      throw invalidOutbox();
    }
    return stat;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return null;
    }
    throw error;
  }
}

async function prepareDirectory(directory: string): Promise<void> {
  try {
    await fs.mkdir(directory, { recursive: true, mode: 0o700 });
    const stat = await fs.lstat(directory);
    if (
      !stat.isDirectory() ||
      stat.isSymbolicLink() ||
      (typeof process.getuid === 'function' && stat.uid !== process.getuid())
    ) {
      throw unavailableOutbox();
    }
    await fs.chmod(directory, 0o700);
  } catch (error: unknown) {
    if (error instanceof CapabilityOutboxError) {
      throw error;
    }
    throw unavailableOutbox();
  }
}

function toComplete(record: CapabilityRecord): ProofSessionCompleteResponse {
  return Object.freeze({
    version: PROOF_BRIDGE_VERSION,
    sessionId: record.sessionId,
    status: 'complete',
    proofCapability: record.capability,
  });
}

class EncryptedCapabilityOutbox implements ProofCapabilityOutbox {
  readonly #filePath: string;
  readonly #directory: string;
  readonly #now: () => number;
  readonly #random: (size: number) => Buffer;
  readonly #key: Buffer;
  readonly #salt: Buffer;
  #reservations: CapabilityReservation[];
  #records: CapabilityRecord[];
  #acknowledgements: AcknowledgementRecord[];
  #mutationTail: Promise<void> = Promise.resolve();
  #mutationInProgress = false;
  #closed = false;

  constructor(
    options: Required<Pick<CapabilityOutboxOptions, 'filePath' | 'now' | 'random'>>,
    key: Buffer,
    salt: Buffer,
    plaintext: PlaintextOutbox,
  ) {
    this.#filePath = options.filePath;
    this.#directory = path.dirname(options.filePath);
    this.#now = options.now;
    this.#random = options.random;
    this.#key = key;
    this.#salt = salt;
    this.#reservations = plaintext.reservations;
    this.#records = plaintext.records;
    this.#acknowledgements = plaintext.acknowledgements;
    this.#removeExpired();
  }

  assertRequestAvailable(candidateRequestId: string): void {
    this.#assertOpen();
    if (this.#mutationInProgress) {
      throw unavailableOutbox();
    }
    this.#assertRequestAvailableUnlocked(candidateRequestId);
  }

  #assertRequestAvailableUnlocked(candidateRequestId: string): void {
    const normalized = requestId(candidateRequestId);
    this.#removeExpired();
    if (this.#reservations.some((record) => record.requestId === normalized)) {
      throw new CapabilityOutboxError(
        'PROOF_RESULT_IN_PROGRESS',
        'A proof attempt for this request is already reserved or may have been submitted. Do not prove it again.',
      );
    }
    if (this.#records.some((record) => record.requestId === normalized)) {
      throw resultAvailable();
    }
    if (this.#acknowledgements.some((record) => record.requestId === normalized)) {
      throw resultAlreadyDelivered();
    }
  }

  async reserve(
    candidateSessionId: string,
    candidateBinding: CapabilityBinding,
    candidateAuthorizationExpiresAt: string,
  ): Promise<void> {
    await this.#mutate(async () => {
      const normalizedSessionId = sessionId(candidateSessionId);
      const binding = parseBinding(candidateBinding);
      const authorizationExpiresAt = canonicalUnsigned(candidateAuthorizationExpiresAt, true);
      this.#removeExpired();
      if (
        BigInt(authorizationExpiresAt) <= this.#nowSeconds() ||
        BigInt(binding.validUntil) <= this.#nowSeconds() ||
        BigInt(authorizationExpiresAt) > BigInt(binding.validUntil)
      ) {
        throw new CapabilityOutboxError('POLICY_REQUEST_EXPIRED', 'The Funder policy request expired.');
      }
      this.#assertRequestAvailableUnlocked(binding.requestId);
      if (
        this.#reservations.some((record) => record.sessionId === normalizedSessionId) ||
        this.#records.some((record) => record.sessionId === normalizedSessionId) ||
        this.#acknowledgements.some((record) => record.sessionId === normalizedSessionId)
      ) {
        throw resultBindingMismatch();
      }
      if (this.#reservations.length + this.#records.length >= MAX_OUTBOX_RECORDS) {
        throw unavailableOutbox();
      }
      const previous = this.#reservations;
      this.#reservations = [
        ...this.#reservations,
        Object.freeze({
          version: OUTBOX_SCHEMA_VERSION,
          requestId: binding.requestId,
          sessionId: normalizedSessionId,
          state: 'awaiting_authorization',
          authorizationExpiresAt,
          binding,
        }),
      ];
      try {
        await this.#write();
      } catch (error: unknown) {
        this.#reservations = previous;
        throw error;
      }
    });
  }

  async markProving(candidateSessionId: string, candidateRequestId: string): Promise<void> {
    await this.#mutate(async () => {
      const normalizedSessionId = sessionId(candidateSessionId);
      const normalizedRequestId = requestId(candidateRequestId);
      this.#removeExpired();
      const index = this.#reservations.findIndex(
        (record) => record.sessionId === normalizedSessionId && record.requestId === normalizedRequestId,
      );
      if (index < 0) {
        throw resultBindingMismatch();
      }
      if (this.#reservations[index].state === 'proving') {
        return;
      }
      const previous = this.#reservations;
      this.#reservations = this.#reservations.map((record, candidateIndex) =>
        candidateIndex === index ? Object.freeze({ ...record, state: 'proving' as const }) : record,
      );
      try {
        await this.#write();
      } catch (error: unknown) {
        this.#reservations = previous;
        throw error;
      }
    });
  }

  async releaseAwaiting(candidateSessionId: string, candidateRequestId: string): Promise<void> {
    await this.#mutate(async () => {
      const normalizedSessionId = sessionId(candidateSessionId);
      const normalizedRequestId = requestId(candidateRequestId);
      this.#removeExpired();
      const reservation = this.#reservations.find(
        (record) => record.sessionId === normalizedSessionId && record.requestId === normalizedRequestId,
      );
      if (reservation === undefined || reservation.state !== 'awaiting_authorization') {
        return;
      }
      const previous = this.#reservations;
      this.#reservations = this.#reservations.filter((record) => record !== reservation);
      try {
        await this.#write();
      } catch (error: unknown) {
        this.#reservations = previous;
        throw error;
      }
    });
  }

  async persist(candidateSessionId: string, candidateCapability: ProofCapability): Promise<void> {
    await this.#mutate(async () => {
      const normalizedSessionId = sessionId(candidateSessionId);
      const capability = parseCapability(candidateCapability);
      this.#removeExpired();
      if (BigInt(capability.validUntil) <= this.#nowSeconds()) {
        throw new CapabilityOutboxError('POLICY_REQUEST_EXPIRED', 'The Funder policy request expired.');
      }
      const sameRequest = this.#records.find((record) => record.requestId === capability.requestId);
      if (sameRequest !== undefined) {
        if (
          sameRequest.sessionId === normalizedSessionId &&
          sameRequest.capability.lookupKey === capability.lookupKey
        ) {
          return;
        }
        throw resultBindingMismatch();
      }
      const reservationIndex = this.#reservations.findIndex(
        (record) => record.sessionId === normalizedSessionId && record.requestId === capability.requestId,
      );
      if (
        reservationIndex < 0 ||
        this.#reservations[reservationIndex].state !== 'proving' ||
        BINDING_KEYS.some((key) => this.#reservations[reservationIndex].binding[key] !== bindingFor(capability)[key]) ||
        this.#records.some((record) => record.sessionId === normalizedSessionId) ||
        this.#acknowledgements.some(
          (record) => record.requestId === capability.requestId || record.sessionId === normalizedSessionId,
        )
      ) {
        throw resultBindingMismatch();
      }
      if (this.#records.length >= MAX_OUTBOX_RECORDS) {
        throw unavailableOutbox();
      }
      const previousReservations = this.#reservations;
      const previousRecords = this.#records;
      this.#reservations = this.#reservations.filter((_, index) => index !== reservationIndex);
      this.#records = [
        ...this.#records,
        Object.freeze({
          version: OUTBOX_SCHEMA_VERSION,
          requestId: capability.requestId,
          sessionId: normalizedSessionId,
          storedAt: this.#nowSeconds().toString(),
          binding: bindingFor(capability),
          capability,
        }),
      ];
      try {
        await this.#write();
      } catch (error: unknown) {
        this.#reservations = previousReservations;
        this.#records = previousRecords;
        throw error;
      }
    });
  }

  recoverByRequest(candidateRequestId: string): ProofSessionCompleteResponse {
    this.#assertOpen();
    if (this.#mutationInProgress) {
      throw new CapabilityOutboxError(
        'PROOF_RESULT_IN_PROGRESS',
        'The encrypted proof result outbox is being durably updated. Retry recovery without re-proving.',
      );
    }
    const normalized = requestId(candidateRequestId);
    this.#removeExpired();
    const record = this.#records.find((candidate) => candidate.requestId === normalized);
    if (record === undefined) {
      if (this.#reservations.some((candidate) => candidate.requestId === normalized)) {
        throw new CapabilityOutboxError(
          'PROOF_RESULT_IN_PROGRESS',
          'A proof attempt for this request is reserved or has an indeterminate submission state. Do not prove it again.',
        );
      }
      throw resultNotFound();
    }
    return toComplete(record);
  }

  recoverBySession(candidateSessionId: string): ProofSessionCompleteResponse {
    this.#assertOpen();
    if (this.#mutationInProgress) {
      throw new CapabilityOutboxError(
        'PROOF_RESULT_IN_PROGRESS',
        'The encrypted proof result outbox is being durably updated. Retry status without re-proving.',
      );
    }
    const normalized = sessionId(candidateSessionId);
    this.#removeExpired();
    const record = this.#records.find((candidate) => candidate.sessionId === normalized);
    if (record === undefined) {
      if (this.#reservations.some((candidate) => candidate.sessionId === normalized)) {
        throw new CapabilityOutboxError(
          'PROOF_RESULT_IN_PROGRESS',
          'A proof attempt for this session is reserved or has an indeterminate submission state.',
        );
      }
      throw resultNotFound();
    }
    return toComplete(record);
  }

  async acknowledge(candidateSessionId: string, candidateRequestId: string): Promise<void> {
    await this.#mutate(async () => {
      const normalizedSessionId = sessionId(candidateSessionId);
      const normalizedRequestId = requestId(candidateRequestId);
      this.#removeExpired();
      if (
        this.#acknowledgements.some(
          (record) => record.sessionId === normalizedSessionId && record.requestId === normalizedRequestId,
        )
      ) {
        return;
      }
      const index = this.#records.findIndex(
        (record) => record.sessionId === normalizedSessionId && record.requestId === normalizedRequestId,
      );
      if (index < 0) {
        const colliding =
          this.#reservations.some(
            (record) => record.sessionId === normalizedSessionId || record.requestId === normalizedRequestId,
          ) ||
          this.#records.some(
            (record) => record.sessionId === normalizedSessionId || record.requestId === normalizedRequestId,
          ) ||
          this.#acknowledgements.some(
            (record) => record.sessionId === normalizedSessionId || record.requestId === normalizedRequestId,
          );
        throw colliding ? resultBindingMismatch() : resultNotFound();
      }
      const record = this.#records[index];
      if (this.#acknowledgements.length >= MAX_ACKNOWLEDGEMENTS) {
        throw unavailableOutbox();
      }
      const previousRecords = this.#records;
      const previousAcknowledgements = this.#acknowledgements;
      this.#records = this.#records.filter((_, candidateIndex) => candidateIndex !== index);
      this.#acknowledgements = [
        ...this.#acknowledgements,
        Object.freeze({
          version: OUTBOX_SCHEMA_VERSION,
          requestId: normalizedRequestId,
          sessionId: normalizedSessionId,
          expiresAt: record.capability.validUntil,
          acknowledgedAt: this.#nowSeconds().toString(),
        }),
      ];
      try {
        await this.#write();
      } catch (error: unknown) {
        this.#records = previousRecords;
        this.#acknowledgements = previousAcknowledgements;
        throw error;
      }
    });
  }

  close(): void {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    this.#reservations = [];
    this.#records = [];
    this.#acknowledgements = [];
    this.#key.fill(0);
    this.#salt.fill(0);
  }

  async flush(): Promise<void> {
    await this.#mutate(async () => {
      this.#removeExpired();
      await this.#write();
    });
  }

  async #mutate(operation: () => Promise<void>): Promise<void> {
    this.#assertOpen();
    const previous = this.#mutationTail;
    let release!: () => void;
    this.#mutationTail = new Promise<void>((resolve) => {
      release = resolve;
    });
    await previous;
    try {
      this.#assertOpen();
      this.#mutationInProgress = true;
      await operation();
    } finally {
      this.#mutationInProgress = false;
      release();
    }
  }

  #assertOpen(): void {
    if (this.#closed) {
      throw unavailableOutbox();
    }
  }

  #nowSeconds(): bigint {
    return BigInt(Math.floor(this.#now() / 1_000));
  }

  #removeExpired(): void {
    const now = this.#nowSeconds();
    this.#reservations = this.#reservations.filter((record) =>
      record.state === 'awaiting_authorization'
        ? BigInt(record.authorizationExpiresAt) > now
        : BigInt(record.binding.validUntil) > now,
    );
    this.#records = this.#records.filter((record) => BigInt(record.capability.validUntil) > now);
    this.#acknowledgements = this.#acknowledgements.filter((record) => BigInt(record.expiresAt) > now);
  }

  async #write(): Promise<void> {
    const plaintext: PlaintextOutbox = {
      version: OUTBOX_SCHEMA_VERSION,
      reservations: this.#reservations,
      records: this.#records,
      acknowledgements: this.#acknowledgements,
    };
    const serialized = Buffer.from(JSON.stringify(plaintext), 'utf8');
    const iv = this.#random(IV_BYTES);
    if (iv.length !== IV_BYTES) {
      throw unavailableOutbox();
    }
    const cipher = createCipheriv('aes-256-gcm', this.#key, iv);
    cipher.setAAD(OUTBOX_AAD);
    const ciphertext = Buffer.concat([cipher.update(serialized), cipher.final()]);
    const envelope: EncryptedEnvelope = {
      version: OUTBOX_SCHEMA_VERSION,
      kdf: 'scrypt-v1',
      salt: this.#salt.toString('base64'),
      iv: iv.toString('base64'),
      tag: cipher.getAuthTag().toString('base64'),
      ciphertext: ciphertext.toString('base64'),
    };
    serialized.fill(0);
    ciphertext.fill(0);
    const encoded = Buffer.from(`${JSON.stringify(envelope)}\n`, 'utf8');
    if (encoded.length > MAX_OUTBOX_FILE_BYTES) {
      encoded.fill(0);
      throw unavailableOutbox();
    }
    const temporaryPath = path.join(this.#directory, `.outbox-${process.pid}-${this.#random(16).toString('hex')}.tmp`);
    let handle: fs.FileHandle | undefined;
    try {
      const existing = await safeExistingFile(this.#filePath);
      if (existing !== null && (existing.mode & 0o077) !== 0) {
        await fs.chmod(this.#filePath, 0o600);
      }
      handle = await fs.open(temporaryPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      await handle.writeFile(encoded);
      await handle.sync();
      await handle.close();
      handle = undefined;
      await fs.rename(temporaryPath, this.#filePath);
      await fs.chmod(this.#filePath, 0o600);
      const directoryHandle = await fs.open(this.#directory, constants.O_RDONLY);
      try {
        await directoryHandle.sync();
      } finally {
        await directoryHandle.close();
      }
    } catch (error: unknown) {
      await handle?.close().catch(() => undefined);
      await fs.unlink(temporaryPath).catch(() => undefined);
      if (error instanceof CapabilityOutboxError) {
        throw error;
      }
      throw unavailableOutbox();
    } finally {
      encoded.fill(0);
    }
  }
}

export async function openCapabilityOutbox(options: CapabilityOutboxOptions): Promise<ProofCapabilityOutbox> {
  const filePath = path.resolve(options.filePath ?? DEFAULT_CAPABILITY_OUTBOX_PATH);
  const now = options.now ?? Date.now;
  const random = options.random ?? randomBytes;
  await prepareDirectory(path.dirname(filePath));
  const existing = await safeExistingFile(filePath);
  let salt: Buffer;
  let plaintext: PlaintextOutbox;
  if (existing === null) {
    salt = random(SALT_BYTES);
    if (salt.length !== SALT_BYTES) {
      throw unavailableOutbox();
    }
    plaintext = { version: OUTBOX_SCHEMA_VERSION, reservations: [], records: [], acknowledgements: [] };
  } else {
    let encoded: string;
    try {
      encoded = await fs.readFile(filePath, 'utf8');
    } catch {
      throw invalidOutbox();
    }
    let envelope: EncryptedEnvelope;
    try {
      envelope = parseEnvelope(JSON.parse(encoded) as unknown);
    } catch (error: unknown) {
      if (error instanceof CapabilityOutboxError) {
        throw error;
      }
      throw invalidOutbox();
    }
    salt = Buffer.from(envelope.salt, 'base64');
    const key = await deriveKey(options.password, salt);
    let decrypted: Buffer;
    try {
      const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'base64'));
      decipher.setAAD(OUTBOX_AAD);
      decipher.setAuthTag(Buffer.from(envelope.tag, 'base64'));
      decrypted = Buffer.concat([decipher.update(Buffer.from(envelope.ciphertext, 'base64')), decipher.final()]);
    } catch {
      key.fill(0);
      throw invalidOutbox();
    }
    try {
      plaintext = parsePlaintext(JSON.parse(decrypted.toString('utf8')) as unknown);
    } catch (error: unknown) {
      key.fill(0);
      throw error instanceof CapabilityOutboxError ? error : invalidOutbox();
    } finally {
      decrypted.fill(0);
    }
    const outbox = new EncryptedCapabilityOutbox({ filePath, now, random }, key, salt, plaintext);
    try {
      await outbox.flush();
      return outbox;
    } catch (error: unknown) {
      outbox.close();
      throw error;
    }
  }
  const key = await deriveKey(options.password, salt);
  const outbox = new EncryptedCapabilityOutbox({ filePath, now, random }, key, salt, plaintext);
  try {
    await outbox.flush();
    return outbox;
  } catch (error: unknown) {
    outbox.close();
    throw error;
  }
}
