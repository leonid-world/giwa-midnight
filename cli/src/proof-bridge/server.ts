// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import * as http from 'node:http';
import type { AuthorizationProof } from '../authorization.js';
import { LocalAttestationApiError } from '../attestation-errors.js';
import { UINT16_MAX, UINT32_MAX, UINT64_MAX, UINT256_MAX, type SubjectRole } from '../giwa.js';
import { ProofSessionStoreError } from './session-store.js';
import { CapabilityOutboxError } from './capability-outbox.js';
import {
  PROOF_BRIDGE_MAX_BODY_BYTES,
  type ParsedProofChallengeInput,
  type ProofBridgeErrorResponse,
  type ProofChallengeRequest,
  type ProofAcknowledgementRequest,
  type ProofRecoveryRequest,
  type ProofSessionRequest,
  type ProofSubmissionRequest,
} from './types.js';
import type { ProofBridgeController } from './runtime.js';

const CHALLENGE_PATH = '/v2/proof-sessions/challenge';
const PROVE_PATH = '/v2/proof-sessions/prove';
const STATUS_PATH = '/v2/proof-sessions/status';
const CANCEL_PATH = '/v2/proof-sessions/cancel';
const RECOVER_PATH = '/v2/proof-sessions/recover';
const ACK_PATH = '/v2/proof-sessions/ack';
const PROTECTED_PATHS = new Set([CHALLENGE_PATH, PROVE_PATH, STATUS_PATH, CANCEL_PATH, RECOVER_PATH, ACK_PATH]);
const SESSION_ID_PATTERN = /^0x[0-9a-f]{64}$/;
const BYTES32_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const CHALLENGE_KEYS = [
  'annualRevenueKrw',
  'debtRatioBps',
  'onchainReceivableId',
  'overdueCount',
  'policyRequest',
  'subjectRole',
  'version',
] as const;
const POLICY_REQUEST_KEYS = [
  'requestId',
  'intendedFunderWallet',
  'minAnnualRevenueKrw',
  'maxDebtRatioBps',
  'maxOverdueCount',
  'validUntil',
] as const;
const SESSION_KEYS = ['sessionId', 'version'] as const;
const RECOVER_KEYS = ['requestId', 'version'] as const;
const ACK_KEYS = ['requestId', 'sessionId', 'version'] as const;
const PROVE_KEYS = ['authorization', 'sessionId', 'version'] as const;
const AUTHORIZATION_KEYS = ['authorizationId', 'signature', 'signer', 'typedDataHash', 'version'] as const;

export const PROOF_BRIDGE_REQUEST_TIMEOUT_MS = 10_000;
export const PROOF_BRIDGE_HEADERS_TIMEOUT_MS = 5_000;

export class ProofBridgeHttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly publicMessage: string,
  ) {
    super(publicMessage);
    this.name = 'ProofBridgeHttpError';
  }
}

export interface ProofBridgeServerOptions {
  readonly controller: ProofBridgeController;
  readonly allowedOrigins?: ReadonlySet<string>;
  readonly allowedHosts?: ReadonlySet<string>;
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function hasExactKeys(value: Record<string, unknown>, expected: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function invalidRequest(): ProofBridgeHttpError {
  return new ProofBridgeHttpError(400, 'INVALID_REQUEST', 'The request body is invalid.');
}

function requireExactRecord(value: unknown, expected: ReadonlyArray<string>): Record<string, unknown> {
  if (!isRecord(value) || !hasExactKeys(value, expected)) {
    throw invalidRequest();
  }
  return value;
}

function parseCanonicalUnsigned(value: unknown, maximum: bigint, positive = false): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw invalidRequest();
  }
  const parsed = BigInt(value);
  if (parsed > maximum || (positive && parsed === 0n)) {
    throw invalidRequest();
  }
  return parsed;
}

function parseSubjectRole(value: unknown): SubjectRole {
  if (value !== 'SELLER' && value !== 'BUYER') {
    throw invalidRequest();
  }
  return value;
}

export function parseChallengeRequest(
  value: unknown,
  nowSeconds: bigint = BigInt(Math.floor(Date.now() / 1_000)),
): ParsedProofChallengeInput {
  const body = requireExactRecord(value, CHALLENGE_KEYS) as unknown as ProofChallengeRequest;
  if (body.version !== 2) {
    throw invalidRequest();
  }
  const policyRequest = requireExactRecord(body.policyRequest, POLICY_REQUEST_KEYS);
  if (
    typeof policyRequest.requestId !== 'string' ||
    !SESSION_ID_PATTERN.test(policyRequest.requestId) ||
    policyRequest.requestId === ZERO_BYTES32 ||
    typeof policyRequest.intendedFunderWallet !== 'string' ||
    !/^0x[0-9a-f]{40}$/.test(policyRequest.intendedFunderWallet) ||
    policyRequest.intendedFunderWallet === ZERO_ADDRESS
  ) {
    throw invalidRequest();
  }
  const validUntil = parseCanonicalUnsigned(policyRequest.validUntil, UINT64_MAX, true);
  if (validUntil <= nowSeconds) {
    throw invalidRequest();
  }
  return Object.freeze({
    onchainReceivableId: parseCanonicalUnsigned(body.onchainReceivableId, UINT256_MAX, true),
    subjectRole: parseSubjectRole(body.subjectRole),
    annualRevenueKrw: parseCanonicalUnsigned(body.annualRevenueKrw, UINT64_MAX),
    debtRatioBps: parseCanonicalUnsigned(body.debtRatioBps, UINT32_MAX),
    overdueCount: parseCanonicalUnsigned(body.overdueCount, UINT16_MAX),
    policyRequest: Object.freeze({
      requestId: policyRequest.requestId,
      intendedFunderWallet: policyRequest.intendedFunderWallet,
      minAnnualRevenueKrw: parseCanonicalUnsigned(policyRequest.minAnnualRevenueKrw, UINT64_MAX),
      maxDebtRatioBps: parseCanonicalUnsigned(policyRequest.maxDebtRatioBps, UINT32_MAX),
      maxOverdueCount: parseCanonicalUnsigned(policyRequest.maxOverdueCount, UINT16_MAX),
      validUntil,
    }),
  });
}

export function parseSessionRequest(value: unknown): ProofSessionRequest {
  const body = requireExactRecord(value, SESSION_KEYS);
  if (
    body.version !== 2 ||
    typeof body.sessionId !== 'string' ||
    !SESSION_ID_PATTERN.test(body.sessionId) ||
    body.sessionId === ZERO_BYTES32
  ) {
    throw invalidRequest();
  }
  return { version: 2, sessionId: body.sessionId };
}

export function parseRecoveryRequest(value: unknown): ProofRecoveryRequest {
  const body = requireExactRecord(value, RECOVER_KEYS);
  if (
    body.version !== 2 ||
    typeof body.requestId !== 'string' ||
    !SESSION_ID_PATTERN.test(body.requestId) ||
    body.requestId === ZERO_BYTES32
  ) {
    throw invalidRequest();
  }
  return { version: 2, requestId: body.requestId };
}

export function parseAcknowledgementRequest(value: unknown): ProofAcknowledgementRequest {
  const body = requireExactRecord(value, ACK_KEYS);
  if (
    body.version !== 2 ||
    typeof body.requestId !== 'string' ||
    !SESSION_ID_PATTERN.test(body.requestId) ||
    body.requestId === ZERO_BYTES32 ||
    typeof body.sessionId !== 'string' ||
    !SESSION_ID_PATTERN.test(body.sessionId) ||
    body.sessionId === ZERO_BYTES32
  ) {
    throw invalidRequest();
  }
  return { version: 2, requestId: body.requestId, sessionId: body.sessionId };
}

export function parseProofSubmissionRequest(value: unknown): ProofSubmissionRequest {
  const body = requireExactRecord(value, PROVE_KEYS);
  if (
    body.version !== 2 ||
    typeof body.sessionId !== 'string' ||
    !SESSION_ID_PATTERN.test(body.sessionId) ||
    body.sessionId === ZERO_BYTES32
  ) {
    throw invalidRequest();
  }
  const proof = requireExactRecord(body.authorization, AUTHORIZATION_KEYS);
  if (
    proof.version !== 2 ||
    typeof proof.authorizationId !== 'string' ||
    !BYTES32_PATTERN.test(proof.authorizationId) ||
    proof.authorizationId.toLowerCase() === ZERO_BYTES32 ||
    typeof proof.typedDataHash !== 'string' ||
    !BYTES32_PATTERN.test(proof.typedDataHash) ||
    proof.typedDataHash.toLowerCase() === ZERO_BYTES32 ||
    typeof proof.signer !== 'string' ||
    !EVM_ADDRESS_PATTERN.test(proof.signer) ||
    proof.signer.toLowerCase() === ZERO_ADDRESS ||
    typeof proof.signature !== 'string' ||
    !SIGNATURE_PATTERN.test(proof.signature)
  ) {
    throw invalidRequest();
  }
  const authorization: AuthorizationProof = {
    version: 2,
    authorizationId: proof.authorizationId,
    typedDataHash: proof.typedDataHash,
    signer: proof.signer,
    signature: proof.signature,
  };
  return { version: 2, sessionId: body.sessionId, authorization };
}

function setSecurityHeaders(response: http.ServerResponse): void {
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Pragma', 'no-cache');
  response.setHeader('X-Content-Type-Options', 'nosniff');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('X-Frame-Options', 'DENY');
  response.setHeader('Content-Security-Policy', "default-src 'none'; frame-ancestors 'none'");
}

function sendJson(response: http.ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  setSecurityHeaders(response);
  response.statusCode = status;
  response.setHeader('Content-Type', 'application/json; charset=utf-8');
  response.setHeader('Content-Length', Buffer.byteLength(json, 'utf8'));
  response.end(json);
}

function sendError(response: http.ServerResponse, error: ProofBridgeHttpError): void {
  const body: ProofBridgeErrorResponse = {
    error: { code: error.code, message: error.publicMessage },
  };
  sendJson(response, error.status, body);
}

function mapError(error: unknown): ProofBridgeHttpError {
  if (error instanceof ProofBridgeHttpError) {
    return error;
  }
  if (error instanceof ProofSessionStoreError) {
    const status = error.code === 'PROOF_SESSION_NOT_FOUND' ? 404 : error.code === 'PROOF_SESSION_BUSY' ? 409 : 409;
    return new ProofBridgeHttpError(status, error.code, error.message);
  }
  if (error instanceof CapabilityOutboxError) {
    const status =
      error.code === 'PROOF_RESULT_NOT_FOUND'
        ? 404
        : error.code === 'POLICY_REQUEST_EXPIRED'
          ? 410
          : error.code.startsWith('PROOF_RESULT_')
            ? 409
            : 503;
    return new ProofBridgeHttpError(status, error.code, error.publicMessage);
  }
  if (error instanceof LocalAttestationApiError) {
    return new ProofBridgeHttpError(error.status, error.code, error.publicMessage);
  }
  return new ProofBridgeHttpError(502, 'PROOF_BRIDGE_UNAVAILABLE', 'The local Midnight proof service is unavailable.');
}

async function readJsonBody(request: http.IncomingMessage): Promise<unknown> {
  const contentLength = request.headers['content-length'];
  if (
    typeof contentLength === 'string' &&
    (/^(0|[1-9][0-9]*)$/.test(contentLength) === false || BigInt(contentLength) > PROOF_BRIDGE_MAX_BODY_BYTES)
  ) {
    request.resume();
    throw new ProofBridgeHttpError(413, 'PAYLOAD_TOO_LARGE', 'The request body is too large.');
  }
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    total += buffer.length;
    if (total > PROOF_BRIDGE_MAX_BODY_BYTES) {
      request.resume();
      throw new ProofBridgeHttpError(413, 'PAYLOAD_TOO_LARGE', 'The request body is too large.');
    }
    chunks.push(buffer);
  }
  if (total === 0) {
    throw invalidRequest();
  }
  try {
    return JSON.parse(Buffer.concat(chunks, total).toString('utf8')) as unknown;
  } catch {
    throw new ProofBridgeHttpError(400, 'INVALID_JSON', 'The JSON request body is invalid.');
  }
}

function validateRequestBoundary(
  request: http.IncomingMessage,
  allowedOrigins: ReadonlySet<string>,
  allowedHosts: ReadonlySet<string>,
): string {
  const rawUrl = request.url ?? '';
  if (!PROTECTED_PATHS.has(rawUrl)) {
    throw new ProofBridgeHttpError(404, 'NOT_FOUND', 'The requested local endpoint was not found.');
  }
  if (request.method !== 'POST') {
    throw new ProofBridgeHttpError(405, 'METHOD_NOT_ALLOWED', 'Only POST is allowed.');
  }
  const remoteAddress = request.socket.remoteAddress;
  if (remoteAddress !== '127.0.0.1' && remoteAddress !== '::ffff:127.0.0.1') {
    throw new ProofBridgeHttpError(403, 'LOOPBACK_REQUIRED', 'The local proof service accepts loopback requests only.');
  }
  if (typeof request.headers.host !== 'string' || !allowedHosts.has(request.headers.host.toLowerCase())) {
    throw new ProofBridgeHttpError(403, 'HOST_REJECTED', 'The local request host is not allowed.');
  }
  if (typeof request.headers.origin !== 'string' || !allowedOrigins.has(request.headers.origin)) {
    throw new ProofBridgeHttpError(403, 'ORIGIN_REJECTED', 'The local browser origin is not allowed.');
  }
  if (request.headers['sec-fetch-site'] !== 'same-origin') {
    throw new ProofBridgeHttpError(403, 'BROWSER_CONTEXT_REQUIRED', 'A same-origin browser request is required.');
  }
  if (request.headers['x-gasok-midnight-ui'] !== '1') {
    throw new ProofBridgeHttpError(403, 'UI_HEADER_REQUIRED', 'The GASOK Midnight UI header is required.');
  }
  if (request.headers['content-type']?.trim().toLowerCase() !== 'application/json') {
    throw new ProofBridgeHttpError(415, 'JSON_BODY_REQUIRED', 'Content-Type must be application/json.');
  }
  const encoding = request.headers['content-encoding'];
  if (encoding !== undefined && encoding.toLowerCase() !== 'identity') {
    throw new ProofBridgeHttpError(415, 'UNSUPPORTED_CONTENT_ENCODING', 'Compressed request bodies are not supported.');
  }
  return rawUrl;
}

export function createProofBridgeServer(options: ProofBridgeServerOptions): http.Server {
  const allowedOrigins = options.allowedOrigins ?? new Set(['http://127.0.0.1:5173', 'http://localhost:5173']);
  const allowedHosts =
    options.allowedHosts ?? new Set(['127.0.0.1:5173', 'localhost:5173', '127.0.0.1:4200', 'localhost:4200']);
  const server = http.createServer((request, response) => {
    void (async () => {
      try {
        const path = validateRequestBoundary(request, allowedOrigins, allowedHosts);
        const body = await readJsonBody(request);
        if (path === CHALLENGE_PATH) {
          sendJson(response, 201, await options.controller.createChallenge(parseChallengeRequest(body)));
          return;
        }
        if (path === PROVE_PATH) {
          const parsed = parseProofSubmissionRequest(body);
          sendJson(response, 202, await options.controller.startProof(parsed.sessionId, parsed.authorization));
          return;
        }
        if (path === RECOVER_PATH) {
          const parsed = parseRecoveryRequest(body);
          sendJson(response, 200, options.controller.recover(parsed.requestId));
          return;
        }
        if (path === ACK_PATH) {
          const parsed = parseAcknowledgementRequest(body);
          sendJson(response, 200, await options.controller.acknowledge(parsed.sessionId, parsed.requestId));
          return;
        }
        const parsed = parseSessionRequest(body);
        sendJson(
          response,
          200,
          path === STATUS_PATH
            ? options.controller.getStatus(parsed.sessionId)
            : await options.controller.cancel(parsed.sessionId),
        );
      } catch (error: unknown) {
        request.resume();
        if (!response.headersSent && !response.destroyed) {
          sendError(response, mapError(error));
        }
      }
    })();
  });
  server.requestTimeout = PROOF_BRIDGE_REQUEST_TIMEOUT_MS;
  server.headersTimeout = PROOF_BRIDGE_HEADERS_TIMEOUT_MS;
  server.keepAliveTimeout = PROOF_BRIDGE_HEADERS_TIMEOUT_MS;
  server.maxHeadersCount = 32;
  return server;
}
