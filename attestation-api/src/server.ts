import restify from 'restify';
import type { Server as NodeHttpServer } from 'node:http';
import { MAX_FIELD, type JubjubPoint } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import {
  AUTHORIZATION_PROTOCOL,
  AuthorizationCapacityError,
  AuthorizationChallengeStore,
  AuthorizationGenerationError,
  AuthorizationValidationError,
  POLICY_VERSION,
  PROVIDER_ID,
  buildAttestationRequestCommitment,
  buildAuthorizationChallengeResponse,
  buildAuthorizationMessage,
  verifyAuthorizationSignature,
} from './authorization.js';
import { signFinancialData, getPublicKey } from './signing.js';
import {
  ContextValidationError,
  deriveAttestationContext,
  getApprovedMidnightContractAddress,
  normalizeMidnightContractAddress,
} from './context.js';
import {
  createGiwaSepoliaReceivableResolver,
  GIWA_CHAIN_ID,
  GiwaReceivableNotFoundError,
  GiwaRpcError,
  RECEIVABLE_FINANCE_ADDRESS,
  type GiwaReceivableResolver,
} from './giwa.js';
import type {
  AttestationRequest,
  AttestationResponse,
  AuthorizationChallengeRequest,
  AuthorizationProof,
  ErrorResponse,
  ProviderInfoResponse,
  HealthResponse,
  ParsedAttestationRequest,
  SubjectRole,
} from './types.js';

const UINT16_MAX = (1n << 16n) - 1n;
const UINT32_MAX = (1n << 32n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const AUTHORIZATION_CHALLENGE_PATH = '/authorization-challenges';
const ATTESTATION_PATH = '/attest';
const AUTHORIZATION_SALT_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const AUTHORIZATION_ID_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const TYPED_DATA_HASH_PATTERN = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE_PATTERN = /^0x[0-9a-fA-F]{130}$/;
const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;
const ZERO_BYTES32 = `0x${'0'.repeat(64)}`;

const CHALLENGE_REQUEST_KEYS = [
  'annualRevenueKrw',
  'authorizationSalt',
  'companyCommitmentHash',
  'debtRatioBps',
  'midnightContractAddress',
  'onchainReceivableId',
  'overdueCount',
  'subjectRole',
  'version',
] as const;
const ATTESTATION_REQUEST_KEYS = [...CHALLENGE_REQUEST_KEYS, 'authorization'].sort();
const AUTHORIZATION_PROOF_KEYS = [
  'authorizationId',
  'signature',
  'signer',
  'typedDataHash',
  'version',
] as const;

export const MAX_ATTESTATION_BODY_BYTES = 4_096;
export const REQUEST_TIMEOUT_MS = 10_000;
export const HEADERS_TIMEOUT_MS = 5_000;

class PublicApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly publicMessage: string,
  ) {
    super(publicMessage);
    this.name = 'PublicApiError';
  }
}

export interface CreateServerOptions {
  receivableResolver?: GiwaReceivableResolver;
  approvedMidnightContractAddress?: string;
  authorizationStore?: AuthorizationChallengeStore;
}

type JsonRecord = Record<string, unknown>;
type RestifyServerWithNodeServer = restify.Server & { server: NodeHttpServer };

function invalidRequest(): PublicApiError {
  return new PublicApiError(400, 'INVALID_REQUEST', 'The request body is invalid.');
}

function isRecord(value: unknown): value is JsonRecord {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: JsonRecord, expectedKeys: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value).sort();
  const expected = [...expectedKeys].sort();
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

function requireExactRecord(value: unknown, expectedKeys: ReadonlyArray<string>): JsonRecord {
  if (!isRecord(value) || !hasExactKeys(value, expectedKeys)) {
    throw invalidRequest();
  }
  return value;
}

function parseDecimalString(value: unknown, maximum: bigint): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw invalidRequest();
  }

  const parsed = BigInt(value);
  if (parsed > maximum) {
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

function parseRequest(
  body: JsonRecord,
  approvedMidnightContractAddress: string,
): ParsedAttestationRequest {
  if (body.version !== 1) {
    throw invalidRequest();
  }
  const annualRevenueKrw = parseDecimalString(body.annualRevenueKrw, UINT64_MAX);
  const debtRatioBps = parseDecimalString(body.debtRatioBps, UINT32_MAX);
  const overdueCount = parseDecimalString(body.overdueCount, UINT16_MAX);
  const companyCommitmentHash = parseDecimalString(body.companyCommitmentHash, MAX_FIELD);
  const onchainReceivableId = parseDecimalString(body.onchainReceivableId, UINT256_MAX);
  if (onchainReceivableId === 0n) {
    throw invalidRequest();
  }
  const subjectRole = parseSubjectRole(body.subjectRole);
  if (
    typeof body.authorizationSalt !== 'string' ||
    !AUTHORIZATION_SALT_PATTERN.test(body.authorizationSalt) ||
    body.authorizationSalt.toLowerCase() === ZERO_BYTES32
  ) {
    throw invalidRequest();
  }

  let midnightContractAddress: string;
  try {
    midnightContractAddress = normalizeMidnightContractAddress(body.midnightContractAddress);
  } catch {
    throw invalidRequest();
  }
  if (midnightContractAddress !== approvedMidnightContractAddress) {
    throw new PublicApiError(
      400,
      'UNAPPROVED_MIDNIGHT_CONTRACT',
      'The requested Midnight deployment is not approved.',
    );
  }

  return Object.freeze({
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    companyCommitmentHash,
    authorizationSalt: body.authorizationSalt.toLowerCase(),
    midnightContractAddress,
    onchainReceivableId,
    subjectRole,
  });
}

function locateAuthorizationId(value: unknown): string {
  if (!isRecord(value) || typeof value.authorizationId !== 'string' ||
      !AUTHORIZATION_ID_PATTERN.test(value.authorizationId)) {
    throw invalidRequest();
  }
  return value.authorizationId.toLowerCase();
}

function parseAuthorizationProof(value: unknown): AuthorizationProof {
  const proof = requireExactRecord(value, AUTHORIZATION_PROOF_KEYS);
  if (
    proof.version !== 1 ||
    typeof proof.authorizationId !== 'string' || !AUTHORIZATION_ID_PATTERN.test(proof.authorizationId) ||
    typeof proof.typedDataHash !== 'string' || !TYPED_DATA_HASH_PATTERN.test(proof.typedDataHash) ||
    typeof proof.signer !== 'string' || !EVM_ADDRESS_PATTERN.test(proof.signer) ||
    proof.signer.toLowerCase() === ZERO_ADDRESS ||
    typeof proof.signature !== 'string' || !SIGNATURE_PATTERN.test(proof.signature)
  ) {
    throw new AuthorizationValidationError();
  }
  return {
    version: 1,
    authorizationId: proof.authorizationId.toLowerCase(),
    typedDataHash: proof.typedDataHash.toLowerCase(),
    signer: proof.signer.toLowerCase(),
    signature: proof.signature.toLowerCase(),
  };
}

function sendJson(response: restify.Response, status: number, body: unknown): void {
  response.header('Cache-Control', 'no-store');
  response.header('X-Content-Type-Options', 'nosniff');
  response.send(status, body);
}

function sendError(response: restify.Response, error: PublicApiError): void {
  const body: ErrorResponse = {
    error: {
      code: error.code,
      message: error.publicMessage,
    },
  };
  sendJson(response, error.status, body);
}

function mapError(error: unknown): PublicApiError {
  if (error instanceof PublicApiError) {
    return error;
  }
  if (error instanceof AuthorizationValidationError) {
    return new PublicApiError(
      401,
      'AUTHORIZATION_INVALID',
      'The wallet authorization is invalid or no longer available.',
    );
  }
  if (error instanceof AuthorizationCapacityError) {
    return new PublicApiError(
      429,
      'AUTHORIZATION_CAPACITY_EXCEEDED',
      'The local authorization service is temporarily at capacity.',
    );
  }
  if (error instanceof AuthorizationGenerationError) {
    return new PublicApiError(
      503,
      'AUTHORIZATION_UNAVAILABLE',
      'The local authorization service is temporarily unavailable.',
    );
  }
  if (error instanceof GiwaReceivableNotFoundError) {
    return new PublicApiError(404, 'GIWA_RECEIVABLE_NOT_FOUND', 'The GIWA receivable was not found.');
  }
  if (error instanceof GiwaRpcError) {
    return new PublicApiError(
      502,
      'GIWA_RPC_UNAVAILABLE',
      'GIWA receivable verification is unavailable.',
    );
  }
  if (error instanceof ContextValidationError) {
    return invalidRequest();
  }
  return new PublicApiError(500, 'INTERNAL_ERROR', 'The request could not be completed.');
}

function requireProtectedJson(
  req: restify.Request,
  res: restify.Response,
  next: restify.Next,
): void {
  if (
    req.method !== 'POST' ||
    (req.path() !== ATTESTATION_PATH && req.path() !== AUTHORIZATION_CHALLENGE_PATH)
  ) {
    next();
    return;
  }

  const contentType = req.headers['content-type'];
  const mediaType = typeof contentType === 'string'
    ? contentType.split(';', 1)[0].trim().toLowerCase()
    : '';
  if (mediaType !== 'application/json') {
    req.resume();
    sendError(res, new PublicApiError(415, 'JSON_BODY_REQUIRED', 'Content-Type must be application/json.'));
    return;
  }

  const contentEncoding = req.headers['content-encoding'];
  if (contentEncoding !== undefined && contentEncoding.toLowerCase() !== 'identity') {
    req.resume();
    sendError(res, new PublicApiError(415, 'UNSUPPORTED_CONTENT_ENCODING', 'Compressed request bodies are not supported.'));
    return;
  }

  next();
}

function sameAuthorizationMessage(left: ReturnType<typeof buildAuthorizationMessage>, right: typeof left): boolean {
  return Object.keys(left).every((key) =>
    left[key as keyof typeof left] === right[key as keyof typeof right]);
}

export function createServer(
  providerSk: bigint,
  options: CreateServerOptions = {},
): restify.Server {
  const providerPk: JubjubPoint = getPublicKey(providerSk);
  const approvedMidnightContractAddress = getApprovedMidnightContractAddress(
    options.approvedMidnightContractAddress,
  );
  const authorizationStore = options.authorizationStore ?? new AuthorizationChallengeStore();
  const receivableResolver = options.receivableResolver ?? createGiwaSepoliaReceivableResolver();
  const server = restify.createServer({ name: 'gasok-mock-attestation-api' });
  const nodeServer = (server as RestifyServerWithNodeServer).server;
  nodeServer.requestTimeout = REQUEST_TIMEOUT_MS;
  nodeServer.headersTimeout = HEADERS_TIMEOUT_MS;
  nodeServer.keepAliveTimeout = HEADERS_TIMEOUT_MS;
  server.use(requireProtectedJson);
  server.use(restify.plugins.bodyParser({
    maxBodySize: MAX_ATTESTATION_BODY_BYTES,
    mapParams: false,
  }));
  server.on('restifyError', (
    _req: restify.Request,
    res: restify.Response,
    error: Error,
    callback: () => void,
  ) => {
    if (!res.headersSent && error.name === 'InvalidContentError') {
      sendError(res, new PublicApiError(400, 'INVALID_JSON', 'The JSON request body is invalid.'));
    } else if (!res.headersSent && error.name === 'PayloadTooLargeError') {
      sendError(res, new PublicApiError(413, 'PAYLOAD_TOO_LARGE', 'The request body is too large.'));
    }
    callback();
  });

  server.post(AUTHORIZATION_CHALLENGE_PATH, async (req: restify.Request, res: restify.Response) => {
    try {
      const body = requireExactRecord(req.body, CHALLENGE_REQUEST_KEYS) as unknown as AuthorizationChallengeRequest;
      const parsed = parseRequest(body as unknown as JsonRecord, approvedMidnightContractAddress);
      const receivable = await receivableResolver.resolve(parsed.onchainReceivableId);
      if (receivable.id !== parsed.onchainReceivableId) {
        throw new GiwaRpcError('GIWA resolver returned a different receivable');
      }
      const context = deriveAttestationContext(
        parsed.midnightContractAddress,
        receivable,
        parsed.subjectRole,
      );
      const record = authorizationStore.issue((authorizationId, issuedAt, expiresAt) =>
        buildAuthorizationMessage(
          parsed,
          context.partyWallet,
          authorizationId,
          issuedAt,
          expiresAt,
        ));
      sendJson(res, 201, buildAuthorizationChallengeResponse(record));
    } catch (error: unknown) {
      sendError(res, mapError(error));
    }
  });

  server.post(ATTESTATION_PATH, async (req: restify.Request, res: restify.Response) => {
    let challenge;
    try {
      const untrustedBody = isRecord(req.body) ? req.body : {};
      const authorizationId = locateAuthorizationId(untrustedBody.authorization);

      // The challenge is removed before the remaining request or signature is
      // examined, so a failed attempt cannot be corrected and replayed.
      challenge = authorizationStore.take(authorizationId);

      const body = requireExactRecord(untrustedBody, ATTESTATION_REQUEST_KEYS) as unknown as AttestationRequest;
      const proof = parseAuthorizationProof(body.authorization);
      const parsed = parseRequest(body as unknown as JsonRecord, approvedMidnightContractAddress);
      const requestCommitment = buildAttestationRequestCommitment(parsed, challenge.message.partyWallet);
      if (
        challenge.message.authorizationId !== proof.authorizationId ||
        challenge.message.midnightContractAddress !== `0x${parsed.midnightContractAddress}` ||
        challenge.message.receivableFinanceAddress !== RECEIVABLE_FINANCE_ADDRESS ||
        challenge.message.onchainReceivableId !== parsed.onchainReceivableId.toString() ||
        challenge.message.subjectRole !== parsed.subjectRole ||
        challenge.message.providerId !== PROVIDER_ID.toString() ||
        challenge.message.policyVersion !== POLICY_VERSION.toString() ||
        challenge.message.attestationRequestCommitment !== requestCommitment
      ) {
        throw new AuthorizationValidationError();
      }

      // Re-read GIWA immediately before authorization verification and provider
      // signing so a role-wallet change after challenge issuance is rejected.
      const receivable = await receivableResolver.resolve(parsed.onchainReceivableId);
      if (receivable.id !== parsed.onchainReceivableId) {
        throw new GiwaRpcError('GIWA resolver returned a different receivable');
      }
      const context = deriveAttestationContext(
        parsed.midnightContractAddress,
        receivable,
        parsed.subjectRole,
      );
      const expectedMessage = buildAuthorizationMessage(
        parsed,
        context.partyWallet,
        proof.authorizationId,
        challenge.message.issuedAt,
        challenge.message.expiresAt,
      );
      if (!sameAuthorizationMessage(expectedMessage, challenge.message)) {
        throw new AuthorizationValidationError();
      }
      verifyAuthorizationSignature(expectedMessage, proof, context.partyWallet);

      const signature = signFinancialData(
        providerSk,
        parsed.annualRevenueKrw,
        parsed.debtRatioBps,
        parsed.overdueCount,
        parsed.companyCommitmentHash,
        context.bindingHashField,
        context.deploymentHashField,
        BigInt(PROVIDER_ID),
        BigInt(POLICY_VERSION),
      );

      const response: AttestationResponse = {
        signature: {
          announcement: {
            x: signature.announcement.x.toString(),
            y: signature.announcement.y.toString(),
          },
          response: signature.response.toString(),
        },
        providerId: PROVIDER_ID,
        policyVersion: POLICY_VERSION,
        midnightContractAddress: context.midnightContractAddress,
        binding: {
          giwaChainId: GIWA_CHAIN_ID.toString(),
          receivableFinanceAddress: RECEIVABLE_FINANCE_ADDRESS,
          onchainReceivableId: parsed.onchainReceivableId.toString(),
          subjectRole: parsed.subjectRole,
          partyWallet: context.partyWallet,
        },
        attestationType: 'mock',
        authorizationProtocol: AUTHORIZATION_PROTOCOL,
      };

      sendJson(res, 200, response);
    } catch (error: unknown) {
      sendError(res, mapError(error));
    }
  });

  server.get('/provider-info', (_req: restify.Request, res: restify.Response, next: restify.Next) => {
    const response: ProviderInfoResponse = {
      providerId: PROVIDER_ID,
      publicKey: {
        x: providerPk.x.toString(),
        y: providerPk.y.toString(),
      },
      approvedMidnightContractAddress,
      attestationType: 'mock',
      authorizationProtocol: AUTHORIZATION_PROTOCOL,
    };
    sendJson(res, 200, response);
    return next();
  });

  server.get('/health', (_req: restify.Request, res: restify.Response, next: restify.Next) => {
    const response: HealthResponse = {
      status: 'ok',
      providerId: PROVIDER_ID,
      approvedMidnightContractAddress,
      attestationType: 'mock',
      authorizationProtocol: AUTHORIZATION_PROTOCOL,
    };
    sendJson(res, 200, response);
    return next();
  });

  return server;
}
