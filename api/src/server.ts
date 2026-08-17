import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { verifyProofCapability } from './capability.js';
import {
  invalidJsonBody,
  jsonBodyRequired,
  PublicApiError,
  requestBodyTooLarge,
} from './errors.js';
import { NETWORK_ID } from './config.js';
import type { GetEligibilityResult } from './eligibility.js';
import type { EligibilityResolutionJson, ErrorJson } from './types.js';

const RESOLVE_PATH = '/v1/eligibility-results/resolve';
const MAX_JSON_BODY_BYTES = 4_096;

export interface ApiServerDependencies {
  readonly getEligibilityResult: GetEligibilityResult;
  readonly approvedContractAddress: string;
}

function sendJson(response: ServerResponse, status: number, body: unknown): void {
  const json = JSON.stringify(body);
  response.writeHead(status, {
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(json),
    'X-Content-Type-Options': 'nosniff',
  });
  response.end(json);
}

function sendError(response: ServerResponse, error: PublicApiError): void {
  const body: ErrorJson = {
    error: {
      code: error.code,
      message: error.publicMessage,
    },
  };
  sendJson(response, error.status, body);
}

function pathnameOf(request: IncomingMessage): string {
  try {
    return new URL(request.url ?? '/', 'http://127.0.0.1').pathname;
  } catch {
    return '/';
  }
}

function requireJsonContentType(request: IncomingMessage): void {
  const contentType = request.headers['content-type'];
  if (
    typeof contentType !== 'string' ||
    contentType.split(';', 1)[0].trim().toLowerCase() !== 'application/json'
  ) {
    throw jsonBodyRequired();
  }
}

async function readJsonBody(request: IncomingMessage): Promise<unknown> {
  const contentLength = request.headers['content-length'];
  if (
    typeof contentLength === 'string' &&
    /^\d+$/.test(contentLength) &&
    Number(contentLength) > MAX_JSON_BODY_BYTES
  ) {
    request.resume();
    throw requestBodyTooLarge();
  }

  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    size += buffer.length;
    if (size > MAX_JSON_BODY_BYTES) {
      request.resume();
      throw requestBodyTooLarge();
    }
    chunks.push(buffer);
  }

  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8')) as unknown;
  } catch {
    throw invalidJsonBody();
  }
}

export function createApiServer({ getEligibilityResult, approvedContractAddress }: ApiServerDependencies): Server {
  return createHttpServer(async (request, response) => {
    const pathname = pathnameOf(request);

    if (pathname === '/health') {
      if (request.method !== 'GET') {
        response.setHeader('Allow', 'GET');
        sendError(response, new PublicApiError(405, 'METHOD_NOT_ALLOWED', 'Only GET is supported for this endpoint.'));
        return;
      }
      sendJson(response, 200, {
        status: 'ok',
        service: 'gasok-midnight-read-api',
        networkId: NETWORK_ID,
      });
      return;
    }

    if (pathname !== RESOLVE_PATH) {
      sendError(response, new PublicApiError(404, 'NOT_FOUND', 'The requested endpoint does not exist.'));
      return;
    }

    if (request.method !== 'POST') {
      response.setHeader('Allow', 'POST');
      sendError(response, new PublicApiError(405, 'METHOD_NOT_ALLOWED', 'Only POST is supported for this endpoint.'));
      return;
    }

    try {
      requireJsonContentType(request);
      const requestBody = await readJsonBody(request);
      const verified = verifyProofCapability(requestBody, approvedContractAddress);
      const result = await getEligibilityResult(
        verified.capability.midnightContractAddress,
        verified.lookupKeyBytes,
      );
      const responseBody: EligibilityResolutionJson = {
        networkId: NETWORK_ID,
        contractAddress: verified.capability.midnightContractAddress,
        context: {
          giwaChainId: verified.capability.giwaChainId,
          receivableFinanceAddress: verified.capability.receivableFinanceAddress,
          onchainReceivableId: verified.capability.onchainReceivableId,
          subjectRole: verified.capability.subjectRole,
          partyWallet: verified.capability.partyWallet,
        },
        result: {
          lookupKey: verified.capability.lookupKey,
          ...result,
        },
      };
      sendJson(response, 200, responseBody);
    } catch (error: unknown) {
      if (error instanceof PublicApiError) {
        sendError(response, error);
      } else {
        sendError(response, new PublicApiError(500, 'INTERNAL_ERROR', 'The request could not be completed.'));
      }
    }
  });
}
