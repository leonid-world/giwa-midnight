import { createServer as createHttpServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { PublicApiError, invalidContractAddress, unapprovedContractAddress } from './errors.js';
import { NETWORK_ID } from './config.js';
import type { GetEligibilityResults } from './eligibility.js';
import type { ErrorJson } from './types.js';

const ELIGIBILITY_PATH = /^\/v1\/contracts\/([^/]+)\/eligibility-results$/;
const CONTRACT_ADDRESS = /^[0-9a-fA-F]{64}$/;

export interface ApiServerDependencies {
  readonly getEligibilityResults: GetEligibilityResults;
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

export function createApiServer({ getEligibilityResults, approvedContractAddress }: ApiServerDependencies): Server {
  return createHttpServer(async (request, response) => {
    const pathname = pathnameOf(request);

    if (request.method !== 'GET') {
      response.setHeader('Allow', 'GET');
      sendError(response, new PublicApiError(405, 'METHOD_NOT_ALLOWED', 'Only GET requests are supported.'));
      return;
    }

    if (pathname === '/health') {
      sendJson(response, 200, {
        status: 'ok',
        service: 'gasok-midnight-read-api',
        networkId: NETWORK_ID,
      });
      return;
    }

    const match = ELIGIBILITY_PATH.exec(pathname);
    if (match === null) {
      sendError(response, new PublicApiError(404, 'NOT_FOUND', 'The requested endpoint does not exist.'));
      return;
    }

    const contractAddress = match[1];
    if (!CONTRACT_ADDRESS.test(contractAddress)) {
      sendError(response, invalidContractAddress());
      return;
    }

    const normalizedContractAddress = contractAddress.toLowerCase();
    if (normalizedContractAddress !== approvedContractAddress) {
      sendError(response, unapprovedContractAddress());
      return;
    }

    try {
      const result = await getEligibilityResults(normalizedContractAddress);
      sendJson(response, 200, result);
    } catch (error) {
      if (error instanceof PublicApiError) {
        sendError(response, error);
      } else {
        sendError(response, new PublicApiError(500, 'INTERNAL_ERROR', 'The request could not be completed.'));
      }
    }
  });
}
