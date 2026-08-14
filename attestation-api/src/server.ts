import restify from 'restify';
import { MAX_FIELD, type JubjubPoint } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { signFinancialData, getPublicKey } from './signing.js';
import type { AttestationRequest, AttestationResponse, ProviderInfoResponse, HealthResponse } from './types.js';

const UINT16_MAX = (1n << 16n) - 1n;
const UINT32_MAX = (1n << 32n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;

class RequestValidationError extends Error {}

function parseDecimalString(value: unknown, fieldName: string, maximum: bigint): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new RequestValidationError(`${fieldName} must be an unsigned decimal string`);
  }

  const parsed = BigInt(value);
  if (parsed > maximum) {
    throw new RequestValidationError(`${fieldName} is outside its supported range`);
  }
  return parsed;
}

export function createServer(providerSk: bigint, providerId: number): restify.Server {
  if (!Number.isInteger(providerId) || providerId < 0 || BigInt(providerId) > UINT16_MAX) {
    throw new Error('Mock attestation provider ID must fit Uint<16>');
  }

  const server = restify.createServer({ name: 'gasok-mock-attestation-api' });
  server.use(restify.plugins.bodyParser());

  const providerPk: JubjubPoint = getPublicKey(providerSk);

  server.post('/attest', (req: restify.Request, res: restify.Response, next: restify.Next) => {
    try {
      const body = (req.body ?? {}) as Partial<AttestationRequest>;
      const annualRevenueKrw = parseDecimalString(body.annualRevenueKrw, 'annualRevenueKrw', UINT64_MAX);
      const debtRatioBps = parseDecimalString(body.debtRatioBps, 'debtRatioBps', UINT32_MAX);
      const overdueCount = parseDecimalString(body.overdueCount, 'overdueCount', UINT16_MAX);
      const companyCommitmentHash = parseDecimalString(
        body.companyCommitmentHash,
        'companyCommitmentHash',
        MAX_FIELD,
      );

      const signature = signFinancialData(
        providerSk,
        annualRevenueKrw,
        debtRatioBps,
        overdueCount,
        companyCommitmentHash,
      );

      const response: AttestationResponse = {
        signature: {
          announcement: {
            x: signature.announcement.x.toString(),
            y: signature.announcement.y.toString(),
          },
          response: signature.response.toString(),
        },
        providerId,
        attestationType: 'mock',
      };

      res.send(200, response);
    } catch (err: unknown) {
      if (err instanceof RequestValidationError) {
        res.send(400, { error: err.message });
      } else {
        res.send(500, { error: 'Mock attestation signing failed' });
      }
    }
    return next();
  });

  server.get('/provider-info', (_req: restify.Request, res: restify.Response, next: restify.Next) => {
    const response: ProviderInfoResponse = {
      providerId,
      publicKey: {
        x: providerPk.x.toString(),
        y: providerPk.y.toString(),
      },
      attestationType: 'mock',
    };
    res.send(200, response);
    return next();
  });

  server.get('/health', (_req: restify.Request, res: restify.Response, next: restify.Next) => {
    const response: HealthResponse = {
      status: 'ok',
      providerId,
      attestationType: 'mock',
    };
    res.send(200, response);
    return next();
  });

  return server;
}
