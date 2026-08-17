import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { contractNotFound } from '../errors.js';
import { createApiServer } from '../server.js';
import type { GetEligibilityResult } from '../eligibility.js';
import { DEFAULT_GASOK_CONTRACT_ADDRESS } from '../config.js';
import { createValidCapability } from './fixture.js';

const RESOLVE_PATH = '/v1/eligibility-results/resolve';
const servers: Server[] = [];

async function start(getEligibilityResult: GetEligibilityResult): Promise<string> {
  const server = createApiServer({
    getEligibilityResult,
    approvedContractAddress: DEFAULT_GASOK_CONTRACT_ADDRESS,
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function postJson(baseUrl: string, body: unknown): Promise<Response> {
  return fetch(`${baseUrl}${RESOLVE_PATH}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  });
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    })),
  );
});

describe('proof-capability HTTP API', () => {
  it('reports local health with no-store caching and no CORS', async () => {
    const baseUrl = await start(vi.fn());
    const response = await fetch(`${baseUrl}/health`);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    await expect(response.json()).resolves.toEqual({
      status: 'ok',
      service: 'gasok-midnight-read-api',
      networkId: 'undeployed',
    });
  });

  it('resolves one exact result and returns only normalized allowlisted context', async () => {
    const capability = createValidCapability();
    const getEligibilityResult = vi.fn<GetEligibilityResult>().mockResolvedValue({
      eligible: true,
      providerId: '1',
      policyVersion: '1',
    });
    const baseUrl = await start(getEligibilityResult);
    const response = await postJson(baseUrl, capability);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(response.headers.get('access-control-allow-origin')).toBeNull();
    expect(getEligibilityResult).toHaveBeenCalledOnce();
    const [contractAddress, lookupKey] = getEligibilityResult.mock.calls[0];
    expect(contractAddress).toBe(capability.midnightContractAddress);
    expect(Buffer.from(lookupKey).toString('hex')).toBe(capability.lookupKey.slice(2));

    const body = await response.json() as Record<string, unknown>;
    expect(body).toEqual({
      networkId: 'undeployed',
      contractAddress: capability.midnightContractAddress,
      context: {
        giwaChainId: capability.giwaChainId,
        receivableFinanceAddress: capability.receivableFinanceAddress,
        onchainReceivableId: capability.onchainReceivableId,
        subjectRole: capability.subjectRole,
        partyWallet: capability.partyWallet,
      },
      result: {
        lookupKey: capability.lookupKey,
        eligible: true,
        providerId: '1',
        policyVersion: '1',
      },
    });
    expect(body.companyCommitment).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('annualRevenueKrw');
    expect(JSON.stringify(body)).not.toContain('signature');
    expect(JSON.stringify(body)).not.toContain('secret');
  });

  it('disables the old public enumeration route', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>();
    const baseUrl = await start(getEligibilityResult);
    const response = await fetch(
      `${baseUrl}/v1/contracts/${DEFAULT_GASOK_CONTRACT_ADDRESS}/eligibility-results`,
    );

    expect(response.status).toBe(404);
    expect(getEligibilityResult).not.toHaveBeenCalled();
  });

  it('requires POST for capability resolution', async () => {
    const baseUrl = await start(vi.fn());
    const response = await fetch(`${baseUrl}${RESOLVE_PATH}`);

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('POST');
  });

  it('requires an application/json body', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>();
    const baseUrl = await start(getEligibilityResult);
    const response = await fetch(`${baseUrl}${RESOLVE_PATH}`, {
      method: 'POST',
      body: JSON.stringify(createValidCapability()),
    });

    expect(response.status).toBe(415);
    expect(getEligibilityResult).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'JSON_BODY_REQUIRED' },
    });
  });

  it('rejects malformed JSON safely', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>();
    const baseUrl = await start(getEligibilityResult);
    const response = await fetch(`${baseUrl}${RESOLVE_PATH}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{',
    });

    expect(response.status).toBe(400);
    expect(getEligibilityResult).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'INVALID_JSON_BODY' },
    });
  });

  it('rejects oversized capability bodies before querying the Indexer', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>();
    const baseUrl = await start(getEligibilityResult);
    const response = await postJson(baseUrl, {
      ...createValidCapability(),
      padding: 'x'.repeat(5_000),
    });

    expect(response.status).toBe(413);
    expect(getEligibilityResult).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'REQUEST_BODY_TOO_LARGE' },
    });
  });

  it('rejects extra financial fields under the strict v1 schema', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>();
    const baseUrl = await start(getEligibilityResult);
    const response = await postJson(baseUrl, {
      ...createValidCapability(),
      annualRevenueKrw: '500000000',
    });

    expect(response.status).toBe(400);
    expect(getEligibilityResult).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'INVALID_PROOF_CAPABILITY' },
    });
  });

  it('rejects a mismatched lookup key before querying the Indexer', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>();
    const baseUrl = await start(getEligibilityResult);
    const response = await postJson(baseUrl, createValidCapability({
      lookupKey: `0x${'ff'.repeat(32)}`,
    }));

    expect(response.status).toBe(400);
    expect(getEligibilityResult).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toMatchObject({
      error: { code: 'CAPABILITY_LOOKUP_MISMATCH' },
    });
  });

  it('returns safe reader errors without implementation details', async () => {
    const getEligibilityResult = vi.fn<GetEligibilityResult>().mockRejectedValue(contractNotFound());
    const baseUrl = await start(getEligibilityResult);
    const response = await postJson(baseUrl, createValidCapability());

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({
      error: {
        code: 'CONTRACT_NOT_FOUND',
        message: 'No public contract state was found for this address.',
      },
    });
  });
});
