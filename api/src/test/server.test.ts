import type { AddressInfo } from 'node:net';
import type { Server } from 'node:http';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { contractNotFound } from '../errors.js';
import { createApiServer } from '../server.js';
import type { GetEligibilityResults } from '../eligibility.js';

const ADDRESS = 'ABCDEF0123456789'.repeat(4);
const servers: Server[] = [];

async function start(getEligibilityResults: GetEligibilityResults): Promise<string> {
  const server = createApiServer({
    getEligibilityResults,
    approvedContractAddress: ADDRESS.toLowerCase(),
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

afterEach(async () => {
  await Promise.all(
    servers.splice(0).map((server) => new Promise<void>((resolve, reject) => {
      server.close((error) => (error ? reject(error) : resolve()));
    })),
  );
});

describe('read-only HTTP API', () => {
  it('reports a local undeployed health response with no-store caching', async () => {
    const baseUrl = await start(vi.fn());
    const response = await fetch(`${baseUrl}/health`);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    await expect(response.json()).resolves.toEqual({
      status: 'ok',
      service: 'gasok-midnight-read-api',
      networkId: 'undeployed',
    });
  });

  it('normalizes the contract address and returns the agreed response shape', async () => {
    const getEligibilityResults = vi.fn<GetEligibilityResults>().mockImplementation(async (contractAddress) => ({
      networkId: 'undeployed',
      contractAddress,
      results: [{ commitment: '01', eligible: true, providerId: '1', policyVersion: '1' }],
    }));
    const baseUrl = await start(getEligibilityResults);
    const response = await fetch(`${baseUrl}/v1/contracts/${ADDRESS}/eligibility-results`);

    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(getEligibilityResults).toHaveBeenCalledWith(ADDRESS.toLowerCase());
    await expect(response.json()).resolves.toEqual({
      networkId: 'undeployed',
      contractAddress: ADDRESS.toLowerCase(),
      results: [{ commitment: '01', eligible: true, providerId: '1', policyVersion: '1' }],
    });
  });

  it('rejects malformed addresses before querying the Indexer', async () => {
    const getEligibilityResults = vi.fn<GetEligibilityResults>();
    const baseUrl = await start(getEligibilityResults);
    const response = await fetch(`${baseUrl}/v1/contracts/not-hex/eligibility-results`);

    expect(response.status).toBe(400);
    expect(getEligibilityResults).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({
      error: {
        code: 'INVALID_CONTRACT_ADDRESS',
        message: 'Contract address must be exactly 64 hexadecimal characters.',
      },
    });
  });

  it('rejects a well-formed address that is not the configured GASOK contract', async () => {
    const getEligibilityResults = vi.fn<GetEligibilityResults>();
    const baseUrl = await start(getEligibilityResults);
    const response = await fetch(
      `${baseUrl}/v1/contracts/${'0'.repeat(64)}/eligibility-results`,
    );

    expect(response.status).toBe(404);
    expect(getEligibilityResults).not.toHaveBeenCalled();
    await expect(response.json()).resolves.toEqual({
      error: {
        code: 'UNAPPROVED_CONTRACT_ADDRESS',
        message: 'This is not the configured GASOK Midnight contract.',
      },
    });
  });

  it('returns safe public errors without implementation details', async () => {
    const getEligibilityResults = vi.fn<GetEligibilityResults>().mockRejectedValue(contractNotFound());
    const baseUrl = await start(getEligibilityResults);
    const response = await fetch(`${baseUrl}/v1/contracts/${ADDRESS}/eligibility-results`);

    expect(response.status).toBe(404);
    await expect(response.json()).resolves.toEqual({
      error: {
        code: 'CONTRACT_NOT_FOUND',
        message: 'No public contract state was found for this address.',
      },
    });
  });

  it('allows GET only', async () => {
    const baseUrl = await start(vi.fn());
    const response = await fetch(`${baseUrl}/health`, { method: 'POST' });

    expect(response.status).toBe(405);
    expect(response.headers.get('allow')).toBe('GET');
  });
});
