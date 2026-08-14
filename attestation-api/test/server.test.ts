import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { createServer } from '../src/server.js';
import { generateKeyPair } from '../src/signing.js';
import type restify from 'restify';

setNetworkId('undeployed');

describe('Attestation API Server', () => {
  let server: restify.Server;
  let baseUrl: string;
  const { sk, pk } = generateKeyPair();
  const providerId = 42;

  beforeAll(async () => {
    server = createServer(sk, providerId);
    await new Promise<void>((resolve) => {
      server.listen(0, '127.0.0.1', () => {
        const addr = server.address();
        const port = typeof addr === 'string' ? addr : addr?.port;
        baseUrl = `http://127.0.0.1:${port}`;
        resolve();
      });
    });
  });

  afterAll(async () => {
    await new Promise<void>((resolve) => {
      server.close(() => resolve());
    });
  });

  it('GET /health returns ok status', async () => {
    const res = await fetch(`${baseUrl}/health`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
    expect(body.providerId).toBe(providerId);
    expect(body.attestationType).toBe('mock');
    expect(res.headers.get('access-control-allow-origin')).toBeNull();
  });

  it('GET /provider-info returns provider public key', async () => {
    const res = await fetch(`${baseUrl}/provider-info`);
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.providerId).toBe(providerId);
    expect(body.publicKey.x).toBe(pk.x.toString());
    expect(body.publicKey.y).toBe(pk.y.toString());
    expect(body.attestationType).toBe('mock');
  });

  it('POST /attest returns valid attestation', async () => {
    const res = await fetch(`${baseUrl}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        annualRevenueKrw: '500000000',
        debtRatioBps: '20000',
        overdueCount: '1',
        companyCommitmentHash: '12345678901234567890',
      }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.signature).toBeDefined();
    expect(body.signature.announcement).toBeDefined();
    expect(body.signature.announcement.x).toBeDefined();
    expect(body.signature.announcement.y).toBeDefined();
    expect(body.signature.response).toBeDefined();
    expect(body.providerId).toBe(providerId);
    expect(body.attestationType).toBe('mock');
    expect(body.message).toBeUndefined();
    expect(JSON.stringify(body)).not.toContain('500000000');
    expect(JSON.stringify(body)).not.toContain('20000');
  });

  it('POST /attest returns 400 for missing fields', async () => {
    const res = await fetch(`${baseUrl}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        annualRevenueKrw: '500000000',
        // missing other fields
      }),
    });
    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('debtRatioBps');
  });

  it.each([
    ['annualRevenueKrw', '-1'],
    ['annualRevenueKrw', '18446744073709551616'],
    ['debtRatioBps', '4294967296'],
    ['overdueCount', '65536'],
    ['companyCommitmentHash', '-1'],
  ])('POST /attest returns 400 when %s is invalid', async (field, value) => {
    const request = {
      annualRevenueKrw: '500000000',
      debtRatioBps: '20000',
      overdueCount: '1',
      companyCommitmentHash: '12345678901234567890',
      [field]: value,
    };
    const res = await fetch(`${baseUrl}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(request),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain(field);
  });

  it('rejects non-string financial values instead of accepting JSON numbers', async () => {
    const res = await fetch(`${baseUrl}/attest`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        annualRevenueKrw: 500000000,
        debtRatioBps: '20000',
        overdueCount: '1',
        companyCommitmentHash: '12345678901234567890',
      }),
    });

    expect(res.status).toBe(400);
    const body = await res.json();
    expect(body.error).toContain('annualRevenueKrw');
  });
});
