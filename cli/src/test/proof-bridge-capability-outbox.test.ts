// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import type { ProofCapability } from '../api.js';
import {
  CapabilityOutboxError,
  openCapabilityOutbox,
  type CapabilityBinding,
  type ProofCapabilityOutbox,
} from '../proof-bridge/capability-outbox.js';

const SESSION_ID = `0x${'1'.repeat(64)}`;
const REQUEST_ID = `0x${'2'.repeat(64)}`;
const PASSWORD = 'Local-Outbox-Test-Password!2026';
const NOW_MS = 1_800_000_000_000;

const capability: ProofCapability = Object.freeze({
  version: 2,
  evaluationVersion: 2,
  midnightContractAddress: '3'.repeat(64),
  companyCommitment: `0x${'4'.repeat(64)}`,
  lookupKey: `0x${'5'.repeat(64)}`,
  giwaChainId: '91342',
  receivableFinanceAddress: `0x${'6'.repeat(40)}`,
  onchainReceivableId: '2',
  subjectRole: 'SELLER',
  partyWallet: `0x${'7'.repeat(40)}`,
  requestId: REQUEST_ID,
  intendedFunderWallet: `0x${'8'.repeat(40)}`,
  minAnnualRevenueKrw: '500000000',
  maxDebtRatioBps: '20000',
  maxOverdueCount: '1',
  policyRequestHash: `0x${'9'.repeat(64)}`,
  profileAsOf: '1800000000',
  validUntil: '1800003600',
});

const binding: CapabilityBinding = Object.freeze({
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

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories.splice(0).map(async (directory) => await fs.rm(directory, { recursive: true })),
  );
});

async function temporaryOutboxPath(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gasok-capability-outbox-test-'));
  temporaryDirectories.push(directory);
  return path.join(directory, 'private', 'outbox.enc');
}

async function open(filePath: string, password = PASSWORD, now = () => NOW_MS): Promise<ProofCapabilityOutbox> {
  return await openCapabilityOutbox({ filePath, password, now });
}

async function finalize(outbox: ProofCapabilityOutbox): Promise<void> {
  await outbox.reserve(SESSION_ID, binding, '1800000120');
  await outbox.markProving(SESSION_ID, REQUEST_ID);
  await outbox.persist(SESSION_ID, capability);
}

describe('encrypted durable proof capability outbox', () => {
  it('atomically encrypts only the exact request-bound capability and recovers it after restart', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    await finalize(outbox);
    expect(outbox.recoverByRequest(REQUEST_ID)).toEqual({
      version: 2,
      sessionId: SESSION_ID,
      status: 'complete',
      proofCapability: capability,
    });
    outbox.close();

    const encoded = await fs.readFile(filePath, 'utf8');
    expect(encoded).not.toContain(REQUEST_ID);
    expect(encoded).not.toContain(capability.companyCommitment);
    expect(encoded).not.toContain(capability.lookupKey);
    expect(encoded).not.toContain('annualRevenueKrw');
    expect(encoded).not.toContain('secretPin');
    expect(encoded).not.toContain('signature');
    expect((await fs.stat(filePath)).mode & 0o777).toBe(0o600);
    expect((await fs.stat(path.dirname(filePath))).mode & 0o777).toBe(0o700);

    const restarted = await open(filePath);
    expect(restarted.recoverBySession(SESSION_ID).proofCapability).toEqual(capability);
    expect(() => restarted.assertRequestAvailable(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_AVAILABLE' }),
    );
    restarted.close();
  });

  it('fails closed on a wrong password or authenticated ciphertext tampering', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    await finalize(outbox);
    outbox.close();

    await expect(open(filePath, 'Wrong-Password!2026')).rejects.toMatchObject({
      code: 'CAPABILITY_OUTBOX_INVALID',
    });

    const envelope = JSON.parse(await fs.readFile(filePath, 'utf8')) as Record<string, unknown>;
    const ciphertext = Buffer.from(String(envelope.ciphertext), 'base64');
    ciphertext[0] ^= 1;
    envelope.ciphertext = ciphertext.toString('base64');
    await fs.writeFile(filePath, `${JSON.stringify(envelope)}\n`, { mode: 0o600 });
    await expect(open(filePath)).rejects.toMatchObject({ code: 'CAPABILITY_OUTBOX_INVALID' });
  });

  it('persists a pre-submission reservation, blocks duplicate proof, and expires safely', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    await outbox.reserve(SESSION_ID, binding, '1800000120');
    expect(() => outbox.assertRequestAvailable(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_IN_PROGRESS' }),
    );
    expect(() => outbox.recoverByRequest(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_IN_PROGRESS' }),
    );
    outbox.close();

    const restarted = await open(filePath);
    expect(() => restarted.assertRequestAvailable(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_IN_PROGRESS' }),
    );
    restarted.close();

    const afterAuthorizationExpiry = await open(filePath, PASSWORD, () => 1_800_000_121_000);
    expect(() => afterAuthorizationExpiry.assertRequestAvailable(REQUEST_ID)).not.toThrow();
    afterAuthorizationExpiry.close();
  });

  it('serializes concurrent durable reservations without losing either request on restart', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    const secondRequestId = `0x${'a'.repeat(64)}`;
    const secondSessionId = `0x${'b'.repeat(64)}`;
    const secondBinding: CapabilityBinding = Object.freeze({
      ...binding,
      requestId: secondRequestId,
      onchainReceivableId: '3',
      partyWallet: `0x${'c'.repeat(40)}`,
    });

    await Promise.all([
      outbox.reserve(SESSION_ID, binding, '1800000120'),
      outbox.reserve(secondSessionId, secondBinding, '1800000120'),
    ]);
    outbox.close();

    const restarted = await open(filePath);
    expect(() => restarted.assertRequestAvailable(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_IN_PROGRESS' }),
    );
    expect(() => restarted.assertRequestAvailable(secondRequestId)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_IN_PROGRESS' }),
    );
    restarted.close();
  });

  it('keeps an indeterminate proving reservation until policy expiry after restart', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    await outbox.reserve(SESSION_ID, binding, '1800000120');
    await outbox.markProving(SESSION_ID, REQUEST_ID);
    outbox.close();

    const afterAuthorizationExpiry = await open(filePath, PASSWORD, () => 1_800_000_121_000);
    expect(() => afterAuthorizationExpiry.assertRequestAvailable(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_IN_PROGRESS' }),
    );
    afterAuthorizationExpiry.close();

    const afterPolicyExpiry = await open(filePath, PASSWORD, () => 1_800_003_600_000);
    expect(() => afterPolicyExpiry.assertRequestAvailable(REQUEST_ID)).not.toThrow();
    afterPolicyExpiry.close();
  });

  it('deletes the capability only after acknowledgement and keeps ACK idempotent across restart', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    await finalize(outbox);
    await outbox.acknowledge(SESSION_ID, REQUEST_ID);
    expect(() => outbox.recoverByRequest(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_NOT_FOUND' }),
    );
    await expect(outbox.acknowledge(SESSION_ID, REQUEST_ID)).resolves.toBeUndefined();
    outbox.close();

    const restarted = await open(filePath);
    await expect(restarted.acknowledge(SESSION_ID, REQUEST_ID)).resolves.toBeUndefined();
    expect(() => restarted.assertRequestAvailable(REQUEST_ID)).toThrow(
      expect.objectContaining({ code: 'PROOF_RESULT_ALREADY_DELIVERED' }),
    );
    restarted.close();
  });

  it('rejects an exact-binding mismatch and never accepts extra private fields', async () => {
    const filePath = await temporaryOutboxPath();
    const outbox = await open(filePath);
    await expect(
      outbox.reserve(SESSION_ID, { ...binding, partyWallet: `0x${'f'.repeat(40)}` }, '1800000120'),
    ).resolves.toBeUndefined();
    await outbox.markProving(SESSION_ID, REQUEST_ID);
    await expect(outbox.persist(SESSION_ID, capability)).rejects.toMatchObject({
      code: 'PROOF_RESULT_BINDING_MISMATCH',
    });
    outbox.close();

    const secondPath = await temporaryOutboxPath();
    const second = await open(secondPath);
    await second.reserve(SESSION_ID, binding, '1800000120');
    await second.markProving(SESSION_ID, REQUEST_ID);
    await expect(
      second.persist(SESSION_ID, { ...capability, rawAnnualRevenueKrw: '700000000' } as ProofCapability),
    ).rejects.toBeInstanceOf(CapabilityOutboxError);
    second.close();
  });

  it('fails startup when the configured outbox directory cannot be established', async () => {
    const parent = await fs.mkdtemp(path.join(os.tmpdir(), 'gasok-capability-outbox-file-'));
    temporaryDirectories.push(parent);
    const blocker = path.join(parent, 'not-a-directory');
    await fs.writeFile(blocker, 'block');
    await expect(open(path.join(blocker, 'outbox.enc'))).rejects.toMatchObject({
      code: 'CAPABILITY_OUTBOX_UNAVAILABLE',
    });
  });
});
