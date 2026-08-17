// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { chmod, mkdtemp, readFile, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, expect, it, vi } from 'vitest';
import { generateFreshWalletMnemonic } from '../api';
import type { AuthorizationChallenge } from '../authorization';
import { writeFreshWalletMnemonicOnce, writeRoleAuthorizationRequest } from '../cli';
import { createLogger } from '../logger-utils';

describe('CLI secret handling', () => {
  it('writes a fresh mnemonic exactly once only to an interactive terminal', () => {
    const mnemonic = generateFreshWalletMnemonic();
    const write = vi.fn();

    writeFreshWalletMnemonicOnce(mnemonic, { isTTY: true, write });

    expect(mnemonic.trim().split(/\s+/)).toHaveLength(24);
    expect(write).toHaveBeenCalledOnce();
    expect(String(write.mock.calls[0][0])).toContain(mnemonic);

    const redirectedWrite = vi.fn();
    expect(() => writeFreshWalletMnemonicOnce(mnemonic, { isTTY: false, write: redirectedWrite })).toThrow(
      'interactive TTY',
    );
    expect(redirectedWrite).not.toHaveBeenCalled();
  });

  it('contains no logger call that references the mnemonic identifier', async () => {
    const sourceDirectory = fileURLToPath(new URL('..', import.meta.url));
    for (const fileName of ['api.ts', 'cli.ts']) {
      const source = await readFile(path.join(sourceDirectory, fileName), 'utf8');
      expect(source, fileName).not.toMatch(
        /logger\.(?:trace|debug|info|warn|error|fatal)\s*\([^)]*\bmnemonic\b[^)]*\)/i,
      );
    }
  });

  it('shows the EIP-712 signing request only on an interactive terminal', () => {
    const challenge = {
      version: 1,
      message: { partyWallet: `0x${'12'.repeat(20)}` },
    } as unknown as AuthorizationChallenge;
    const write = vi.fn();

    writeRoleAuthorizationRequest(challenge, { isTTY: true, write });

    expect(write).toHaveBeenCalledOnce();
    expect(String(write.mock.calls[0][0])).toContain('EIP-712');
    expect(String(write.mock.calls[0][0])).toContain(challenge.message.partyWallet);
    expect(String(write.mock.calls[0][0])).not.toContain('authorizationSalt');

    const redirectedWrite = vi.fn();
    expect(() => writeRoleAuthorizationRequest(challenge, { isTTY: false, write: redirectedWrite })).toThrow(
      'interactive TTY',
    );
    expect(redirectedWrite).not.toHaveBeenCalled();
  });

  it('does not log authorization requests, signatures, salts, or raw financial values', async () => {
    const sourceDirectory = fileURLToPath(new URL('..', import.meta.url));
    for (const fileName of ['api.ts', 'authorization.ts', 'cli.ts']) {
      const source = await readFile(path.join(sourceDirectory, fileName), 'utf8');
      expect(source, fileName).not.toMatch(
        /logger\.(?:trace|debug|info|warn|error|fatal)\s*\([^)]*\b(?:authorizationRequest|authorizationSalt|signature|annualRevenueKrw|debtRatioBps|overdueCount)\b[^)]*\)/i,
      );
      expect(source, fileName).not.toMatch(
        /\.question\s*\([^)]*(?:private\s*key|privateKey|recovery\s*phrase)[^)]*\)/i,
      );
    }
  });

  it('tightens an existing log file to owner-only permissions', async () => {
    const directory = await mkdtemp(path.join(tmpdir(), 'gasok-midnight-cli-log-'));
    const logPath = path.join(directory, 'existing.log');
    await writeFile(logPath, 'pre-existing log\n', { mode: 0o644 });
    await chmod(logPath, 0o644);

    await expect(createLogger(logPath)).resolves.toBeDefined();

    expect((await stat(logPath)).mode & 0o777).toBe(0o600);
  });
});
