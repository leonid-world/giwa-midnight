// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import * as fs from 'node:fs/promises';
import * as os from 'node:os';
import * as path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { PrivateStateProcessLockError, acquirePrivateStateProcessLock } from '../private-state-process-lock.js';

const tempDirs: string[] = [];

async function temporaryLockPath(): Promise<string> {
  const directory = await fs.mkdtemp(path.join(os.tmpdir(), 'gasok-midnight-lock-test-'));
  tempDirs.push(directory);
  return path.join(directory, 'private-state.lock');
}

afterEach(async () => {
  await Promise.all(tempDirs.splice(0).map((directory) => fs.rm(directory, { recursive: true, force: true })));
});

describe('private-state process lock', () => {
  it('prevents a second live process owner and permits reuse after release', async () => {
    const lockPath = await temporaryLockPath();
    const first = await acquirePrivateStateProcessLock('interactive-cli', lockPath);
    await expect(acquirePrivateStateProcessLock('proof-bridge', lockPath)).rejects.toBeInstanceOf(
      PrivateStateProcessLockError,
    );

    await first.release();
    const second = await acquirePrivateStateProcessLock('proof-bridge', lockPath);
    await second.release();
    await expect(fs.stat(lockPath)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('removes only a well-formed lock whose recorded process is gone', async () => {
    const lockPath = await temporaryLockPath();
    await fs.writeFile(
      lockPath,
      JSON.stringify({
        version: 1,
        pid: 2_147_483_647,
        owner: 'old-proof-bridge',
        startedAt: '2026-08-17T00:00:00.000Z',
        nonce: 'a'.repeat(64),
      }),
      { mode: 0o600 },
    );

    const lock = await acquirePrivateStateProcessLock('proof-bridge', lockPath);
    await lock.release();
  });

  it('fails closed and preserves a corrupt existing lock file', async () => {
    const lockPath = await temporaryLockPath();
    await fs.writeFile(lockPath, 'not-json', { mode: 0o600 });

    await expect(acquirePrivateStateProcessLock('proof-bridge', lockPath)).rejects.toThrow(/lock file is invalid/);
    await expect(fs.readFile(lockPath, 'utf8')).resolves.toBe('not-json');
  });

  it('does not delete a lock file that was replaced by another owner', async () => {
    const lockPath = await temporaryLockPath();
    const lock = await acquirePrivateStateProcessLock('proof-bridge', lockPath);
    const replacement = JSON.stringify({
      version: 1,
      pid: process.pid,
      owner: 'interactive-cli',
      startedAt: new Date().toISOString(),
      nonce: 'b'.repeat(64),
    });
    await fs.writeFile(lockPath, replacement, { mode: 0o600 });

    await lock.release();
    await expect(fs.readFile(lockPath, 'utf8')).resolves.toBe(replacement);
  });
});
