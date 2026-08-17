// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { constants } from 'node:fs';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { randomBytes } from 'node:crypto';
import { currentDir } from './config.js';

export const PRIVATE_STATE_PROCESS_LOCK_PATH = path.resolve(currentDir, '..', '.gasok-midnight-private-state.lock');

interface LockFileRecord {
  readonly version: 1;
  readonly pid: number;
  readonly owner: string;
  readonly startedAt: string;
  readonly nonce: string;
}

export interface PrivateStateProcessLock {
  readonly path: string;
  readonly owner: string;
  release(): Promise<void>;
}

export class PrivateStateProcessLockError extends Error {
  constructor(message = 'Another GASOK Midnight CLI or Proof Bridge process is already using local private state.') {
    super(message);
    this.name = 'PrivateStateProcessLockError';
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function parseLockFile(value: string): LockFileRecord | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value) as unknown;
  } catch {
    return null;
  }
  const expectedKeys = ['nonce', 'owner', 'pid', 'startedAt', 'version'];
  const actualKeys = isRecord(parsed) ? Object.keys(parsed).sort() : [];
  if (
    !isRecord(parsed) ||
    actualKeys.length !== expectedKeys.length ||
    !actualKeys.every((key, index) => key === expectedKeys[index]) ||
    parsed.version !== 1 ||
    typeof parsed.pid !== 'number' ||
    !Number.isSafeInteger(parsed.pid) ||
    parsed.pid <= 0 ||
    typeof parsed.owner !== 'string' ||
    !/^[a-z0-9-]{1,64}$/.test(parsed.owner) ||
    typeof parsed.startedAt !== 'string' ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(parsed.startedAt) ||
    Number.isNaN(Date.parse(parsed.startedAt)) ||
    typeof parsed.nonce !== 'string' ||
    !/^[0-9a-f]{64}$/.test(parsed.nonce)
  ) {
    return null;
  }
  return parsed as unknown as LockFileRecord;
}

function isProcessRunning(pid: number): boolean {
  try {
    process.kill(pid, 0);
    return true;
  } catch (error: unknown) {
    return (error as NodeJS.ErrnoException).code !== 'ESRCH';
  }
}

async function removeStaleRegularLock(lockPath: string): Promise<boolean> {
  let stat;
  try {
    stat = await fs.lstat(lockPath);
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return true;
    }
    throw error;
  }
  if (!stat.isFile() || stat.isSymbolicLink()) {
    throw new PrivateStateProcessLockError('The GASOK Midnight private-state lock path is not a regular file.');
  }
  if (stat.size > 4_096 || (typeof process.getuid === 'function' && stat.uid !== process.getuid())) {
    throw new PrivateStateProcessLockError('The GASOK Midnight private-state lock file is invalid.');
  }

  let existing: LockFileRecord | null = null;
  try {
    existing = parseLockFile(await fs.readFile(lockPath, 'utf8'));
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return true;
    }
    throw error;
  }
  if (existing === null) {
    throw new PrivateStateProcessLockError(
      'The GASOK Midnight private-state lock file is invalid; remove it only after confirming no CLI or Proof Bridge process is running.',
    );
  }
  if (isProcessRunning(existing.pid)) {
    return false;
  }

  try {
    await fs.unlink(lockPath);
    return true;
  } catch (error: unknown) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
      return true;
    }
    throw error;
  }
}

export async function acquirePrivateStateProcessLock(
  owner: string,
  lockPath = PRIVATE_STATE_PROCESS_LOCK_PATH,
): Promise<PrivateStateProcessLock> {
  if (!/^[a-z0-9-]{1,64}$/.test(owner)) {
    throw new Error('Private-state lock owner is invalid.');
  }
  await fs.mkdir(path.dirname(lockPath), { recursive: true });
  const record: LockFileRecord = {
    version: 1,
    pid: process.pid,
    owner,
    startedAt: new Date().toISOString(),
    nonce: randomBytes(32).toString('hex'),
  };

  let handle: fs.FileHandle | undefined;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      handle = await fs.open(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
      await handle.writeFile(`${JSON.stringify(record)}\n`, { encoding: 'utf8' });
      await handle.sync();
      await handle.close();
      handle = undefined;
      break;
    } catch (error: unknown) {
      await handle?.close().catch(() => undefined);
      handle = undefined;
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') {
        throw error;
      }
      if (!(await removeStaleRegularLock(lockPath)) || attempt === 1) {
        throw new PrivateStateProcessLockError();
      }
    }
  }

  let released = false;
  return {
    path: lockPath,
    owner,
    async release(): Promise<void> {
      if (released) {
        return;
      }
      released = true;
      let current: LockFileRecord | null;
      try {
        current = parseLockFile(await fs.readFile(lockPath, 'utf8'));
      } catch (error: unknown) {
        if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
          return;
        }
        throw error;
      }
      if (current?.nonce !== record.nonce || current.pid !== record.pid) {
        return;
      }
      await fs.unlink(lockPath).catch((error: unknown) => {
        if ((error as NodeJS.ErrnoException).code !== 'ENOENT') {
          throw error;
        }
      });
    },
  };
}
