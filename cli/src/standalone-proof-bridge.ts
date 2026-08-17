// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { createLogger } from './logger-utils.js';
import { StandaloneConfig } from './config.js';
import { acquirePrivateStateProcessLock } from './private-state-process-lock.js';
import { runStandaloneProofBridge } from './proof-bridge/local-runtime.js';

const config = new StandaloneConfig();
const logger = await createLogger(config.logDir);
const processLock = await acquirePrivateStateProcessLock('proof-bridge');
try {
  await runStandaloneProofBridge(logger);
} finally {
  await processLock.release();
}
