// This file is part of the ZKLoan Credit Scorer example.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0
// Licensed under the Apache License, Version 2.0 (the "License");
// You may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import path from 'path';
import * as api from '../api';
import type { WalletContext } from '../api';
import { type GasokEligibilityProviders } from '../common-types';
import { currentDir } from '../config';
import { createLogger } from '../logger-utils';
import { TestEnvironment } from './commons';
import { getInitialPrivateState } from '../state.utils';
import { describe, it, expect, beforeAll, afterAll } from 'vitest';

const logDir = path.resolve(currentDir, '..', 'logs', 'tests', `${new Date().toISOString()}.log`);
const logger = await createLogger(logDir);

describe('GASOK Financial Eligibility API', () => {
  let testEnvironment: TestEnvironment;
  let walletContext: WalletContext;
  let providers: GasokEligibilityProviders;

  beforeAll(
    async () => {
      api.setLogger(logger);
      testEnvironment = new TestEnvironment(logger);
      const testConfiguration = await testEnvironment.start();
      walletContext = await testEnvironment.getWallet();
      providers = await api.configureProviders(walletContext, testConfiguration.dappConfig);
    },
    1000 * 60 * 45,
  );

  afterAll(async () => {
    await testEnvironment.shutdown();
  });

  // Skipped: requires a running attestation API (see zkloan-credit-scorer-attestation-api)
  // and registered provider on-chain. The deploy + ledger-read portion still works.
  it.skip('should deploy the contract and verify eligibility [@slow]', async () => {
    const contract = await api.deploy(providers, getInitialPrivateState());
    expect(contract).not.toBeNull();

    // Check initial state
    const initialState = await api.displayContractState(providers, contract);
    expect(initialState.ledgerState).not.toBeNull();

    await new Promise((resolve) => setTimeout(resolve, 2000));
    const secretPin = 1234n;

    const attestationApiUrl = process.env.ATTESTATION_API_URL ?? 'http://localhost:4000';

    const response = await api.verifyEligibility(
      contract,
      providers,
      500_000_000n,
      20_000n,
      1n,
      secretPin,
      attestationApiUrl,
    );
    expect(response.txId).toMatch(/[0-9a-f]{64}/);
    expect(response.blockHeight).toBeGreaterThan(BigInt(0));

    // Verify the public result state is queryable.
    const stateAfter = await api.displayContractState(providers, contract);
    expect(stateAfter.contractAddress).toEqual(initialState.contractAddress);
  });
});
