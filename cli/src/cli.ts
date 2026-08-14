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

import { stdin as input, stdout as output } from 'node:process';
import { createInterface, type Interface } from 'node:readline/promises';
import { type Logger } from 'pino';
import { type StartedDockerComposeEnvironment, type DockerComposeEnvironment } from 'testcontainers';
import { type GasokEligibilityProviders, type DeployedGasokEligibilityContract } from './common-types';
import { type Config, StandaloneConfig } from './config';
import * as api from './api';
import type { WalletContext } from './api';
import { getInitialPrivateState } from './state.utils';
import 'dotenv/config';

let logger: Logger;

/**
 * This seed gives access to tokens minted in the genesis block of a local development node - only
 * used in standalone networks to build a wallet with initial funds.
 */
const GENESIS_MINT_WALLET_SEED = '0000000000000000000000000000000000000000000000000000000000000001';

const DEPLOY_OR_JOIN_QUESTION = `
You can do one of the following:
  1. Deploy a new GASOK Financial Eligibility contract
  2. Join an existing GASOK Financial Eligibility contract
  3. Exit
Which would you like to do? `;

const MAIN_LOOP_QUESTION = `
You can do one of the following:
  1. Verify GASOK financial eligibility
  2. Display public contract state
  3. Display wallet balances
  4. [Admin] Rotate admin role to new derived public key
  5. [Admin] Register Mock Attestation Provider
  6. [Admin] Remove Mock Attestation Provider
  7. Exit
Which would you like to do? `;

const join = async (
  providers: GasokEligibilityProviders,
  rli: Interface,
): Promise<DeployedGasokEligibilityContract> => {
  const contractAddress = await rli.question('What is the contract address (in hex)? ');
  return await api.joinContract(providers, contractAddress);
};

const deployOrJoin = async (
  providers: GasokEligibilityProviders,
  rli: Interface,
): Promise<DeployedGasokEligibilityContract | null> => {
  while (true) {
    const choice = await rli.question(DEPLOY_OR_JOIN_QUESTION);
    switch (choice) {
      case '1':
        return await api.deploy(providers, getInitialPrivateState());
      case '2':
        return await join(providers, rli);
      case '3':
        logger.info('Exiting...');
        return null;
      default:
        logger.error(`Invalid choice: ${choice}`);
    }
  }
};

const parseUint = (input: string, label: string, max: bigint): bigint => {
  const value = input.trim();
  if (!/^\d+$/.test(value)) {
    throw new Error(`${label} must be a non-negative integer.`);
  }
  const parsed = BigInt(value);
  if (parsed > max) {
    throw new Error(`${label} exceeds the supported range.`);
  }
  return parsed;
};

const verifyEligibilityFlow = async (
  contract: DeployedGasokEligibilityContract,
  providers: GasokEligibilityProviders,
  rli: Interface,
): Promise<void> => {
  const annualRevenueKrwStr = await rli.question('Enter annual revenue in integer KRW: ');
  const debtRatioBpsStr = await rli.question('Enter debt ratio in basis points (200.00% = 20000): ');
  const overdueCountStr = await rli.question('Enter overdue count: ');
  const pinStr = await rli.question('Enter your secret PIN: ');

  const annualRevenueKrw = parseUint(annualRevenueKrwStr, 'Annual revenue', (1n << 64n) - 1n);
  const debtRatioBps = parseUint(debtRatioBpsStr, 'Debt ratio', (1n << 32n) - 1n);
  const overdueCount = parseUint(overdueCountStr, 'Overdue count', (1n << 16n) - 1n);
  const pin = parseUint(pinStr, 'PIN', (1n << 16n) - 1n);

  const attestationApiUrl = process.env.ATTESTATION_API_URL || 'http://localhost:4000';

  await api.verifyEligibility(contract, providers, annualRevenueKrw, debtRatioBps, overdueCount, pin, attestationApiUrl);
  logger.info('GASOK financial eligibility proof submitted successfully!');
};

// Rotate the admin role to a public key the new admin already derived
// locally. The new admin runs `deriveAdminPublicKey(userSecret)` against
// their own 32-byte user secret and hands the resulting public key (64 hex
// chars) to the current admin. No private key is exchanged.
const rotateAdminFlow = async (contract: DeployedGasokEligibilityContract, rli: Interface): Promise<void> => {
  const input = await rli.question(
    'Enter the new admin derived public key (64 hex chars). ' +
      'The new admin generates this with `deriveAdminPublicKey(companySecret)` and shares only the result: ',
  );
  const hex = input.trim().toLowerCase().replace(/^0x/, '');
  if (!/^[0-9a-f]{64}$/.test(hex)) {
    throw new Error('New admin public key must be exactly 64 hex chars (32 bytes).');
  }
  await api.rotateAdmin(contract, Uint8Array.from(Buffer.from(hex, 'hex')));
  logger.info('Admin role rotated successfully!');
};

const registerProviderFlow = async (contract: DeployedGasokEligibilityContract, rli: Interface): Promise<void> => {
  const providerIdStr = await rli.question('Enter the provider ID (number): ');
  const pkXStr = await rli.question('Enter the provider public key X coordinate (bigint): ');
  const pkYStr = await rli.question('Enter the provider public key Y coordinate (bigint): ');

  const providerId = BigInt(providerIdStr);
  const providerPk = { x: BigInt(pkXStr), y: BigInt(pkYStr) };

  await api.registerProvider(contract, providerId, providerPk);
  logger.info('Attestation provider registered successfully!');
};

const removeProviderFlow = async (contract: DeployedGasokEligibilityContract, rli: Interface): Promise<void> => {
  const providerIdStr = await rli.question('Enter the provider ID to remove (number): ');
  const providerId = BigInt(providerIdStr);

  await api.removeProvider(contract, providerId);
  logger.info('Attestation provider removed successfully!');
};

const mainLoop = async (
  providers: GasokEligibilityProviders,
  walletContext: WalletContext,
  rli: Interface,
): Promise<void> => {
  const contract = await deployOrJoin(providers, rli);
  if (contract === null) {
    return;
  }
  while (true) {
    const choice = await rli.question(MAIN_LOOP_QUESTION);
    try {
      switch (choice) {
        case '1':
          await verifyEligibilityFlow(contract, providers, rli);
          break;
        case '2':
          await api.displayContractState(providers, contract);
          break;
        case '3':
          await api.displayWalletBalances(walletContext.wallet);
          break;
        case '4':
          await rotateAdminFlow(contract, rli);
          break;
        case '5':
          await registerProviderFlow(contract, rli);
          break;
        case '6':
          await removeProviderFlow(contract, rli);
          break;
        case '7':
          logger.info('Exiting...');
          return;
        default:
          logger.error(`Invalid choice: ${choice}`);
      }
    } catch (e) {
      if (e instanceof Error) {
        logger.error(`Operation failed: ${e.message}`);
      } else {
        logger.error(`Operation failed: ${e}`);
      }
    }
  }
};

const buildWalletFromMnemonic = async (config: Config, rli: Interface): Promise<WalletContext> => {
  const mnemonic = await rli.question('Enter your wallet mnemonic (24 words): ');
  return await api.buildWalletAndWaitForFunds(config, mnemonic);
};

const WALLET_LOOP_QUESTION = `
You can do one of the following:
  1. Build a fresh wallet
  2. Build wallet from a mnemonic
  3. Use mnemonic from .env file
  4. Exit
Which would you like to do? `;

const buildWallet = async (config: Config, rli: Interface): Promise<WalletContext | null> => {
  if (config instanceof StandaloneConfig) {
    // For standalone, use genesis wallet with hex seed
    return await api.buildWalletFromHexSeed(config, GENESIS_MINT_WALLET_SEED);
  }

  // Check if mnemonic is available in environment
  const envMnemonic = process.env.WALLET_MNEMONIC;

  while (true) {
    const choice = await rli.question(WALLET_LOOP_QUESTION);
    switch (choice) {
      case '1':
        return await api.buildFreshWallet(config);
      case '2':
        return await buildWalletFromMnemonic(config, rli);
      case '3':
        if (envMnemonic) {
          logger.info('Using mnemonic from .env file...');
          return await api.buildWalletAndWaitForFunds(config, envMnemonic);
        } else {
          logger.error('No WALLET_MNEMONIC found in .env file');
        }
        break;
      case '4':
        logger.info('Exiting...');
        return null;
      default:
        logger.error(`Invalid choice: ${choice}`);
    }
  }
};

const mapContainerPort = (env: StartedDockerComposeEnvironment, url: string, containerName: string) => {
  const mappedUrl = new URL(url);
  const container = env.getContainer(containerName);

  mappedUrl.port = String(container.getFirstMappedPort());

  return mappedUrl.toString().replace(/\/+$/, '');
};

export const run = async (config: Config, _logger: Logger, dockerEnv?: DockerComposeEnvironment): Promise<void> => {
  logger = _logger;
  api.setLogger(_logger);
  const rli = createInterface({ input, output, terminal: true });
  let env;
  let walletContext: WalletContext | null = null;

  if (dockerEnv !== undefined) {
    env = await dockerEnv.up();

    if (config instanceof StandaloneConfig) {
      config.indexer = mapContainerPort(env, config.indexer, 'zkloan-indexer');
      config.indexerWS = mapContainerPort(env, config.indexerWS, 'zkloan-indexer');
      config.node = mapContainerPort(env, config.node, 'zkloan-node');
      config.proofServer = mapContainerPort(env, config.proofServer, 'zkloan-proof-server');
    }
  }

  try {
    walletContext = await buildWallet(config, rli);
    if (walletContext !== null) {
      const providers = await api.configureProviders(walletContext, config);
      await mainLoop(providers, walletContext, rli);
    }
  } catch (e) {
    if (e instanceof Error) {
      logger.error(`Found error '${e.message}'`);
      logger.info('Exiting...');
      logger.debug(`${e.stack}`);
    } else {
      throw e;
    }
  } finally {
    try {
      rli.close();
      rli.removeAllListeners();
    } catch (e) {
      logger.error(`Error closing readline interface: ${e}`);
    } finally {
      try {
        if (walletContext !== null) {
          await api.closeWallet(walletContext);
        }
      } catch (e) {
        logger.error(`Error closing wallet: ${e}`);
      } finally {
        try {
          if (env !== undefined) {
            await env.down();
            logger.info('Goodbye');
          }
        } catch (e) {
          logger.error(`Error shutting down docker environment: ${e}`);
        }
      }
    }
  }
};
