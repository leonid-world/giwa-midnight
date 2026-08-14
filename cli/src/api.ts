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

import 'dotenv/config';
import {
  type ContractAddress,
  transientHash,
  CompactTypeBytes,
} from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { GasokEligibility, type GasokEligibilityPrivateState, witnesses } from 'zkloan-credit-scorer-contract';
import * as ledger from '@midnight-ntwrk/midnight-js-protocol/ledger';
import { CompiledContract } from '@midnight-ntwrk/midnight-js-protocol/compact-js';
import { deployContract, findDeployedContract } from '@midnight-ntwrk/midnight-js-contracts';
import { httpClientProofProvider } from '@midnight-ntwrk/midnight-js-http-client-proof-provider';
import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { NodeZkConfigProvider } from '@midnight-ntwrk/midnight-js-node-zk-config-provider';
import { levelPrivateStateProvider } from '@midnight-ntwrk/midnight-js-level-private-state-provider';
import {
  type FinalizedTxData,
  type MidnightProvider,
  type WalletProvider,
  type UnboundTransaction,
} from '@midnight-ntwrk/midnight-js-types';
import { assertIsContractAddress } from '@midnight-ntwrk/midnight-js-utils';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';

// Wallet SDK imports (consolidated through the @midnight-ntwrk/wallet-sdk barrel
// introduced alongside Midnight.js 4.1.x / ledger-v8 8.1.0).
import {
  HDWallet,
  Roles,
  WalletFacade,
  ShieldedWallet,
  DustWallet,
  UnshieldedWallet,
  createKeystore,
  InMemoryTransactionHistoryStorage,
  WalletEntrySchema,
  PublicKey as UnshieldedPublicKey,
  type UnshieldedKeystore,
} from '@midnight-ntwrk/wallet-sdk';
import * as bip39 from '@scure/bip39';
import { wordlist as english } from '@scure/bip39/wordlists/english.js';

import { webcrypto } from 'crypto';
import { type Logger } from 'pino';
import * as Rx from 'rxjs';
import { WebSocket } from 'ws';
import { Buffer } from 'buffer';
import {
  type GasokEligibilityContract,
  type GasokEligibilityPrivateStateId,
  type GasokEligibilityProviders,
  type DeployedGasokEligibilityContract,
  type GasokEligibilityCircuits,
} from './common-types';
import { type Config, contractConfig } from './config';
import { getInitialPrivateState } from './state.utils';

let logger: Logger;
// @ts-expect-error: It's needed to enable WebSocket usage through apollo
globalThis.WebSocket = WebSocket;

// Types for the new wallet
export interface WalletContext {
  wallet: WalletFacade;
  shieldedSecretKeys: ledger.ZswapSecretKeys;
  dustSecretKey: ledger.DustSecretKey;
  unshieldedKeystore: UnshieldedKeystore;
}

export const getGasokEligibilityLedgerState = async (
  providers: GasokEligibilityProviders,
  contractAddress: ContractAddress,
): Promise<GasokEligibility.Ledger | null> => {
  assertIsContractAddress(contractAddress);
  logger.info('Checking contract ledger state...');
  const state = await providers.publicDataProvider
    .queryContractState(contractAddress)
    .then((contractState) => (contractState != null ? GasokEligibility.ledger(contractState.data) : null));
  return state;
};

// Create compiled contract using the stable API pattern
export const gasokEligibilityCompiledContract = CompiledContract.make<GasokEligibilityContract>(
  'GasokEligibility',
  GasokEligibility.Contract,
).pipe(CompiledContract.withWitnesses(witnesses), CompiledContract.withCompiledFileAssets(contractConfig.zkConfigPath));

export const joinContract = async (
  providers: GasokEligibilityProviders,
  contractAddress: string,
): Promise<DeployedGasokEligibilityContract> => {
  const contract = await findDeployedContract(providers as any, {
    contractAddress,
    compiledContract: gasokEligibilityCompiledContract,
    privateStateId: 'gasokEligibilityPrivateState',
    initialPrivateState: getInitialPrivateState(),
  });
  logger.info(`Joined contract at address: ${contract.deployTxData.public.contractAddress}`);

  return contract as any;
};

export const deploy = async (
  providers: GasokEligibilityProviders,
  privateState: GasokEligibilityPrivateState,
): Promise<DeployedGasokEligibilityContract> => {
  logger.info('Deploying GASOK Financial Eligibility contract...');

  const contract = await deployContract(providers as any, {
    compiledContract: gasokEligibilityCompiledContract,
    privateStateId: 'gasokEligibilityPrivateState',
    initialPrivateState: privateState,
    // Note: as of midnight-js 4.1.x, `args` is conditionally typed and must be
    // omitted entirely when the contract constructor takes no arguments.
  });
  logger.info(`Deployed contract at address: ${contract.deployTxData.public.contractAddress}`);

  return contract as any;
};

// GASOK financial-eligibility operations

const bytes32Type = new CompactTypeBytes(32);
const { pureCircuits } = GasokEligibility;

export const deriveCompanyCommitment = (companySecretKey: Uint8Array, pin: bigint): Uint8Array => {
  return pureCircuits.deriveCompanyCommitment(companySecretKey, pin);
};

export const computeCompanyCommitmentHash = (companySecretKey: Uint8Array, pin: bigint): bigint => {
  return transientHash(bytes32Type, deriveCompanyCommitment(companySecretKey, pin));
};

export const fetchAttestation = async (
  attestationApiUrl: string,
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  companyCommitmentHash: bigint,
): Promise<{ announcement: { x: bigint; y: bigint }; response: bigint }> => {
  const res = await fetch(`${attestationApiUrl}/attest`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      annualRevenueKrw: annualRevenueKrw.toString(),
      debtRatioBps: debtRatioBps.toString(),
      overdueCount: overdueCount.toString(),
      companyCommitmentHash: companyCommitmentHash.toString(),
    }),
  });
  if (!res.ok) {
    throw new Error(`Mock Attestation API error: ${res.status} ${await res.text()}`);
  }
  const data = (await res.json()) as { signature: { announcement: { x: string; y: string }; response: string } };
  return {
    announcement: { x: BigInt(data.signature.announcement.x), y: BigInt(data.signature.announcement.y) },
    response: BigInt(data.signature.response),
  };
};

export const verifyEligibility = async (
  contract: DeployedGasokEligibilityContract,
  providers: GasokEligibilityProviders,
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  secretPin: bigint,
  attestationApiUrl: string,
): Promise<FinalizedTxData> => {
  const currentState = await providers.privateStateProvider.get('gasokEligibilityPrivateState');
  if (!currentState) {
    throw new Error('No private state found');
  }

  const companyCommitmentHash = computeCompanyCommitmentHash(currentState.companySecretKey, secretPin);
  logger.info('Computed pseudonymous company commitment hash for mock attestation');

  logger.info(`Fetching mock attestation from ${attestationApiUrl}...`);
  const signature = await fetchAttestation(
    attestationApiUrl,
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    companyCommitmentHash,
  );

  const providerRes = await fetch(`${attestationApiUrl}/provider-info`);
  if (!providerRes.ok) {
    throw new Error(`Mock provider info error: ${providerRes.status} ${await providerRes.text()}`);
  }
  const providerInfo = (await providerRes.json()) as { providerId: number };

  const updatedState: GasokEligibilityPrivateState = {
    ...currentState,
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    attestationSignature: signature,
    attestationProviderId: BigInt(providerInfo.providerId),
  };
  await providers.privateStateProvider.set('gasokEligibilityPrivateState', updatedState);
  logger.info(`Private state updated with mock attestation (provider ${providerInfo.providerId})`);

  logger.info('Generating and submitting GASOK financial eligibility proof...');
  const finalizedTxData = await contract.callTx.verifyEligibility(secretPin);
  logger.info(`Transaction ${finalizedTxData.public.txId} added in block ${finalizedTxData.public.blockHeight}`);
  return finalizedTxData.public;
};

// Hand the admin role over by writing the new admin's derived public key
// to the ledger. The new admin generates their secret locally and computes
// `deriveAdminPublicKey(secret)` off-chain; only the resulting 32-byte
// public key crosses the wire. No private key is ever transmitted.
export const rotateAdmin = async (
  contract: DeployedGasokEligibilityContract,
  newAdminPublicKey: Uint8Array,
): Promise<FinalizedTxData> => {
  logger.info('Rotating admin role to new derived public key...');
  const finalizedTxData = await contract.callTx.rotateAdmin(newAdminPublicKey);
  logger.info(`Transaction ${finalizedTxData.public.txId} added in block ${finalizedTxData.public.blockHeight}`);
  return finalizedTxData.public;
};

// Compute the AdminPublicKey for a given user secret. Run by a prospective
// new admin to obtain the 32-byte public key they hand to the current admin.
// Same `userSecretKey` is used for both per-user identity (PIN-bound) and
// the admin role (no PIN) — different domain separators inside the contract
// keep them logically independent.
export const deriveAdminPublicKey = (companySecretKey: Uint8Array): Uint8Array => {
  return pureCircuits.deriveAdminPublicKey(companySecretKey);
};

export const registerProvider = async (
  contract: DeployedGasokEligibilityContract,
  providerId: bigint,
  providerPk: { x: bigint; y: bigint },
): Promise<FinalizedTxData> => {
  logger.info(`Registering attestation provider ${providerId}...`);
  const finalizedTxData = await contract.callTx.registerProvider(providerId, providerPk);
  logger.info(`Transaction ${finalizedTxData.public.txId} added in block ${finalizedTxData.public.blockHeight}`);
  return finalizedTxData.public;
};

export const removeProvider = async (
  contract: DeployedGasokEligibilityContract,
  providerId: bigint,
): Promise<FinalizedTxData> => {
  logger.info(`Removing attestation provider ${providerId}...`);
  const finalizedTxData = await contract.callTx.removeProvider(providerId);
  logger.info(`Transaction ${finalizedTxData.public.txId} added in block ${finalizedTxData.public.blockHeight}`);
  return finalizedTxData.public;
};

export const displayContractState = async (
  providers: GasokEligibilityProviders,
  contract: DeployedGasokEligibilityContract,
): Promise<{ ledgerState: GasokEligibility.Ledger | null; contractAddress: string }> => {
  const contractAddress = contract.deployTxData.public.contractAddress;
  const ledgerState = await getGasokEligibilityLedgerState(providers, contractAddress);
  if (ledgerState === null) {
    logger.info(`There is no GASOK Financial Eligibility contract deployed at ${contractAddress}.`);
  } else {
    logger.info(`Contract address: ${contractAddress}`);
    logger.info(`Admin public key: ${Buffer.from(ledgerState.contractAdmin).toString('hex')}`);
    logger.info(`Registered providers: ${ledgerState.providers.size()}`);
    logger.info(`Public eligibility results: ${ledgerState.eligibilityResults.size()}`);
    for (const [commitment, result] of ledgerState.eligibilityResults) {
      logger.info(
        `Commitment ${Buffer.from(commitment).toString('hex')}: eligible=${result.eligible}, ` +
          `providerId=${result.providerId}, policyVersion=${result.policyVersion}`,
      );
    }
  }
  return { contractAddress, ledgerState };
};

/**
 * Create wallet and midnight provider from WalletFacade using stable API
 */
export const createWalletAndMidnightProvider = async (
  walletContext: WalletContext,
): Promise<WalletProvider & MidnightProvider> => {
  // Wait for wallet to sync first
  await Rx.firstValueFrom(walletContext.wallet.state().pipe(Rx.filter((s) => s.isSynced)));

  return {
    getCoinPublicKey(): ledger.CoinPublicKey {
      return walletContext.shieldedSecretKeys.coinPublicKey;
    },

    getEncryptionPublicKey(): ledger.EncPublicKey {
      return walletContext.shieldedSecretKeys.encryptionPublicKey;
    },

    async balanceTx(tx: UnboundTransaction, ttl?: Date): Promise<ledger.FinalizedTransaction> {
      const txTtl = ttl ?? new Date(Date.now() + 30 * 60 * 1000); // 30 min default TTL

      // Use the wallet facade to balance the unbound (proven) transaction
      const recipe = await walletContext.wallet.balanceUnboundTransaction(
        tx,
        {
          shieldedSecretKeys: walletContext.shieldedSecretKeys,
          dustSecretKey: walletContext.dustSecretKey,
        },
        { ttl: txTtl },
      );

      // Finalize the recipe to get the final transaction
      const finalizedTx = await walletContext.wallet.finalizeRecipe(recipe);
      return finalizedTx;
    },

    async submitTx(tx: ledger.FinalizedTransaction): Promise<ledger.TransactionId> {
      return await walletContext.wallet.submitTransaction(tx);
    },
  };
};

export const waitForSync = (wallet: WalletFacade) =>
  Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.throttleTime(5_000),
      Rx.tap((state) => {
        logger.info(`Waiting for wallet sync. Synced: ${state.isSynced}`);
      }),
      Rx.filter((state) => state.isSynced),
    ),
  );

export const waitForFunds = (wallet: WalletFacade) =>
  Rx.firstValueFrom(
    wallet.state().pipe(
      Rx.throttleTime(10_000),
      Rx.tap((state) => {
        const unshielded = state.unshielded?.balances[ledger.nativeToken().raw] ?? 0n;
        const shielded = state.shielded?.balances[ledger.nativeToken().raw] ?? 0n;
        logger.info(
          `Waiting for NIGHT funds. Synced: ${state.isSynced}, Unshielded: ${unshielded}, Shielded: ${shielded}`,
        );
      }),
      Rx.filter((state) => state.isSynced),
      Rx.map(
        (s) =>
          (s.unshielded?.balances[ledger.nativeToken().raw] ?? 0n) +
          (s.shielded?.balances[ledger.nativeToken().raw] ?? 0n),
      ),
      Rx.filter((balance) => balance > 0n),
    ),
  );

/**
 * Display wallet balances.
 *
 * On Midnight, NIGHT is the user-facing token and DUST is the fee resource
 * generated from registered NIGHT UTXOs. Testnets use the prefixed
 * tNIGHT / tDUST variants. We query the native token for NIGHT and the
 * dust wallet for DUST and surface both so it's obvious which is which.
 */
export const displayWalletBalances = async (
  wallet: WalletFacade,
): Promise<{ unshielded: bigint; shielded: bigint; total: bigint; dust: bigint }> => {
  const state = await Rx.firstValueFrom(wallet.state());
  const unshielded = state.unshielded?.balances[ledger.nativeToken().raw] ?? 0n;
  const shielded = state.shielded?.balances[ledger.nativeToken().raw] ?? 0n;
  const total = unshielded + shielded;
  const dust = state.dust?.balance(new Date()) ?? 0n;

  logger.info(`Unshielded NIGHT balance: ${unshielded}`);
  logger.info(`Shielded NIGHT balance: ${shielded}`);
  logger.info(`Total NIGHT balance: ${total}`);
  logger.info(`DUST balance (for fees): ${dust}`);

  return { unshielded, shielded, total, dust };
};

/**
 * Register unshielded Night UTXOs for dust generation
 * This is required before the wallet can pay transaction fees
 */
export const registerNightForDust = async (walletContext: WalletContext): Promise<boolean> => {
  const state = await Rx.firstValueFrom(walletContext.wallet.state().pipe(Rx.filter((s) => s.isSynced)));

  // Check if we have unshielded coins that are not registered for dust generation
  const unregisteredNightUtxos =
    state.unshielded?.availableCoins.filter((coin) => coin.meta.registeredForDustGeneration === false) ?? [];

  if (unregisteredNightUtxos.length === 0) {
    logger.info('No unshielded Night UTXOs available for dust registration, or all are already registered');

    // Check current dust balance
    const dustBalance = state.dust?.balance(new Date()) ?? 0n;
    logger.info(`Current dust balance: ${dustBalance}`);

    return dustBalance > 0n;
  }

  logger.info(`Found ${unregisteredNightUtxos.length} unshielded Night UTXOs not registered for dust generation`);
  logger.info('Registering Night UTXOs for dust generation...');

  try {
    const recipe = await walletContext.wallet.registerNightUtxosForDustGeneration(
      unregisteredNightUtxos,
      walletContext.unshieldedKeystore.getPublicKey(),
      (payload) => walletContext.unshieldedKeystore.signData(payload),
    );

    logger.info('Finalizing dust registration transaction...');
    const finalizedTx = await walletContext.wallet.finalizeRecipe(recipe);

    logger.info('Submitting dust registration transaction...');
    const txId = await walletContext.wallet.submitTransaction(finalizedTx);
    logger.info(`Dust registration submitted with tx id: ${txId}`);

    // Wait for dust to be available
    logger.info('Waiting for dust to be generated...');
    await Rx.firstValueFrom(
      walletContext.wallet.state().pipe(
        Rx.throttleTime(5_000),
        Rx.tap((s) => {
          const dustBalance = s.dust?.balance(new Date()) ?? 0n;
          logger.info(`Dust balance: ${dustBalance}`);
        }),
        Rx.filter((s) => (s.dust?.balance(new Date()) ?? 0n) > 0n),
      ),
    );

    logger.info('Dust registration complete!');
    return true;
  } catch (e) {
    logger.error(`Failed to register Night UTXOs for dust: ${e}`);
    return false;
  }
};

/**
 * Convert mnemonic phrase to seed buffer using BIP39 standard
 * This generates a 64-byte seed as expected by Midnight HD wallet
 */
export const mnemonicToSeed = async (mnemonic: string): Promise<Buffer> => {
  const words = mnemonic.trim().split(/\s+/);
  if (!bip39.validateMnemonic(words.join(' '), english)) {
    throw new Error('Invalid mnemonic phrase');
  }
  // Use BIP39 standard seed derivation (PBKDF2) - produces 64 bytes
  const seed = await bip39.mnemonicToSeed(words.join(' '));
  return Buffer.from(seed);
};

/**
 * Initialize wallet with seed using the new wallet SDK
 */
export const initWalletWithSeed = async (seed: Buffer, config: Config): Promise<WalletContext> => {
  const hdWallet = HDWallet.fromSeed(seed);

  if (hdWallet.type !== 'seedOk') {
    throw new Error('Failed to initialize HDWallet');
  }

  const derivationResult = hdWallet.hdWallet
    .selectAccount(0)
    .selectRoles([Roles.Zswap, Roles.NightExternal, Roles.Dust])
    .deriveKeysAt(0);

  if (derivationResult.type !== 'keysDerived') {
    throw new Error('Failed to derive keys');
  }

  hdWallet.hdWallet.clear();

  const shieldedSecretKeys = ledger.ZswapSecretKeys.fromSeed(derivationResult.keys[Roles.Zswap]);
  const dustSecretKey = ledger.DustSecretKey.fromSeed(derivationResult.keys[Roles.Dust]);

  const unshieldedKeystore = createKeystore(derivationResult.keys[Roles.NightExternal], config.networkId as any);

  // Separate configurations for each wallet type (matching example-counter pattern)
  // Convert http:// to ws:// for relay URL (wallet SDK expects WebSocket)
  const relayURL = new URL(config.node.replace(/^http/, 'ws'));

  const shieldedConfig = {
    networkId: config.networkId,
    indexerClientConnection: {
      indexerHttpUrl: config.indexer,
      indexerWsUrl: config.indexerWS,
    },
    provingServerUrl: new URL(config.proofServer),
    relayURL,
    // As of the wallet-sdk 1.x line, every wallet variant's default configuration
    // (shielded/unshielded/dust) requires its own transaction-history storage.
    txHistoryStorage: new InMemoryTransactionHistoryStorage(WalletEntrySchema),
  };

  const unshieldedConfig = {
    networkId: config.networkId,
    indexerClientConnection: {
      indexerHttpUrl: config.indexer,
      indexerWsUrl: config.indexerWS,
    },
    txHistoryStorage: new InMemoryTransactionHistoryStorage(WalletEntrySchema),
  };

  const dustConfig = {
    networkId: config.networkId,
    costParameters: {
      additionalFeeOverhead: 300_000_000_000_000n,
      feeBlocksMargin: 5,
    },
    indexerClientConnection: {
      indexerHttpUrl: config.indexer,
      indexerWsUrl: config.indexerWS,
    },
    provingServerUrl: new URL(config.proofServer),
    relayURL,
    txHistoryStorage: new InMemoryTransactionHistoryStorage(WalletEntrySchema),
  };

  const unifiedConfig = {
    ...shieldedConfig,
    ...unshieldedConfig,
    ...dustConfig,
  };

  const facade = await WalletFacade.init({
    configuration: unifiedConfig,
    shielded: () => ShieldedWallet(shieldedConfig).startWithSecretKeys(shieldedSecretKeys),
    unshielded: () =>
      UnshieldedWallet(unshieldedConfig).startWithPublicKey(UnshieldedPublicKey.fromKeyStore(unshieldedKeystore)),
    dust: () =>
      DustWallet(dustConfig).startWithSecretKey(dustSecretKey, ledger.LedgerParameters.initialParameters().dust),
  });
  await facade.start(shieldedSecretKeys, dustSecretKey);

  return { wallet: facade, shieldedSecretKeys, dustSecretKey, unshieldedKeystore };
};

/**
 * Build wallet from mnemonic and wait for funds
 */
export const buildWalletAndWaitForFunds = async (config: Config, mnemonic: string): Promise<WalletContext> => {
  logger.info('Building wallet from mnemonic...');

  const seed = await mnemonicToSeed(mnemonic);
  const walletContext = await initWalletWithSeed(seed, config);

  logger.info(`Your wallet address: ${walletContext.unshieldedKeystore.getBech32Address().asString()}`);

  // Wait for sync first
  logger.info('Waiting for wallet to sync...');
  await waitForSync(walletContext.wallet);

  // Display and check balance
  const { total } = await displayWalletBalances(walletContext.wallet);

  if (total === 0n) {
    logger.info('Waiting to receive tokens...');
    await waitForFunds(walletContext.wallet);
    await displayWalletBalances(walletContext.wallet);
  }

  // Register Night UTXOs for dust generation (required for paying fees)
  await registerNightForDust(walletContext);

  return walletContext;
};

export const randomBytes = (length: number): Uint8Array => {
  const bytes = new Uint8Array(length);
  webcrypto.getRandomValues(bytes);
  return bytes;
};

/**
 * Generate a fresh wallet with random mnemonic
 */
export const buildFreshWallet = async (config: Config): Promise<WalletContext> => {
  const mnemonic = bip39.generateMnemonic(english, 256);
  logger.info(`Generated new wallet mnemonic: ${mnemonic}`);
  return await buildWalletAndWaitForFunds(config, mnemonic);
};

/**
 * Build wallet from hex seed (for backwards compatibility with genesis wallet)
 */
export const buildWalletFromHexSeed = async (config: Config, hexSeed: string): Promise<WalletContext> => {
  logger.info('Building wallet from hex seed...');
  const seed = Buffer.from(hexSeed, 'hex');
  const walletContext = await initWalletWithSeed(seed, config);

  logger.info(`Your wallet address: ${walletContext.unshieldedKeystore.getBech32Address().asString()}`);

  // Wait for sync first
  logger.info('Waiting for wallet to sync...');
  await waitForSync(walletContext.wallet);

  // Display and check balance
  const { total } = await displayWalletBalances(walletContext.wallet);

  if (total === 0n) {
    logger.info('Waiting to receive tokens...');
    await waitForFunds(walletContext.wallet);
    await displayWalletBalances(walletContext.wallet);
  }

  // Register Night UTXOs for dust generation (required for paying fees)
  await registerNightForDust(walletContext);

  return walletContext;
};

export const configureProviders = async (
  walletContext: WalletContext,
  config: Config,
): Promise<GasokEligibilityProviders> => {
  // Set global network ID - required before contract deployment
  setNetworkId(config.networkId);

  const walletAndMidnightProvider = await createWalletAndMidnightProvider(walletContext);

  const storagePassword = process.env.MIDNIGHT_STORAGE_PASSWORD;
  if (!storagePassword) {
    throw new Error(
      'MIDNIGHT_STORAGE_PASSWORD is not set. Set it in zkloan-credit-scorer-cli/.env (see .env.example). ' +
        'The level-private-state-provider requires it to encrypt private state on disk.',
    );
  }

  const zkConfigProvider = new NodeZkConfigProvider<GasokEligibilityCircuits>(contractConfig.zkConfigPath);

  return {
    privateStateProvider: levelPrivateStateProvider<typeof GasokEligibilityPrivateStateId>({
      privateStateStoreName: contractConfig.privateStateStoreName,
      privateStoragePasswordProvider: () => storagePassword,
      accountId: walletContext.unshieldedKeystore.getBech32Address().asString(),
    }),
    publicDataProvider: indexerPublicDataProvider(config.indexer, config.indexerWS),
    zkConfigProvider,
    proofProvider: httpClientProofProvider(config.proofServer, zkConfigProvider),
    walletProvider: walletAndMidnightProvider,
    midnightProvider: walletAndMidnightProvider,
  };
};

export function setLogger(_logger: Logger) {
  logger = _logger;
}

export const closeWallet = async (walletContext: WalletContext): Promise<void> => {
  try {
    await walletContext.wallet.stop();
  } catch (e) {
    logger.error(`Error closing wallet: ${e}`);
  }
};
