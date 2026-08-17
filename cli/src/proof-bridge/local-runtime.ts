// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import type * as http from 'node:http';
import type { ContractAddress } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import type { Logger } from 'pino';
import * as api from '../api.js';
import type { DeployedGasokEligibilityContract, GasokEligibilityProviders } from '../common-types.js';
import { StandaloneConfig } from '../config.js';
import {
  GIWA_CHAIN_ID,
  RECEIVABLE_FINANCE_ADDRESS,
  bytesToHex,
  validateGiwaDeploymentConfig,
  type GiwaDeploymentConfig,
} from '../giwa.js';
import { ProofBridgeRuntime, type ProofBridgeOperations } from './runtime.js';
import { createProofBridgeServer } from './server.js';

export const PINNED_MIDNIGHT_CONTRACT_ADDRESS =
  '7e3ea9d741ce0f5862db6f46d0ad720be2586cd7d0405ec77e4a0478aa50f4fb' as ContractAddress;
export const LOCAL_ATTESTATION_API_URL = 'http://127.0.0.1:4000';
export const LOCAL_PROOF_BRIDGE_HOST = '127.0.0.1';
export const LOCAL_PROOF_BRIDGE_PORT = 4_200;
export const LOCAL_DEV_GENESIS_WALLET_SEED = '0000000000000000000000000000000000000000000000000000000000000001';
const PROVIDER_ID = 2n;
const PROVIDER_INFO_MAX_BYTES = 4_096;
export const INDEXER_PREFLIGHT_TIMEOUT_MS = 10_000;

export interface ProviderInfo {
  readonly providerId: 2;
  readonly publicKey: { readonly x: bigint; readonly y: bigint };
  readonly approvedMidnightContractAddress: string;
}

export interface PreflightLedgerState {
  readonly giwaChainId: bigint;
  readonly receivableFinanceAddress: Uint8Array;
  readonly providers: {
    member(providerId: bigint): boolean;
    lookup(providerId: bigint): { readonly x: bigint; readonly y: bigint };
  };
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  value !== null && typeof value === 'object' && !Array.isArray(value);

function hasExactKeys(value: Record<string, unknown>, expected: ReadonlyArray<string>): boolean {
  const actual = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  return actual.length === sortedExpected.length && actual.every((key, index) => key === sortedExpected[index]);
}

function canonicalField(value: unknown): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error('The local Mock Provider identity response is invalid.');
  }
  return BigInt(value);
}

async function readBoundedProviderInfo(response: Response, signal: AbortSignal): Promise<string> {
  if (response.body === null) {
    return '';
  }
  const reader = response.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  try {
    while (true) {
      if (signal.aborted) {
        throw new Error('The local Mock Provider identity request timed out.');
      }
      const { done, value } = await reader.read();
      if (done) {
        break;
      }
      if (value === undefined || total + value.byteLength > PROVIDER_INFO_MAX_BYTES) {
        void reader.cancel().catch(() => undefined);
        throw new Error('The local Mock Provider identity response is too large.');
      }
      total += value.byteLength;
      chunks.push(Buffer.from(value));
    }
  } catch (error: unknown) {
    if (signal.aborted) {
      void reader.cancel().catch(() => undefined);
      throw new Error('The local Mock Provider identity request timed out.');
    }
    throw error;
  }
  if (signal.aborted) {
    throw new Error('The local Mock Provider identity request timed out.');
  }
  return Buffer.concat(chunks, total).toString('utf8');
}

export function parseProviderInfo(value: unknown): ProviderInfo {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, [
      'approvedMidnightContractAddress',
      'attestationType',
      'authorizationProtocol',
      'providerId',
      'publicKey',
    ]) ||
    value.providerId !== 2 ||
    value.attestationType !== 'mock' ||
    value.authorizationProtocol !== 'eip712-role-wallet-v1' ||
    typeof value.approvedMidnightContractAddress !== 'string' ||
    value.approvedMidnightContractAddress !== PINNED_MIDNIGHT_CONTRACT_ADDRESS ||
    !isRecord(value.publicKey) ||
    !hasExactKeys(value.publicKey, ['x', 'y'])
  ) {
    throw new Error('The local Mock Provider identity response is invalid.');
  }
  return Object.freeze({
    providerId: 2,
    publicKey: Object.freeze({
      x: canonicalField(value.publicKey.x),
      y: canonicalField(value.publicKey.y),
    }),
    approvedMidnightContractAddress: PINNED_MIDNIGHT_CONTRACT_ADDRESS,
  });
}

export function validateLocalPreflight(
  ledgerState: PreflightLedgerState | null,
  providerInfo: ProviderInfo,
): GiwaDeploymentConfig {
  if (
    ledgerState === null ||
    ledgerState.giwaChainId !== GIWA_CHAIN_ID ||
    bytesToHex(ledgerState.receivableFinanceAddress) !== RECEIVABLE_FINANCE_ADDRESS ||
    !ledgerState.providers.member(PROVIDER_ID)
  ) {
    throw new Error('The pinned local Midnight contract or Provider 2 registration is unavailable.');
  }
  const registeredProvider = ledgerState.providers.lookup(PROVIDER_ID);
  if (registeredProvider.x !== providerInfo.publicKey.x || registeredProvider.y !== providerInfo.publicKey.y) {
    throw new Error('The running local Mock Provider does not match Provider 2 registered on Midnight.');
  }
  return validateGiwaDeploymentConfig({
    chainId: ledgerState.giwaChainId,
    receivableFinanceAddress: ledgerState.receivableFinanceAddress,
  });
}

export async function requireExistingPinnedPrivateState(providers: GasokEligibilityProviders): Promise<void> {
  providers.privateStateProvider.setContractAddress(PINNED_MIDNIGHT_CONTRACT_ADDRESS);
  if ((await providers.privateStateProvider.get('gasokEligibilityPrivateState')) === null) {
    throw new Error(
      'No existing private state was found for the pinned contract. Run the verified CLI join flow first.',
    );
  }
}

export async function fetchProviderInfo(): Promise<ProviderInfo> {
  const signal = AbortSignal.timeout(api.ATTESTATION_REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(`${LOCAL_ATTESTATION_API_URL}/provider-info`, {
      method: 'GET',
      redirect: 'error',
      signal,
      headers: { Accept: 'application/json' },
    });
  } catch {
    throw new Error('The local Mock Provider identity is unavailable.');
  }
  const contentType = response.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase();
  if (contentType !== 'application/json') {
    void response.body?.cancel().catch(() => undefined);
    throw new Error('The local Mock Provider identity response is invalid.');
  }
  const declaredLength = response.headers.get('content-length');
  if (
    declaredLength !== null &&
    /^(0|[1-9][0-9]*)$/.test(declaredLength) &&
    BigInt(declaredLength) > PROVIDER_INFO_MAX_BYTES
  ) {
    void response.body?.cancel().catch(() => undefined);
    throw new Error('The local Mock Provider identity response is too large.');
  }
  const text = await readBoundedProviderInfo(response, signal);
  if (!response.ok) {
    throw new Error('The local Mock Provider identity is unavailable.');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text) as unknown;
  } catch {
    throw new Error('The local Mock Provider identity response is invalid.');
  }
  return parseProviderInfo(parsed);
}

async function withIndexerPreflightTimeout<T>(operation: () => Promise<T>, timeoutMs: number): Promise<T> {
  if (!Number.isSafeInteger(timeoutMs) || timeoutMs <= 0) {
    throw new Error('The local Midnight Indexer preflight timeout is invalid.');
  }
  let timer: NodeJS.Timeout | undefined;
  const timeout = new Promise<never>((_, reject) => {
    timer = setTimeout(
      () => reject(new Error('The local Midnight Indexer preflight timed out.')),
      timeoutMs,
    );
  });
  try {
    return await Promise.race([operation(), timeout]);
  } finally {
    if (timer !== undefined) {
      clearTimeout(timer);
    }
  }
}

export async function preflightContractAndProvider(
  providers: GasokEligibilityProviders,
  contractAddress: ContractAddress,
  indexerTimeoutMs = INDEXER_PREFLIGHT_TIMEOUT_MS,
): Promise<GiwaDeploymentConfig> {
  // This is intentionally a boot-only query, before the HTTP server can accept
  // any private tuple. The SDK exposes no AbortSignal, so the local deadline
  // bounds startup without ever leaving raw financial inputs in an orphan task.
  const ledgerState = await withIndexerPreflightTimeout(
    async () => await api.getGasokEligibilityLedgerState(providers, contractAddress),
    indexerTimeoutMs,
  );
  const providerInfo = await fetchProviderInfo();
  return validateLocalPreflight(ledgerState, providerInfo);
}

function createLocalOperations(
  providers: GasokEligibilityProviders,
  contract: DeployedGasokEligibilityContract,
  configuredGiwa: GiwaDeploymentConfig,
): ProofBridgeOperations<api.PreparedEligibilityVerification> {
  return {
    async prepare(input) {
      const prepared = await api.prepareEligibilityVerificationWithGiwaConfig(
        contract,
        providers,
        configuredGiwa,
        input.onchainReceivableId,
        input.subjectRole,
        input.annualRevenueKrw,
        input.debtRatioBps,
        input.overdueCount,
        input.secretPin,
        LOCAL_ATTESTATION_API_URL,
      );
      return {
        prepared,
        authorizationRequest: prepared.authorizationChallenge,
      };
    },
    async complete(prepared, authorization, onStage) {
      const verification = await api.completeEligibilityVerification(
        contract,
        providers,
        prepared,
        authorization,
        LOCAL_ATTESTATION_API_URL,
        { onStage },
      );
      return verification.proofCapability;
    },
  };
}

async function closeServer(server: http.Server): Promise<void> {
  if (!server.listening) {
    return;
  }
  await new Promise<void>((resolve, reject) => {
    server.close((error) => (error === undefined ? resolve() : reject(error)));
  });
}

async function waitForShutdownSignal(): Promise<void> {
  await new Promise<void>((resolve) => {
    const finish = () => {
      process.off('SIGINT', finish);
      process.off('SIGTERM', finish);
      resolve();
    };
    process.once('SIGINT', finish);
    process.once('SIGTERM', finish);
  });
}

export async function runStandaloneProofBridge(logger: Logger): Promise<void> {
  const config = new StandaloneConfig();
  api.setLogger(logger);
  let walletContext: api.WalletContext | null = null;
  let server: http.Server | null = null;
  let runtime: ProofBridgeRuntime<api.PreparedEligibilityVerification> | null = null;
  try {
    walletContext = await api.buildWalletFromHexSeed(config, LOCAL_DEV_GENESIS_WALLET_SEED);
    const providers = await api.configureProviders(walletContext, config);
    const configuredGiwa = await preflightContractAndProvider(providers, PINNED_MIDNIGHT_CONTRACT_ADDRESS);
    await requireExistingPinnedPrivateState(providers);
    const contract = await api.joinContract(providers, PINNED_MIDNIGHT_CONTRACT_ADDRESS);
    runtime = new ProofBridgeRuntime({
      operations: createLocalOperations(providers, contract, configuredGiwa),
      logger,
    });
    server = createProofBridgeServer({ controller: runtime });
    await new Promise<void>((resolve, reject) => {
      const onError = (error: Error) => reject(error);
      server?.once('error', onError);
      server?.listen(LOCAL_PROOF_BRIDGE_PORT, LOCAL_PROOF_BRIDGE_HOST, () => {
        server?.off('error', onError);
        resolve();
      });
    });
    logger.info(
      `Local-only GASOK Midnight Proof Bridge listening on http://${LOCAL_PROOF_BRIDGE_HOST}:${LOCAL_PROOF_BRIDGE_PORT}`,
    );
    await waitForShutdownSignal();
  } finally {
    if (server !== null) {
      await closeServer(server);
    }
    await runtime?.shutdown();
    if (walletContext !== null) {
      await api.closeWallet(walletContext);
    }
  }
}
