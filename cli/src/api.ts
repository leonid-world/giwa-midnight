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
  MAX_FIELD,
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
import {
  bytesToHex,
  fixedHexToBytes,
  getDefaultGiwaDeploymentConfig,
  isZeroBytes,
  normalizeEvmAddress,
  normalizeMidnightContractAddress,
  receivableIdToBytes,
  subjectRoleToCode,
  validateGiwaDeploymentConfig,
  type GiwaDeploymentConfig,
  type SubjectRole,
} from './giwa';
import {
  AUTHORIZATION_PROVIDER_ID,
  createAuthorizationChallengeRequest,
  generateAuthorizationSalt,
  parseAuthorizationChallenge,
  validateAuthorizationProof,
  type AuthorizationChallenge,
  type AuthorizationChallengeRequest,
  type AuthorizationExpectedContext,
  type AuthorizationProof,
  type RoleAuthorizationCallback,
} from './authorization';

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
  assertIsContractAddress(contractAddress);
  providers.privateStateProvider.setContractAddress(contractAddress);
  const existingPrivateState = await providers.privateStateProvider.get('gasokEligibilityPrivateState');
  // Midnight.js treats initialPrivateState as an explicit overwrite during find.
  // Omit it when this wallet already has contract-scoped state so its company
  // secret (and any admin authority derived from it) survives CLI restarts.
  if (existingPrivateState === null) {
    logger.info('No private state exists for this wallet and contract; creating a new non-admin participant state.');
  }
  const contract =
    existingPrivateState === null
      ? await findDeployedContract(providers as any, {
          contractAddress,
          compiledContract: gasokEligibilityCompiledContract,
          privateStateId: 'gasokEligibilityPrivateState',
          initialPrivateState: getInitialPrivateState(),
        })
      : await findDeployedContract(providers as any, {
          contractAddress,
          compiledContract: gasokEligibilityCompiledContract,
          privateStateId: 'gasokEligibilityPrivateState',
        });
  logger.info(`Joined contract at address: ${contract.deployTxData.public.contractAddress}`);

  return contract as any;
};

export const deploy = async (
  providers: GasokEligibilityProviders,
  privateState: GasokEligibilityPrivateState,
  configuredGiwa: GiwaDeploymentConfig = getDefaultGiwaDeploymentConfig(),
): Promise<DeployedGasokEligibilityContract> => {
  logger.info('Deploying GASOK Financial Eligibility contract...');

  const giwa = validateGiwaDeploymentConfig(configuredGiwa);

  const contract = await deployContract(providers as any, {
    compiledContract: gasokEligibilityCompiledContract,
    privateStateId: 'gasokEligibilityPrivateState',
    initialPrivateState: privateState,
    args: [giwa.chainId, giwa.receivableFinanceAddress],
  });
  logger.info(`Deployed contract at address: ${contract.deployTxData.public.contractAddress}`);

  return contract as any;
};

// GASOK financial-eligibility operations

const bytes32Type = new CompactTypeBytes(32);
const { pureCircuits } = GasokEligibility;
const POLICY_VERSION = 1;

export interface AttestedReceivableBinding {
  readonly giwaChainId: bigint;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: bigint;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
}

export interface ValidatedMockAttestation {
  readonly signature: { announcement: { x: bigint; y: bigint }; response: bigint };
  readonly providerId: bigint;
  readonly policyVersion: 1;
  readonly midnightContractAddress: string;
  readonly binding: AttestedReceivableBinding;
}

export interface ProofCapability {
  readonly version: 1;
  readonly midnightContractAddress: string;
  readonly companyCommitment: string;
  readonly lookupKey: string;
  readonly giwaChainId: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
}

export interface EligibilityVerification {
  readonly finalizedTxData: FinalizedTxData;
  readonly proofCapability: ProofCapability;
}

export type EligibilityProofStage = 'attesting' | 'proving_and_submitting';

export interface PreparedEligibilityVerification {
  readonly authorizationChallenge: AuthorizationChallenge;
  readonly authorizationRequest: AuthorizationChallengeRequest;
  readonly companyCommitment: Uint8Array;
  readonly expectedContext: AuthorizationExpectedContext;
  readonly inputs: {
    readonly annualRevenueKrw: bigint;
    readonly debtRatioBps: bigint;
    readonly overdueCount: bigint;
    readonly secretPin: bigint;
  };
}

export interface CompleteEligibilityVerificationOptions {
  readonly onStage?: (stage: EligibilityProofStage) => void;
}

interface ExpectedAttestationContext extends AuthorizationExpectedContext {
  readonly partyWallet?: string;
}

type JsonRecord = Record<string, unknown>;

const ATTESTATION_RESPONSE_KEYS = [
  'signature',
  'providerId',
  'policyVersion',
  'midnightContractAddress',
  'binding',
  'attestationType',
  'authorizationProtocol',
] as const;
const ATTESTATION_SIGNATURE_KEYS = ['announcement', 'response'] as const;
const ATTESTATION_ANNOUNCEMENT_KEYS = ['x', 'y'] as const;
const ATTESTATION_BINDING_KEYS = [
  'giwaChainId',
  'receivableFinanceAddress',
  'onchainReceivableId',
  'subjectRole',
  'partyWallet',
] as const;

export const ATTESTATION_REQUEST_TIMEOUT_MS = 10_000;
export const MAX_ATTESTATION_RESPONSE_BYTES = 64 * 1024;

const INVALID_ATTESTATION_API_URL =
  'Mock Attestation API URL must be an HTTP loopback base URL without credentials, query, fragment, or path.';

class AttestationResponseTooLargeError extends Error {}

class AttestationResponseAbortedError extends Error {}

type LocalAttestationPath = '/attest' | '/authorization-challenges';

export function resolveLocalAttestationEndpoint(
  attestationApiUrl: string,
  path: LocalAttestationPath = '/attest',
): URL {
  if (
    typeof attestationApiUrl !== 'string' ||
    attestationApiUrl.length === 0 ||
    attestationApiUrl.length > 2_048 ||
    attestationApiUrl !== attestationApiUrl.trim()
  ) {
    throw new Error(INVALID_ATTESTATION_API_URL);
  }

  let baseUrl: URL;
  try {
    baseUrl = new URL(attestationApiUrl);
  } catch {
    throw new Error(INVALID_ATTESTATION_API_URL);
  }

  const isLoopbackHost =
    baseUrl.hostname === 'localhost' ||
    baseUrl.hostname === '127.0.0.1' ||
    baseUrl.hostname === '[::1]' ||
    baseUrl.hostname === '::1';
  if (
    baseUrl.protocol !== 'http:' ||
    !isLoopbackHost ||
    baseUrl.username !== '' ||
    baseUrl.password !== '' ||
    baseUrl.search !== '' ||
    baseUrl.hash !== '' ||
    baseUrl.pathname !== '/' ||
    baseUrl.port === '0'
  ) {
    throw new Error(INVALID_ATTESTATION_API_URL);
  }

  return new URL(path, baseUrl);
}

async function readLimitedAttestationResponse(response: Response, signal: AbortSignal): Promise<string> {
  if (signal.aborted) {
    throw new AttestationResponseAbortedError();
  }
  const declaredLength = response.headers.get('content-length');
  if (
    declaredLength !== null &&
    /^[0-9]+$/.test(declaredLength) &&
    BigInt(declaredLength) > BigInt(MAX_ATTESTATION_RESPONSE_BYTES)
  ) {
    void response.body?.cancel().catch(() => undefined);
    throw new AttestationResponseTooLargeError();
  }
  if (response.body === null) {
    return '';
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let byteLength = 0;
  let rejectForAbort: (() => void) | undefined;
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectForAbort = () => reject(new AttestationResponseAbortedError());
    signal.addEventListener('abort', rejectForAbort, { once: true });
  });

  try {
    while (true) {
      if (signal.aborted) {
        throw new AttestationResponseAbortedError();
      }
      const { done, value } = await Promise.race([reader.read(), aborted]);
      if (done) {
        break;
      }
      if (value === undefined || byteLength + value.byteLength > MAX_ATTESTATION_RESPONSE_BYTES) {
        void reader.cancel().catch(() => undefined);
        throw new AttestationResponseTooLargeError();
      }
      byteLength += value.byteLength;
      chunks.push(value);
    }
  } finally {
    if (rejectForAbort !== undefined) {
      signal.removeEventListener('abort', rejectForAbort);
    }
    if (signal.aborted) {
      void reader.cancel().catch(() => undefined);
    }
  }

  return Buffer.concat(chunks.map((chunk) => Buffer.from(chunk)), byteLength).toString('utf8');
}

function requireRecord(value: unknown, label: string): JsonRecord {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new Error(`Mock Attestation API returned an invalid ${label}.`);
  }
  return value as JsonRecord;
}

function requireExactRecord(
  value: unknown,
  label: string,
  expectedKeys: ReadonlyArray<string>,
): JsonRecord {
  const record = requireRecord(value, label);
  const actual = Object.keys(record).sort();
  const expected = [...expectedKeys].sort();
  if (actual.length !== expected.length || !actual.every((key, index) => key === expected[index])) {
    throw new Error(`Mock Attestation API returned an invalid ${label}.`);
  }
  return record;
}

function parseCanonicalDecimal(value: unknown, label: string, maximum: bigint): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new Error(`Mock Attestation API returned a non-canonical ${label}.`);
  }
  const parsed = BigInt(value);
  if (parsed > maximum) {
    throw new Error(`Mock Attestation API returned an out-of-range ${label}.`);
  }
  return parsed;
}

function parseCanonicalEvmAddress(value: unknown, label: string): string {
  if (typeof value !== 'string') {
    throw new Error(`Mock Attestation API returned an invalid ${label}.`);
  }
  const normalized = normalizeEvmAddress(value, label);
  if (value !== normalized || isZeroBytes(fixedHexToBytes(value, 20, label, { requirePrefix: true }))) {
    throw new Error(`Mock Attestation API returned a non-canonical ${label}.`);
  }
  return normalized;
}

export function parseAttestationResponse(
  value: unknown,
  expected: ExpectedAttestationContext,
): ValidatedMockAttestation {
  const data = requireExactRecord(value, 'response', ATTESTATION_RESPONSE_KEYS);
  if (data.attestationType !== 'mock') {
    throw new Error('Attestation response is not marked as mock data.');
  }
  if (data.authorizationProtocol !== 'eip712-role-wallet-v1') {
    throw new Error('Mock Attestation API returned an unsupported wallet authorization protocol.');
  }
  if (data.providerId !== AUTHORIZATION_PROVIDER_ID) {
    throw new Error('Mock Attestation API returned an unsupported providerId.');
  }
  if (data.policyVersion !== POLICY_VERSION) {
    throw new Error('Mock Attestation API returned an unsupported policyVersion.');
  }

  if (typeof data.midnightContractAddress !== 'string') {
    throw new Error('Mock Attestation API returned an invalid Midnight contract address.');
  }
  const midnightContractAddress = normalizeMidnightContractAddress(data.midnightContractAddress);
  if (
    data.midnightContractAddress !== midnightContractAddress ||
    midnightContractAddress !== expected.midnightContractAddress
  ) {
    throw new Error('Mock attestation is bound to a different Midnight contract.');
  }

  const signature = requireExactRecord(data.signature, 'signature', ATTESTATION_SIGNATURE_KEYS);
  const announcement = requireExactRecord(
    signature.announcement,
    'signature announcement',
    ATTESTATION_ANNOUNCEMENT_KEYS,
  );
  const parsedSignature = {
    announcement: {
      x: parseCanonicalDecimal(announcement.x, 'signature announcement.x', MAX_FIELD),
      y: parseCanonicalDecimal(announcement.y, 'signature announcement.y', MAX_FIELD),
    },
    response: parseCanonicalDecimal(signature.response, 'signature response', MAX_FIELD),
  };

  const binding = requireExactRecord(data.binding, 'GIWA receivable binding', ATTESTATION_BINDING_KEYS);
  const giwaChainId = parseCanonicalDecimal(binding.giwaChainId, 'binding.giwaChainId', (1n << 64n) - 1n);
  if (giwaChainId !== expected.giwa.chainId) {
    throw new Error('Mock attestation is bound to a different GIWA chain.');
  }

  const receivableFinanceAddress = parseCanonicalEvmAddress(
    binding.receivableFinanceAddress,
    'binding.receivableFinanceAddress',
  );
  const expectedReceivableFinanceAddress = bytesToHex(expected.giwa.receivableFinanceAddress);
  if (receivableFinanceAddress !== expectedReceivableFinanceAddress) {
    throw new Error('Mock attestation is bound to a different ReceivableFinance contract.');
  }

  const onchainReceivableId = parseCanonicalDecimal(
    binding.onchainReceivableId,
    'binding.onchainReceivableId',
    (1n << 256n) - 1n,
  );
  if (onchainReceivableId === 0n || onchainReceivableId !== expected.onchainReceivableId) {
    throw new Error('Mock attestation is bound to a different GIWA receivable.');
  }
  if (binding.subjectRole !== expected.subjectRole) {
    throw new Error('Mock attestation is bound to a different receivable party role.');
  }

  const partyWallet = parseCanonicalEvmAddress(binding.partyWallet, 'binding.partyWallet');
  if (expected.partyWallet !== undefined && partyWallet !== expected.partyWallet) {
    throw new Error('Mock attestation is bound to a different authorized GIWA party wallet.');
  }

  return {
    signature: parsedSignature,
    providerId: BigInt(data.providerId as number),
    policyVersion: 1,
    midnightContractAddress,
    binding: {
      giwaChainId,
      receivableFinanceAddress,
      onchainReceivableId,
      subjectRole: expected.subjectRole,
      partyWallet,
    },
  };
}

export const deriveCompanyCommitment = (companySecretKey: Uint8Array, pin: bigint): Uint8Array => {
  return pureCircuits.deriveCompanyCommitment(companySecretKey, pin);
};

export const computeCompanyCommitmentHash = (companySecretKey: Uint8Array, pin: bigint): bigint => {
  return transientHash(bytes32Type, deriveCompanyCommitment(companySecretKey, pin));
};

export const deriveGiwaReceivableBindingHash = (
  configuredGiwa: GiwaDeploymentConfig,
  subject: GasokEligibility.GiwaReceivableSubject,
): Uint8Array => {
  const giwa = validateGiwaDeploymentConfig(configuredGiwa);
  return pureCircuits.deriveGiwaReceivableBindingHash(giwa.chainId, giwa.receivableFinanceAddress, subject);
};

export const deriveMidnightDeploymentHash = (midnightContractAddress: string): Uint8Array => {
  return pureCircuits.deriveMidnightDeploymentHash(
    fixedHexToBytes(normalizeMidnightContractAddress(midnightContractAddress), 32, 'Midnight contract address'),
  );
};

export const deriveReceivableEligibilityKey = (
  companyCommitment: Uint8Array,
  bindingHash: Uint8Array,
  deploymentHash: Uint8Array,
): Uint8Array => {
  return pureCircuits.deriveReceivableEligibilityKey(companyCommitment, bindingHash, deploymentHash);
};

async function postLocalAttestationJson(
  attestationApiUrl: string,
  path: LocalAttestationPath,
  body: unknown,
): Promise<unknown> {
  const endpoint = resolveLocalAttestationEndpoint(attestationApiUrl, path);
  const signal = AbortSignal.timeout(ATTESTATION_REQUEST_TIMEOUT_MS);
  let response: Response;
  try {
    response = await fetch(endpoint, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      redirect: 'error',
      signal,
      body: JSON.stringify(body),
    });
  } catch {
    if (signal.aborted) {
      throw new Error('Mock Attestation API request timed out.');
    }
    throw new Error('Could not contact the local Mock Attestation API.');
  }

  let responseText: string;
  try {
    responseText = await readLimitedAttestationResponse(response, signal);
  } catch (error) {
    if (signal.aborted || error instanceof AttestationResponseAbortedError) {
      throw new Error('Mock Attestation API request timed out.');
    }
    if (error instanceof AttestationResponseTooLargeError) {
      throw new Error(`Mock Attestation API response exceeds ${MAX_ATTESTATION_RESPONSE_BYTES} bytes.`);
    }
    throw new Error('Could not read the local Mock Attestation API response.');
  }

  if (signal.aborted) {
    throw new Error('Mock Attestation API request timed out.');
  }

  if (!response.ok) {
    throw new Error(`Mock Attestation API returned HTTP ${response.status}.`);
  }

  let parsedResponse: unknown;
  try {
    parsedResponse = JSON.parse(responseText) as unknown;
  } catch {
    throw new Error('Mock Attestation API returned invalid JSON.');
  }
  return parsedResponse;
}

export const fetchAuthorizationChallenge = async (
  attestationApiUrl: string,
  request: AuthorizationChallengeRequest,
  expected: AuthorizationExpectedContext,
): Promise<AuthorizationChallenge> => {
  const response = await postLocalAttestationJson(
    attestationApiUrl,
    '/authorization-challenges',
    request,
  );
  return parseAuthorizationChallenge(response, request, expected);
};

export const fetchAttestation = async (
  attestationApiUrl: string,
  request: AuthorizationChallengeRequest,
  authorization: AuthorizationProof,
  expected: ExpectedAttestationContext,
): Promise<ValidatedMockAttestation> => {
  const response = await postLocalAttestationJson(attestationApiUrl, '/attest', {
    ...request,
    authorization,
  });
  return parseAttestationResponse(response, expected);
};

const emptyAttestationSignature = () => ({
  announcement: { x: 0n, y: 0n },
  response: 0n,
});

export const sanitizeEligibilityPrivateState = (
  privateState: GasokEligibilityPrivateState,
): GasokEligibilityPrivateState => ({
  ...privateState,
  annualRevenueKrw: 0n,
  debtRatioBps: 0n,
  overdueCount: 0n,
  attestationSignature: emptyAttestationSignature(),
  attestationProviderId: 0n,
});

const hasTransientEligibilityData = (privateState: GasokEligibilityPrivateState): boolean =>
  privateState.annualRevenueKrw !== 0n ||
  privateState.debtRatioBps !== 0n ||
  privateState.overdueCount !== 0n ||
  privateState.attestationSignature.announcement.x !== 0n ||
  privateState.attestationSignature.announcement.y !== 0n ||
  privateState.attestationSignature.response !== 0n ||
  privateState.attestationProviderId !== 0n;

export const prepareEligibilityVerificationWithGiwaConfig = async (
  contract: DeployedGasokEligibilityContract,
  providers: GasokEligibilityProviders,
  configuredGiwa: GiwaDeploymentConfig,
  onchainReceivableId: bigint,
  subjectRole: SubjectRole,
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  secretPin: bigint,
  attestationApiUrl: string,
): Promise<PreparedEligibilityVerification> => {
  const giwa = validateGiwaDeploymentConfig(configuredGiwa);
  const persistedState = await providers.privateStateProvider.get('gasokEligibilityPrivateState');
  if (!persistedState) {
    throw new Error('No private state found');
  }

  // A previous interrupted run may have stopped after writing witness inputs.
  // Clear those values before creating a new request; the stable company secret
  // remains unchanged.
  const currentState = sanitizeEligibilityPrivateState(persistedState);
  if (hasTransientEligibilityData(persistedState)) {
    await providers.privateStateProvider.set('gasokEligibilityPrivateState', currentState);
    logger.info('Cleared transient financial witness data from private state');
  }

  const contractAddress = normalizeMidnightContractAddress(contract.deployTxData.public.contractAddress);
  const companyCommitment = deriveCompanyCommitment(currentState.companySecretKey, secretPin);
  const companyCommitmentHash = transientHash(bytes32Type, companyCommitment);
  logger.info('Computed pseudonymous company commitment hash for mock attestation');

  const expectedContext: AuthorizationExpectedContext = {
    midnightContractAddress: contractAddress,
    onchainReceivableId,
    subjectRole,
    giwa,
  };
  const authorizationRequest = createAuthorizationChallengeRequest(
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    companyCommitmentHash,
    expectedContext,
    generateAuthorizationSalt(),
  );

  logger.info('Requesting one-time GIWA role-wallet authorization from the local mock provider...');
  const authorizationChallenge = await fetchAuthorizationChallenge(
    attestationApiUrl,
    authorizationRequest,
    expectedContext,
  );

  return Object.freeze({
    authorizationChallenge,
    authorizationRequest,
    companyCommitment,
    expectedContext,
    inputs: Object.freeze({
      annualRevenueKrw,
      debtRatioBps,
      overdueCount,
      secretPin,
    }),
  });
};

export const prepareEligibilityVerification = async (
  contract: DeployedGasokEligibilityContract,
  providers: GasokEligibilityProviders,
  onchainReceivableId: bigint,
  subjectRole: SubjectRole,
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  secretPin: bigint,
  attestationApiUrl: string,
): Promise<PreparedEligibilityVerification> => {
  const ledgerState = await getGasokEligibilityLedgerState(providers, contract.deployTxData.public.contractAddress);
  if (ledgerState === null) {
    throw new Error('The GASOK Financial Eligibility contract state is unavailable.');
  }
  return await prepareEligibilityVerificationWithGiwaConfig(
    contract,
    providers,
    {
      chainId: ledgerState.giwaChainId,
      receivableFinanceAddress: ledgerState.receivableFinanceAddress,
    },
    onchainReceivableId,
    subjectRole,
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    secretPin,
    attestationApiUrl,
  );
};

export const completeEligibilityVerification = async (
  contract: DeployedGasokEligibilityContract,
  providers: GasokEligibilityProviders,
  prepared: PreparedEligibilityVerification,
  authorizationValue: unknown,
  attestationApiUrl: string,
  options: CompleteEligibilityVerificationOptions = {},
): Promise<EligibilityVerification> => {
  const currentState = await providers.privateStateProvider.get('gasokEligibilityPrivateState');
  if (!currentState) {
    throw new Error('No private state found');
  }

  const contractAddress = normalizeMidnightContractAddress(contract.deployTxData.public.contractAddress);
  if (contractAddress !== prepared.expectedContext.midnightContractAddress) {
    throw new Error('The prepared authorization belongs to a different Midnight contract.');
  }

  const recomputedCompanyCommitment = deriveCompanyCommitment(
    currentState.companySecretKey,
    prepared.inputs.secretPin,
  );
  if (!Buffer.from(recomputedCompanyCommitment).equals(Buffer.from(prepared.companyCommitment))) {
    throw new Error('The local private identity changed after the authorization request was created.');
  }

  const authorization = validateAuthorizationProof(
    authorizationValue,
    prepared.authorizationChallenge,
  );

  options.onStage?.('attesting');
  logger.info('Fetching the authorized mock attestation from the local provider...');
  const attestation = await fetchAttestation(
    attestationApiUrl,
    prepared.authorizationRequest,
    authorization,
    {
      ...prepared.expectedContext,
      partyWallet: prepared.authorizationChallenge.message.partyWallet,
    },
  );

  const subject: GasokEligibility.GiwaReceivableSubject = {
    receivableId: receivableIdToBytes(prepared.expectedContext.onchainReceivableId),
    subjectRole: subjectRoleToCode(prepared.expectedContext.subjectRole),
    partyWallet: fixedHexToBytes(attestation.binding.partyWallet, 20, 'Attested party wallet', {
      requirePrefix: true,
    }),
  };
  const bindingHash = deriveGiwaReceivableBindingHash(prepared.expectedContext.giwa, subject);
  const deploymentHash = deriveMidnightDeploymentHash(contractAddress);
  const lookupKey = deriveReceivableEligibilityKey(
    prepared.companyCommitment,
    bindingHash,
    deploymentHash,
  );
  logger.info('Computed the opaque receivable eligibility lookup key');

  const sanitizedState = sanitizeEligibilityPrivateState(currentState);
  const witnessState: GasokEligibilityPrivateState = {
    ...sanitizedState,
    annualRevenueKrw: prepared.inputs.annualRevenueKrw,
    debtRatioBps: prepared.inputs.debtRatioBps,
    overdueCount: prepared.inputs.overdueCount,
    attestationSignature: attestation.signature,
    attestationProviderId: attestation.providerId,
  };

  let witnessStateWriteWasAttempted = false;
  let finalizedTxData: FinalizedTxData | undefined;
  let proofFailure: unknown;
  let proofFailed = false;
  try {
    // Mark the attempt before awaiting the encrypted write. A storage provider
    // can persist data and still reject later (for example during a flush), so
    // cleanup must run even when this promise does not resolve successfully.
    witnessStateWriteWasAttempted = true;
    await providers.privateStateProvider.set('gasokEligibilityPrivateState', witnessState);
    logger.info(`Private witness prepared with mock attestation (provider ${attestation.providerId})`);

    options.onStage?.('proving_and_submitting');
    logger.info('Generating and submitting GASOK financial eligibility proof...');
    const callResult = await contract.callTx.verifyEligibility(prepared.inputs.secretPin, subject);
    finalizedTxData = callResult.public as FinalizedTxData;
  } catch (error: unknown) {
    proofFailed = true;
    proofFailure = error;
  }

  if (witnessStateWriteWasAttempted) {
    let cleanupSucceeded = false;
    for (let attempt = 0; attempt < 2 && !cleanupSucceeded; attempt += 1) {
      try {
        await providers.privateStateProvider.set('gasokEligibilityPrivateState', sanitizedState);
        cleanupSucceeded = true;
      } catch {
        // Cleanup is idempotent and safe to retry. Never include the storage
        // exception in logs because a provider error may reflect witness data.
      }
    }
    if (cleanupSucceeded) {
      logger.info('Cleared transient financial witness data from private state');
    } else {
      logger.error(
        { code: 'PRIVATE_STATE_CLEANUP_PENDING' },
        'Transient witness cleanup must be retried before another proof session.',
      );
    }
  }

  if (proofFailed) {
    throw proofFailure;
  }
  if (finalizedTxData === undefined) {
    throw new Error('The finalized Midnight transaction result is unavailable.');
  }

  logger.info(`Transaction ${finalizedTxData.txId} added in block ${finalizedTxData.blockHeight}`);
  return {
    finalizedTxData,
    proofCapability: {
      version: 1,
      midnightContractAddress: contractAddress,
      companyCommitment: bytesToHex(prepared.companyCommitment),
      lookupKey: bytesToHex(lookupKey),
      giwaChainId: prepared.expectedContext.giwa.chainId.toString(),
      receivableFinanceAddress: bytesToHex(prepared.expectedContext.giwa.receivableFinanceAddress),
      onchainReceivableId: prepared.expectedContext.onchainReceivableId.toString(),
      subjectRole: prepared.expectedContext.subjectRole,
      partyWallet: attestation.binding.partyWallet,
    },
  };
};

export const verifyEligibility = async (
  contract: DeployedGasokEligibilityContract,
  providers: GasokEligibilityProviders,
  onchainReceivableId: bigint,
  subjectRole: SubjectRole,
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  secretPin: bigint,
  attestationApiUrl: string,
  authorizeRoleWallet: RoleAuthorizationCallback,
): Promise<EligibilityVerification> => {
  const prepared = await prepareEligibilityVerification(
    contract,
    providers,
    onchainReceivableId,
    subjectRole,
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    secretPin,
    attestationApiUrl,
  );
  return await completeEligibilityVerification(
    contract,
    providers,
    prepared,
    await authorizeRoleWallet(prepared.authorizationChallenge),
    attestationApiUrl,
  );
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
    logger.info(`Sealed GIWA chain ID: ${ledgerState.giwaChainId}`);
    logger.info(`Sealed ReceivableFinance address: ${bytesToHex(ledgerState.receivableFinanceAddress)}`);
    logger.info(`Admin public key: ${Buffer.from(ledgerState.contractAdmin).toString('hex')}`);
    logger.info(`Registered providers: ${ledgerState.providers.size()}`);
    logger.info(`Public eligibility results: ${ledgerState.eligibilityResults.size()}`);
    for (const [lookupKey, result] of ledgerState.eligibilityResults) {
      logger.info(
        `Lookup key ${bytesToHex(lookupKey)}: eligible=${result.eligible}, ` +
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
  logger.info('Building wallet from the provided recovery phrase...');

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
export const generateFreshWalletMnemonic = (): string => bip39.generateMnemonic(english, 256);

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
