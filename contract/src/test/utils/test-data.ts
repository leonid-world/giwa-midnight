// This file is derived from the Midnight ZK Loan example test utilities.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import { type GasokEligibilityPrivateState } from '../../witnesses.js';
import {
  pureCircuits,
  type FunderPolicyRequest,
  type GiwaReceivableSubject,
  type Schnorr_SchnorrSignature,
} from '../../managed/zkloan-credit-scorer/contract/index.js';
import { ecMulGenerator, type JubjubPoint } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import * as crypto from 'crypto';

export const UINT256_MAX = (1n << 256n) - 1n;
export const GIWA_CHAIN_ID = 91342n;
export const RECEIVABLE_FINANCE_ADDRESS_HEX = '0x0f264334f98BA0d22f7Fc6Bb901a5Fa36158a315';
export const SELLER_ROLE = 1n;
export const BUYER_ROLE = 2n;
export const SELLER_WALLET_HEX = '0x1111111111111111111111111111111111111111';
export const BUYER_WALLET_HEX = '0x2222222222222222222222222222222222222222';
export const EVALUATION_VERSION = 2n;
export const PROFILE_AS_OF = 1n;
export const DEFAULT_POLICY_REQUEST: FunderPolicyRequest = {
  requestId: Uint8Array.from(Buffer.from('11'.repeat(32), 'hex')),
  intendedFunderWallet: Uint8Array.from(Buffer.from('33'.repeat(20), 'hex')),
  minAnnualRevenueKrw: 500000000n,
  maxDebtRatioBps: 20000n,
  maxOverdueCount: 1n,
  validUntil: 4000000000n,
};

export function uint256ToBytes(value: bigint): Uint8Array {
  if (value < 0n || value > UINT256_MAX) {
    throw new RangeError('uint256 value must be between 0 and 2^256 - 1');
  }

  return Uint8Array.from(Buffer.from(value.toString(16).padStart(64, '0'), 'hex'));
}

export function bytesToUint256(bytes: Uint8Array): bigint {
  if (bytes.length !== 32) {
    throw new RangeError('uint256 byte representation must contain exactly 32 bytes');
  }

  return BigInt(`0x${Buffer.from(bytes).toString('hex')}`);
}

export function evmAddressToBytes(address: string): Uint8Array {
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    throw new Error('EVM address must be a 0x-prefixed 20-byte hexadecimal value');
  }

  return Uint8Array.from(Buffer.from(address.slice(2), 'hex'));
}

export const RECEIVABLE_FINANCE_ADDRESS = evmAddressToBytes(RECEIVABLE_FINANCE_ADDRESS_HEX);

export function createGiwaReceivableSubject(
  receivableId: bigint = 1n,
  subjectRole: bigint = SELLER_ROLE,
  partyWallet: Uint8Array = evmAddressToBytes(SELLER_WALLET_HEX),
): GiwaReceivableSubject {
  return {
    receivableId: uint256ToBytes(receivableId),
    subjectRole,
    partyWallet: Uint8Array.from(partyWallet),
  };
}

export type FinancialAttestationMessage = [
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  companyCommitmentHash: bigint,
  giwaReceivableBindingHash: bigint,
  midnightDeploymentHash: bigint,
  policyRequestHash: bigint,
  providerId: bigint,
  evaluationVersion: bigint,
  profileAsOf: bigint,
  validUntil: bigint,
];

export type FinancialAttestationBinding = {
  companyCommitmentHash: bigint;
  giwaReceivableBindingHash: bigint;
  midnightDeploymentHash: bigint;
  policyRequestHash: bigint;
  providerId?: bigint;
  evaluationVersion?: bigint;
  profileAsOf?: bigint;
  validUntil?: bigint;
};

export function buildFinancialAttestationMessage(
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  binding: FinancialAttestationBinding,
): FinancialAttestationMessage {
  return [
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    binding.companyCommitmentHash,
    binding.giwaReceivableBindingHash,
    binding.midnightDeploymentHash,
    binding.policyRequestHash,
    binding.providerId ?? 1n,
    binding.evaluationVersion ?? EVALUATION_VERSION,
    binding.profileAsOf ?? PROFILE_AS_OF,
    binding.validUntil ?? DEFAULT_POLICY_REQUEST.validUntil,
  ];
}

export const financialProfiles = [
  {
    profileId: 'eligible-boundary',
    annualRevenueKrw: 500000000n,
    debtRatioBps: 20000n,
    overdueCount: 1n,
  },
  {
    profileId: 'eligible-comfortable',
    annualRevenueKrw: 1200000000n,
    debtRatioBps: 12500n,
    overdueCount: 0n,
  },
  {
    profileId: 'ineligible-revenue',
    annualRevenueKrw: 499999999n,
    debtRatioBps: 20000n,
    overdueCount: 1n,
  },
  {
    profileId: 'ineligible-debt',
    annualRevenueKrw: 500000000n,
    debtRatioBps: 20001n,
    overdueCount: 1n,
  },
  {
    profileId: 'ineligible-overdue',
    annualRevenueKrw: 500000000n,
    debtRatioBps: 20000n,
    overdueCount: 2n,
  },
] as const;

const JUBJUB_ORDER = 6554484396890773809930967563523245729705921265872317281365359162392183254199n;
const TWO_248 = 452312848583266388373324160190187140051835877600158453279131187530910662656n;

function randomScalar(): bigint {
  const bytes = crypto.randomBytes(32);
  const value = BigInt(`0x${bytes.toString('hex')}`);
  return value % JUBJUB_ORDER;
}

export function generateProviderKeyPair(): { sk: bigint; pk: JubjubPoint } {
  const sk = randomScalar();
  return { sk, pk: ecMulGenerator(sk) };
}

export function schnorrSign(sk: bigint, msg: bigint[]): Schnorr_SchnorrSignature {
  const pk = ecMulGenerator(sk);
  const nonce = randomScalar();
  const announcement = ecMulGenerator(nonce);
  const challengeFull = pureCircuits.schnorrChallenge(
    announcement.x,
    announcement.y,
    pk.x,
    pk.y,
    msg,
  );
  const challenge = challengeFull % TWO_248;
  const response = (((nonce + challenge * sk) % JUBJUB_ORDER) + JUBJUB_ORDER) % JUBJUB_ORDER;
  return { announcement, response };
}

export function generateCompanySecret(): Uint8Array {
  return new Uint8Array(crypto.randomBytes(32));
}

export function createSignedFinancialProfile(
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  providerSk: bigint,
  binding: FinancialAttestationBinding,
  companySecretKey: Uint8Array = generateCompanySecret(),
): GasokEligibilityPrivateState {
  const providerId = binding.providerId ?? 1n;
  const message = buildFinancialAttestationMessage(
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    binding,
  );

  return {
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    attestationSignature: schnorrSign(providerSk, message),
    attestationProviderId: providerId,
    attestationProfileAsOf: binding.profileAsOf ?? PROFILE_AS_OF,
    companySecretKey,
  };
}

export function createSignedFinancialProfileFromFixture(
  index: number,
  providerSk: bigint,
  binding: FinancialAttestationBinding,
  companySecretKey: Uint8Array = generateCompanySecret(),
): GasokEligibilityPrivateState {
  const profile = financialProfiles[index];
  if (!profile) {
    throw new Error(`Index ${index} is out of bounds. Must be between 0 and ${financialProfiles.length - 1}.`);
  }

  return createSignedFinancialProfile(
    profile.annualRevenueKrw,
    profile.debtRatioBps,
    profile.overdueCount,
    providerSk,
    binding,
    companySecretKey,
  );
}
