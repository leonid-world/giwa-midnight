// This file is derived from the Midnight ZK Loan example test utilities.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import { type GasokEligibilityPrivateState } from '../../witnesses.js';
import { pureCircuits, type Schnorr_SchnorrSignature } from '../../managed/zkloan-credit-scorer/contract/index.js';
import { ecMulGenerator, type JubjubPoint } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import * as crypto from 'crypto';

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
  companyCommitmentHash: bigint,
  providerId: bigint = 1n,
  companySecretKey: Uint8Array = generateCompanySecret(),
): GasokEligibilityPrivateState {
  const message = [annualRevenueKrw, debtRatioBps, overdueCount, companyCommitmentHash];

  return {
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    attestationSignature: schnorrSign(providerSk, message),
    attestationProviderId: providerId,
    companySecretKey,
  };
}

export function createSignedFinancialProfileFromFixture(
  index: number,
  providerSk: bigint,
  companyCommitmentHash: bigint,
  providerId: bigint = 1n,
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
    companyCommitmentHash,
    providerId,
    companySecretKey,
  );
}
