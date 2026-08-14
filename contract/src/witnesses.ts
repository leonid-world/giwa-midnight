// This file is derived from midnightntwrk/example-zkloan.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import { Ledger } from './managed/zkloan-credit-scorer/contract/index.js';
import { WitnessContext } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';

export type SchnorrSignature = {
  announcement: { x: bigint; y: bigint };
  response: bigint;
};

// These values live only in the encrypted local private-state provider. The
// witness hands them to the proving circuit; it does not write them to the
// public Midnight ledger.
export type GasokEligibilityPrivateState = {
  annualRevenueKrw: bigint;
  debtRatioBps: bigint;
  overdueCount: bigint;
  attestationSignature: SchnorrSignature;
  attestationProviderId: bigint;
  companySecretKey: Uint8Array;
};

const TWO_248 = 452312848583266388373324160190187140051835877600158453279131187530910662656n;

export const witnesses = {
  getAttestedFinancialWitness: ({
    privateState,
  }: WitnessContext<Ledger, GasokEligibilityPrivateState>): [
    GasokEligibilityPrivateState,
    [{ annualRevenueKrw: bigint; debtRatioBps: bigint; overdueCount: bigint }, SchnorrSignature, bigint],
  ] => [
    privateState,
    [
      {
        annualRevenueKrw: privateState.annualRevenueKrw,
        debtRatioBps: privateState.debtRatioBps,
        overdueCount: privateState.overdueCount,
      },
      privateState.attestationSignature,
      privateState.attestationProviderId,
    ],
  ],

  getSchnorrReduction: (
    { privateState }: WitnessContext<Ledger, GasokEligibilityPrivateState>,
    challengeHash: bigint,
  ): [GasokEligibilityPrivateState, [bigint, bigint]] => {
    const q = challengeHash / TWO_248;
    const r = challengeHash % TWO_248;
    return [privateState, [q, r]];
  },

  getCompanySecret: ({
    privateState,
  }: WitnessContext<Ledger, GasokEligibilityPrivateState>): [GasokEligibilityPrivateState, Uint8Array] => {
    if (!privateState.companySecretKey || privateState.companySecretKey.length !== 32) {
      throw new Error('getCompanySecret: companySecretKey is missing or wrong length');
    }
    return [privateState, privateState.companySecretKey];
  },
};
