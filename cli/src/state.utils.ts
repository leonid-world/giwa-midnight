// This file is derived from the official ZK Loan example.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import { webcrypto } from 'node:crypto';
import { type GasokEligibilityPrivateState } from 'zkloan-credit-scorer-contract';

function generateCompanySecret(): Uint8Array {
  const bytes = new Uint8Array(32);
  webcrypto.getRandomValues(bytes);
  return bytes;
}

// Financial values are supplied interactively only when a verification is
// requested. They are not hard-coded into source or written to public state.
export function getInitialPrivateState(
  companySecretKey: Uint8Array = generateCompanySecret(),
): GasokEligibilityPrivateState {
  return {
    annualRevenueKrw: 0n,
    debtRatioBps: 0n,
    overdueCount: 0n,
    attestationSignature: { announcement: { x: 0n, y: 0n }, response: 0n },
    attestationProviderId: 0n,
    companySecretKey,
  };
}
