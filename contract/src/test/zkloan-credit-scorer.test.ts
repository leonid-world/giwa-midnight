// This file is derived from the Midnight ZK Loan example tests.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { describe, expect, it } from 'vitest';
import { GasokEligibilitySimulator } from './zkloan-credit-scorer.simulator.js';
import { createSignedFinancialProfile, generateProviderKeyPair } from './utils/test-data.js';

setNetworkId('undeployed');

describe('GASOK financial eligibility contract', () => {
  const defaultPin = 1234n;

  function setAttestedFinancialState(
    simulator: GasokEligibilitySimulator,
    annualRevenueKrw: bigint,
    debtRatioBps: bigint,
    overdueCount: bigint,
    options: {
      pin?: bigint;
      providerId?: bigint;
      providerSk?: bigint;
      companySecretKey?: Uint8Array;
    } = {},
  ): void {
    const pin = options.pin ?? defaultPin;
    const providerId = options.providerId ?? simulator.providerId;
    const providerSk = options.providerSk ?? simulator.providerSk;
    const companySecretKey = options.companySecretKey ?? simulator.getPrivateState().companySecretKey;
    const commitmentHash = simulator.computeCompanyCommitmentHash(companySecretKey, pin);

    simulator.setPrivateState(
      createSignedFinancialProfile(
        annualRevenueKrw,
        debtRatioBps,
        overdueCount,
        providerSk,
        commitmentHash,
        providerId,
        companySecretKey,
      ),
    );
  }

  function readResult(simulator: GasokEligibilitySimulator, pin: bigint = defaultPin) {
    const companyCommitment = simulator.deriveCompanyCommitment(
      simulator.getPrivateState().companySecretKey,
      pin,
    );
    return simulator.getLedger().eligibilityResults.lookup(companyCommitment);
  }

  it('records eligible=true exactly at all three policy boundaries', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 500000000n, 20000n, 1n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator)).toEqual({
      eligible: true,
      providerId: 1n,
      policyVersion: 1n,
    });
  });

  it('accepts revenue values that require more than 32 bits', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 5000000000n, 12000n, 0n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(true);
  });

  it('records eligible=false when revenue is one KRW below the threshold', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 499999999n, 20000n, 1n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(false);
  });

  it('records eligible=false when debt ratio is one basis point above the threshold', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 500000000n, 20001n, 1n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(false);
  });

  it('supports a debt ratio above Uint16 range and records it as ineligible', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 500000000n, 70000n, 0n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(false);
  });

  it('records eligible=false when overdue count is one above the threshold', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 500000000n, 20000n, 2n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(false);
  });

  it('stores only the approved public result fields', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 900000000n, 15000n, 0n);

    const ledger = simulator.verifyEligibility(defaultPin);
    const result = readResult(simulator);

    expect(Object.keys(result).sort()).toEqual(['eligible', 'policyVersion', 'providerId']);
    expect('annualRevenueKrw' in result).toBe(false);
    expect('debtRatioBps' in result).toBe(false);
    expect('overdueCount' in result).toBe(false);
    expect('attestationSignature' in result).toBe(false);
    expect('loans' in ledger).toBe(false);
  });

  it('keys the public result by a deterministic secret-and-PIN commitment', () => {
    const simulator = new GasokEligibilitySimulator();
    const secret = simulator.companySecretKey;

    const first = simulator.deriveCompanyCommitment(secret, defaultPin);
    const second = simulator.deriveCompanyCommitment(secret, defaultPin);
    const otherPin = simulator.deriveCompanyCommitment(secret, 4321n);
    const otherSecret = simulator.deriveCompanyCommitment(simulator.generateCompanySecret(), defaultPin);

    expect(first).toEqual(second);
    expect(first).not.toEqual(otherPin);
    expect(first).not.toEqual(otherSecret);
  });

  it.each([
    ['annual revenue', { annualRevenueKrw: 500000001n }],
    ['debt ratio', { debtRatioBps: 19999n }],
    ['overdue count', { overdueCount: 0n }],
  ])('rejects a signature after tampering with %s', (_label, mutation) => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 500000000n, 20000n, 1n);
    simulator.setPrivateState({ ...simulator.getPrivateState(), ...mutation });

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow();
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it('rejects an attestation bound to a different PIN commitment', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n, { pin: defaultPin });

    expect(() => simulator.verifyEligibility(4321n)).toThrow();
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it('rejects replay of one company attestation under another company secret', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n);
    simulator.setPrivateState({
      ...simulator.getPrivateState(),
      companySecretKey: simulator.generateCompanySecret(),
    });

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow();
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it('rejects an attestation from an unregistered provider ID', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n, { providerId: 99n });

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow('Attestation provider not registered');
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it('rejects an attestation after its provider is removed', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n);
    simulator.removeProvider(simulator.providerId);

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow('Attestation provider not registered');
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it('accepts a signature from a second registered provider and publishes its ID', () => {
    const simulator = new GasokEligibilitySimulator();
    const secondProvider = generateProviderKeyPair();
    simulator.registerProvider(2n, secondProvider.pk);
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n, {
      providerId: 2n,
      providerSk: secondProvider.sk,
    });

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator)).toEqual({
      eligible: true,
      providerId: 2n,
      policyVersion: 1n,
    });
  });

  it('prevents a non-admin company secret from registering a provider', () => {
    const simulator = new GasokEligibilitySimulator();
    simulator.setCompanySecret(simulator.generateCompanySecret());

    expect(() => simulator.registerProvider(2n, generateProviderKeyPair().pk)).toThrow(
      'Only admin can register providers',
    );
  });

  it('rotates the admin role without exposing either admin secret', () => {
    const simulator = new GasokEligibilitySimulator();
    const newAdminSecret = simulator.generateCompanySecret();
    const newAdminPublicKey = simulator.deriveAdminPublicKey(newAdminSecret);

    simulator.rotateAdmin(newAdminPublicKey);
    simulator.setCompanySecret(newAdminSecret);
    simulator.registerProvider(2n, generateProviderKeyPair().pk);

    expect(simulator.getLedger().providers.member(2n)).toBe(true);
    expect(simulator.getLedger().contractAdmin).toEqual(newAdminPublicKey);
  });
});
