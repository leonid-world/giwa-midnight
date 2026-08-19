// This file is derived from the Midnight ZK Loan example tests.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { ecAdd, ecMul, ecMulGenerator } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { describe, expect, it } from 'vitest';
import {
  pureCircuits,
  type FunderPolicyRequest,
  type GiwaReceivableSubject,
} from '../managed/zkloan-credit-scorer/contract/index.js';
import { GasokEligibilitySimulator } from './zkloan-credit-scorer.simulator.js';
import {
  BUYER_ROLE,
  BUYER_WALLET_HEX,
  GIWA_CHAIN_ID,
  RECEIVABLE_FINANCE_ADDRESS,
  SELLER_ROLE,
  SELLER_WALLET_HEX,
  UINT256_MAX,
  bytesToUint256,
  createGiwaReceivableSubject,
  DEFAULT_POLICY_REQUEST,
  createSignedFinancialProfile,
  evmAddressToBytes,
  generateProviderKeyPair,
  uint256ToBytes,
} from './utils/test-data.js';

setNetworkId('undeployed');

const TWO_248 = 1n << 248n;

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
      subject?: GiwaReceivableSubject;
      giwaChainId?: bigint;
      receivableFinanceAddress?: Uint8Array;
      midnightContractAddressBytes?: Uint8Array;
      policyRequest?: FunderPolicyRequest;
    } = {},
  ): void {
    const pin = options.pin ?? defaultPin;
    const providerId = options.providerId ?? simulator.providerId;
    const providerSk = options.providerSk ?? simulator.providerSk;
    const companySecretKey = options.companySecretKey ?? simulator.getPrivateState().companySecretKey;
    const subject = options.subject ?? simulator.defaultSubject;
    const binding = simulator.createAttestationBinding(companySecretKey, pin, subject, {
      giwaChainId: options.giwaChainId,
      receivableFinanceAddress: options.receivableFinanceAddress,
      midnightContractAddressBytes: options.midnightContractAddressBytes,
      providerId,
      policyRequest: options.policyRequest,
    });

    simulator.setPrivateState(
      createSignedFinancialProfile(
        annualRevenueKrw,
        debtRatioBps,
        overdueCount,
        providerSk,
        binding,
        companySecretKey,
      ),
    );
  }

  function readResult(
    simulator: GasokEligibilitySimulator,
    pin: bigint = defaultPin,
    subject: GiwaReceivableSubject = simulator.defaultSubject,
  ) {
    const key = simulator.deriveReceivableEligibilityKey(
      simulator.getPrivateState().companySecretKey,
      pin,
      subject,
    );
    return simulator.getLedger().eligibilityResults.lookup(key);
  }

  it('records eligible=true exactly at all three policy boundaries', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 500000000n, 20000n, 1n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator)).toEqual({
      eligible: true,
      providerId: 1n,
      evaluationVersion: 2n,
      profileAsOf: 1n,
      validUntil: 4000000000n,
    });
  });

  it('evaluates the exact Funder thresholds rather than a hard-coded policy', () => {
    const simulator = new GasokEligibilitySimulator();
    const relaxedPolicy: FunderPolicyRequest = {
      ...DEFAULT_POLICY_REQUEST,
      requestId: uint256ToBytes(99n),
      minAnnualRevenueKrw: 100n,
      maxDebtRatioBps: 30000n,
      maxOverdueCount: 5n,
    };
    setAttestedFinancialState(simulator, 499999999n, 25000n, 2n, { policyRequest: relaxedPolicy });

    simulator.verifyEligibility(defaultPin, simulator.defaultSubject, relaxedPolicy);

    const key = simulator.deriveReceivableEligibilityKey(
      simulator.companySecretKey,
      defaultPin,
      simulator.defaultSubject,
      { policyRequest: relaxedPolicy },
    );
    expect(simulator.getLedger().eligibilityResults.lookup(key).eligible).toBe(true);
  });

  it('rejects policy threshold, audience, request ID, or expiry tampering after provider signing', () => {
    const mutations: FunderPolicyRequest[] = [
      { ...DEFAULT_POLICY_REQUEST, minAnnualRevenueKrw: DEFAULT_POLICY_REQUEST.minAnnualRevenueKrw + 1n },
      { ...DEFAULT_POLICY_REQUEST, intendedFunderWallet: evmAddressToBytes(BUYER_WALLET_HEX) },
      { ...DEFAULT_POLICY_REQUEST, requestId: uint256ToBytes(123n) },
      { ...DEFAULT_POLICY_REQUEST, validUntil: DEFAULT_POLICY_REQUEST.validUntil - 1n },
    ];
    for (const alteredPolicy of mutations) {
      const simulator = new GasokEligibilitySimulator();
      setAttestedFinancialState(simulator, 500000000n, 20000n, 1n);
      expect(() => simulator.verifyEligibility(defaultPin, simulator.defaultSubject, alteredPolicy)).toThrow();
      expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
    }
  });

  it('binds company commitments to the request ID even if a Uint16 nonce repeats', () => {
    const simulator = new GasokEligibilitySimulator();
    const otherPolicy = { ...DEFAULT_POLICY_REQUEST, requestId: uint256ToBytes(2n) };
    expect(simulator.deriveCompanyCommitment(simulator.companySecretKey, 7n, DEFAULT_POLICY_REQUEST))
      .not.toEqual(simulator.deriveCompanyCommitment(simulator.companySecretKey, 7n, otherPolicy));
  });

  it('rejects a policy at its exact block-time expiry boundary', () => {
    const blockTime = 2_000_000_000;
    const simulator = new GasokEligibilitySimulator(blockTime);
    const expiredPolicy: FunderPolicyRequest = {
      ...DEFAULT_POLICY_REQUEST,
      requestId: uint256ToBytes(77n),
      validUntil: BigInt(blockTime),
    };
    setAttestedFinancialState(simulator, 500000000n, 20000n, 1n, { policyRequest: expiredPolicy });
    expect(() => simulator.verifyEligibility(defaultPin, simulator.defaultSubject, expiredPolicy))
      .toThrow('Policy request has expired');
  });

  it('accepts revenue values that require more than 32 bits', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 5000000000n, 12000n, 0n);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(true);
  });

  it.each([
    ['revenue is one KRW below the threshold', 499999999n, 20000n, 1n],
    ['debt ratio is one basis point above the threshold', 500000000n, 20001n, 1n],
    ['debt ratio exceeds the Uint16 range', 500000000n, 70000n, 0n],
    ['overdue count is one above the threshold', 500000000n, 20000n, 2n],
  ])('records eligible=false when %s', (_label, revenue, debtRatio, overdueCount) => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, revenue, debtRatio, overdueCount);

    simulator.verifyEligibility(defaultPin);

    expect(readResult(simulator).eligible).toBe(false);
  });

  it('stores only the outcome, provider, evaluation version, and freshness metadata publicly', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 900000000n, 15000n, 0n);

    const ledger = simulator.verifyEligibility(defaultPin);
    const result = readResult(simulator);

    expect(Object.keys(result).sort()).toEqual([
      'eligible', 'evaluationVersion', 'profileAsOf', 'providerId', 'validUntil',
    ]);
    expect('annualRevenueKrw' in result).toBe(false);
    expect('debtRatioBps' in result).toBe(false);
    expect('overdueCount' in result).toBe(false);
    expect('attestationSignature' in result).toBe(false);
    expect('receivableId' in result).toBe(false);
    expect('subjectRole' in result).toBe(false);
    expect('partyWallet' in result).toBe(false);
    expect('loans' in ledger).toBe(false);
  });

  it('stores seller and buyer results under distinct opaque keys', () => {
    const simulator = new GasokEligibilitySimulator();
    const seller = createGiwaReceivableSubject(
      7n,
      SELLER_ROLE,
      evmAddressToBytes(SELLER_WALLET_HEX),
    );
    const buyer = createGiwaReceivableSubject(
      7n,
      BUYER_ROLE,
      evmAddressToBytes(BUYER_WALLET_HEX),
    );
    const secret = simulator.getPrivateState().companySecretKey;

    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n, { subject: seller });
    simulator.verifyEligibility(defaultPin, seller);
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n, { subject: buyer });
    simulator.verifyEligibility(defaultPin, buyer);

    const sellerKey = simulator.deriveReceivableEligibilityKey(secret, defaultPin, seller);
    const buyerKey = simulator.deriveReceivableEligibilityKey(secret, defaultPin, buyer);
    expect(sellerKey).not.toEqual(buyerKey);
    expect(simulator.getLedger().eligibilityResults.size()).toBe(2n);
    expect(simulator.getLedger().eligibilityResults.lookup(sellerKey).eligible).toBe(true);
    expect(simulator.getLedger().eligibilityResults.lookup(buyerKey).eligible).toBe(true);
  });

  it('changes the lookup key for every company, GIWA context, and Midnight deployment input', () => {
    const simulator = new GasokEligibilitySimulator();
    const secret = simulator.companySecretKey;
    const subject = createGiwaReceivableSubject();
    const otherId = createGiwaReceivableSubject(2n, subject.subjectRole, subject.partyWallet);
    const otherRole = createGiwaReceivableSubject(1n, BUYER_ROLE, subject.partyWallet);
    const otherWallet = createGiwaReceivableSubject(
      1n,
      SELLER_ROLE,
      evmAddressToBytes(BUYER_WALLET_HEX),
    );
    const otherGiwaContract = evmAddressToBytes('0x3333333333333333333333333333333333333333');
    const otherMidnightDeployment = uint256ToBytes(42n);

    const keys = [
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, subject),
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, otherId),
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, otherRole),
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, otherWallet),
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, subject, {
        giwaChainId: GIWA_CHAIN_ID + 1n,
      }),
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, subject, {
        receivableFinanceAddress: otherGiwaContract,
      }),
      simulator.deriveReceivableEligibilityKey(secret, defaultPin, subject, {
        midnightContractAddressBytes: otherMidnightDeployment,
      }),
      simulator.deriveReceivableEligibilityKey(simulator.generateCompanySecret(), defaultPin, subject),
      simulator.deriveReceivableEligibilityKey(secret, 4321n, subject),
    ];
    const keyHexes = keys.map((key) => Buffer.from(key).toString('hex'));

    expect(new Set(keyHexes).size).toBe(keys.length);
  });

  it('round-trips and hashes the maximum uint256 receivable ID', () => {
    const simulator = new GasokEligibilitySimulator();
    const maxBytes = uint256ToBytes(UINT256_MAX);
    const maxSubject = createGiwaReceivableSubject(UINT256_MAX);
    const previousSubject = createGiwaReceivableSubject(UINT256_MAX - 1n);

    expect(maxBytes).toHaveLength(32);
    expect([...maxBytes]).toEqual(new Array<number>(32).fill(255));
    expect(bytesToUint256(maxBytes)).toBe(UINT256_MAX);
    expect(simulator.deriveGiwaReceivableBindingHash(maxSubject)).toEqual(
      simulator.deriveGiwaReceivableBindingHash(maxSubject),
    );
    expect(simulator.deriveGiwaReceivableBindingHash(maxSubject)).not.toEqual(
      simulator.deriveGiwaReceivableBindingHash(previousSubject),
    );
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

  it.each([
    [
      'receivable ID',
      () => createGiwaReceivableSubject(2n, SELLER_ROLE, evmAddressToBytes(SELLER_WALLET_HEX)),
    ],
    [
      'seller/buyer role',
      () => createGiwaReceivableSubject(1n, BUYER_ROLE, evmAddressToBytes(SELLER_WALLET_HEX)),
    ],
    [
      'party wallet',
      () => createGiwaReceivableSubject(1n, SELLER_ROLE, evmAddressToBytes(BUYER_WALLET_HEX)),
    ],
  ])('rejects replay under a different %s', (_label, createAlteredSubject) => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n);

    expect(() => simulator.verifyEligibility(defaultPin, createAlteredSubject())).toThrow();
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it.each([
    ['GIWA chain', { giwaChainId: GIWA_CHAIN_ID + 1n }],
    [
      'ReceivableFinance contract',
      { receivableFinanceAddress: evmAddressToBytes('0x3333333333333333333333333333333333333333') },
    ],
    ['Midnight deployment', { midnightContractAddressBytes: uint256ToBytes(42n) }],
  ])('rejects an attestation signed for a different %s', (_label, signedContext) => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n, signedContext);

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow();
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
  });

  it('rejects an attestation bound to a different pseudonym nonce commitment', () => {
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

  it('rejects an exact replay before evaluating the private witness again', () => {
    const simulator = new GasokEligibilitySimulator();
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n);

    simulator.verifyEligibility(defaultPin);

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow('Eligibility result already exists');
    expect(simulator.getLedger().eligibilityResults.size()).toBe(1n);
  });

  it.each([0n, 3n, 255n])('rejects invalid subject role %s', (invalidRole) => {
    const simulator = new GasokEligibilitySimulator();
    const invalidSubject = createGiwaReceivableSubject(
      1n,
      invalidRole,
      evmAddressToBytes(SELLER_WALLET_HEX),
    );

    expect(() => simulator.deriveGiwaReceivableBindingHash(invalidSubject)).toThrow(
      'Subject role must be SELLER or BUYER',
    );
  });

  it('rejects a zero receivable ID', () => {
    const simulator = new GasokEligibilitySimulator();
    const invalidSubject = createGiwaReceivableSubject(0n);

    expect(() => simulator.deriveGiwaReceivableBindingHash(invalidSubject)).toThrow(
      'GIWA receivable ID must be positive',
    );
  });

  it('rejects a zero party wallet', () => {
    const simulator = new GasokEligibilitySimulator();
    const invalidSubject = createGiwaReceivableSubject(1n, SELLER_ROLE, new Uint8Array(20));

    expect(() => simulator.deriveGiwaReceivableBindingHash(invalidSubject)).toThrow(
      'GIWA party wallet must not be zero',
    );
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
      evaluationVersion: 2n,
      profileAsOf: 1n,
      validUntil: 4000000000n,
    });
  });

  it('rejects the identity provider key that would make any message signature forgeable', () => {
    const simulator = new GasokEligibilitySimulator();
    const identityProviderKey = ecMulGenerator(0n);
    const forgedResponse = 7n;
    const forgedAnnouncement = ecMulGenerator(forgedResponse);
    const arbitraryMessage = [1n, 2n, 3n, 4n, 5n, 6n, 7n, 2n, 2n, 1n, 4000000000n];
    const challenge = pureCircuits.schnorrChallenge(
      forgedAnnouncement.x,
      forgedAnnouncement.y,
      identityProviderKey.x,
      identityProviderKey.y,
      arbitraryMessage,
    ) % TWO_248;

    // With the identity public key, the verifier equation holds without a
    // secret because c * identity is still identity and R was chosen as sG.
    const lhs = ecMulGenerator(forgedResponse);
    const rhs = ecAdd(forgedAnnouncement, ecMul(identityProviderKey, challenge));
    expect({ x: identityProviderKey.x, y: identityProviderKey.y }).toEqual({ x: 0n, y: 1n });
    expect({ x: lhs.x, y: lhs.y }).toEqual({ x: rhs.x, y: rhs.y });

    expect(() => simulator.registerProvider(2n, identityProviderKey)).toThrow(
      'Provider public key must not be the Jubjub identity',
    );
    expect(simulator.getLedger().providers.member(2n)).toBe(false);
  });

  it('rejects provider-ID tampering even when both providers are registered', () => {
    const simulator = new GasokEligibilitySimulator();
    const secondProvider = generateProviderKeyPair();
    simulator.registerProvider(2n, secondProvider.pk);
    setAttestedFinancialState(simulator, 800000000n, 10000n, 0n);
    simulator.setPrivateState({
      ...simulator.getPrivateState(),
      attestationProviderId: 2n,
    });

    expect(() => simulator.verifyEligibility(defaultPin)).toThrow();
    expect(simulator.getLedger().eligibilityResults.size()).toBe(0n);
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

  it('seals the configured local GIWA chain and ReceivableFinance address at deployment', () => {
    const simulator = new GasokEligibilitySimulator();

    expect(simulator.getLedger().giwaChainId).toBe(GIWA_CHAIN_ID);
    expect(simulator.getLedger().receivableFinanceAddress).toEqual(RECEIVABLE_FINANCE_ADDRESS);
  });
});
