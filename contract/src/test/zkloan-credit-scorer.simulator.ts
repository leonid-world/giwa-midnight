// This file is derived from the Midnight ZK Loan example simulator.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import {
  type CircuitContext,
  createConstructorContext,
  createCircuitContext,
  encodeContractAddress,
  sampleContractAddress,
  type ContractAddress,
  type JubjubPoint,
  transientHash,
  CompactTypeBytes,
} from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import {
  Contract,
  type GiwaReceivableSubject,
  type FunderPolicyRequest,
  type Ledger,
  ledger,
  pureCircuits,
} from '../managed/zkloan-credit-scorer/contract/index.js';
import { type GasokEligibilityPrivateState, witnesses } from '../witnesses.js';
import { createEitherTestUser } from './utils/address.js';
import {
  type FinancialAttestationBinding,
  GIWA_CHAIN_ID,
  RECEIVABLE_FINANCE_ADDRESS,
  createGiwaReceivableSubject,
  DEFAULT_POLICY_REQUEST,
  createSignedFinancialProfileFromFixture,
  generateCompanySecret,
  generateProviderKeyPair,
} from './utils/test-data.js';

const bytes32Type = new CompactTypeBytes(32);

export class GasokEligibilitySimulator {
  readonly contract: Contract<GasokEligibilityPrivateState>;
  circuitContext: CircuitContext<GasokEligibilityPrivateState>;
  readonly providerSk: bigint;
  readonly providerPk: JubjubPoint;
  readonly providerId: bigint = 1n;
  readonly companySecretKey: Uint8Array;
  readonly giwaChainId: bigint = GIWA_CHAIN_ID;
  readonly receivableFinanceAddress: Uint8Array = Uint8Array.from(RECEIVABLE_FINANCE_ADDRESS);
  readonly midnightContractAddress: ContractAddress;
  readonly midnightContractAddressBytes: Uint8Array;
  readonly defaultSubject: GiwaReceivableSubject;

  constructor(blockTimeSeconds = 2_000_000_000) {
    const deployer = createEitherTestUser('GASOK deployer');
    this.contract = new Contract<GasokEligibilityPrivateState>(witnesses);
    this.midnightContractAddress = sampleContractAddress();
    this.midnightContractAddressBytes = encodeContractAddress(this.midnightContractAddress);
    this.defaultSubject = createGiwaReceivableSubject();

    const providerKeyPair = generateProviderKeyPair();
    this.providerSk = providerKeyPair.sk;
    this.providerPk = providerKeyPair.pk;

    // The deployer's secret establishes the initial admin and the default
    // pseudonymous company commitment. It remains only in private state.
    this.companySecretKey = generateCompanySecret();
    const initialPrivateState = createSignedFinancialProfileFromFixture(
      0,
      this.providerSk,
      this.createAttestationBinding(this.companySecretKey, 1234n, this.defaultSubject),
      this.companySecretKey,
    );

    const { currentPrivateState, currentContractState, currentZswapLocalState } = this.contract.initialState(
      createConstructorContext(initialPrivateState, deployer.left.hex),
      this.giwaChainId,
      this.receivableFinanceAddress,
    );
    this.circuitContext = createCircuitContext(
      this.midnightContractAddress,
      currentZswapLocalState,
      currentContractState,
      currentPrivateState,
      undefined,
      undefined,
      blockTimeSeconds,
    );

    this.registerProvider(this.providerId, this.providerPk);
  }

  public deriveCompanyCommitment(
    companySecret: Uint8Array,
    pin: bigint,
    policyRequest: FunderPolicyRequest = DEFAULT_POLICY_REQUEST,
  ): Uint8Array {
    return pureCircuits.deriveCompanyCommitment(companySecret, pin, policyRequest.requestId);
  }

  public deriveAdminPublicKey(companySecret: Uint8Array): Uint8Array {
    return pureCircuits.deriveAdminPublicKey(companySecret);
  }

  public computeCompanyCommitmentHash(
    companySecret: Uint8Array,
    pin: bigint,
    policyRequest: FunderPolicyRequest = DEFAULT_POLICY_REQUEST,
  ): bigint {
    return transientHash(bytes32Type, this.deriveCompanyCommitment(companySecret, pin, policyRequest));
  }

  public deriveGiwaReceivableBindingHash(
    subject: GiwaReceivableSubject,
    giwaChainId: bigint = this.giwaChainId,
    receivableFinanceAddress: Uint8Array = this.receivableFinanceAddress,
  ): Uint8Array {
    return pureCircuits.deriveGiwaReceivableBindingHash(giwaChainId, receivableFinanceAddress, subject);
  }

  public computeGiwaReceivableBindingHash(
    subject: GiwaReceivableSubject,
    giwaChainId: bigint = this.giwaChainId,
    receivableFinanceAddress: Uint8Array = this.receivableFinanceAddress,
  ): bigint {
    return transientHash(
      bytes32Type,
      this.deriveGiwaReceivableBindingHash(subject, giwaChainId, receivableFinanceAddress),
    );
  }

  public deriveMidnightDeploymentHash(
    midnightContractAddressBytes: Uint8Array = this.midnightContractAddressBytes,
  ): Uint8Array {
    return pureCircuits.deriveMidnightDeploymentHash(midnightContractAddressBytes);
  }

  public computeMidnightDeploymentHash(
    midnightContractAddressBytes: Uint8Array = this.midnightContractAddressBytes,
  ): bigint {
    return transientHash(bytes32Type, this.deriveMidnightDeploymentHash(midnightContractAddressBytes));
  }

  public deriveReceivableEligibilityKey(
    companySecret: Uint8Array,
    pin: bigint,
    subject: GiwaReceivableSubject = this.defaultSubject,
    options: {
      giwaChainId?: bigint;
      receivableFinanceAddress?: Uint8Array;
      midnightContractAddressBytes?: Uint8Array;
      policyRequest?: FunderPolicyRequest;
    } = {},
  ): Uint8Array {
    const policyRequest = options.policyRequest ?? DEFAULT_POLICY_REQUEST;
    const companyCommitment = this.deriveCompanyCommitment(companySecret, pin, policyRequest);
    const bindingHash = this.deriveGiwaReceivableBindingHash(
      subject,
      options.giwaChainId,
      options.receivableFinanceAddress,
    );
    const deploymentHash = this.deriveMidnightDeploymentHash(options.midnightContractAddressBytes);

    const policyRequestHash = pureCircuits.derivePolicyRequestHash(policyRequest);
    return pureCircuits.deriveReceivableEligibilityKey(companyCommitment, bindingHash, deploymentHash, policyRequestHash);
  }

  public createAttestationBinding(
    companySecret: Uint8Array,
    pin: bigint,
    subject: GiwaReceivableSubject = this.defaultSubject,
    options: {
      giwaChainId?: bigint;
      receivableFinanceAddress?: Uint8Array;
      midnightContractAddressBytes?: Uint8Array;
      providerId?: bigint;
      policyRequest?: FunderPolicyRequest;
    } = {},
  ): FinancialAttestationBinding {
    return {
      companyCommitmentHash: this.computeCompanyCommitmentHash(
        companySecret,
        pin,
        options.policyRequest ?? DEFAULT_POLICY_REQUEST,
      ),
      giwaReceivableBindingHash: this.computeGiwaReceivableBindingHash(
        subject,
        options.giwaChainId,
        options.receivableFinanceAddress,
      ),
      midnightDeploymentHash: this.computeMidnightDeploymentHash(options.midnightContractAddressBytes),
      policyRequestHash: transientHash(
        bytes32Type,
        pureCircuits.derivePolicyRequestHash(options.policyRequest ?? DEFAULT_POLICY_REQUEST),
      ),
      providerId: options.providerId ?? this.providerId,
      evaluationVersion: 2n,
      profileAsOf: 1n,
      validUntil: (options.policyRequest ?? DEFAULT_POLICY_REQUEST).validUntil,
    };
  }

  public generateCompanySecret(): Uint8Array {
    return generateCompanySecret();
  }

  public setCompanySecret(secret: Uint8Array): void {
    this.circuitContext = {
      ...this.circuitContext,
      currentPrivateState: {
        ...this.circuitContext.currentPrivateState,
        companySecretKey: secret,
      },
    };
  }

  public getLedger(): Ledger {
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  public getPrivateState(): GasokEligibilityPrivateState {
    return this.circuitContext.currentPrivateState;
  }

  public setPrivateState(privateState: GasokEligibilityPrivateState): void {
    this.circuitContext = {
      ...this.circuitContext,
      currentPrivateState: privateState,
    };
  }

  public verifyEligibility(
    secretPin: bigint,
    subject: GiwaReceivableSubject = this.defaultSubject,
    policyRequest: FunderPolicyRequest = DEFAULT_POLICY_REQUEST,
  ): Ledger {
    this.circuitContext = this.contract.impureCircuits.verifyEligibility(
      this.circuitContext,
      secretPin,
      subject,
      policyRequest,
    ).context;
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  public rotateAdmin(newAdminPublicKey: Uint8Array): Ledger {
    this.circuitContext = this.contract.impureCircuits.rotateAdmin(this.circuitContext, newAdminPublicKey).context;
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  public registerProvider(providerId: bigint, providerPk: JubjubPoint): Ledger {
    this.circuitContext = this.contract.impureCircuits.registerProvider(
      this.circuitContext,
      providerId,
      providerPk,
    ).context;
    return ledger(this.circuitContext.currentQueryContext.state);
  }

  public removeProvider(providerId: bigint): Ledger {
    this.circuitContext = this.contract.impureCircuits.removeProvider(this.circuitContext, providerId).context;
    return ledger(this.circuitContext.currentQueryContext.state);
  }
}
