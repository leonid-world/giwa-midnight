// This file is derived from the Midnight ZK Loan example simulator.
// Copyright (C) 2025 Midnight Foundation
// SPDX-License-Identifier: Apache-2.0

import {
  type CircuitContext,
  createConstructorContext,
  createCircuitContext,
  sampleContractAddress,
  type JubjubPoint,
  transientHash,
  CompactTypeBytes,
} from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { Contract, type Ledger, ledger, pureCircuits } from '../managed/zkloan-credit-scorer/contract/index.js';
import { type GasokEligibilityPrivateState, witnesses } from '../witnesses.js';
import { createEitherTestUser } from './utils/address.js';
import {
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

  constructor() {
    const deployer = createEitherTestUser('GASOK deployer');
    this.contract = new Contract<GasokEligibilityPrivateState>(witnesses);

    const providerKeyPair = generateProviderKeyPair();
    this.providerSk = providerKeyPair.sk;
    this.providerPk = providerKeyPair.pk;

    // The deployer's secret establishes the initial admin and the default
    // pseudonymous company commitment. It remains only in private state.
    this.companySecretKey = generateCompanySecret();
    const commitmentHash = this.computeCompanyCommitmentHash(this.companySecretKey, 1234n);
    const initialPrivateState = createSignedFinancialProfileFromFixture(
      0,
      this.providerSk,
      commitmentHash,
      this.providerId,
      this.companySecretKey,
    );

    const { currentPrivateState, currentContractState, currentZswapLocalState } = this.contract.initialState(
      createConstructorContext(initialPrivateState, deployer.left.hex),
    );
    this.circuitContext = createCircuitContext(
      sampleContractAddress(),
      currentZswapLocalState,
      currentContractState,
      currentPrivateState,
    );

    this.registerProvider(this.providerId, this.providerPk);
  }

  public deriveCompanyCommitment(companySecret: Uint8Array, pin: bigint): Uint8Array {
    return pureCircuits.deriveCompanyCommitment(companySecret, pin);
  }

  public deriveAdminPublicKey(companySecret: Uint8Array): Uint8Array {
    return pureCircuits.deriveAdminPublicKey(companySecret);
  }

  public computeCompanyCommitmentHash(companySecret: Uint8Array, pin: bigint): bigint {
    return transientHash(bytes32Type, this.deriveCompanyCommitment(companySecret, pin));
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

  public verifyEligibility(secretPin: bigint): Ledger {
    this.circuitContext = this.contract.impureCircuits.verifyEligibility(this.circuitContext, secretPin).context;
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
