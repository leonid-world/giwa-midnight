import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type EligibilityResult = { eligible: boolean;
                                  providerId: bigint;
                                  evaluationVersion: bigint;
                                  profileAsOf: bigint;
                                  validUntil: bigint
                                };

export type GiwaReceivableSubject = { receivableId: Uint8Array;
                                      subjectRole: bigint;
                                      partyWallet: Uint8Array
                                    };

export type FunderPolicyRequest = { requestId: Uint8Array;
                                    intendedFunderWallet: Uint8Array;
                                    minAnnualRevenueKrw: bigint;
                                    maxDebtRatioBps: bigint;
                                    maxOverdueCount: bigint;
                                    validUntil: bigint
                                  };

export type CompanySecretKey = Uint8Array;

export type CompanyCommitment = Uint8Array;

export type GiwaReceivableBindingHash = Uint8Array;

export type PolicyRequestHash = Uint8Array;

export type ReceivableEligibilityKey = Uint8Array;

export type MidnightDeploymentHash = Uint8Array;

export type AdminPublicKey = Uint8Array;

export type Schnorr_SchnorrSignature = { announcement: __compactRuntime.JubjubPoint;
                                         response: bigint
                                       };

export type Witnesses<PS> = {
  getSchnorrReduction(context: __compactRuntime.WitnessContext<Ledger, PS>,
                      challengeHash_0: bigint): [PS, [bigint, bigint]];
  getAttestedFinancialWitness(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, [{ annualRevenueKrw: bigint,
                                                                                             debtRatioBps: bigint,
                                                                                             overdueCount: bigint
                                                                                           },
                                                                                           Schnorr_SchnorrSignature,
                                                                                           bigint,
                                                                                           bigint]];
  getCompanySecret(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, CompanySecretKey];
}

export type ImpureCircuits<PS> = {
  verifyEligibility(context: __compactRuntime.CircuitContext<PS>,
                    pseudonymNonce_0: bigint,
                    subject_0: GiwaReceivableSubject,
                    policyRequest_0: FunderPolicyRequest): __compactRuntime.CircuitResults<PS, []>;
  registerProvider(context: __compactRuntime.CircuitContext<PS>,
                   providerId_0: bigint,
                   providerPk_0: __compactRuntime.JubjubPoint): __compactRuntime.CircuitResults<PS, []>;
  removeProvider(context: __compactRuntime.CircuitContext<PS>,
                 providerId_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  rotateAdmin(context: __compactRuntime.CircuitContext<PS>,
              newAdmin_0: AdminPublicKey): __compactRuntime.CircuitResults<PS, []>;
}

export type ProvableCircuits<PS> = {
  verifyEligibility(context: __compactRuntime.CircuitContext<PS>,
                    pseudonymNonce_0: bigint,
                    subject_0: GiwaReceivableSubject,
                    policyRequest_0: FunderPolicyRequest): __compactRuntime.CircuitResults<PS, []>;
  registerProvider(context: __compactRuntime.CircuitContext<PS>,
                   providerId_0: bigint,
                   providerPk_0: __compactRuntime.JubjubPoint): __compactRuntime.CircuitResults<PS, []>;
  removeProvider(context: __compactRuntime.CircuitContext<PS>,
                 providerId_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  rotateAdmin(context: __compactRuntime.CircuitContext<PS>,
              newAdmin_0: AdminPublicKey): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
  deriveCompanyCommitment(sk_0: CompanySecretKey,
                          pseudonymNonce_0: bigint,
                          requestId_0: Uint8Array): CompanyCommitment;
  deriveAdminPublicKey(sk_0: CompanySecretKey): AdminPublicKey;
  deriveGiwaReceivableBindingHash(configuredGiwaChainId_0: bigint,
                                  configuredReceivableFinanceAddress_0: Uint8Array,
                                  subject_0: GiwaReceivableSubject): GiwaReceivableBindingHash;
  deriveMidnightDeploymentHash(contractAddress_0: Uint8Array): MidnightDeploymentHash;
  derivePolicyRequestHash(request_0: FunderPolicyRequest): PolicyRequestHash;
  deriveReceivableEligibilityKey(companyCommitment_0: CompanyCommitment,
                                 bindingHash_0: GiwaReceivableBindingHash,
                                 deploymentHash_0: MidnightDeploymentHash,
                                 policyRequestHash_0: PolicyRequestHash): ReceivableEligibilityKey;
  schnorrChallenge(ann_x_0: bigint,
                   ann_y_0: bigint,
                   pk_x_0: bigint,
                   pk_y_0: bigint,
                   msg_0: bigint[]): bigint;
}

export type Circuits<PS> = {
  deriveCompanyCommitment(context: __compactRuntime.CircuitContext<PS>,
                          sk_0: CompanySecretKey,
                          pseudonymNonce_0: bigint,
                          requestId_0: Uint8Array): __compactRuntime.CircuitResults<PS, CompanyCommitment>;
  deriveAdminPublicKey(context: __compactRuntime.CircuitContext<PS>,
                       sk_0: CompanySecretKey): __compactRuntime.CircuitResults<PS, AdminPublicKey>;
  deriveGiwaReceivableBindingHash(context: __compactRuntime.CircuitContext<PS>,
                                  configuredGiwaChainId_0: bigint,
                                  configuredReceivableFinanceAddress_0: Uint8Array,
                                  subject_0: GiwaReceivableSubject): __compactRuntime.CircuitResults<PS, GiwaReceivableBindingHash>;
  deriveMidnightDeploymentHash(context: __compactRuntime.CircuitContext<PS>,
                               contractAddress_0: Uint8Array): __compactRuntime.CircuitResults<PS, MidnightDeploymentHash>;
  derivePolicyRequestHash(context: __compactRuntime.CircuitContext<PS>,
                          request_0: FunderPolicyRequest): __compactRuntime.CircuitResults<PS, PolicyRequestHash>;
  deriveReceivableEligibilityKey(context: __compactRuntime.CircuitContext<PS>,
                                 companyCommitment_0: CompanyCommitment,
                                 bindingHash_0: GiwaReceivableBindingHash,
                                 deploymentHash_0: MidnightDeploymentHash,
                                 policyRequestHash_0: PolicyRequestHash): __compactRuntime.CircuitResults<PS, ReceivableEligibilityKey>;
  verifyEligibility(context: __compactRuntime.CircuitContext<PS>,
                    pseudonymNonce_0: bigint,
                    subject_0: GiwaReceivableSubject,
                    policyRequest_0: FunderPolicyRequest): __compactRuntime.CircuitResults<PS, []>;
  registerProvider(context: __compactRuntime.CircuitContext<PS>,
                   providerId_0: bigint,
                   providerPk_0: __compactRuntime.JubjubPoint): __compactRuntime.CircuitResults<PS, []>;
  removeProvider(context: __compactRuntime.CircuitContext<PS>,
                 providerId_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  rotateAdmin(context: __compactRuntime.CircuitContext<PS>,
              newAdmin_0: AdminPublicKey): __compactRuntime.CircuitResults<PS, []>;
  schnorrChallenge(context: __compactRuntime.CircuitContext<PS>,
                   ann_x_0: bigint,
                   ann_y_0: bigint,
                   pk_x_0: bigint,
                   pk_y_0: bigint,
                   msg_0: bigint[]): __compactRuntime.CircuitResults<PS, bigint>;
}

export type Ledger = {
  eligibilityResults: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: ReceivableEligibilityKey): boolean;
    lookup(key_0: ReceivableEligibilityKey): EligibilityResult;
    [Symbol.iterator](): Iterator<[ReceivableEligibilityKey, EligibilityResult]>
  };
  readonly contractAdmin: AdminPublicKey;
  providers: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: bigint): boolean;
    lookup(key_0: bigint): __compactRuntime.JubjubPoint;
    [Symbol.iterator](): Iterator<[bigint, __compactRuntime.JubjubPoint]>
  };
  readonly giwaChainId: bigint;
  readonly receivableFinanceAddress: Uint8Array;
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>,
               configuredGiwaChainId_0: bigint,
               configuredReceivableFinanceAddress_0: Uint8Array): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
