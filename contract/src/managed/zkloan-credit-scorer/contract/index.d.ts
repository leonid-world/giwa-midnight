import type * as __compactRuntime from '@midnight-ntwrk/compact-runtime';

export type EligibilityResult = { eligible: boolean;
                                  providerId: bigint;
                                  policyVersion: bigint
                                };

export type CompanySecretKey = Uint8Array;

export type CompanyCommitment = Uint8Array;

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
                                                                                           bigint]];
  getCompanySecret(context: __compactRuntime.WitnessContext<Ledger, PS>): [PS, CompanySecretKey];
}

export type ImpureCircuits<PS> = {
  verifyEligibility(context: __compactRuntime.CircuitContext<PS>,
                    secretPin_0: bigint): __compactRuntime.CircuitResults<PS, []>;
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
                    secretPin_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  registerProvider(context: __compactRuntime.CircuitContext<PS>,
                   providerId_0: bigint,
                   providerPk_0: __compactRuntime.JubjubPoint): __compactRuntime.CircuitResults<PS, []>;
  removeProvider(context: __compactRuntime.CircuitContext<PS>,
                 providerId_0: bigint): __compactRuntime.CircuitResults<PS, []>;
  rotateAdmin(context: __compactRuntime.CircuitContext<PS>,
              newAdmin_0: AdminPublicKey): __compactRuntime.CircuitResults<PS, []>;
}

export type PureCircuits = {
  deriveCompanyCommitment(sk_0: CompanySecretKey, pin_0: bigint): CompanyCommitment;
  deriveAdminPublicKey(sk_0: CompanySecretKey): AdminPublicKey;
  schnorrChallenge(ann_x_0: bigint,
                   ann_y_0: bigint,
                   pk_x_0: bigint,
                   pk_y_0: bigint,
                   msg_0: bigint[]): bigint;
}

export type Circuits<PS> = {
  deriveCompanyCommitment(context: __compactRuntime.CircuitContext<PS>,
                          sk_0: CompanySecretKey,
                          pin_0: bigint): __compactRuntime.CircuitResults<PS, CompanyCommitment>;
  deriveAdminPublicKey(context: __compactRuntime.CircuitContext<PS>,
                       sk_0: CompanySecretKey): __compactRuntime.CircuitResults<PS, AdminPublicKey>;
  verifyEligibility(context: __compactRuntime.CircuitContext<PS>,
                    secretPin_0: bigint): __compactRuntime.CircuitResults<PS, []>;
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
    member(key_0: CompanyCommitment): boolean;
    lookup(key_0: CompanyCommitment): EligibilityResult;
    [Symbol.iterator](): Iterator<[CompanyCommitment, EligibilityResult]>
  };
  readonly contractAdmin: AdminPublicKey;
  providers: {
    isEmpty(): boolean;
    size(): bigint;
    member(key_0: bigint): boolean;
    lookup(key_0: bigint): __compactRuntime.JubjubPoint;
    [Symbol.iterator](): Iterator<[bigint, __compactRuntime.JubjubPoint]>
  };
}

export type ContractReferenceLocations = any;

export declare const contractReferenceLocations : ContractReferenceLocations;

export declare class Contract<PS = any, W extends Witnesses<PS> = Witnesses<PS>> {
  witnesses: W;
  circuits: Circuits<PS>;
  impureCircuits: ImpureCircuits<PS>;
  provableCircuits: ProvableCircuits<PS>;
  constructor(witnesses: W);
  initialState(context: __compactRuntime.ConstructorContext<PS>): __compactRuntime.ConstructorResult<PS>;
}

export declare function ledger(state: __compactRuntime.StateValue | __compactRuntime.ChargedState): Ledger;
export declare const pureCircuits: PureCircuits;
