export type SubjectRole = 'SELLER' | 'BUYER';

export interface ProofCapabilityV2 {
  readonly version: 2;
  readonly evaluationVersion: 2;
  readonly midnightContractAddress: string;
  readonly companyCommitment: string;
  readonly lookupKey: string;
  readonly giwaChainId: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
  readonly requestId: string;
  readonly intendedFunderWallet: string;
  readonly minAnnualRevenueKrw: string;
  readonly maxDebtRatioBps: string;
  readonly maxOverdueCount: string;
  readonly policyRequestHash: string;
  readonly profileAsOf: string;
  readonly validUntil: string;
}

export interface EligibilityResultJson {
  readonly lookupKey: string;
  readonly eligible: boolean;
  readonly providerId: string;
  readonly evaluationVersion: 2;
  readonly profileAsOf: string;
  readonly validUntil: string;
}

export interface EligibilityContextJson {
  readonly giwaChainId: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
  readonly requestId: string;
  readonly intendedFunderWallet: string;
  readonly minAnnualRevenueKrw: string;
  readonly maxDebtRatioBps: string;
  readonly maxOverdueCount: string;
  readonly policyRequestHash: string;
}

export interface EligibilityResolutionJson {
  readonly version: 2;
  readonly networkId: 'undeployed';
  readonly contractAddress: string;
  readonly context: EligibilityContextJson;
  readonly result: EligibilityResultJson;
}

export interface ErrorJson {
  readonly error: { readonly code: string; readonly message: string };
}
