export type SubjectRole = 'SELLER' | 'BUYER';

export interface ProofCapabilityV1 {
  readonly version: 1;
  readonly midnightContractAddress: string;
  readonly companyCommitment: string;
  readonly lookupKey: string;
  readonly giwaChainId: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
}

export interface EligibilityResultJson {
  readonly lookupKey: string;
  readonly eligible: boolean;
  readonly providerId: string;
  readonly policyVersion: string;
}

export interface EligibilityContextJson {
  readonly giwaChainId: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
}

export interface EligibilityResolutionJson {
  readonly networkId: 'undeployed';
  readonly contractAddress: string;
  readonly context: EligibilityContextJson;
  readonly result: EligibilityResultJson;
}

export interface ErrorJson {
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}
