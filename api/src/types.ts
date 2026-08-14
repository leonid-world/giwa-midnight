export interface EligibilityResultJson {
  readonly commitment: string;
  readonly eligible: boolean;
  readonly providerId: string;
  readonly policyVersion: string;
}

export interface EligibilityResultsJson {
  readonly networkId: 'undeployed';
  readonly contractAddress: string;
  readonly results: readonly EligibilityResultJson[];
}

export interface ErrorJson {
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}
