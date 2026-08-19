export type SubjectRole = 'SELLER' | 'BUYER';

export type AuthorizationProtocol = 'eip712-role-wallet-v2';

export interface FunderPolicyRequestWire {
  readonly requestId: string;
  readonly intendedFunderWallet: string;
  readonly minAnnualRevenueKrw: string;
  readonly maxDebtRatioBps: string;
  readonly maxOverdueCount: string;
  readonly validUntil: string;
}

export interface AuthorizationChallengeRequest {
  readonly version: 2;
  readonly annualRevenueKrw: string;
  readonly debtRatioBps: string;
  readonly overdueCount: string;
  readonly companyCommitmentHash: string;
  readonly authorizationSalt: string;
  readonly midnightContractAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly policyRequest: FunderPolicyRequestWire;
}

export interface AuthorizationProof {
  readonly version: 2;
  readonly authorizationId: string;
  readonly typedDataHash: string;
  readonly signer: string;
  readonly signature: string;
}

export interface AttestationRequest extends AuthorizationChallengeRequest {
  authorization: AuthorizationProof;
}

export interface ParsedAttestationRequest {
  readonly annualRevenueKrw: bigint;
  readonly debtRatioBps: bigint;
  readonly overdueCount: bigint;
  readonly companyCommitmentHash: bigint;
  readonly authorizationSalt: string;
  readonly midnightContractAddress: string;
  readonly onchainReceivableId: bigint;
  readonly subjectRole: SubjectRole;
  readonly policyRequest: {
    readonly requestId: string;
    readonly intendedFunderWallet: string;
    readonly minAnnualRevenueKrw: bigint;
    readonly maxDebtRatioBps: bigint;
    readonly maxOverdueCount: bigint;
    readonly validUntil: bigint;
  };
}

export interface AuthorizationDomain {
  readonly name: 'GASOK Mock Attestation';
  readonly version: '2';
  readonly chainId: string;
}

export interface AuthorizationTypeField {
  readonly name: string;
  readonly type: string;
}

export interface AuthorizationTypes {
  readonly GASOKRoleAttestationAuthorization: ReadonlyArray<AuthorizationTypeField>;
}

export interface AuthorizationMessage {
  readonly purpose: string;
  readonly authorizationId: string;
  readonly midnightContractAddress: string;
  readonly receivableFinanceAddress: string;
  readonly onchainReceivableId: string;
  readonly subjectRole: SubjectRole;
  readonly partyWallet: string;
  readonly requestId: string;
  readonly intendedFunderWallet: string;
  readonly minAnnualRevenueKrw: string;
  readonly maxDebtRatioBps: string;
  readonly maxOverdueCount: string;
  readonly attestationRequestCommitment: string;
  readonly providerId: string;
  readonly evaluationVersion: string;
  readonly profileAsOf: string;
  readonly policyValidUntil: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface AuthorizationChallengeResponse {
  readonly version: 2;
  readonly domain: AuthorizationDomain;
  readonly primaryType: 'GASOKRoleAttestationAuthorization';
  readonly types: AuthorizationTypes;
  readonly message: AuthorizationMessage;
}

export interface GiwaReceivableBinding {
  giwaChainId: string;
  receivableFinanceAddress: string;
  onchainReceivableId: string;
  subjectRole: SubjectRole;
  partyWallet: string;
}

export interface AttestationResponse {
  signature: {
    announcement: { x: string; y: string }; // bigint as decimal strings
    response: string;
  };
  providerId: number;
  evaluationVersion: 2;
  policyRequestHash: string;
  profileAsOf: string;
  validUntil: string;
  midnightContractAddress: string;
  binding: GiwaReceivableBinding;
  attestationType: 'mock';
  authorizationProtocol: AuthorizationProtocol;
}

export interface ProviderInfoResponse {
  providerId: number;
  publicKey: { x: string; y: string };
  approvedMidnightContractAddress: string;
  attestationType: 'mock';
  authorizationProtocol: AuthorizationProtocol;
}

export interface HealthResponse {
  status: string;
  providerId: number;
  approvedMidnightContractAddress: string;
  attestationType: 'mock';
  authorizationProtocol: AuthorizationProtocol;
}

export interface ErrorResponse {
  readonly error: {
    readonly code: string;
    readonly message: string;
  };
}
