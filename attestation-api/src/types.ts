export type SubjectRole = 'SELLER' | 'BUYER';

export type AuthorizationProtocol = 'eip712-role-wallet-v1';

export interface AuthorizationChallengeRequest {
  version: 1;
  annualRevenueKrw: string;
  debtRatioBps: string;
  overdueCount: string;
  companyCommitmentHash: string;
  authorizationSalt: string;
  midnightContractAddress: string;
  onchainReceivableId: string;
  subjectRole: SubjectRole;
}

export interface AuthorizationProof {
  version: 1;
  authorizationId: string;
  typedDataHash: string;
  signer: string;
  signature: string;
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
}

export interface AuthorizationDomain {
  readonly name: 'GASOK Mock Attestation';
  readonly version: '1';
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
  readonly attestationRequestCommitment: string;
  readonly providerId: string;
  readonly policyVersion: string;
  readonly issuedAt: string;
  readonly expiresAt: string;
}

export interface AuthorizationChallengeResponse {
  readonly version: 1;
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
  policyVersion: number;
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
