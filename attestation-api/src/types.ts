export interface AttestationRequest {
  annualRevenueKrw: string;
  debtRatioBps: string;
  overdueCount: string;
  companyCommitmentHash: string;
}

export interface AttestationResponse {
  signature: {
    announcement: { x: string; y: string }; // bigint as decimal strings
    response: string;
  };
  providerId: number;
  attestationType: 'mock';
}

export interface ProviderInfoResponse {
  providerId: number;
  publicKey: { x: string; y: string };
  attestationType: 'mock';
}

export interface HealthResponse {
  status: string;
  providerId: number;
  attestationType: 'mock';
}
