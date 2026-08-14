export class PublicApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    readonly publicMessage: string,
  ) {
    super(publicMessage);
    this.name = 'PublicApiError';
  }
}

export const invalidContractAddress = () =>
  new PublicApiError(400, 'INVALID_CONTRACT_ADDRESS', 'Contract address must be exactly 64 hexadecimal characters.');

export const unapprovedContractAddress = () =>
  new PublicApiError(404, 'UNAPPROVED_CONTRACT_ADDRESS', 'This is not the configured GASOK Midnight contract.');

export const contractNotFound = () =>
  new PublicApiError(404, 'CONTRACT_NOT_FOUND', 'No public contract state was found for this address.');

export const indexerUnavailable = () =>
  new PublicApiError(502, 'MIDNIGHT_INDEXER_UNAVAILABLE', 'The local Midnight Indexer could not be queried.');

export const invalidContractState = () =>
  new PublicApiError(502, 'INVALID_CONTRACT_STATE', 'The public contract state could not be decoded.');
