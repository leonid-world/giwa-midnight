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

export const unapprovedContractAddress = () =>
  new PublicApiError(404, 'UNAPPROVED_CONTRACT_ADDRESS', 'This is not the configured GASOK Midnight contract.');

export const contractNotFound = () =>
  new PublicApiError(404, 'CONTRACT_NOT_FOUND', 'No public contract state was found for this address.');

export const indexerUnavailable = () =>
  new PublicApiError(502, 'MIDNIGHT_INDEXER_UNAVAILABLE', 'The local Midnight Indexer could not be queried.');

export const invalidContractState = () =>
  new PublicApiError(502, 'INVALID_CONTRACT_STATE', 'The public contract state could not be decoded.');

export const invalidJsonBody = () =>
  new PublicApiError(400, 'INVALID_JSON_BODY', 'The request body must be valid JSON.');

export const jsonBodyRequired = () =>
  new PublicApiError(415, 'JSON_BODY_REQUIRED', 'Content-Type must be application/json.');

export const requestBodyTooLarge = () =>
  new PublicApiError(413, 'REQUEST_BODY_TOO_LARGE', 'The request body is too large.');

export const invalidProofCapability = () =>
  new PublicApiError(400, 'INVALID_PROOF_CAPABILITY', 'The proof capability does not match the v1 schema.');

export const unapprovedGiwaContext = () =>
  new PublicApiError(400, 'UNAPPROVED_GIWA_CONTEXT', 'The proof capability is not for the configured GIWA deployment.');

export const capabilityLookupMismatch = () =>
  new PublicApiError(400, 'CAPABILITY_LOOKUP_MISMATCH', 'The proof capability lookup key is invalid.');

export const eligibilityResultNotFound = () =>
  new PublicApiError(404, 'ELIGIBILITY_RESULT_NOT_FOUND', 'No eligibility result exists for this proof capability.');
