// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from 'vitest';
import {
  LocalAttestationApiError,
  parseLocalAttestationApiError,
  type LocalAttestationErrorCode,
  type LocalAttestationPath,
} from '../attestation-errors.js';

const privateMarker = 'annualRevenueKrw=500000000 secretPin=1234';

describe('local Mock Provider public errors', () => {
  it.each([
    ['/authorization-challenges', 404, 'GIWA_RECEIVABLE_NOT_FOUND'],
    ['/authorization-challenges', 502, 'GIWA_RPC_UNAVAILABLE'],
    ['/attest', 404, 'GIWA_RECEIVABLE_NOT_FOUND'],
    ['/attest', 502, 'GIWA_RPC_UNAVAILABLE'],
    ['/attest', 409, 'POLICY_REQUEST_EXPIRED'],
    ['/attest', 403, 'ROLE_WALLET_MISMATCH'],
  ] as const)(
    'promotes only the allowlisted %s HTTP %i %s tuple without reflecting its message',
    (path, status, code) => {
      const error = parseLocalAttestationApiError(
        path,
        status,
        JSON.stringify({ error: { code, message: privateMarker } }),
      );

      expect(error).toBeInstanceOf(LocalAttestationApiError);
      expect(error).toMatchObject({ code, status });
      expect(error?.message).not.toContain(privateMarker);
      expect(error?.stack).not.toContain(privateMarker);
      expect(JSON.stringify(error)).not.toContain(privateMarker);
    },
  );

  it.each([
    ['/authorization-challenges', 403, 'ROLE_WALLET_MISMATCH'],
    ['/authorization-challenges', 409, 'POLICY_REQUEST_EXPIRED'],
    ['/authorization-challenges', 500, 'GIWA_RECEIVABLE_NOT_FOUND'],
    ['/authorization-challenges', 404, 'GIWA_RPC_UNAVAILABLE'],
    ['/attest', 403, 'UNKNOWN_PROVIDER_ERROR'],
  ] as const)(
    'does not promote an unapproved %s HTTP %i %s tuple',
    (path, status, code) => {
      expect(
        parseLocalAttestationApiError(
          path as LocalAttestationPath,
          status,
          JSON.stringify({ error: { code, message: privateMarker } }),
        ),
      ).toBeNull();
    },
  );

  it.each([
    'not-json',
    JSON.stringify({ code: 'GIWA_RPC_UNAVAILABLE', message: privateMarker }),
    JSON.stringify({ error: { code: 'GIWA_RPC_UNAVAILABLE' } }),
    JSON.stringify({
      error: { code: 'GIWA_RPC_UNAVAILABLE', message: privateMarker, details: privateMarker },
    }),
  ])('rejects a malformed Provider error envelope', (body) => {
    expect(parseLocalAttestationApiError('/authorization-challenges', 502, body)).toBeNull();
  });

  it.each([
    'GIWA_RECEIVABLE_NOT_FOUND',
    'GIWA_RPC_UNAVAILABLE',
    'POLICY_REQUEST_EXPIRED',
    'ROLE_WALLET_MISMATCH',
  ] as const)('constructs %s only from its local canonical definition', (code: LocalAttestationErrorCode) => {
    const error = new LocalAttestationApiError(code);
    expect(error.message).toBe(error.publicMessage);
    expect(error.message).not.toContain(privateMarker);
  });
});
