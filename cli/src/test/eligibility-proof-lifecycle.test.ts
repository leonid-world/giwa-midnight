// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import { Wallet } from 'ethers';
import type { Logger } from 'pino';
import { GasokEligibility, type GasokEligibilityPrivateState } from 'zkloan-credit-scorer-contract';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import * as api from '../api.js';
import {
  AUTHORIZATION_DOMAIN,
  AUTHORIZATION_FIELDS,
  AUTHORIZATION_PRIMARY_TYPE,
  AUTHORIZATION_PURPOSE,
  AUTHORIZATION_TTL_SECONDS,
  buildAttestationRequestCommitment,
  hashAuthorizationChallenge,
  type RoleAuthorizationCallback,
  type AuthorizationChallenge,
  type AuthorizationChallengeRequest,
} from '../authorization.js';
import type { DeployedGasokEligibilityContract, GasokEligibilityProviders } from '../common-types.js';
import { bytesToHex, getDefaultGiwaDeploymentConfig } from '../giwa.js';
import {
  ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE,
  ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE,
  EligibilityResultAlreadyExistsError,
} from '../proof-errors.js';
import { getInitialPrivateState } from '../state.utils.js';

const CONTRACT_ADDRESS = '12caaf76aef1de1c584b67462018810f6e4e7eb2535e136f560cb621e24a3f36';
const RECEIVABLE_FINANCE = '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315';
const POLICY_REQUEST = {
  requestId: `0x${'3'.repeat(64)}`,
  intendedFunderWallet: `0x${'4'.repeat(40)}`,
  minAnnualRevenueKrw: 500_000_000n,
  maxDebtRatioBps: 20_000n,
  maxOverdueCount: 1n,
  validUntil: 4_000_000_000n,
};
const signingTypes = {
  [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS.map((field) => ({ ...field })),
};

interface Fixture {
  readonly contract: DeployedGasokEligibilityContract;
  readonly providers: GasokEligibilityProviders;
  readonly writes: GasokEligibilityPrivateState[];
  readonly verifyCircuit: ReturnType<typeof vi.fn>;
  readonly authorize: RoleAuthorizationCallback;
  getState(): GasokEligibilityPrivateState;
  setState(state: GasokEligibilityPrivateState): void;
}

function rawChallenge(request: AuthorizationChallengeRequest, partyWallet: string): AuthorizationChallenge {
  const issuedAt = BigInt(Math.floor(Date.now() / 1_000));
  return {
    version: 2,
    domain: AUTHORIZATION_DOMAIN,
    primaryType: AUTHORIZATION_PRIMARY_TYPE,
    types: { [AUTHORIZATION_PRIMARY_TYPE]: AUTHORIZATION_FIELDS },
    message: {
      purpose: AUTHORIZATION_PURPOSE,
      authorizationId: `0x${'1'.repeat(64)}`,
      midnightContractAddress: `0x${request.midnightContractAddress}`,
      receivableFinanceAddress: RECEIVABLE_FINANCE,
      onchainReceivableId: request.onchainReceivableId,
      subjectRole: request.subjectRole,
      partyWallet,
      requestId: request.policyRequest.requestId,
      intendedFunderWallet: request.policyRequest.intendedFunderWallet,
      minAnnualRevenueKrw: request.policyRequest.minAnnualRevenueKrw,
      maxDebtRatioBps: request.policyRequest.maxDebtRatioBps,
      maxOverdueCount: request.policyRequest.maxOverdueCount,
      attestationRequestCommitment: buildAttestationRequestCommitment(request, partyWallet, issuedAt.toString()),
      providerId: '2',
      evaluationVersion: '2',
      profileAsOf: issuedAt.toString(),
      policyValidUntil: request.policyRequest.validUntil,
      issuedAt: issuedAt.toString(),
      expiresAt: (issuedAt + AUTHORIZATION_TTL_SECONDS).toString(),
    },
  };
}

function createFixture(
  options: { circuitFailure?: unknown; witnessWriteFailure?: Error; cleanupWriteFailure?: Error } = {},
): Fixture {
  const signer = Wallet.createRandom();
  const partyWallet = signer.address.toLowerCase();
  let state = getInitialPrivateState(new Uint8Array(32).fill(7));
  const writes: GasokEligibilityPrivateState[] = [];
  const privateStateProvider = {
    setContractAddress: vi.fn(),
    get: vi.fn(async () => state),
    set: vi.fn(async (_id: string, next: GasokEligibilityPrivateState) => {
      state = next;
      writes.push(next);
      if (options.witnessWriteFailure !== undefined && writes.length === 1) {
        throw options.witnessWriteFailure;
      }
      if (options.cleanupWriteFailure !== undefined && writes.length >= 2) {
        throw options.cleanupWriteFailure;
      }
    }),
  };
  const providers = {
    privateStateProvider,
    publicDataProvider: {
      queryContractState: vi.fn(async () => ({ data: new Uint8Array() })),
    },
  } as unknown as GasokEligibilityProviders;
  const verifyCircuit = vi.fn(async () => {
    if (options.circuitFailure !== undefined) {
      throw options.circuitFailure;
    }
    return {
      public: {
        txId: 'f'.repeat(64),
        blockHeight: 12n,
      },
    };
  });
  const contract = {
    deployTxData: { public: { contractAddress: CONTRACT_ADDRESS } },
    callTx: { verifyEligibility: verifyCircuit },
  } as unknown as DeployedGasokEligibilityContract;
  const authorize = vi.fn(async (challenge: AuthorizationChallenge) => {
    const signature = await signer.signTypedData(challenge.domain, signingTypes, challenge.message);
    return {
      version: 2,
      authorizationId: challenge.message.authorizationId,
      typedDataHash: hashAuthorizationChallenge(challenge),
      signer: partyWallet,
      signature,
    };
  });

  let issuedProfileAsOf = '0';

  vi.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
    const endpoint = String(input);
    const request = JSON.parse(String(init?.body)) as AuthorizationChallengeRequest;
    if (endpoint.endsWith('/authorization-challenges')) {
      const challenge = rawChallenge(request, partyWallet);
      issuedProfileAsOf = challenge.message.profileAsOf;
      return new Response(JSON.stringify(challenge), { status: 201 });
    }
    if (endpoint.endsWith('/attest')) {
      return new Response(
        JSON.stringify({
          signature: {
            announcement: { x: '1', y: '2' },
            response: '3',
          },
          providerId: 2,
          evaluationVersion: 2,
          policyRequestHash: bytesToHex(api.derivePolicyRequestHash({
            requestId: request.policyRequest.requestId,
            intendedFunderWallet: request.policyRequest.intendedFunderWallet,
            minAnnualRevenueKrw: BigInt(request.policyRequest.minAnnualRevenueKrw),
            maxDebtRatioBps: BigInt(request.policyRequest.maxDebtRatioBps),
            maxOverdueCount: BigInt(request.policyRequest.maxOverdueCount),
            validUntil: BigInt(request.policyRequest.validUntil),
          })),
          profileAsOf: issuedProfileAsOf,
          validUntil: request.policyRequest.validUntil,
          midnightContractAddress: CONTRACT_ADDRESS,
          binding: {
            giwaChainId: '91342',
            receivableFinanceAddress: RECEIVABLE_FINANCE,
            onchainReceivableId: request.onchainReceivableId,
            subjectRole: request.subjectRole,
            partyWallet,
          },
          attestationType: 'mock',
          authorizationProtocol: 'eip712-role-wallet-v2',
        }),
        { status: 200 },
      );
    }
    throw new Error('Unexpected test endpoint.');
  });

  return {
    contract,
    providers,
    writes,
    verifyCircuit,
    authorize,
    getState: () => state,
    setState: (next) => {
      state = next;
    },
  };
}

function expectSanitized(state: GasokEligibilityPrivateState): void {
  expect(state.annualRevenueKrw).toBe(0n);
  expect(state.debtRatioBps).toBe(0n);
  expect(state.overdueCount).toBe(0n);
  expect(state.attestationProviderId).toBe(0n);
  expect(state.attestationSignature).toEqual({
    announcement: { x: 0n, y: 0n },
    response: 0n,
  });
}

beforeEach(() => {
  api.setLogger({ info: vi.fn(), warn: vi.fn(), error: vi.fn() } as unknown as Logger);
  vi.spyOn(GasokEligibility, 'ledger').mockReturnValue({
    giwaChainId: 91_342n,
    receivableFinanceAddress: getDefaultGiwaDeploymentConfig().receivableFinanceAddress,
    providers: { size: () => 1n },
    eligibilityResults: { size: () => 0n },
  } as unknown as GasokEligibility.Ledger);
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe('split eligibility proof lifecycle', () => {
  it('prepares a Bridge challenge from the boot-validated GIWA config without querying Indexer again', async () => {
    const fixture = createFixture();

    const prepared = await api.prepareEligibilityVerificationWithGiwaConfig(
      fixture.contract,
      fixture.providers,
      getDefaultGiwaDeploymentConfig(),
      1n,
      'SELLER',
      500_000_000n,
      20_000n,
      1n,
      1234n,
      POLICY_REQUEST,
      'http://127.0.0.1:4000',
    );

    expect(prepared.expectedContext.giwa).toEqual(getDefaultGiwaDeploymentConfig());
    expect(fixture.providers.publicDataProvider.queryContractState).not.toHaveBeenCalled();
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });

  it('keeps the original wrapper single-pass and clears witness values after success', async () => {
    const fixture = createFixture();
    const verification = await api.verifyEligibility(
      fixture.contract,
      fixture.providers,
      1n,
      'SELLER',
      500_000_000n,
      20_000n,
      1n,
      1234n,
      POLICY_REQUEST,
      'http://127.0.0.1:4000',
      fixture.authorize,
    );

    expect(verification.proofCapability.subjectRole).toBe('SELLER');
    expect(fixture.authorize).toHaveBeenCalledOnce();
    expect(fixture.verifyCircuit).toHaveBeenCalledOnce();
    expect(globalThis.fetch).toHaveBeenCalledTimes(2);
    expect(fixture.writes).toHaveLength(2);
    expect(fixture.writes[0]).toMatchObject({
      annualRevenueKrw: 500_000_000n,
      debtRatioBps: 20_000n,
      overdueCount: 1n,
      attestationProviderId: 2n,
    });
    expectSanitized(fixture.writes[1]);
    expectSanitized(fixture.getState());
  });

  it('clears witness values in finally when proof generation or submission fails', async () => {
    const fixture = createFixture({ circuitFailure: new Error('proof server rejected') });

    await expect(
      api.verifyEligibility(
        fixture.contract,
        fixture.providers,
        2n,
        'BUYER',
        499_999_999n,
        20_001n,
        2n,
        4321n,
        POLICY_REQUEST,
        'http://127.0.0.1:4000',
        fixture.authorize,
      ),
    ).rejects.toThrow('proof server rejected');

    expect(fixture.writes).toHaveLength(2);
    expect(fixture.writes[0].attestationProviderId).toBe(2n);
    expectSanitized(fixture.writes[1]);
    expectSanitized(fixture.getState());
  });

  it.each([
    new Error('Eligibility result already exists'),
    new Error(
      "Unexpected error executing scoped transaction '<unnamed>': Error: failed assert: Eligibility result already exists",
      {
        cause: Object.assign(new Error('failed assert: Eligibility result already exists'), { name: 'CompactError' }),
      },
    ),
  ])('classifies only the exact duplicate-result assertion from callTx', async (circuitFailure) => {
    const fixture = createFixture({ circuitFailure });

    let thrown: unknown;
    try {
      await api.verifyEligibility(
        fixture.contract,
        fixture.providers,
        2n,
        'SELLER',
        500_000_000n,
        20_000n,
        1n,
        4321n,
        POLICY_REQUEST,
        'http://127.0.0.1:4000',
        fixture.authorize,
      );
    } catch (error: unknown) {
      thrown = error;
    }

    expect(thrown).toBeInstanceOf(EligibilityResultAlreadyExistsError);
    expect(thrown).toMatchObject({
      code: ELIGIBILITY_RESULT_ALREADY_EXISTS_CODE,
      message: ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE,
      publicMessage: ELIGIBILITY_RESULT_ALREADY_EXISTS_MESSAGE,
    });
    expect((thrown as Error).cause).toBeUndefined();
    expect(fixture.writes).toHaveLength(2);
    expectSanitized(fixture.writes[1]);
  });

  it('does not classify a near-match SDK cause that contains private diagnostics', async () => {
    const compactCause = Object.assign(
      new Error('failed assert: Eligibility result already exists secretPin=do-not-reflect'),
      { name: 'CompactError' },
    );
    const sdkWrapper = new Error('Unexpected scoped transaction failure containing private diagnostics', {
      cause: compactCause,
    });
    const fixture = createFixture({ circuitFailure: sdkWrapper });

    await expect(
      api.verifyEligibility(
        fixture.contract,
        fixture.providers,
        2n,
        'SELLER',
        500_000_000n,
        20_000n,
        1n,
        4321n,
        POLICY_REQUEST,
        'http://127.0.0.1:4000',
        fixture.authorize,
      ),
    ).rejects.toBe(sdkWrapper);

    expect(fixture.writes).toHaveLength(2);
    expectSanitized(fixture.writes[1]);
  });

  it('attempts cleanup when the witness write persists data and then rejects', async () => {
    const fixture = createFixture({ witnessWriteFailure: new Error('late encrypted-state flush failure') });

    await expect(
      api.verifyEligibility(
        fixture.contract,
        fixture.providers,
        3n,
        'SELLER',
        500_000_000n,
        20_000n,
        1n,
        9876n,
        POLICY_REQUEST,
        'http://127.0.0.1:4000',
        fixture.authorize,
      ),
    ).rejects.toThrow('late encrypted-state flush failure');

    expect(fixture.verifyCircuit).not.toHaveBeenCalled();
    expect(fixture.writes).toHaveLength(2);
    expect(fixture.writes[0].attestationProviderId).toBe(2n);
    expectSanitized(fixture.writes[1]);
    expectSanitized(fixture.getState());
  });

  it('preserves a finalized proof capability when encrypted-state cleanup reports failure', async () => {
    const fixture = createFixture({ cleanupWriteFailure: new Error('storage flush failed after sanitize') });

    const verification = await api.verifyEligibility(
      fixture.contract,
      fixture.providers,
      4n,
      'BUYER',
      499_999_999n,
      20_001n,
      2n,
      2468n,
      POLICY_REQUEST,
      'http://127.0.0.1:4000',
      fixture.authorize,
    );

    expect(verification.finalizedTxData.txId).toBe('f'.repeat(64));
    expect(verification.proofCapability.onchainReceivableId).toBe('4');
    expect(fixture.verifyCircuit).toHaveBeenCalledOnce();
    expect(fixture.writes).toHaveLength(3);
    expectSanitized(fixture.getState());
  });

  it('re-reads private state at completion and rejects a changed company identity', async () => {
    const fixture = createFixture();
    const prepared = await api.prepareEligibilityVerification(
      fixture.contract,
      fixture.providers,
      1n,
      'SELLER',
      500_000_000n,
      20_000n,
      1n,
      1234n,
      POLICY_REQUEST,
      'http://127.0.0.1:4000',
    );
    fixture.setState(getInitialPrivateState(new Uint8Array(32).fill(8)));

    await expect(
      api.completeEligibilityVerification(fixture.contract, fixture.providers, prepared, {}, 'http://127.0.0.1:4000'),
    ).rejects.toThrow('private identity changed');
    expect(fixture.verifyCircuit).not.toHaveBeenCalled();
    expect(globalThis.fetch).toHaveBeenCalledOnce();
  });
});
