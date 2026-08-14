import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import { contractNotFound, indexerUnavailable, invalidContractState } from './errors.js';
import { NETWORK_ID } from './config.js';
import type { EligibilityResultsJson } from './types.js';

interface PublicEligibilityResult {
  readonly eligible: boolean;
  readonly providerId: bigint;
  readonly policyVersion: bigint;
}

interface PublicEligibilityLedger {
  readonly eligibilityResults: Iterable<readonly [Uint8Array, PublicEligibilityResult]>;
}

export type QueryContractState = (
  contractAddress: string,
) => Promise<{ readonly data: unknown } | null>;

export type DecodeLedger = (data: unknown) => PublicEligibilityLedger;

export interface EligibilityReaderDependencies {
  readonly queryContractState: QueryContractState;
  readonly decodeLedger?: DecodeLedger;
}

export type GetEligibilityResults = (contractAddress: string) => Promise<EligibilityResultsJson>;

const decodeGasokEligibilityLedger: DecodeLedger = (data) =>
  GasokEligibility.ledger(data as Parameters<typeof GasokEligibility.ledger>[0]);

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function createEligibilityReader({
  queryContractState,
  decodeLedger = decodeGasokEligibilityLedger,
}: EligibilityReaderDependencies): GetEligibilityResults {
  return async (contractAddress) => {
    let state: Awaited<ReturnType<QueryContractState>>;
    try {
      state = await queryContractState(contractAddress);
    } catch {
      throw indexerUnavailable();
    }

    if (state === null) {
      throw contractNotFound();
    }

    let ledger: PublicEligibilityLedger;
    try {
      ledger = decodeLedger(state.data);
    } catch {
      throw invalidContractState();
    }

    const results = Array.from(ledger.eligibilityResults, ([commitment, result]) => ({
      commitment: bytesToHex(commitment),
      eligible: result.eligible,
      providerId: result.providerId.toString(),
      policyVersion: result.policyVersion.toString(),
    })).sort((left, right) => left.commitment.localeCompare(right.commitment));

    return {
      networkId: NETWORK_ID,
      contractAddress,
      results,
    };
  };
}
