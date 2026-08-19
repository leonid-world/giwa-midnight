import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import {
  GIWA_CHAIN_ID,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from './config.js';
import {
  contractNotFound,
  eligibilityResultNotFound,
  indexerUnavailable,
  invalidContractState,
  PublicApiError,
} from './errors.js';

interface PublicEligibilityResult {
  readonly eligible: boolean;
  readonly providerId: bigint;
  readonly evaluationVersion: bigint;
  readonly profileAsOf: bigint;
  readonly validUntil: bigint;
}

interface PublicEligibilityMap {
  member(key: Uint8Array): boolean;
  lookup(key: Uint8Array): PublicEligibilityResult;
}

interface PublicEligibilityLedger {
  readonly eligibilityResults: PublicEligibilityMap;
  readonly giwaChainId: bigint;
  readonly receivableFinanceAddress: Uint8Array;
}

export interface ExactEligibilityResult {
  readonly eligible: boolean;
  readonly providerId: string;
  readonly evaluationVersion: 2;
  readonly profileAsOf: string;
  readonly validUntil: string;
}

export type QueryContractState = (
  contractAddress: string,
) => Promise<{ readonly data: unknown } | null>;

export type DecodeLedger = (data: unknown) => PublicEligibilityLedger;

export interface EligibilityReaderDependencies {
  readonly queryContractState: QueryContractState;
  readonly decodeLedger?: DecodeLedger;
}

export type GetEligibilityResult = (
  contractAddress: string,
  lookupKey: Uint8Array,
) => Promise<ExactEligibilityResult>;

const decodeGasokEligibilityLedger: DecodeLedger = (data) =>
  GasokEligibility.ledger(data as Parameters<typeof GasokEligibility.ledger>[0]);

function bytesToHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, '0')).join('');
}

export function createEligibilityReader({
  queryContractState,
  decodeLedger = decodeGasokEligibilityLedger,
}: EligibilityReaderDependencies): GetEligibilityResult {
  return async (contractAddress, lookupKey) => {
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
      if (
        ledger.giwaChainId !== GIWA_CHAIN_ID ||
        `0x${bytesToHex(ledger.receivableFinanceAddress)}` !== GIWA_RECEIVABLE_FINANCE_ADDRESS
      ) {
        throw new Error('Unexpected GIWA deployment configuration');
      }
    } catch {
      throw invalidContractState();
    }

    try {
      if (!ledger.eligibilityResults.member(lookupKey)) {
        throw eligibilityResultNotFound();
      }
      const result = ledger.eligibilityResults.lookup(lookupKey);
      if (
        typeof result.eligible !== 'boolean' ||
        typeof result.providerId !== 'bigint' ||
        typeof result.evaluationVersion !== 'bigint' ||
        result.evaluationVersion !== 2n ||
        typeof result.profileAsOf !== 'bigint' ||
        typeof result.validUntil !== 'bigint' ||
        result.profileAsOf <= 0n ||
        result.profileAsOf > result.validUntil
      ) {
        throw new Error('Malformed eligibility result');
      }
      return {
        eligible: result.eligible,
        providerId: result.providerId.toString(),
        evaluationVersion: 2,
        profileAsOf: result.profileAsOf.toString(),
        validUntil: result.validUntil.toString(),
      };
    } catch (error: unknown) {
      if (error instanceof PublicApiError) {
        throw error;
      }
      throw invalidContractState();
    }
  };
}
