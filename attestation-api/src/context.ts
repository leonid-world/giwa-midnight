import {
  CompactTypeBytes,
  transientHash,
} from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import {
  GIWA_CHAIN_ID,
  RECEIVABLE_FINANCE_ADDRESS,
  type GiwaReceivable,
  walletForRole,
} from './giwa.js';
import type { SubjectRole } from './types.js';

const { pureCircuits } = GasokEligibility;
const bytes32Type = new CompactTypeBytes(32);
const MIDNIGHT_CONTRACT_ADDRESS_PATTERN = /^(?:0x)?([0-9a-fA-F]{64})$/;
export const DEFAULT_APPROVED_MIDNIGHT_CONTRACT_ADDRESS =
  '12caaf76aef1de1c584b67462018810f6e4e7eb2535e136f560cb621e24a3f36' as const;

export interface AttestationContext {
  midnightContractAddress: string;
  bindingHashField: bigint;
  deploymentHashField: bigint;
  partyWallet: string;
}

export class ContextValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ContextValidationError';
  }
}

function hexToBytes(value: string, byteLength: number, fieldName: string): Uint8Array {
  const normalized = value.startsWith('0x') ? value.slice(2) : value;
  if (!new RegExp(`^[0-9a-fA-F]{${byteLength * 2}}$`).test(normalized)) {
    throw new ContextValidationError(`${fieldName} has an invalid hexadecimal encoding`);
  }
  return Uint8Array.from(Buffer.from(normalized, 'hex'));
}

function uint256ToBytes(value: bigint): Uint8Array {
  const encoded = value.toString(16).padStart(64, '0');
  return Uint8Array.from(Buffer.from(encoded, 'hex'));
}

export function normalizeMidnightContractAddress(value: unknown): string {
  if (typeof value !== 'string') {
    throw new ContextValidationError('midnightContractAddress must be exactly 64 hexadecimal characters');
  }
  const match = value.trim().match(MIDNIGHT_CONTRACT_ADDRESS_PATTERN);
  if (!match) {
    throw new ContextValidationError('midnightContractAddress must be exactly 64 hexadecimal characters');
  }
  return match[1].toLowerCase();
}

export function getApprovedMidnightContractAddress(
  value: string | undefined = process.env.MIDNIGHT_CONTRACT_ADDRESS,
): string {
  return normalizeMidnightContractAddress(value ?? DEFAULT_APPROVED_MIDNIGHT_CONTRACT_ADDRESS);
}

export function deriveAttestationContext(
  midnightContractAddressInput: unknown,
  receivable: GiwaReceivable,
  subjectRole: SubjectRole,
): AttestationContext {
  const midnightContractAddress = normalizeMidnightContractAddress(midnightContractAddressInput);
  const partyWallet = walletForRole(receivable, subjectRole);
  const bindingHash = pureCircuits.deriveGiwaReceivableBindingHash(
    GIWA_CHAIN_ID,
    hexToBytes(RECEIVABLE_FINANCE_ADDRESS, 20, 'receivableFinanceAddress'),
    {
      receivableId: uint256ToBytes(receivable.id),
      subjectRole: subjectRole === 'SELLER' ? 1n : 2n,
      partyWallet: hexToBytes(partyWallet, 20, 'partyWallet'),
    },
  );
  const deploymentHash = pureCircuits.deriveMidnightDeploymentHash(
    hexToBytes(midnightContractAddress, 32, 'midnightContractAddress'),
  );

  return {
    midnightContractAddress,
    bindingHashField: transientHash(bytes32Type, bindingHash),
    deploymentHashField: transientHash(bytes32Type, deploymentHash),
    partyWallet,
  };
}
