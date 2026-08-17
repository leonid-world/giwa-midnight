import { timingSafeEqual } from 'node:crypto';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import {
  GIWA_CHAIN_ID,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from './config.js';
import {
  capabilityLookupMismatch,
  invalidProofCapability,
  unapprovedContractAddress,
  unapprovedGiwaContext,
} from './errors.js';
import type { ProofCapabilityV1, SubjectRole } from './types.js';

const { pureCircuits } = GasokEligibility;
const UINT256_MAX = (1n << 256n) - 1n;
const HEX_32 = /^[0-9a-fA-F]{64}$/;
const PREFIXED_HEX_32 = /^0x[0-9a-fA-F]{64}$/;
const EVM_ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const ZERO_EVM_ADDRESS = `0x${'0'.repeat(40)}`;
const CAPABILITY_KEYS = [
  'companyCommitment',
  'giwaChainId',
  'lookupKey',
  'midnightContractAddress',
  'onchainReceivableId',
  'partyWallet',
  'receivableFinanceAddress',
  'subjectRole',
  'version',
] as const;

export interface VerifiedProofCapability {
  readonly capability: ProofCapabilityV1;
  readonly lookupKeyBytes: Uint8Array;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === CAPABILITY_KEYS.length &&
    keys.every((key, index) => key === CAPABILITY_KEYS[index]);
}

function normalizeHex32(value: unknown): string {
  if (typeof value !== 'string' || !HEX_32.test(value)) {
    throw invalidProofCapability();
  }
  return value.toLowerCase();
}

function normalizePrefixedHex32(value: unknown): string {
  if (typeof value !== 'string' || !PREFIXED_HEX_32.test(value)) {
    throw invalidProofCapability();
  }
  return value.toLowerCase();
}

function normalizeEvmAddress(value: unknown): string {
  if (typeof value !== 'string' || !EVM_ADDRESS.test(value)) {
    throw invalidProofCapability();
  }
  const normalized = value.toLowerCase();
  if (normalized === ZERO_EVM_ADDRESS) {
    throw invalidProofCapability();
  }
  return normalized;
}

function parseReceivableId(value: unknown): bigint {
  if (typeof value !== 'string' || !/^[1-9][0-9]*$/.test(value)) {
    throw invalidProofCapability();
  }
  const parsed = BigInt(value);
  if (parsed > UINT256_MAX) {
    throw invalidProofCapability();
  }
  return parsed;
}

function parseSubjectRole(value: unknown): SubjectRole {
  if (value !== 'SELLER' && value !== 'BUYER') {
    throw invalidProofCapability();
  }
  return value;
}

function hexToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.startsWith('0x') ? value.slice(2) : value, 'hex'));
}

function uint256ToBytes(value: bigint): Uint8Array {
  return hexToBytes(value.toString(16).padStart(64, '0'));
}

function sameBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

export function verifyProofCapability(
  value: unknown,
  approvedContractAddress: string,
): VerifiedProofCapability {
  if (!isRecord(value) || !hasExactKeys(value) || value.version !== 1) {
    throw invalidProofCapability();
  }

  const midnightContractAddress = normalizeHex32(value.midnightContractAddress);
  const companyCommitment = normalizePrefixedHex32(value.companyCommitment);
  const lookupKey = normalizePrefixedHex32(value.lookupKey);
  const receivableFinanceAddress = normalizeEvmAddress(value.receivableFinanceAddress);
  const partyWallet = normalizeEvmAddress(value.partyWallet);
  const onchainReceivableId = parseReceivableId(value.onchainReceivableId);
  const subjectRole = parseSubjectRole(value.subjectRole);

  if (typeof value.giwaChainId !== 'string' || !/^[1-9][0-9]*$/.test(value.giwaChainId)) {
    throw invalidProofCapability();
  }

  if (midnightContractAddress !== approvedContractAddress) {
    throw unapprovedContractAddress();
  }
  if (
    value.giwaChainId !== GIWA_CHAIN_ID.toString() ||
    receivableFinanceAddress !== GIWA_RECEIVABLE_FINANCE_ADDRESS
  ) {
    throw unapprovedGiwaContext();
  }

  let computedLookupKey: Uint8Array;
  try {
    const bindingHash = pureCircuits.deriveGiwaReceivableBindingHash(
      GIWA_CHAIN_ID,
      hexToBytes(receivableFinanceAddress),
      {
        receivableId: uint256ToBytes(onchainReceivableId),
        subjectRole: subjectRole === 'SELLER' ? 1n : 2n,
        partyWallet: hexToBytes(partyWallet.slice(2)),
      },
    );
    const deploymentHash = pureCircuits.deriveMidnightDeploymentHash(
      hexToBytes(midnightContractAddress),
    );
    computedLookupKey = pureCircuits.deriveReceivableEligibilityKey(
      hexToBytes(companyCommitment),
      bindingHash,
      deploymentHash,
    );
  } catch {
    throw invalidProofCapability();
  }

  const lookupKeyBytes = hexToBytes(lookupKey);
  if (!sameBytes(computedLookupKey, lookupKeyBytes)) {
    throw capabilityLookupMismatch();
  }

  return {
    capability: {
      version: 1,
      midnightContractAddress,
      companyCommitment,
      lookupKey,
      giwaChainId: GIWA_CHAIN_ID.toString(),
      receivableFinanceAddress,
      onchainReceivableId: onchainReceivableId.toString(),
      subjectRole,
      partyWallet,
    },
    lookupKeyBytes,
  };
}
