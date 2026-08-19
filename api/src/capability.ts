import { timingSafeEqual } from 'node:crypto';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import { GIWA_CHAIN_ID, GIWA_RECEIVABLE_FINANCE_ADDRESS } from './config.js';
import {
  capabilityLookupMismatch,
  invalidProofCapability,
  unapprovedContractAddress,
  unapprovedGiwaContext,
} from './errors.js';
import type { ProofCapabilityV2, SubjectRole } from './types.js';

const { pureCircuits } = GasokEligibility;
const UINT16_MAX = (1n << 16n) - 1n;
const UINT32_MAX = (1n << 32n) - 1n;
const UINT64_MAX = (1n << 64n) - 1n;
const UINT256_MAX = (1n << 256n) - 1n;
const LOWER_HEX_32 = /^[0-9a-f]{64}$/;
const LOWER_PREFIXED_HEX_32 = /^0x[0-9a-f]{64}$/;
const LOWER_EVM_ADDRESS = /^0x[0-9a-f]{40}$/;
const ZERO_PREFIXED_HEX_32 = `0x${'0'.repeat(64)}`;
const ZERO_HEX_32 = '0'.repeat(64);
const ZERO_EVM_ADDRESS = `0x${'0'.repeat(40)}`;
const CAPABILITY_KEYS = [
  'companyCommitment', 'evaluationVersion', 'giwaChainId', 'intendedFunderWallet',
  'lookupKey', 'maxDebtRatioBps', 'maxOverdueCount', 'midnightContractAddress',
  'minAnnualRevenueKrw', 'onchainReceivableId', 'partyWallet', 'policyRequestHash',
  'profileAsOf', 'receivableFinanceAddress', 'requestId', 'subjectRole', 'validUntil', 'version',
] as const;

export interface VerifiedProofCapability {
  readonly capability: ProofCapabilityV2;
  readonly lookupKeyBytes: Uint8Array;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>): boolean {
  const keys = Object.keys(value).sort();
  return keys.length === CAPABILITY_KEYS.length && keys.every((key, index) => key === CAPABILITY_KEYS[index]);
}

function requireLowerHex32(value: unknown, prefixed: boolean): string {
  if (typeof value !== 'string' || !(prefixed ? LOWER_PREFIXED_HEX_32 : LOWER_HEX_32).test(value) ||
      (prefixed ? value === ZERO_PREFIXED_HEX_32 : value === ZERO_HEX_32)) {
    throw invalidProofCapability();
  }
  return value;
}

function requireEvmAddress(value: unknown): string {
  if (typeof value !== 'string' || !LOWER_EVM_ADDRESS.test(value) || value === ZERO_EVM_ADDRESS) {
    throw invalidProofCapability();
  }
  return value;
}

function parseUint(value: unknown, maximum: bigint, positive = false): bigint {
  if (typeof value !== 'string' || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw invalidProofCapability();
  }
  const parsed = BigInt(value);
  if (parsed > maximum || (positive && parsed === 0n)) {
    throw invalidProofCapability();
  }
  return parsed;
}

function parseSubjectRole(value: unknown): SubjectRole {
  if (value !== 'SELLER' && value !== 'BUYER') throw invalidProofCapability();
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

export function verifyProofCapability(value: unknown, approvedContractAddress: string): VerifiedProofCapability {
  if (!isRecord(value) || !hasExactKeys(value) || value.version !== 2 || value.evaluationVersion !== 2) {
    throw invalidProofCapability();
  }

  const midnightContractAddress = requireLowerHex32(value.midnightContractAddress, false);
  const companyCommitment = requireLowerHex32(value.companyCommitment, true);
  const lookupKey = requireLowerHex32(value.lookupKey, true);
  const policyRequestHash = requireLowerHex32(value.policyRequestHash, true);
  const requestId = requireLowerHex32(value.requestId, true);
  const receivableFinanceAddress = requireEvmAddress(value.receivableFinanceAddress);
  const partyWallet = requireEvmAddress(value.partyWallet);
  const intendedFunderWallet = requireEvmAddress(value.intendedFunderWallet);
  const onchainReceivableId = parseUint(value.onchainReceivableId, UINT256_MAX, true);
  const minAnnualRevenueKrw = parseUint(value.minAnnualRevenueKrw, UINT64_MAX);
  const maxDebtRatioBps = parseUint(value.maxDebtRatioBps, UINT32_MAX);
  const maxOverdueCount = parseUint(value.maxOverdueCount, UINT16_MAX);
  const profileAsOf = parseUint(value.profileAsOf, UINT64_MAX, true);
  const validUntil = parseUint(value.validUntil, UINT64_MAX, true);
  const subjectRole = parseSubjectRole(value.subjectRole);
  const giwaChainId = parseUint(value.giwaChainId, UINT64_MAX, true);
  if (profileAsOf > validUntil) throw invalidProofCapability();

  if (midnightContractAddress !== approvedContractAddress) throw unapprovedContractAddress();
  if (giwaChainId !== GIWA_CHAIN_ID || receivableFinanceAddress !== GIWA_RECEIVABLE_FINANCE_ADDRESS) {
    throw unapprovedGiwaContext();
  }

  let computedPolicyRequestHash: Uint8Array;
  let computedLookupKey: Uint8Array;
  try {
    computedPolicyRequestHash = pureCircuits.derivePolicyRequestHash({
      requestId: hexToBytes(requestId),
      intendedFunderWallet: hexToBytes(intendedFunderWallet),
      minAnnualRevenueKrw,
      maxDebtRatioBps,
      maxOverdueCount,
      validUntil,
    });
    const bindingHash = pureCircuits.deriveGiwaReceivableBindingHash(GIWA_CHAIN_ID, hexToBytes(receivableFinanceAddress), {
      receivableId: uint256ToBytes(onchainReceivableId),
      subjectRole: subjectRole === 'SELLER' ? 1n : 2n,
      partyWallet: hexToBytes(partyWallet),
    });
    const deploymentHash = pureCircuits.deriveMidnightDeploymentHash(hexToBytes(midnightContractAddress));
    computedLookupKey = pureCircuits.deriveReceivableEligibilityKey(
      hexToBytes(companyCommitment), bindingHash, deploymentHash, computedPolicyRequestHash,
    );
  } catch {
    throw invalidProofCapability();
  }

  if (!sameBytes(computedPolicyRequestHash, hexToBytes(policyRequestHash)) ||
      !sameBytes(computedLookupKey, hexToBytes(lookupKey))) {
    throw capabilityLookupMismatch();
  }

  return {
    capability: {
      version: 2, evaluationVersion: 2, midnightContractAddress, companyCommitment, lookupKey,
      giwaChainId: giwaChainId.toString(), receivableFinanceAddress,
      onchainReceivableId: onchainReceivableId.toString(), subjectRole, partyWallet,
      requestId, intendedFunderWallet, minAnnualRevenueKrw: minAnnualRevenueKrw.toString(),
      maxDebtRatioBps: maxDebtRatioBps.toString(), maxOverdueCount: maxOverdueCount.toString(),
      policyRequestHash, profileAsOf: profileAsOf.toString(), validUntil: validUntil.toString(),
    },
    lookupKeyBytes: hexToBytes(lookupKey),
  };
}
