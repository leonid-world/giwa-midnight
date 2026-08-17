// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

export const GIWA_CHAIN_ID = 91_342n;
export const RECEIVABLE_FINANCE_ADDRESS = '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315' as const;

export const UINT8_MAX = (1n << 8n) - 1n;
export const UINT16_MAX = (1n << 16n) - 1n;
export const UINT32_MAX = (1n << 32n) - 1n;
export const UINT64_MAX = (1n << 64n) - 1n;
export const UINT256_MAX = (1n << 256n) - 1n;

export type SubjectRole = 'SELLER' | 'BUYER';

export interface GiwaDeploymentConfig {
  readonly chainId: bigint;
  readonly receivableFinanceAddress: Uint8Array;
}

const unsignedDecimalPattern = /^(0|[1-9][0-9]*)$/;

export function parseUnsignedDecimal(
  input: string,
  label: string,
  maximum: bigint,
  options: { positive?: boolean } = {},
): bigint {
  const value = input.trim();
  if (!unsignedDecimalPattern.test(value)) {
    throw new Error(`${label} must be an unsigned decimal integer.`);
  }

  const parsed = BigInt(value);
  if (options.positive === true && parsed === 0n) {
    throw new Error(`${label} must be greater than zero.`);
  }
  if (parsed > maximum) {
    throw new Error(`${label} exceeds the supported range.`);
  }
  return parsed;
}

export function bigintToFixedBytes(value: bigint, byteLength: number, label: string): Uint8Array {
  const maximum = (1n << BigInt(byteLength * 8)) - 1n;
  if (value < 0n || value > maximum) {
    throw new Error(`${label} does not fit in ${byteLength} bytes.`);
  }
  return Uint8Array.from(Buffer.from(value.toString(16).padStart(byteLength * 2, '0'), 'hex'));
}

export function fixedHexToBytes(
  input: string,
  byteLength: number,
  label: string,
  options: { requirePrefix?: boolean; forbidPrefix?: boolean } = {},
): Uint8Array {
  if (typeof input !== 'string') {
    throw new Error(`${label} must be a hexadecimal string.`);
  }
  const hasPrefix = input.startsWith('0x');
  if (options.requirePrefix === true && !hasPrefix) {
    throw new Error(`${label} must start with 0x.`);
  }
  if (options.forbidPrefix === true && hasPrefix) {
    throw new Error(`${label} must not start with 0x.`);
  }

  const hex = hasPrefix ? input.slice(2) : input;
  if (!new RegExp(`^[0-9a-fA-F]{${byteLength * 2}}$`).test(hex)) {
    throw new Error(`${label} must contain exactly ${byteLength * 2} hexadecimal characters.`);
  }
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function bytesToHex(bytes: Uint8Array, prefix = true): string {
  const hex = Buffer.from(bytes).toString('hex');
  return prefix ? `0x${hex}` : hex;
}

export function normalizeMidnightContractAddress(input: string): string {
  return bytesToHex(fixedHexToBytes(input, 32, 'Midnight contract address'), false);
}

export function normalizeEvmAddress(input: string, label = 'EVM address'): string {
  return bytesToHex(fixedHexToBytes(input, 20, label, { requirePrefix: true }), true);
}

export function isZeroBytes(bytes: Uint8Array): boolean {
  return bytes.every((value) => value === 0);
}

export function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

export function getDefaultGiwaDeploymentConfig(): GiwaDeploymentConfig {
  return {
    chainId: GIWA_CHAIN_ID,
    receivableFinanceAddress: fixedHexToBytes(
      RECEIVABLE_FINANCE_ADDRESS,
      20,
      'ReceivableFinance address',
      { requirePrefix: true },
    ),
  };
}

export function validateGiwaDeploymentConfig(config: GiwaDeploymentConfig): GiwaDeploymentConfig {
  if (config.chainId <= 0n || config.chainId > UINT64_MAX) {
    throw new Error('GIWA chain ID must fit Uint<64> and be greater than zero.');
  }
  if (config.receivableFinanceAddress.length !== 20 || isZeroBytes(config.receivableFinanceAddress)) {
    throw new Error('ReceivableFinance address must be a non-zero 20-byte value.');
  }
  return {
    chainId: config.chainId,
    receivableFinanceAddress: Uint8Array.from(config.receivableFinanceAddress),
  };
}

export function parseSubjectRole(input: string): SubjectRole {
  switch (input.trim().toUpperCase()) {
    case '1':
    case 'SELLER':
      return 'SELLER';
    case '2':
    case 'BUYER':
      return 'BUYER';
    default:
      throw new Error('Subject role must be 1 (SELLER) or 2 (BUYER).');
  }
}

export function subjectRoleToCode(role: SubjectRole): bigint {
  return role === 'SELLER' ? 1n : 2n;
}

export function receivableIdToBytes(receivableId: bigint): Uint8Array {
  if (receivableId <= 0n || receivableId > UINT256_MAX) {
    throw new Error('GIWA receivable ID must fit Uint<256> and be greater than zero.');
  }
  return bigintToFixedBytes(receivableId, 32, 'GIWA receivable ID');
}
