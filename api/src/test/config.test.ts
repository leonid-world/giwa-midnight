import { describe, expect, it } from 'vitest';
import {
  DEFAULT_GASOK_CONTRACT_ADDRESS,
  getApprovedContractAddress,
  GIWA_CHAIN_ID,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from '../config.js';

describe('read adapter deployment pinning', () => {
  it('defaults to the successful Phase 2.5 local Midnight deployment', () => {
    expect(DEFAULT_GASOK_CONTRACT_ADDRESS).toBe(
      '7e3ea9d741ce0f5862db6f46d0ad720be2586cd7d0405ec77e4a0478aa50f4fb',
    );
    expect(getApprovedContractAddress(undefined)).toBe(DEFAULT_GASOK_CONTRACT_ADDRESS);
  });

  it('pins the GIWA Sepolia ReceivableFinance deployment', () => {
    expect(GIWA_CHAIN_ID).toBe(91_342n);
    expect(GIWA_RECEIVABLE_FINANCE_ADDRESS).toBe(
      '0x0f264334f98ba0d22f7fc6bb901a5fa36158a315',
    );
  });

  it('normalizes an explicit approved Midnight address and rejects malformed values', () => {
    expect(getApprovedContractAddress('A'.repeat(64))).toBe('a'.repeat(64));
    expect(() => getApprovedContractAddress('0x' + 'a'.repeat(64))).toThrow(
      'MIDNIGHT_CONTRACT_ADDRESS must be exactly 64 hexadecimal characters',
    );
  });
});
