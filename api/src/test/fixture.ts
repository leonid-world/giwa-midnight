import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import {
  DEFAULT_GASOK_CONTRACT_ADDRESS,
  GIWA_CHAIN_ID,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from '../config.js';
import type { ProofCapabilityV2 } from '../types.js';

setNetworkId('undeployed');

const { pureCircuits } = GasokEligibility;
const COMPANY_COMMITMENT = `0x${'11'.repeat(32)}`;
const PARTY_WALLET = `0x${'22'.repeat(20)}`;
const REQUEST_ID = `0x${'33'.repeat(32)}`;
const INTENDED_FUNDER_WALLET = `0x${'44'.repeat(20)}`;

function hexToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.startsWith('0x') ? value.slice(2) : value, 'hex'));
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Buffer.from(value).toString('hex')}`;
}

export function createValidCapability(
  overrides: Partial<ProofCapabilityV2> = {},
): ProofCapabilityV2 {
  const receivableId = 7n;
  const validUntil = 4000000000n;
  const policyRequestHash = pureCircuits.derivePolicyRequestHash({
    requestId: hexToBytes(REQUEST_ID),
    intendedFunderWallet: hexToBytes(INTENDED_FUNDER_WALLET),
    minAnnualRevenueKrw: 500000000n,
    maxDebtRatioBps: 20000n,
    maxOverdueCount: 1n,
    validUntil,
  });
  const bindingHash = pureCircuits.deriveGiwaReceivableBindingHash(
    GIWA_CHAIN_ID,
    hexToBytes(GIWA_RECEIVABLE_FINANCE_ADDRESS),
    {
      receivableId: hexToBytes(receivableId.toString(16).padStart(64, '0')),
      subjectRole: 1n,
      partyWallet: hexToBytes(PARTY_WALLET),
    },
  );
  const deploymentHash = pureCircuits.deriveMidnightDeploymentHash(
    hexToBytes(DEFAULT_GASOK_CONTRACT_ADDRESS),
  );
  const lookupKey = pureCircuits.deriveReceivableEligibilityKey(
    hexToBytes(COMPANY_COMMITMENT),
    bindingHash,
    deploymentHash,
    policyRequestHash,
  );

  return {
    version: 2,
    evaluationVersion: 2,
    midnightContractAddress: DEFAULT_GASOK_CONTRACT_ADDRESS,
    companyCommitment: COMPANY_COMMITMENT,
    lookupKey: bytesToHex(lookupKey),
    giwaChainId: GIWA_CHAIN_ID.toString(),
    receivableFinanceAddress: GIWA_RECEIVABLE_FINANCE_ADDRESS,
    onchainReceivableId: receivableId.toString(),
    subjectRole: 'SELLER',
    partyWallet: PARTY_WALLET,
    requestId: REQUEST_ID,
    intendedFunderWallet: INTENDED_FUNDER_WALLET,
    minAnnualRevenueKrw: '500000000',
    maxDebtRatioBps: '20000',
    maxOverdueCount: '1',
    policyRequestHash: bytesToHex(policyRequestHash),
    profileAsOf: '2000000000',
    validUntil: validUntil.toString(),
    ...overrides,
  };
}
