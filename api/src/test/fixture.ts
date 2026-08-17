import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
import {
  DEFAULT_GASOK_CONTRACT_ADDRESS,
  GIWA_CHAIN_ID,
  GIWA_RECEIVABLE_FINANCE_ADDRESS,
} from '../config.js';
import type { ProofCapabilityV1 } from '../types.js';

setNetworkId('undeployed');

const { pureCircuits } = GasokEligibility;
const COMPANY_COMMITMENT = `0x${'11'.repeat(32)}`;
const PARTY_WALLET = `0x${'22'.repeat(20)}`;

function hexToBytes(value: string): Uint8Array {
  return Uint8Array.from(Buffer.from(value.startsWith('0x') ? value.slice(2) : value, 'hex'));
}

function bytesToHex(value: Uint8Array): string {
  return `0x${Buffer.from(value).toString('hex')}`;
}

export function createValidCapability(
  overrides: Partial<ProofCapabilityV1> = {},
): ProofCapabilityV1 {
  const receivableId = 7n;
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
  );

  return {
    version: 1,
    midnightContractAddress: DEFAULT_GASOK_CONTRACT_ADDRESS,
    companyCommitment: COMPANY_COMMITMENT,
    lookupKey: bytesToHex(lookupKey),
    giwaChainId: GIWA_CHAIN_ID.toString(),
    receivableFinanceAddress: GIWA_RECEIVABLE_FINANCE_ADDRESS,
    onchainReceivableId: receivableId.toString(),
    subjectRole: 'SELLER',
    partyWallet: PARTY_WALLET,
    ...overrides,
  };
}
