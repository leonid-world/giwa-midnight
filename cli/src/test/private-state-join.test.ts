// This file is part of the GASOK Midnight local proof-of-concept.
// SPDX-License-Identifier: Apache-2.0

import type { Logger } from 'pino';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import type { GasokEligibilityPrivateState } from 'zkloan-credit-scorer-contract';
import type { DeployedGasokEligibilityContract, GasokEligibilityProviders } from '../common-types';
import { getInitialPrivateState } from '../state.utils';

const contractSdkMocks = vi.hoisted(() => ({
  deployContract: vi.fn(),
  findDeployedContract: vi.fn(),
}));

vi.mock('@midnight-ntwrk/midnight-js-contracts', () => contractSdkMocks);

import * as api from '../api';

const contractAddress = '12caaf76aef1de1c584b67462018810f6e4e7eb2535e136f560cb621e24a3f36';
const foundContract = {
  deployTxData: { public: { contractAddress } },
} as unknown as DeployedGasokEligibilityContract;

function createProviders(privateState: GasokEligibilityPrivateState | null) {
  const privateStateProvider = {
    setContractAddress: vi.fn(),
    get: vi.fn(async () => privateState),
  };
  return {
    privateStateProvider,
    providers: { privateStateProvider } as unknown as GasokEligibilityProviders,
  };
}

beforeEach(() => {
  vi.clearAllMocks();
  contractSdkMocks.findDeployedContract.mockResolvedValue(foundContract);
  api.setLogger({ info: vi.fn() } as unknown as Logger);
});

describe('contract join private-state lifecycle', () => {
  it('reuses the contract-scoped private state without passing an overwrite value', async () => {
    const existingPrivateState = getInitialPrivateState(new Uint8Array(32).fill(7));
    const { privateStateProvider, providers } = createProviders(existingPrivateState);

    await expect(api.joinContract(providers, contractAddress)).resolves.toBe(foundContract);

    expect(privateStateProvider.setContractAddress).toHaveBeenCalledWith(contractAddress);
    expect(privateStateProvider.get).toHaveBeenCalledWith('gasokEligibilityPrivateState');
    expect(contractSdkMocks.findDeployedContract).toHaveBeenCalledOnce();
    expect(contractSdkMocks.findDeployedContract.mock.calls[0][1]).not.toHaveProperty('initialPrivateState');
    expect(existingPrivateState.companySecretKey).toEqual(new Uint8Array(32).fill(7));
  });

  it('creates initial private state only when this participant has no state for the contract', async () => {
    const { providers } = createProviders(null);

    await expect(api.joinContract(providers, contractAddress)).resolves.toBe(foundContract);

    const options = contractSdkMocks.findDeployedContract.mock.calls[0][1] as {
      initialPrivateState?: GasokEligibilityPrivateState;
    };
    expect(options.initialPrivateState).toMatchObject({
      annualRevenueKrw: 0n,
      debtRatioBps: 0n,
      overdueCount: 0n,
      attestationProviderId: 0n,
    });
    expect(options.initialPrivateState?.companySecretKey).toHaveLength(32);
  });

  it('does not replace private state when the existing state cannot be read', async () => {
    const { privateStateProvider, providers } = createProviders(null);
    privateStateProvider.get.mockRejectedValue(new Error('private state decryption failed'));

    await expect(api.joinContract(providers, contractAddress)).rejects.toThrow('private state decryption failed');

    expect(contractSdkMocks.findDeployedContract).not.toHaveBeenCalled();
  });
});
