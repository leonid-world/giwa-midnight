import { indexerPublicDataProvider } from '@midnight-ntwrk/midnight-js-indexer-public-data-provider';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { WebSocket } from 'ws';
import {
  INDEXER_HTTP_URL,
  INDEXER_QUERY_TIMEOUT_MS,
  INDEXER_WS_URL,
  NETWORK_ID,
} from './config.js';
import { createEligibilityReader, type GetEligibilityResults, type QueryContractState } from './eligibility.js';
import { withTimeout } from './timeout.js';

function installNodeWebSocket(): void {
  if (globalThis.WebSocket === undefined) {
    Object.assign(globalThis, { WebSocket });
  }
}

export function createLocalEligibilityReader(): GetEligibilityResults {
  setNetworkId(NETWORK_ID);
  installNodeWebSocket();

  const provider = indexerPublicDataProvider(INDEXER_HTTP_URL, INDEXER_WS_URL);
  const queryContractState: QueryContractState = async (contractAddress) =>
    withTimeout(
      provider.queryContractState(
        contractAddress as Parameters<typeof provider.queryContractState>[0],
      ),
      INDEXER_QUERY_TIMEOUT_MS,
    );

  return createEligibilityReader({ queryContractState });
}
