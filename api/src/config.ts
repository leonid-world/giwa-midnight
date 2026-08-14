export const NETWORK_ID = 'undeployed' as const;
export const API_HOST = '127.0.0.1' as const;
export const DEFAULT_API_PORT = 4100;
export const INDEXER_HTTP_URL = 'http://127.0.0.1:8088/api/v4/graphql' as const;
export const INDEXER_WS_URL = 'ws://127.0.0.1:8088/api/v4/graphql/ws' as const;
export const INDEXER_QUERY_TIMEOUT_MS = 10_000;
export const DEFAULT_GASOK_CONTRACT_ADDRESS =
  '59c5528783708cb1535bf0dfbb36af765bfd9ae21c85f36737d6297436a5c643' as const;

const CONTRACT_ADDRESS = /^[0-9a-fA-F]{64}$/;

export function getApprovedContractAddress(
  value: string | undefined = process.env.MIDNIGHT_CONTRACT_ADDRESS,
): string {
  const address = (value ?? DEFAULT_GASOK_CONTRACT_ADDRESS).trim();
  if (!CONTRACT_ADDRESS.test(address)) {
    throw new Error('MIDNIGHT_CONTRACT_ADDRESS must be exactly 64 hexadecimal characters');
  }
  return address.toLowerCase();
}

export function getApiPort(value: string | undefined = process.env.PORT): number {
  if (value === undefined || value === '') {
    return DEFAULT_API_PORT;
  }

  if (!/^\d+$/.test(value)) {
    throw new Error('PORT must be an integer between 1 and 65535');
  }

  const port = Number(value);
  if (!Number.isSafeInteger(port) || port < 1 || port > 65_535) {
    throw new Error('PORT must be an integer between 1 and 65535');
  }
  return port;
}
