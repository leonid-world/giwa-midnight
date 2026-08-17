import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { createServer } from './server.js';
import { getApprovedMidnightContractAddress } from './context.js';
import { generateKeyPair, getPublicKey, parseProviderSecretKey } from './signing.js';
import { AUTHORIZATION_PROTOCOL, PROVIDER_ID } from './authorization.js';

setNetworkId(process.env.NETWORK_ID || 'undeployed');

const PORT = parseInt(process.env.PORT || '4000', 10);
const HOST = '127.0.0.1';

let providerSk: bigint;

if (process.env.PROVIDER_SECRET_KEY) {
  providerSk = parseProviderSecretKey(process.env.PROVIDER_SECRET_KEY);
  console.log('[MOCK] Loaded provider secret key from environment');
} else {
  const keyPair = generateKeyPair();
  providerSk = keyPair.sk;
  console.log('[MOCK] Generated ephemeral provider key pair');
}

const pk = getPublicKey(providerSk);
const approvedMidnightContractAddress = getApprovedMidnightContractAddress();
console.log(`[MOCK] Provider ID: ${PROVIDER_ID}`);
console.log('[MOCK] Provider public key:');
console.log(`  x: ${pk.x}`);
console.log(`  y: ${pk.y}`);
console.log(`Register this provider on-chain with: registerProvider(${PROVIDER_ID}, {x: ${pk.x}n, y: ${pk.y}n})`);
console.log(`[MOCK] Approved Midnight contract: ${approvedMidnightContractAddress}`);
console.log(`[MOCK] Authorization protocol: ${AUTHORIZATION_PROTOCOL}`);

const server = createServer(providerSk, { approvedMidnightContractAddress });
server.listen(PORT, HOST, () => {
  console.log(`[MOCK] Attestation API listening on http://${HOST}:${PORT}`);
});
