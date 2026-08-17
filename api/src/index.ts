import { API_HOST, getApiPort, getApprovedContractAddress } from './config.js';
import { createLocalEligibilityReader } from './midnight.js';
import { createApiServer } from './server.js';

const port = getApiPort();
const approvedContractAddress = getApprovedContractAddress();
const server = createApiServer({
  getEligibilityResult: createLocalEligibilityReader(),
  approvedContractAddress,
});

server.listen(port, API_HOST, () => {
  console.log(`GASOK Midnight read-only API listening on http://${API_HOST}:${port}`);
});
