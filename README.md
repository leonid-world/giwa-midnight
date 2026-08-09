# GASOK Midnight PoC

This repository is the local-only Midnight workspace for GASOK. It begins with
the official ZK Loan tutorial unchanged, then maps the verified CLI flow to
GASOK financial eligibility. It must use only the `undeployed` network.

The existing Vue, Spring Boot, GIWA Solidity, and GIWA Sepolia flows are outside
this repository and remain unchanged during CLI-first phases.

## Workspaces

Use Node 22 (`nvm use`) for the official ZK Loan runtime. Node 24 is installed
locally but is incompatible with the official Attestation API's current
Restify/SPDY dependency path.

- `contract/`: Compact contract and generated artifacts
- `api/`: future shared TypeScript boundary; no Spring Boot replacement
- `cli/`: local wallet, private state, proof, deployment, and state-query flow
- `attestation-api/`: mock-only Schnorr attestation provider

Private financial data, signatures, mnemonics, provider secrets, private state,
and logs are local-only and must not be committed.
