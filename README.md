# GASOK Midnight PoC

This repository is the local-only Midnight workspace for GASOK. It begins with
the official ZK Loan tutorial unchanged, then maps the verified CLI flow to
GASOK financial eligibility. It must use only the `undeployed` network.

Phase 1 and the GASOK Phase 2 CLI flow are verified locally. Phase 2 privately
evaluates annual revenue in integer KRW (`Uint<64>`), debt ratio in basis points
(`Uint<32>`, so 200.00% is 20,000), and overdue count (`Uint<16>`). Only a
pseudonymous commitment, `eligible`, Mock Provider ID, and policy version are
public.

The current package name and generated `managed/zkloan-credit-scorer` path are
retained temporarily to keep the first behavioral conversion small; the active
exported contract API is `GasokEligibility`.

The existing Vue, Spring Boot, GIWA Solidity, and GIWA Sepolia flows are outside
this repository and remain unchanged during CLI-first phases.

## Workspaces

Use Node 22 (`nvm use`) for the official ZK Loan runtime. Node 24 is installed
locally but is incompatible with the official Attestation API's current
Restify/SPDY dependency path.

- `contract/`: Compact contract and generated artifacts
- `api/`: localhost-only public-ledger read adapter for the dev Vue viewer; no
  Spring Boot replacement
- `cli/`: local wallet, private state, proof, deployment, and state-query flow
- `attestation-api/`: mock-only Schnorr attestation provider

Private financial data, signatures, mnemonics, provider secrets, private state,
and logs are local-only and must not be committed.

## Runtime compatibility

Keep `@midnight-ntwrk/onchain-runtime-v3` pinned and hoisted as one physical
`3.0.0` package while using Midnight.js 4.1.1. Compact runtime and Midnight.js
exchange WASM `StateValue` objects during every contract call. Two installed
runtime copies fail their class-identity check even when their JavaScript shapes
are identical.

Verify the installation with:

```sh
npm ls --all @midnight-ntwrk/onchain-runtime-v3
find node_modules -path '*/@midnight-ntwrk/onchain-runtime-v3/package.json' -print
```

Both Compact runtime and Midnight.js protocol must be `deduped` to the single
root package path.

## Phase 3A public viewer

With the local Node and Indexer running, start the read-only adapter under Node
22:

```sh
nvm use 22
npm run build --workspace giwa-midnight-api
npm run start --workspace giwa-midnight-api
```

It binds to `http://127.0.0.1:4100`. The existing Vue development server proxies
`/midnight-api` to it and displays CLI-created public results at `/midnight`.
The adapter cannot request attestations, access the CLI wallet/private state,
generate proofs, register providers, or submit transactions. It reads only the
configured GASOK contract. After redeploying locally, set the public address for
the adapter and update the Vue development environment to the same value:

```sh
MIDNIGHT_CONTRACT_ADDRESS=<64-hex-address> npm run start --workspace giwa-midnight-api
```
