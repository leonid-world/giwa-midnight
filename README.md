# GASOK Midnight PoC

This repository is the local-only Midnight workspace for GASOK. It begins with
the official ZK Loan tutorial unchanged, then maps the verified CLI flow to
GASOK financial eligibility. It must use only the `undeployed` network.

Phase 1 and the GASOK Phase 2 CLI flow are verified locally. Phase 2 privately
evaluates annual revenue in integer KRW (`Uint<64>`), debt ratio in basis points
(`Uint<32>`, so 200.00% is 20,000), and overdue count (`Uint<16>`). Only a
pseudonymous commitment, `eligible`, Mock Provider ID, and policy version are
public.

The current Phase 2.5 contract keeps only an opaque receivable-role lookup key
with `eligible`, Provider ID, and policy version. Provider 2 adds the ADR-017
off-chain EIP-712 issuance gate; it does not change the Compact contract,
eight-field Schnorr message, public ledger schema, or deployed address.

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
- `attestation-api/`: mock-only Provider 1 legacy / Provider 2 EIP-712-gated
  Schnorr attestation provider

Private financial data, signatures, mnemonics, provider secrets, private state,
and logs are local-only and must not be committed.

## Provider 2 authorization handoff

Provider 2 requires a canonical Seller/Buyer EOA authorization before it issues
the existing Schnorr attestation:

1. The CLI keeps the raw mock financial tuple and hidden salt and requests a
   random two-minute challenge.
2. It prints the exact EIP-712 request for manual paste into the existing Vue
   application's development-only `/midnight/authorize` route.
3. Vue validates the fixed GIWA/Midnight/Provider context, selects exactly the
   canonical role wallet in MetaMask, signs, verifies the recovered signer, and
   returns minified one-line JSON for CLI paste.
4. The Mock Provider consumes the challenge once, re-resolves the GIWA role,
   recomputes the salted request commitment, and recovers the EOA before
   Schnorr issuance.

Raw financial values and the hidden salt never enter Vue. Compact verifies the
registered Provider's Schnorr signature; Midnight does not independently verify
the EIP-712 signature. Provider 1 results remain legacy role-context-only
results. Provider 2 registration, actual MetaMask signing, and the complete
local proof/transaction/Indexer E2E are still pending.

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

## Phase 3A capability viewer

With the local Node and Indexer running, start the read-only adapter under Node
22:

```sh
nvm use 22
npm run build --workspace giwa-midnight-api
npm run start --workspace giwa-midnight-api
```

It binds to `http://127.0.0.1:4100`. The existing Vue development server proxies
`/midnight-api` to it and resolves one intentionally shared CLI Proof capability
at `/midnight`; it does not anonymously enumerate public results.
The adapter cannot request attestations, access the CLI wallet/private state,
generate proofs, register providers, or submit transactions. It reads only the
configured GASOK contract. The adapter is the sole address authority for the
viewer; Vue has no Midnight-contract environment default. After an approved
local redeployment, update the adapter's pinned public address:

```sh
MIDNIGHT_CONTRACT_ADDRESS=<64-hex-address> npm run start --workspace giwa-midnight-api
```

Current ADR-017 code checks: authorization-focused Attestation tests `18/18`;
the preceding full Attestation run `71/71` before the latest zero-value patch
(full listen suite not yet rerun afterward); CLI `57` with `1` optional
environment E2E skipped; and Vue lint/build checks passing. These do not replace
the pending full Provider 2 local runtime E2E.
