# GASOK Midnight Workspace Instructions

## Scope

This workspace is a local-only Midnight privacy proof-of-concept. Use only the
`undeployed` network. Do not introduce React, modify GIWA Solidity contracts, or
persist raw financial data in MySQL or Midnight public state.

## Required Order

1. Reproduce the official Midnight ZK Loan example unchanged.
2. Compile the Compact contract.
3. Run the local Node, Indexer, and Proof Server.
4. Complete the official CLI flow.
5. Only then map loan fields to GASOK financial eligibility fields.
6. Verify the GASOK flow through CLI before Vue integration.

## Learning Requirement

The project owner is learning Midnight by building this PoC. For every
Midnight-related task update, explain briefly what each component or command
does in the proof flow and why it is needed. Tie the explanation to the current
implementation or observed runtime behavior rather than presenting theory alone.

## Privacy Rules

- The Attestation API is mock-only and must never be described as bank-verified.
- Keep provider private keys, mnemonics, raw financial inputs, signatures, and
  local private state out of Git, logs, MySQL, and public ledger state.
- Expose only commitments and eligibility outputs publicly.
