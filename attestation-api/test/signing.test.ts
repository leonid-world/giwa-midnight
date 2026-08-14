import { describe, it, expect } from 'vitest';
import { setNetworkId } from '@midnight-ntwrk/midnight-js-network-id';
import { sign, generateKeyPair, signFinancialData } from '../src/signing.js';
import { ecMulGenerator, ecMul, ecAdd } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
const { pureCircuits } = GasokEligibility;

setNetworkId('undeployed');

const JUBJUB_ORDER = 6554484396890773809930967563523245729705921265872317281365359162392183254199n;
const TWO_248 = 452312848583266388373324160190187140051835877600158453279131187530910662656n;

describe('Schnorr signing', () => {
  it('generates valid key pairs', () => {
    const { sk, pk } = generateKeyPair();
    expect(sk).toBeGreaterThan(0n);
    expect(sk).toBeLessThan(JUBJUB_ORDER);
    expect(pk.x).toBeDefined();
    expect(pk.y).toBeDefined();
  });

  it('produces signatures that verify correctly', () => {
    const { sk, pk } = generateKeyPair();
    const msg = [1n, 2n, 3n, 4n];
    const sig = sign(sk, msg);

    // Manual verification: G*s == R + P*c
    const cFull = pureCircuits.schnorrChallenge(
      sig.announcement.x, sig.announcement.y,
      pk.x, pk.y,
      msg,
    );
    const c = cFull % TWO_248;

    const lhs = ecMulGenerator(sig.response);
    const rhs = ecAdd(sig.announcement, ecMul(pk, c));

    expect(lhs.x).toEqual(rhs.x);
    expect(lhs.y).toEqual(rhs.y);
  });

  it('produces different signatures for different messages', () => {
    const { sk } = generateKeyPair();
    const msg1 = [1n, 2n, 3n, 4n];
    const msg2 = [5n, 6n, 7n, 8n];

    const sig1 = sign(sk, msg1);
    const sig2 = sign(sk, msg2);

    // Signatures should differ (different random nonce each time)
    expect(sig1.response).not.toEqual(sig2.response);
  });

  it('signFinancialData signs GASOK fields in contract order', () => {
    const { sk, pk } = generateKeyPair();
    const companyCommitmentHash = 12345678901234567890n;

    const sig = signFinancialData(sk, 500_000_000n, 20_000n, 1n, companyCommitmentHash);

    // Verify manually
    const msg: [bigint, bigint, bigint, bigint] = [500_000_000n, 20_000n, 1n, companyCommitmentHash];
    const cFull = pureCircuits.schnorrChallenge(
      sig.announcement.x, sig.announcement.y,
      pk.x, pk.y,
      msg,
    );
    const c = cFull % TWO_248;

    const lhs = ecMulGenerator(sig.response);
    const rhs = ecAdd(sig.announcement, ecMul(pk, c));

    expect(lhs.x).toEqual(rhs.x);
    expect(lhs.y).toEqual(rhs.y);
  });

  it('signature response is within Jubjub scalar field', () => {
    const { sk } = generateKeyPair();
    const msg = [100n, 200n, 300n, 400n];

    for (let i = 0; i < 10; i++) {
      const sig = sign(sk, msg);
      expect(sig.response).toBeGreaterThanOrEqual(0n);
      expect(sig.response).toBeLessThan(JUBJUB_ORDER);
    }
  });

  it('challenge hash is deterministic for same inputs', () => {
    const cFull1 = pureCircuits.schnorrChallenge(1n, 2n, 3n, 4n, [5n, 6n, 7n, 8n]);
    const cFull2 = pureCircuits.schnorrChallenge(1n, 2n, 3n, 4n, [5n, 6n, 7n, 8n]);
    expect(cFull1).toEqual(cFull2);
  });
});
