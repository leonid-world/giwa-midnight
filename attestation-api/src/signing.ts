import { ecMulGenerator, type JubjubPoint } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { GasokEligibility } from 'zkloan-credit-scorer-contract';
const { pureCircuits } = GasokEligibility;

type SchnorrSignature = {
  announcement: JubjubPoint;
  response: bigint;
};

export type FinancialAttestationMessage = [
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  companyCommitmentHash: bigint,
  bindingHashField: bigint,
  deploymentHashField: bigint,
  providerId: bigint,
  policyVersion: bigint,
];
import * as crypto from 'crypto';

export const JUBJUB_ORDER = 6554484396890773809930967563523245729705921265872317281365359162392183254199n;
const TWO_248 = 452312848583266388373324160190187140051835877600158453279131187530910662656n;

function randomScalar(): bigint {
  while (true) {
    const bytes = crypto.randomBytes(32);
    // Jubjub scalars fit in 252 bits. Masking first avoids the large rejection
    // rate of drawing across the full 256-bit range; rejection keeps the final
    // distribution uniform and excludes the identity-producing zero scalar.
    bytes[0] &= 0x0f;
    const value = BigInt(`0x${bytes.toString('hex')}`);
    if (value > 0n && value < JUBJUB_ORDER) {
      return value;
    }
  }
}

export function requireValidProviderSecretKey(providerSk: bigint): bigint {
  if (providerSk <= 0n || providerSk >= JUBJUB_ORDER) {
    throw new RangeError('Provider secret key must be between 1 and the Jubjub order minus 1');
  }
  return providerSk;
}

export function parseProviderSecretKey(value: string): bigint {
  const trimmed = value.trim();
  const normalized = trimmed.startsWith('0x') ? trimmed.slice(2) : trimmed;
  if (!/^[0-9a-fA-F]{1,64}$/.test(normalized)) {
    throw new Error('PROVIDER_SECRET_KEY must contain 1 to 64 hexadecimal characters');
  }
  return requireValidProviderSecretKey(BigInt(`0x${normalized}`));
}

export function generateKeyPair(): { sk: bigint; pk: JubjubPoint } {
  const sk = randomScalar();
  const pk = ecMulGenerator(sk);
  return { sk, pk };
}

export function getPublicKey(sk: bigint): JubjubPoint {
  return ecMulGenerator(requireValidProviderSecretKey(sk));
}

export function sign(
  sk: bigint,
  msg: bigint[],
): SchnorrSignature {
  const validSk = requireValidProviderSecretKey(sk);
  const pk = ecMulGenerator(validSk);
  const k = randomScalar();
  const R = ecMulGenerator(k);
  // pureCircuits.schnorrChallenge returns the full transientHash output.
  // The circuit truncates it to 248 bits (mod 2^248) before using in EC ops.
  const cFull = pureCircuits.schnorrChallenge(R.x, R.y, pk.x, pk.y, msg);
  const c = cFull % TWO_248;
  // Compute response: s = (k + c * sk) mod JUBJUB_ORDER
  const s = (k + c * validSk) % JUBJUB_ORDER;
  return { announcement: R, response: s };
}

export function signFinancialData(
  sk: bigint,
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  companyCommitmentHash: bigint,
  bindingHashField: bigint,
  deploymentHashField: bigint,
  providerId: bigint,
  policyVersion: bigint,
): SchnorrSignature {
  const msg = buildFinancialAttestationMessage(
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    companyCommitmentHash,
    bindingHashField,
    deploymentHashField,
    providerId,
    policyVersion,
  );
  return sign(sk, msg);
}

export function buildFinancialAttestationMessage(
  annualRevenueKrw: bigint,
  debtRatioBps: bigint,
  overdueCount: bigint,
  companyCommitmentHash: bigint,
  bindingHashField: bigint,
  deploymentHashField: bigint,
  providerId: bigint,
  policyVersion: bigint,
): FinancialAttestationMessage {
  return [
    annualRevenueKrw,
    debtRatioBps,
    overdueCount,
    companyCommitmentHash,
    bindingHashField,
    deploymentHashField,
    providerId,
    policyVersion,
  ];
}
