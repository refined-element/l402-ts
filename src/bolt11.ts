/**
 * Pure TypeScript BOLT11 invoice amount extraction.
 *
 * Parses the human-readable part of a BOLT11 invoice to extract the amount
 * in satoshis. No external Lightning libraries required.
 *
 * BOLT11 format: ln{bc|tb|...}{amount}{multiplier}1{data}
 * Multipliers: m (milli), u (micro), n (nano), p (pico)
 *
 * Uses BigInt internally to avoid floating-point precision issues.
 */

// Match: ln + network + optional(amount + optional multiplier) + "1" separator
const BOLT11_RE =
  /^ln(?<network>[a-z]+?)(?<amount>\d+)?(?<multiplier>[munp])?1/i;

// Multipliers expressed as rational numbers: numerator / denominator
// to avoid floating-point. Result = amount * num / denom (in BTC),
// then multiply by 100_000_000 to get sats.
//
// m = 0.001       => num=1,       denom=1000
// u = 0.000001    => num=1,       denom=1_000_000
// n = 0.000000001 => num=1,       denom=1_000_000_000
// p = 1e-12       => num=1,       denom=1_000_000_000_000
const MULTIPLIERS: Record<string, { num: bigint; denom: bigint }> = {
  m: { num: 1n, denom: 1_000n },
  u: { num: 1n, denom: 1_000_000n },
  n: { num: 1n, denom: 1_000_000_000n },
  p: { num: 1n, denom: 1_000_000_000_000n },
};

const SATS_PER_BTC = 100_000_000n;

/**
 * Extract the amount in satoshis from a BOLT11 invoice string.
 *
 * @param bolt11 A BOLT11-encoded Lightning invoice (e.g., "lnbc10u1p...").
 * @returns Amount in satoshis as a number, or null if no amount is encoded.
 */
export function extractAmountSats(bolt11: string): number | null {
  if (!bolt11) return null;

  const invoice = bolt11.trim().toLowerCase();
  const match = BOLT11_RE.exec(invoice);
  if (!match?.groups) return null;

  const amountStr = match.groups["amount"];
  if (amountStr === undefined) {
    // No amount specified — "any amount" invoice
    return null;
  }

  const amount = BigInt(amountStr);
  const multiplier = match.groups["multiplier"];

  let sats: bigint;
  if (multiplier) {
    const m = MULTIPLIERS[multiplier.toLowerCase()];
    // sats = amount * SATS_PER_BTC * num / denom
    sats = (amount * SATS_PER_BTC * m.num) / m.denom;
  } else {
    // No multiplier means amount is in BTC
    sats = amount * SATS_PER_BTC;
  }

  return Number(sats);
}
