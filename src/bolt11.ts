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
 * Why `extractAmountSats` could not determine an amount.
 *
 * - `"no-amount-encoded"` — the invoice parsed fine but carries no amount
 *   (a zero-amount / "any amount" invoice, where the payer picks the value).
 * - `"unparseable"` — the string could not be read as a BOLT11 invoice at all.
 *
 * Both mean the same thing to a payer (the amount is unknown, so it cannot be
 * authorised), but they point at different causes: the first is a server that
 * sent an amountless invoice, the second a malformed or unsupported one.
 */
export type MissingAmountReason = "no-amount-encoded" | "unparseable";

/**
 * Explain why `extractAmountSats` returned null for a given invoice.
 *
 * Only meaningful when `extractAmountSats(bolt11)` returned null; it re-reads
 * the invoice to separate the two causes. Deliberately off the happy path —
 * callers use it to build an error message, not to decide pay vs. refuse.
 *
 * @param bolt11 The invoice `extractAmountSats` could not price.
 * @returns Which of the two failure modes applies.
 */
export function classifyMissingAmount(bolt11: string): MissingAmountReason {
  if (!bolt11) return "unparseable";

  const match = bolt11.trim().toLowerCase().match(BOLT11_RE);
  if (!match?.groups) return "unparseable";

  // The prefix read cleanly, so a missing amount group is the only way
  // `extractAmountSats` could have returned null for this invoice.
  return "no-amount-encoded";
}

/**
 * Extract the amount in satoshis from a BOLT11 invoice string.
 *
 * @param bolt11 A BOLT11-encoded Lightning invoice (e.g., "lnbc10u1p...").
 * @returns Amount in satoshis as a number, or null if the amount cannot be
 *   determined — either none is encoded or the invoice cannot be parsed. Use
 *   `classifyMissingAmount` to tell those apart. Callers must NOT read null as
 *   "no limit applies": an amount that cannot be determined cannot be checked
 *   against a budget, so it must be refused rather than paid.
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
