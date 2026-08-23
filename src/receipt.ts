/**
 * Parse the Payment-Receipt response header (MPP draft-00).
 *
 * On a successful paid retry the server may attach:
 *
 *   Payment-Receipt: <base64url(JSON)>
 *
 * decoding to `{challengeId, method, reference, status, timestamp}` where
 * `reference` is the payment hash. The receipt never contains the preimage,
 * so it is safe to store and log.
 */

import { decodeBase64Url } from "./base64url.js";
import { extractHeader } from "./challenge.js";
import type { PaymentReceipt } from "./types.js";

/**
 * Parse a Payment-Receipt header from response headers.
 *
 * Tolerant by design: older servers don't send the header, and a malformed
 * receipt must never fail a payment that already succeeded — every parse
 * failure returns null instead of throwing.
 *
 * @returns The parsed receipt, or null when the header is absent or malformed.
 */
export function parsePaymentReceipt(
  headers: Headers | Record<string, string>,
): PaymentReceipt | null {
  const raw = extractHeader(headers, "payment-receipt");
  if (!raw?.trim()) return null;

  const decoded = decodeBase64Url(raw.trim());
  if (decoded === null) return null;

  let json: unknown;
  try {
    json = JSON.parse(decoded);
  } catch {
    return null;
  }
  if (typeof json !== "object" || json === null || Array.isArray(json)) {
    return null;
  }

  const record = json as Record<string, unknown>;
  const field = (value: unknown): string | undefined =>
    typeof value === "string" ? value : undefined;
  return {
    challengeId: field(record.challengeId),
    method: field(record.method),
    reference: field(record.reference),
    status: field(record.status),
    timestamp: field(record.timestamp),
  };
}
