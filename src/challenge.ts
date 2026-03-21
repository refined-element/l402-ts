/**
 * Parse L402 challenges from HTTP 402 responses.
 */

import { ChallengeParseError } from "./errors.js";
import type { L402Challenge, MppChallenge } from "./types.js";

// Matches: L402 macaroon="...", invoice="..."
// Also handles LSAT for backwards compatibility
const CHALLENGE_RE =
  /(?:L402|LSAT)\s+macaroon="(?<macaroon>[^"]+)"\s*,\s*invoice="(?<invoice>[^"]+)"/i;

// Some servers use space-separated key=value without quotes
const CHALLENGE_NOQUOTE_RE =
  /(?:L402|LSAT)\s+macaroon=(?<macaroon>[^\s,]+)\s*,?\s*invoice=(?<invoice>[^\s,]+)/i;

/**
 * Parse a WWW-Authenticate header containing an L402 challenge.
 *
 * Supports formats:
 *   L402 macaroon="<mac>", invoice="<bolt11>"
 *   L402 macaroon=<mac>, invoice=<bolt11>
 *   LSAT macaroon="<mac>", invoice="<bolt11>"  (legacy)
 *
 * @throws {ChallengeParseError} If the header cannot be parsed.
 */
export function parseChallenge(header: string): L402Challenge {
  if (!header) {
    throw new ChallengeParseError(header, "empty header");
  }

  const match =
    CHALLENGE_RE.exec(header) ?? CHALLENGE_NOQUOTE_RE.exec(header);
  if (!match?.groups) {
    throw new ChallengeParseError(header, "no L402/LSAT challenge found");
  }

  const macaroon = match.groups["macaroon"].trim();
  const invoice = match.groups["invoice"].trim();

  if (!macaroon) {
    throw new ChallengeParseError(header, "empty macaroon");
  }
  if (!invoice) {
    throw new ChallengeParseError(header, "empty invoice");
  }

  return { macaroon, invoice };
}

/** Extract the www-authenticate header value from various header formats.
 * Shared by findL402Challenge and findPaymentChallenge for consistent lookup. */
function extractWwwAuthenticate(
  headers: Headers | Record<string, string>,
): string | null {
  if (headers instanceof Headers) {
    return headers.get("www-authenticate");
  }

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === "www-authenticate") {
      return value;
    }
  }
  return null;
}

/**
 * Search response headers for an L402 challenge.
 *
 * @returns Parsed challenge, or null if no L402 challenge found.
 */
export function findL402Challenge(
  headers: Headers | Record<string, string>,
): L402Challenge | null {
  const wwwAuth = extractWwwAuthenticate(headers);
  if (!wwwAuth) return null;

  try {
    return parseChallenge(wwwAuth);
  } catch {
    return null;
  }
}

// ── MPP (Machine Payments Protocol) ──

// Verify header contains a Payment scheme and a lightning method
// Uses \b word boundary to handle comma-concatenated challenges (e.g., "Bearer ..., Payment ...")
const MPP_SCHEME_RE = /\bPayment\s+/i;
const MPP_METHOD_RE = /method="?lightning"?(?=,|\s|$)/i;
// Extract individual fields (order-independent), allowing quoted or unquoted values
const MPP_INVOICE_RE = /invoice="?(?<invoice>[^",\s]+)"?/i;
const MPP_AMOUNT_RE = /amount="?(?<amount>[^",\s]+)"?/i;
const MPP_REALM_RE = /realm="?(?<realm>[^",\s]+)"?/i;

/**
 * Parse a WWW-Authenticate header containing an MPP Payment challenge.
 *
 * Supports format:
 *   Payment realm="...", method="lightning", invoice="<bolt11>", amount="...", currency="sat"
 *
 * @throws {ChallengeParseError} If the header cannot be parsed.
 */
export function parseMppChallenge(header: string): MppChallenge {
  if (!header?.trim()) {
    throw new ChallengeParseError(header ?? "", "empty header");
  }

  if (!MPP_SCHEME_RE.test(header) || !MPP_METHOD_RE.test(header)) {
    throw new ChallengeParseError(
      header,
      'no Payment method="lightning" challenge found',
    );
  }

  const invoiceMatch = MPP_INVOICE_RE.exec(header);
  if (!invoiceMatch?.groups?.invoice) {
    throw new ChallengeParseError(
      header,
      'no Payment method="lightning" challenge found',
    );
  }

  const amountMatch = MPP_AMOUNT_RE.exec(header);
  const realmMatch = MPP_REALM_RE.exec(header);

  return {
    invoice: invoiceMatch.groups.invoice,
    amount: amountMatch?.groups?.amount,
    realm: realmMatch?.groups?.realm,
  };
}

/**
 * Search response headers for an L402 or MPP payment challenge.
 * Prefers L402 when both present. Falls back to MPP.
 *
 * @returns Parsed L402 or MPP challenge, or null if no payment challenge found.
 */
export function findPaymentChallenge(
  headers: Headers | Record<string, string>,
): L402Challenge | MppChallenge | null {
  const raw = extractWwwAuthenticate(headers);
  if (!raw) return null;

  // Try L402 first (preferred)
  try {
    return parseChallenge(raw);
  } catch {
    // Not L402, try MPP
  }

  // Try MPP fallback
  try {
    return parseMppChallenge(raw);
  } catch {
    // Not MPP either
  }

  return null;
}

/** @deprecated Use findPaymentChallenge instead. */
export const findL402OrMppChallenge = findPaymentChallenge;
