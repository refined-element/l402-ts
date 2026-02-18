/**
 * Parse L402 challenges from HTTP 402 responses.
 */

import { ChallengeParseError } from "./errors.js";
import type { L402Challenge } from "./types.js";

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

/**
 * Search response headers for an L402 challenge.
 *
 * @returns Parsed challenge, or null if no L402 challenge found.
 */
export function findL402Challenge(
  headers: Headers | Record<string, string>,
): L402Challenge | null {
  let wwwAuth: string | null | undefined;

  if (headers instanceof Headers) {
    wwwAuth = headers.get("www-authenticate");
  } else {
    // Normalize header names to lowercase for case-insensitive lookup
    const lower: Record<string, string> = {};
    for (const [k, v] of Object.entries(headers)) {
      lower[k.toLowerCase()] = v;
    }
    wwwAuth = lower["www-authenticate"];
  }

  if (!wwwAuth) return null;

  try {
    return parseChallenge(wwwAuth);
  } catch {
    return null;
  }
}
