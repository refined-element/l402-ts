/**
 * Parse L402 challenges from HTTP 402 responses.
 */

import { decodeBase64Url, encodeBase64Url } from "./base64url.js";
import {
  ChallengeExpiredError,
  ChallengeParseError,
  L402Error,
} from "./errors.js";
import type {
  L402Challenge,
  MppChallenge,
  MppDraft00Challenge,
} from "./types.js";

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

/** Extract a header value (case-insensitively) from various header formats.
 * Shared by the challenge finders and the Payment-Receipt parser.
 * Internal — not part of the public package API. */
export function extractHeader(
  headers: Headers | Record<string, string>,
  name: string,
): string | null {
  if (headers instanceof Headers) {
    return headers.get(name);
  }

  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === name) {
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
  const wwwAuth = extractHeader(headers, "www-authenticate");
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

// ── MPP draft-00 (draft-httpauth-payment-00 + draft-lightning-charge-00) ──

// auth-param: token "=" ( quoted-string / token ) — RFC 9110 §11.2
const AUTH_PARAM_RE =
  /([A-Za-z0-9!#$%&'*+.^_`|~-]+)[ \t]*=[ \t]*(?:"((?:[^"\\]|\\.)*)"|([^\s",]+))/g;

// Leading scheme token of a challenge string
const SCHEME_TOKEN_RE = /^[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*(?:[ \t]|$)/;

/**
 * Split a WWW-Authenticate header value into individual challenge strings.
 *
 * Challenges and auth-params share the same comma separator (RFC 9110), so a
 * segment starts a new challenge only when its first token is NOT immediately
 * followed by "=" (i.e., it reads as a scheme name, not a param). Commas
 * inside quoted strings are respected — a `description` may contain one.
 */
function splitAuthChallenges(header: string): string[] {
  const segments: string[] = [];
  let current = "";
  let inQuotes = false;
  for (let i = 0; i < header.length; i++) {
    const ch = header[i];
    if (ch === '"' && header[i - 1] !== "\\") {
      inQuotes = !inQuotes;
    }
    if (ch === "," && !inQuotes) {
      segments.push(current);
      current = "";
    } else {
      current += ch;
    }
  }
  segments.push(current);

  const challenges: string[] = [];
  for (const rawSegment of segments) {
    const segment = rawSegment.trim();
    if (!segment) continue;
    const startsChallenge =
      SCHEME_TOKEN_RE.test(segment) && !/^[^=\s]+=/.test(segment);
    if (startsChallenge || challenges.length === 0) {
      challenges.push(segment);
    } else {
      challenges[challenges.length - 1] += ", " + segment;
    }
  }
  return challenges;
}

/** Parse the auth-params of a single challenge string into a map.
 * Names are lowercased; the first occurrence of a name wins; quoted-string
 * backslash escapes are removed. */
function parseAuthParams(challenge: string): Map<string, string> {
  const body = challenge.replace(/^[A-Za-z][A-Za-z0-9!#$%&'*+.^_`|~-]*[ \t]*/, "");
  const params = new Map<string, string>();
  for (const match of body.matchAll(AUTH_PARAM_RE)) {
    const name = match[1].toLowerCase();
    const value =
      match[2] !== undefined ? match[2].replace(/\\(.)/g, "$1") : match[3];
    if (!params.has(name)) {
      params.set(name, value);
    }
  }
  return params;
}

/**
 * Parse a WWW-Authenticate header containing a modern MPP draft-00 Payment
 * challenge (draft-httpauth-payment-00 + draft-lightning-charge-00).
 *
 * A Payment challenge with a non-empty `request` param is the modern profile:
 *
 *   Payment id="<b64url>", realm="<str>", method="lightning",
 *     intent="charge", request="<b64url(JSON)>", expires="<RFC3339>"
 *
 * Unknown params are ignored (RFC 9110 auth-param rules) — a server may send
 * a SUPERSET header that also carries legacy `invoice=`/`amount=`/`currency=`
 * params; those never influence the parsed modern challenge. The decoded
 * `request` payload supplies `invoice`, `amount`, `currency`, `paymentHash`,
 * and `network`; the spec-defined challenge params are preserved exactly as
 * received so `buildMppDraft00Authorization` can echo them byte-for-byte.
 *
 * @throws {ChallengeParseError} If no modern Payment challenge is present or
 *   the challenge is malformed (bad base64url, bad JSON, missing invoice,
 *   unsupported method/intent/currency, invalid expires).
 * @throws {ChallengeExpiredError} If the challenge's `expires` is already in
 *   the past — an expired challenge must never be paid.
 */
export function parseMppDraft00Challenge(header: string): MppDraft00Challenge {
  if (!header?.trim()) {
    throw new ChallengeParseError(header ?? "", "empty header");
  }

  // Find the first Payment challenge carrying a non-empty `request` param —
  // the draft-00 marker distinguishing modern from legacy.
  let params: Map<string, string> | null = null;
  for (const challenge of splitAuthChallenges(header)) {
    if (!/^Payment(?:[ \t]|$)/i.test(challenge)) continue;
    const candidate = parseAuthParams(challenge);
    if (candidate.get("request")) {
      params = candidate;
      break;
    }
  }
  if (!params) {
    throw new ChallengeParseError(
      header,
      'no Payment challenge with a non-empty "request" param found',
    );
  }

  const method = params.get("method");
  if (method?.toLowerCase() !== "lightning") {
    throw new ChallengeParseError(
      header,
      'unsupported payment method (expected "lightning")',
    );
  }
  const intent = params.get("intent");
  if (intent?.toLowerCase() !== "charge") {
    throw new ChallengeParseError(
      header,
      'unsupported payment intent (expected "charge")',
    );
  }

  const expires = params.get("expires");
  if (expires !== undefined) {
    const expiresAtMs = Date.parse(expires);
    if (Number.isNaN(expiresAtMs)) {
      throw new ChallengeParseError(
        header,
        "invalid expires timestamp (expected RFC3339)",
      );
    }
    if (expiresAtMs <= Date.now()) {
      // Refuse up front: the server will not honor a credential built from
      // an expired challenge, so paying would spend sats for no access.
      throw new ChallengeExpiredError(expires);
    }
  }

  const request = params.get("request")!;
  const decodedRequest = decodeBase64Url(request);
  if (decodedRequest === null) {
    throw new ChallengeParseError(
      header,
      "request param is not valid base64url",
    );
  }
  let requestJson: unknown;
  try {
    requestJson = JSON.parse(decodedRequest);
  } catch {
    throw new ChallengeParseError(
      header,
      "request param does not decode to JSON",
    );
  }
  if (
    typeof requestJson !== "object" ||
    requestJson === null ||
    Array.isArray(requestJson)
  ) {
    throw new ChallengeParseError(
      header,
      "request param does not decode to a JSON object",
    );
  }
  const req = requestJson as Record<string, unknown>;

  const currency = typeof req.currency === "string" ? req.currency : undefined;
  if (currency !== undefined && currency.toLowerCase() !== "sat") {
    throw new ChallengeParseError(
      header,
      'unsupported currency (expected "sat")',
    );
  }

  // amount: decimal string of satoshis; tolerate a bare JSON integer.
  let amount: string | undefined;
  if (req.amount !== undefined) {
    if (typeof req.amount === "string" && /^\d+$/.test(req.amount)) {
      amount = req.amount;
    } else if (
      typeof req.amount === "number" &&
      Number.isSafeInteger(req.amount) &&
      req.amount >= 0
    ) {
      amount = String(req.amount);
    } else {
      throw new ChallengeParseError(
        header,
        "invalid amount in request (expected a decimal string of satoshis)",
      );
    }
  }

  const methodDetails =
    typeof req.methodDetails === "object" &&
    req.methodDetails !== null &&
    !Array.isArray(req.methodDetails)
      ? (req.methodDetails as Record<string, unknown>)
      : {};
  const invoice = methodDetails.invoice;
  if (typeof invoice !== "string" || !invoice.trim()) {
    throw new ChallengeParseError(
      header,
      "request is missing methodDetails.invoice",
    );
  }

  return {
    invoice: invoice.trim(),
    amount,
    currency,
    paymentHash:
      typeof methodDetails.paymentHash === "string"
        ? methodDetails.paymentHash
        : undefined,
    network:
      typeof methodDetails.network === "string"
        ? methodDetails.network
        : undefined,
    id: params.get("id"),
    realm: params.get("realm"),
    method,
    intent,
    request,
    expires,
    digest: params.get("digest"),
    description: params.get("description"),
    opaque: params.get("opaque"),
  };
}

/** Strict hex string pattern for preimage validation (header injection guard,
 * mirrors CredentialCache.authorizationHeader). */
const PREIMAGE_HEX_RE = /^[0-9a-fA-F]+$/;

/**
 * Build the Authorization header value for a modern MPP draft-00 credential:
 *
 *   Payment <base64url(JSON, no padding)>
 *
 * The JSON echoes EVERY spec-defined challenge param exactly as received —
 * `request` in particular is the received encoded string, never decoded and
 * re-encoded. Legacy superset extras (`invoice`/`amount`/`currency`) are
 * unknown params and are NOT echoed. The preimage is lowercased before
 * insertion (wallets sometimes return uppercase hex).
 *
 * NOTE: modern credentials are SINGLE-USE server-side — build one per
 * payment and never cache or replay it.
 *
 * @throws {L402Error} If the preimage is not a hex string.
 */
export function buildMppDraft00Authorization(
  challenge: MppDraft00Challenge,
  preimage: string,
): string {
  if (!PREIMAGE_HEX_RE.test(preimage)) {
    throw new L402Error(
      "Invalid preimage: expected hex string, got non-hex characters",
    );
  }

  const echo: Record<string, string> = {};
  if (challenge.id !== undefined) echo.id = challenge.id;
  if (challenge.realm !== undefined) echo.realm = challenge.realm;
  echo.method = challenge.method;
  echo.intent = challenge.intent;
  echo.request = challenge.request;
  if (challenge.expires !== undefined) echo.expires = challenge.expires;
  if (challenge.digest !== undefined) echo.digest = challenge.digest;
  if (challenge.description !== undefined) {
    echo.description = challenge.description;
  }
  if (challenge.opaque !== undefined) echo.opaque = challenge.opaque;

  const credential = {
    challenge: echo,
    payload: { preimage: preimage.toLowerCase() },
  };
  return `Payment ${encodeBase64Url(JSON.stringify(credential))}`;
}

/**
 * Search response headers for an L402 or MPP payment challenge.
 * Prefers L402 when both present; then a modern draft-00 Payment challenge
 * (non-empty `request` param); then the legacy Payment profile.
 *
 * A malformed modern challenge only falls through to the legacy parser when
 * the header also carries a legacy `invoice=` param (the superset case) — a
 * pure-modern header has no `invoice=`, so the legacy parser refuses it
 * rather than silently retrying a challenge we failed to understand. An
 * EXPIRED modern challenge never falls through: the offer is dead on every
 * profile, so the {@link ChallengeExpiredError} surfaces instead.
 *
 * @returns Parsed challenge, or null if no payment challenge found.
 * @throws {ChallengeExpiredError} If a modern challenge has already expired.
 */
export function findPaymentChallenge(
  headers: Headers | Record<string, string>,
): L402Challenge | MppChallenge | MppDraft00Challenge | null {
  const raw = extractHeader(headers, "www-authenticate");
  if (!raw) return null;

  // Try L402 first (preferred)
  try {
    return parseChallenge(raw);
  } catch {
    // Not L402, try Payment
  }

  // Modern draft-00 Payment is preferred over the legacy profile
  try {
    return parseMppDraft00Challenge(raw);
  } catch (e) {
    if (!(e instanceof ChallengeParseError)) throw e;
    // No (valid) modern challenge — try the legacy profile
  }

  // Try legacy MPP fallback
  try {
    return parseMppChallenge(raw);
  } catch {
    // Not MPP either
  }

  return null;
}

/** @deprecated Use findPaymentChallenge instead. */
export const findL402OrMppChallenge = findPaymentChallenge;
