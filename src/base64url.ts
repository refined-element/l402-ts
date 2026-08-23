/**
 * Base64url helpers for the MPP draft-00 wire format
 * (draft-httpauth-payment-00 / draft-lightning-charge-00).
 *
 * Platform-neutral: uses atob/btoa + TextEncoder/TextDecoder (available in
 * Node 18+ and browsers), no Buffer.
 */

/** Encode a UTF-8 string as base64url without padding. */
export function encodeBase64Url(value: string): string {
  const bytes = new TextEncoder().encode(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Decode a base64url string to UTF-8.
 *
 * Tolerant per draft-00: accepts input with or without padding, and the
 * standard base64 alphabet as well as base64url. Returns null instead of
 * throwing on malformed input.
 */
export function decodeBase64Url(value: string): string | null {
  if (!value) return null;
  const stripped = value.replace(/=+$/g, "");
  if (!/^[A-Za-z0-9_+/-]+$/.test(stripped)) return null;
  const b64 = stripped.replace(/-/g, "+").replace(/_/g, "/");
  const remainder = b64.length % 4;
  if (remainder === 1) return null; // no valid base64 has this length
  const padded = remainder === 0 ? b64 : b64 + "=".repeat(4 - remainder);
  let binary: string;
  try {
    binary = atob(padded);
  } catch {
    return null;
  }
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    return null;
  }
}
