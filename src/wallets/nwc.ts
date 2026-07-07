/**
 * NWC (Nostr Wallet Connect) wallet adapter.
 *
 * Requires optional peer dependencies: @noble/secp256k1, ws
 *
 * Connection string format: nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>
 *
 * Outbound encryption (NIP-47):
 *   - Default is `auto` — the wallet's NIP-47 INFO event (kind 13194) is fetched
 *     once on the first payInvoice (short deadline), its `encryption` tag is read,
 *     and the strongest advertised scheme (nip44_v2 > nip04) is used and cached.
 *     Falls back to nip04 when no INFO event is available (the original NIP-47
 *     default that spec-pre-13194 wallets expect).
 *   - Override via the `NWC_ENCRYPTION` env var: `auto` | `nip04` | `nip44_v2`.
 *     Some wallets (e.g. Alby Hub) require nip44_v2; others (Primal/CoinOS) only
 *     speak nip04. A mismatch silently drops the request — the wallet never
 *     replies — so a wrong scheme surfaces as a timeout, not an error.
 *   - Inbound is auto-detected per-message (`?iv=` => NIP-04, else NIP-44 v2), so
 *     the response scheme is independent of the request scheme.
 *
 * Mirrors the proven MCP NWC client
 * (lightning-enable-mcp/.../nwc_wallet.py) so the two ports stay wire-compatible.
 */

import {
  createCipheriv,
  createDecipheriv,
  createHmac,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import type { Wallet } from "../types.js";
import { PaymentFailedError } from "../errors.js";

/* eslint-disable @typescript-eslint/no-explicit-any */

// Nostr pubkeys and secrets are both 32-byte (256-bit) values serialized as
// 64 hex characters (x-only, no 0x-prefix, no compressed-point byte).
// Uppercase input is normalized to lowercase at ingest before validation/storage.
// See NIP-01. Validating at construction time beats the silent coercion
// inside `hexToBytes()` (it would parseInt non-hex digits as NaN and bake
// zeros into the Uint8Array, producing a wrong shared secret with a confusing
// downstream failure well away from the bad input).
const HEX_32_BYTES = /^[0-9a-f]{64}$/;

// ── Outbound NIP-47 encryption schemes ──
//
// Mirrors the Python/.NET ports so the user-facing contract (env var values,
// tag values, timeout hint) stays aligned across languages.
export const NWC_ENCRYPTION_NIP04 = "nip04";
export const NWC_ENCRYPTION_NIP44_V2 = "nip44_v2";
export const NWC_ENCRYPTION_AUTO = "auto";
export const NWC_ENCRYPTION_DEFAULT = NWC_ENCRYPTION_AUTO;

const VALID_NWC_ENCRYPTIONS = new Set<string>([
  NWC_ENCRYPTION_NIP04,
  NWC_ENCRYPTION_NIP44_V2,
  NWC_ENCRYPTION_AUTO,
]);

// How long to wait for the NIP-47 INFO event before falling back to NIP-04.
// Kept short so a missing/stale relay never delays a real request by more than
// a few seconds.
export const NWC_AUTO_RESOLVE_TIMEOUT_MS = 3_000;

/**
 * Pick the strongest scheme from a NIP-47 INFO event's `encryption` tag value.
 *
 * The spec defines the tag value as a space-separated list of supported schemes
 * (e.g. `"nip04 nip44_v2"`). Prefers `nip44_v2` when listed (more secure);
 * otherwise `nip04`; falls back to `nip04` when the tag is empty/missing/unknown
 * so spec-pre-13194 wallets still work. Pulled out as a pure function so it can
 * be unit-tested without a relay.
 */
export function pickEncryptionFromInfoTag(
  encryptionTagValue: string | null | undefined,
): string {
  if (!encryptionTagValue) return NWC_ENCRYPTION_NIP04;

  const schemes = new Set(
    encryptionTagValue
      .replace(/,/g, " ")
      .replace(/\t/g, " ")
      .split(" ")
      .map((s) => s.trim().toLowerCase())
      .filter(Boolean),
  );

  if (schemes.has(NWC_ENCRYPTION_NIP44_V2)) return NWC_ENCRYPTION_NIP44_V2;
  return NWC_ENCRYPTION_NIP04;
}

// Minimal type surface of @noble/secp256k1 that we call. Declaring this
// locally rather than pulling the package in as a devDep keeps install-time
// surface identical for consumers (it's an optional peer dep at runtime
// only) while still giving TypeScript enough to catch regressions where a
// hex string gets passed where a Uint8Array is required.
export interface NobleSecp256k1 {
  getPublicKey: (privateKey: Uint8Array, compressed?: boolean) => Uint8Array;
  getSharedSecret: (
    privateKey: Uint8Array,
    publicKey: Uint8Array,
  ) => Uint8Array;
  schnorr: {
    // BIP340 sign. @noble/secp256k1 v1 returns a Promise<Uint8Array> whenever
    // `utils.sha256Sync` is unset (the default), so this is async in practice;
    // we always await it (a sync return is handled transparently too). Typing it
    // as the sync-or-async union — and awaiting at the call site — closes the bug
    // where an un-awaited Promise was serialized into the event's `sig` field,
    // producing an invalid event the wallet/relay rejects.
    sign: (
      message: Uint8Array,
      privateKey: Uint8Array,
    ) => Uint8Array | Promise<Uint8Array>;
    // BIP340 verify. @noble/secp256k1 v1 returns a Promise<boolean>; we always
    // await it so a sync return is handled transparently too. We pass every
    // argument as a Uint8Array (never a hex string) to dodge the same
    // hex-vs-Uint8Array coercion pitfall that broke getSharedSecret (commit
    // 2c1de9b) — see verifyNwcResponseEvent.
    verify: (
      signature: Uint8Array,
      message: Uint8Array,
      publicKey: Uint8Array,
    ) => boolean | Promise<boolean>;
  };
}

/**
 * Computes a Nostr (NIP-01) event id: the lowercase hex SHA-256 of the
 * canonical serialization `[0, pubkey, created_at, kind, tags, content]`.
 * Single source of truth shared by the signing path (request events) and the
 * verification path (response/INFO events) so the two can never drift.
 */
async function computeNostrEventId(
  pubkey: string,
  createdAt: number,
  kind: number,
  tags: unknown,
  content: string,
): Promise<string> {
  const serialized = JSON.stringify([0, pubkey, createdAt, kind, tags, content]);
  const idBytes = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(serialized),
    ),
  );
  return bytesToHex(idBytes);
}

const HEX_64 = /^[0-9a-f]{64}$/;
const HEX_128 = /^[0-9a-f]{128}$/;

/**
 * Core BIP340 signature check for a Nostr event, WITHOUT any kind or
 * expected-pubkey constraint. Returns true only when the event is
 * structurally well-formed, its recomputed NIP-01 id matches `event.id`, and
 * `event.sig` is a valid BIP340 Schnorr signature over that id under
 * `event.pubkey`. Any malformed input or crypto exception returns false
 * (fail closed). Shared by the kind-23195 response gate and the kind-13194
 * INFO-event auto-detect gate.
 */
async function verifyEventSignature(
  event: Record<string, unknown>,
  secp256k1: NobleSecp256k1,
): Promise<boolean> {
  try {
    const idHex =
      typeof event["id"] === "string" ? (event["id"] as string).toLowerCase() : "";
    const pubkeyHex =
      typeof event["pubkey"] === "string" ? (event["pubkey"] as string).toLowerCase() : "";
    const sigHex =
      typeof event["sig"] === "string" ? (event["sig"] as string).toLowerCase() : "";
    const createdAt = event["created_at"];
    const kind = event["kind"];
    const tags = event["tags"];
    const content = event["content"];

    if (
      !HEX_64.test(idHex) ||
      !HEX_64.test(pubkeyHex) ||
      !HEX_128.test(sigHex) ||
      typeof createdAt !== "number" ||
      typeof kind !== "number" ||
      !Array.isArray(tags) ||
      typeof content !== "string"
    ) {
      return false;
    }

    const recomputedId = await computeNostrEventId(
      pubkeyHex,
      createdAt,
      kind,
      tags,
      content,
    );
    if (recomputedId !== idHex) return false;

    const verified = await secp256k1.schnorr.verify(
      hexToBytes(sigHex),
      hexToBytes(idHex),
      hexToBytes(pubkeyHex),
    );
    return verified === true;
  } catch {
    return false;
  }
}

/**
 * Verifies that a kind-23195 NIP-47 response event genuinely came from the
 * expected wallet before its (encrypted) content is decrypted and trusted.
 *
 * F-11 — mirrors the MCP server fix shipped in v1.12.8
 * (NwcWalletService.IsResponseEventTrustworthy /
 * nwc_wallet._verify_nostr_event_signature). A relay only proves it relayed an
 * event; it never proves the event is authentic. Without this gate a malicious
 * or compromised relay (or a MITM) can forge a `pay_invoice`/`get_balance`
 * response that matches our subscription filter and feed us a bogus preimage or
 * balance. The NIP-04/NIP-44 encryption already authenticates the sender
 * implicitly, but verifying the BIP340 signature + claimed pubkey is
 * defence-in-depth: it rejects forged/garbage events up front and stays correct
 * against any future NIP-47 extension that decouples sender identity from the
 * encryption key.
 *
 * Returns true only when ALL of the following hold:
 *   1. `event.pubkey` equals `expectedWalletPubkey` (case-insensitive).
 *   2. `event.kind` is exactly 23195 (NIP-47 response). Even a validly-signed
 *      event from the wallet at the wrong kind must not be treated as a response.
 *   3. The recomputed NIP-01 id matches `event.id` (catches tampered
 *      tags/content/etc).
 *   4. The `sig` is a valid BIP340 Schnorr signature over the id bytes under
 *      `event.pubkey`.
 * Any malformed input (missing/short fields, non-hex) returns false — fail
 * closed.
 *
 * Encoding care (see commit 2c1de9b): the event id is a 32-byte value and the
 * BIP340 "message" is those raw id bytes, NOT a re-hash. We feed schnorr.verify
 * Uint8Arrays for sig, message, and pubkey — converting from hex via
 * `hexToBytes` — rather than hex strings, so noble can't silently mis-coerce a
 * string argument.
 */
export async function verifyNwcResponseEvent(
  event: Record<string, unknown>,
  expectedWalletPubkey: string,
  secp256k1: NobleSecp256k1,
): Promise<boolean> {
  const pubkeyHex =
    typeof event["pubkey"] === "string" ? (event["pubkey"] as string).toLowerCase() : "";

  // 1. Claimed pubkey must be the wallet we're talking to.
  if (pubkeyHex !== expectedWalletPubkey.toLowerCase()) return false;

  // 2. This verifier is the gate for NIP-47 *responses* specifically, which
  //    are kind 23195. Rejecting any other kind makes the response contract
  //    explicit: even a validly-signed event from the wallet at the wrong kind
  //    (e.g. a stray 23194 request echo) must not be treated as a
  //    pay_invoice/get_balance response.
  if (event["kind"] !== 23195) return false;

  // 3 + 4. Canonical id recomputation + BIP340 signature verification.
  return verifyEventSignature(event, secp256k1);
}

// ── NIP-04 crypto (ECDH shared-X + AES-256-CBC) ──

/**
 * Compute the ECDH shared x-coordinate between our secret and a wallet pubkey.
 *
 * Uses the even-Y (0x02-prefixed) convention on the x-only Nostr pubkey — the
 * same convention as NIP-04, NIP-44, the Python `_compute_shared_x`, and the
 * historical l402-ts NIP-04 path proven against CoinOS. `getSharedSecret`
 * returns the 65-byte uncompressed point (0x04 || X || Y); we take the raw X.
 *
 * @noble/secp256k1 v2+ requires Uint8Array, not hex strings — passing
 * `"02" + walletPubkey` directly blew up with `expected Uint8Array, got
 * type=string`. Always pass Uint8Arrays.
 */
export function computeSharedX(
  secretBytes: Uint8Array,
  walletPubkeyHex: string,
  secp256k1: NobleSecp256k1,
): Uint8Array {
  const sharedPoint = secp256k1.getSharedSecret(
    secretBytes,
    hexToBytes("02" + walletPubkeyHex.toLowerCase()),
  );
  return sharedPoint.slice(1, 33);
}

/**
 * NIP-04 encrypt: AES-256-CBC with the raw 32-byte shared-X as key. Returns
 * `base64(ciphertext)?iv=base64(iv)`. The `iv` is injectable for
 * known-answer tests; production uses a fresh random 16-byte IV.
 */
export async function encryptNip04(
  plaintext: string,
  sharedX: Uint8Array,
  iv: Uint8Array = globalThis.crypto.getRandomValues(new Uint8Array(16)),
): Promise<string> {
  // Copy inputs into fresh ArrayBuffer-backed views — WebCrypto's BufferSource
  // type (strict under @types/node) rejects a possibly-SharedArrayBuffer-backed
  // Uint8Array parameter.
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    new Uint8Array(sharedX),
    { name: "AES-CBC", length: 256 },
    false,
    ["encrypt"],
  );
  const encrypted = new Uint8Array(
    await globalThis.crypto.subtle.encrypt(
      { name: "AES-CBC", iv: new Uint8Array(iv) },
      key,
      new Uint8Array(new TextEncoder().encode(plaintext)),
    ),
  );
  return `${bytesToBase64(encrypted)}?iv=${bytesToBase64(new Uint8Array(iv))}`;
}

/**
 * NIP-04 decrypt: parse `base64(ciphertext)?iv=base64(iv)` and AES-256-CBC
 * decrypt with the raw 32-byte shared-X. Symmetric with `encryptNip04`.
 */
export async function decryptNip04(
  content: string,
  sharedX: Uint8Array,
): Promise<string> {
  const parts = content.split("?iv=");
  if (parts.length !== 2) {
    throw new Error("Invalid NIP-04 encrypted content (missing ?iv= separator)");
  }
  const ct = base64ToBytes(parts[0]);
  const iv = base64ToBytes(parts[1]);
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    new Uint8Array(sharedX),
    { name: "AES-CBC", length: 256 },
    false,
    ["decrypt"],
  );
  const decrypted = await globalThis.crypto.subtle.decrypt(
    { name: "AES-CBC", iv: new Uint8Array(iv) },
    key,
    new Uint8Array(ct),
  );
  return new TextDecoder().decode(decrypted);
}

// ── NIP-44 v2 crypto (ChaCha20 + HKDF-SHA256 + HMAC-SHA256) ──

/**
 * conversation_key = HKDF-extract(salt="nip44-v2", ikm=shared_x)
 * (HKDF-extract is HMAC-SHA256 with the salt as key over the ikm).
 */
export function deriveConversationKey(sharedX: Uint8Array): Buffer {
  return createHmac("sha256", Buffer.from("nip44-v2"))
    .update(Buffer.from(sharedX))
    .digest();
}

/** HKDF-Expand (RFC 5869) with SHA-256. */
function hkdfExpand(prk: Buffer, info: Uint8Array, length: number): Buffer {
  const hashLen = 32;
  const n = Math.ceil(length / hashLen);
  let okm = Buffer.alloc(0);
  let t = Buffer.alloc(0);
  for (let i = 1; i <= n; i++) {
    t = createHmac("sha256", prk)
      .update(Buffer.concat([t, Buffer.from(info), Buffer.from([i])]))
      .digest();
    okm = Buffer.concat([okm, t]);
  }
  return okm.subarray(0, length);
}

/** NIP-44 v2 padding scheme: pad to a power-of-two-ish bucket, min 32 bytes. */
export function calcPaddedLen(unpaddedLen: number): number {
  if (unpaddedLen <= 0) throw new Error("Plaintext length must be > 0");
  if (unpaddedLen <= 32) return 32;
  // (unpaddedLen - 1).bit_length()
  const bitLength = (unpaddedLen - 1).toString(2).length;
  const nextPower = 1 << bitLength;
  const chunk = Math.max(32, nextPower >> 3);
  return chunk * Math.ceil(unpaddedLen / chunk);
}

/**
 * NIP-44 v2 encrypt. Returns a base64 payload:
 *   base64( version(0x02) || nonce[32] || ciphertext || mac[32] )
 * The 32-byte `nonce` is injectable for known-answer tests; production uses a
 * fresh random nonce. ChaCha20 is the raw stream cipher (NOT AEAD): the 16-byte
 * OpenSSL IV is `\x00\x00\x00\x00` (LE counter) || chacha_nonce[12].
 */
export function encryptNip44(
  plaintext: string,
  sharedX: Uint8Array,
  nonce: Uint8Array = randomBytes(32),
): string {
  const plaintextBytes = Buffer.from(plaintext, "utf-8");
  if (plaintextBytes.length < 1 || plaintextBytes.length > 65535) {
    throw new Error(
      `Plaintext length ${plaintextBytes.length} out of range (1-65535)`,
    );
  }

  const conversationKey = deriveConversationKey(sharedX);
  const messageKeys = hkdfExpand(conversationKey, nonce, 76);
  const chachaKey = messageKeys.subarray(0, 32);
  const chachaNonce = messageKeys.subarray(32, 44);
  const hmacKey = messageKeys.subarray(44, 76);

  // Pad: 2-byte big-endian length + plaintext + zero padding.
  const paddedLen = calcPaddedLen(plaintextBytes.length);
  const padded = Buffer.alloc(2 + paddedLen);
  padded.writeUInt16BE(plaintextBytes.length, 0);
  plaintextBytes.copy(padded, 2);

  const chacha20Nonce = Buffer.concat([Buffer.alloc(4), Buffer.from(chachaNonce)]);
  const cipher = createCipheriv("chacha20", chachaKey, chacha20Nonce);
  const ciphertext = Buffer.concat([cipher.update(padded), cipher.final()]);

  const mac = createHmac("sha256", hmacKey)
    .update(Buffer.concat([Buffer.from(nonce), ciphertext]))
    .digest();

  const payload = Buffer.concat([
    Buffer.from([0x02]),
    Buffer.from(nonce),
    ciphertext,
    mac,
  ]);
  return payload.toString("base64");
}

/**
 * NIP-44 v2 decrypt. Verifies the version byte (0x02) and HMAC before
 * decrypting. Throws on version mismatch or MAC failure (fail closed).
 */
export function decryptNip44(payloadB64: string, sharedX: Uint8Array): string {
  const payload = Buffer.from(payloadB64, "base64");
  if (payload.length < 1 + 32 + 32) {
    throw new Error("NIP-44 payload too short");
  }

  const version = payload[0];
  if (version !== 0x02) {
    throw new Error(
      `Unsupported NIP-44 version: 0x${version.toString(16).padStart(2, "0")}, expected 0x02`,
    );
  }

  const nonce = payload.subarray(1, 33);
  const ciphertext = payload.subarray(33, payload.length - 32);
  const mac = payload.subarray(payload.length - 32);

  const conversationKey = deriveConversationKey(sharedX);
  const messageKeys = hkdfExpand(conversationKey, nonce, 76);
  const chachaKey = messageKeys.subarray(0, 32);
  const chachaNonce = messageKeys.subarray(32, 44);
  const hmacKey = messageKeys.subarray(44, 76);

  const expectedMac = createHmac("sha256", hmacKey)
    .update(Buffer.concat([nonce, ciphertext]))
    .digest();
  if (mac.length !== expectedMac.length || !timingSafeEqual(mac, expectedMac)) {
    throw new Error("NIP-44 HMAC verification failed");
  }

  const chacha20Nonce = Buffer.concat([Buffer.alloc(4), Buffer.from(chachaNonce)]);
  const decipher = createDecipheriv("chacha20", chachaKey, chacha20Nonce);
  const decrypted = Buffer.concat([
    decipher.update(ciphertext),
    decipher.final(),
  ]);

  const plaintextLen = decrypted.readUInt16BE(0);
  return decrypted.subarray(2, 2 + plaintextLen).toString("utf-8");
}

/**
 * Inbound decrypt with per-message scheme auto-detect. A NIP-04 payload carries
 * the `?iv=` separator; a NIP-44 v2 payload is bare base64. This is independent
 * of the outbound scheme — a wallet may reply in either.
 */
async function decryptContent(
  content: string,
  sharedX: Uint8Array,
): Promise<string> {
  if (content.includes("?iv=")) {
    return decryptNip04(content, sharedX);
  }
  return decryptNip44(content, sharedX);
}

export class NwcWallet implements Wallet {
  readonly supportsPreimage = true;

  private _walletPubkey: string;
  private _relay: string;
  private _secret: string;
  private _timeout: number;
  /** Configured outbound encryption: "auto" | "nip04" | "nip44_v2". */
  private _encryption: string;
  /** Cached auto-detect result (null until first resolved). */
  private _resolvedAutoEncryption: string | null = null;
  /** In-flight auto-detect promise so concurrent first-calls share one fetch. */
  private _autoResolvePromise: Promise<string> | null = null;

  constructor(connectionString: string, timeout: number = 60_000) {
    const url = new URL(connectionString);
    this._walletPubkey = (
      url.hostname || url.pathname.replace(/^\/\//, "")
    ).toLowerCase();
    this._relay = url.searchParams.get("relay") ?? "";
    this._secret = (url.searchParams.get("secret") ?? "").toLowerCase();
    this._timeout = timeout;

    // Outbound encryption override via NWC_ENCRYPTION (auto | nip04 | nip44_v2).
    // Default auto. Invalid values fall back to the default with a warning so a
    // typo doesn't silently disable a previously-working wallet.
    this._encryption = NWC_ENCRYPTION_DEFAULT;
    const override = process.env["NWC_ENCRYPTION"];
    if (override) {
      const normalized = override.trim().toLowerCase();
      if (VALID_NWC_ENCRYPTIONS.has(normalized)) {
        this._encryption = normalized;
      } else {
        const allowed = [...VALID_NWC_ENCRYPTIONS].sort().join(", ");
        // eslint-disable-next-line no-console
        console.warn(
          `Ignoring invalid NWC_ENCRYPTION="${override}" (allowed: ${allowed}). ` +
            `Falling back to default "${NWC_ENCRYPTION_DEFAULT}".`,
        );
      }
    }

    if (!this._walletPubkey) {
      throw new Error("NWC connection string missing wallet pubkey");
    }
    if (!HEX_32_BYTES.test(this._walletPubkey)) {
      throw new Error(
        "NWC wallet pubkey must be 64 hex chars (uppercase is normalized to lowercase at ingest) (32-byte x-only Nostr pubkey)",
      );
    }
    if (!this._relay) {
      throw new Error("NWC connection string missing relay URL");
    }
    if (!this._secret) {
      throw new Error("NWC connection string missing secret");
    }
    if (!HEX_32_BYTES.test(this._secret)) {
      throw new Error(
        "NWC secret must be 64 hex chars (uppercase is normalized to lowercase at ingest) (32-byte Nostr private key)",
      );
    }
  }

  /**
   * Pay via NWC protocol (NIP-47 pay_invoice).
   *
   * This requires the optional peer dependencies `@noble/secp256k1` and `ws`.
   * Install them with: `npm install "@noble/secp256k1@^1.7.1" ws`
   *
   * NOTE: pin @noble/secp256k1 to v1.x. The schnorr/getSharedSecret API this
   * client uses only matches the v1.x line — v2.0.0 removed `schnorr` from the
   * main export, and v3.x reintroduced it with an incompatible API (the NWC
   * tests fail against both). A bare `npm install @noble/secp256k1` now pulls
   * v3 and breaks NWC, hence the explicit `^1.7.1`.
   */
  async payInvoice(bolt11: string): Promise<string> {
    // Lazy-import optional dependencies. The `as string` cast on the module
    // specifier forces a dynamic import (bundlers leave it alone), which
    // means TypeScript can't infer the return type, so we cast the resolved
    // namespace to a minimal local interface (`NobleSecp256k1`) covering only
    // the functions we actually call.
    let secp256k1: NobleSecp256k1;
    let WebSocketCtor: any;
    try {
      secp256k1 = (await import(
        /* webpackIgnore: true */ "@noble/secp256k1" as string,
      )) as unknown as NobleSecp256k1;
    } catch {
      throw new Error(
        'NWC wallet requires @noble/secp256k1 (v1.x). Install with: npm install "@noble/secp256k1@^1.7.1"',
      );
    }
    try {
      const wsModule = await import(/* webpackIgnore: true */ "ws" as string);
      WebSocketCtor = wsModule.default ?? wsModule;
    } catch {
      throw new Error("NWC wallet requires ws. Install with: npm install ws");
    }

    // Derive keypair from secret.
    const secretBytes = hexToBytes(this._secret);
    const pubkeyBytes: Uint8Array = secp256k1.getPublicKey(secretBytes, true);
    const pubkeyHex = bytesToHex(pubkeyBytes).slice(2); // drop 02/03 prefix for nostr x-only

    // Resolve outbound encryption. When "auto" (default), fetch the wallet's
    // NIP-47 INFO event once (cached). Explicit schemes skip the fetch.
    const effectiveEncryption =
      this._encryption === NWC_ENCRYPTION_AUTO
        ? await this._resolveAutoEncryption(secp256k1, WebSocketCtor)
        : this._encryption;

    // Build + encrypt the NIP-47 pay_invoice request. Shared-X is the single
    // source of truth for the ECDH — reused for outbound encrypt and inbound
    // decrypt so the two can't drift.
    const sharedX = computeSharedX(secretBytes, this._walletPubkey, secp256k1);
    const content = JSON.stringify({
      method: "pay_invoice",
      params: { invoice: bolt11 },
    });

    let encryptedContent: string;
    let tags: string[][];
    if (effectiveEncryption === NWC_ENCRYPTION_NIP44_V2) {
      encryptedContent = encryptNip44(content, sharedX);
      // The "encryption" tag signals nip44_v2 to the wallet.
      tags = [
        ["p", this._walletPubkey],
        ["encryption", "nip44_v2"],
      ];
    } else {
      encryptedContent = await encryptNip04(content, sharedX);
      // No "encryption" tag for NIP-04 — the original NIP-47 default.
      tags = [["p", this._walletPubkey]];
    }

    // Build unsigned event (kind 23194 = NWC request).
    const createdAt = Math.floor(Date.now() / 1000);
    const event: Record<string, unknown> = {
      kind: 23194,
      created_at: createdAt,
      tags,
      content: encryptedContent,
      pubkey: pubkeyHex,
    };

    // Compute event id (SHA-256 of serialized event). Shares the exact
    // serialization with verifyEventSignature so request and response id
    // derivations can't drift.
    const eventId = await computeNostrEventId(
      pubkeyHex,
      createdAt,
      23194,
      event["tags"],
      encryptedContent,
    );
    event["id"] = eventId;

    // Sign with Schnorr. schnorr.sign is async in @noble/secp256k1 v1
    // (utils.sha256Sync unset) — it MUST be awaited. The un-awaited Promise
    // previously serialized into `event.sig` as garbage, yielding an event the
    // wallet/relay rejects. Normalize to a fresh Uint8Array so bytesToHex sees
    // real bytes regardless of subtype.
    const sig = new Uint8Array(
      await secp256k1.schnorr.sign(hexToBytes(eventId), secretBytes),
    );
    event["sig"] = bytesToHex(sig);

    // Connect to relay and send.
    return new Promise<string>((resolve, reject) => {
      const ws = new WebSocketCtor(this._relay);
      const subId = bytesToHex(
        globalThis.crypto.getRandomValues(new Uint8Array(8)),
      );
      const timer = setTimeout(() => {
        ws.close();
        // Name the most likely cause: an outbound encryption mismatch. A wallet
        // that doesn't speak the scheme we used silently drops the request, so
        // the symptom is a timeout, not an error. Point at the other scheme.
        const alt =
          effectiveEncryption === NWC_ENCRYPTION_NIP44_V2
            ? NWC_ENCRYPTION_NIP04
            : NWC_ENCRYPTION_NIP44_V2;
        reject(
          new PaymentFailedError(
            `NWC wallet did not respond within ${Math.round(this._timeout / 1000)}s ` +
              `using ${effectiveEncryption} encryption. Most common cause: encryption ` +
              `mismatch — try setting NWC_ENCRYPTION=${alt} if your wallet ` +
              `(e.g. Alby Hub needs nip44_v2; Primal/CoinOS need nip04) requires the ` +
              `other scheme.`,
            bolt11,
          ),
        );
      }, this._timeout);

      ws.on("open", () => {
        // Subscribe with an `#e` request-id filter so we only receive the
        // response to THIS request (plus `#p` = our pubkey), not unrelated
        // NIP-47 traffic on the relay.
        ws.send(
          JSON.stringify([
            "REQ",
            subId,
            {
              kinds: [23195],
              "#e": [eventId],
              "#p": [pubkeyHex],
              since: createdAt - 1,
            },
          ]),
        );
        ws.send(JSON.stringify(["EVENT", event]));
      });

      ws.on("message", async (data: any) => {
        try {
          const msg = JSON.parse(data.toString()) as unknown[];
          if (!Array.isArray(msg) || msg.length < 3) return;
          if (msg[0] !== "EVENT" || msg[1] !== subId) return;

          const responseEvent = msg[2] as Record<string, unknown>;

          // F-11: verify the response event is authentically from our wallet
          // BEFORE decrypting/acting on its content. A relay only proves it
          // relayed an event — it never proves authenticity. Drop unverified
          // events and keep waiting for the real one (a forged event must not
          // abort a still-pending legitimate payment).
          const trusted = await verifyNwcResponseEvent(
            responseEvent,
            this._walletPubkey,
            secp256k1,
          );
          if (!trusted) return;

          // Decrypt response with per-message scheme auto-detect (`?iv=` =>
          // NIP-04, else NIP-44 v2). Independent of the request scheme.
          const decrypted = await decryptContent(
            responseEvent["content"] as string,
            sharedX,
          );
          const result = JSON.parse(decrypted) as Record<string, unknown>;

          clearTimeout(timer);
          ws.close();

          if (result["error"]) {
            const err = result["error"] as Record<string, unknown>;
            reject(
              new PaymentFailedError(
                `NWC error ${err["code"] ?? "unknown"}: ${err["message"] ?? "unknown error"}`,
                bolt11,
              ),
            );
            return;
          }

          const preimage = (result["result"] as Record<string, unknown>)?.[
            "preimage"
          ] as string | undefined;
          if (!preimage) {
            reject(
              new PaymentFailedError(
                "NWC payment succeeded but no preimage returned",
                bolt11,
              ),
            );
            return;
          }

          resolve(preimage);
        } catch {
          // Ignore parse errors, wait for next message.
        }
      });

      ws.on("error", (err: Error) => {
        clearTimeout(timer);
        reject(
          new PaymentFailedError(`NWC WebSocket error: ${err.message}`, bolt11),
        );
      });
    });
  }

  /**
   * Resolve outbound encryption when configured as "auto". Fetches the wallet's
   * NIP-47 INFO event (kind 13194) once on the first request, picks the
   * strongest advertised scheme, and caches it for this instance's lifetime.
   * Concurrent first-calls share a single in-flight fetch. Any failure falls
   * back to NIP-04.
   */
  private async _resolveAutoEncryption(
    secp256k1: NobleSecp256k1,
    WebSocketCtor: any,
  ): Promise<string> {
    if (this._resolvedAutoEncryption !== null) {
      return this._resolvedAutoEncryption;
    }
    if (this._autoResolvePromise === null) {
      this._autoResolvePromise = this._fetchEncryptionFromInfoEvent(
        secp256k1,
        WebSocketCtor,
      )
        .then((resolved) => {
          this._resolvedAutoEncryption = resolved;
          return resolved;
        })
        .catch(() => {
          this._resolvedAutoEncryption = NWC_ENCRYPTION_NIP04;
          return NWC_ENCRYPTION_NIP04;
        })
        .finally(() => {
          this._autoResolvePromise = null;
        });
    }
    return this._autoResolvePromise;
  }

  /**
   * One-shot WebSocket REQ for the wallet's kind-13194 (NIP-47 INFO) event.
   * Always resolves to a scheme — timeouts, malformed/unsigned events, and
   * missing INFO all translate to the NIP-04 fallback so a flaky relay or older
   * wallet never makes every future request fail. Verifies the INFO event's
   * pubkey + BIP340 signature so a malicious relay can't forge one to force an
   * encryption downgrade.
   */
  private _fetchEncryptionFromInfoEvent(
    secp256k1: NobleSecp256k1,
    WebSocketCtor: any,
  ): Promise<string> {
    return new Promise<string>((resolve) => {
      let settled = false;
      const finish = (scheme: string) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        try {
          ws.close();
        } catch {
          /* ignore */
        }
        resolve(scheme);
      };

      const ws = new WebSocketCtor(this._relay);
      const subId = bytesToHex(
        globalThis.crypto.getRandomValues(new Uint8Array(8)),
      );
      const timer = setTimeout(
        () => finish(NWC_ENCRYPTION_NIP04),
        NWC_AUTO_RESOLVE_TIMEOUT_MS,
      );

      ws.on("open", () => {
        ws.send(
          JSON.stringify([
            "REQ",
            subId,
            {
              kinds: [13194],
              authors: [this._walletPubkey],
              limit: 1,
            },
          ]),
        );
      });

      ws.on("message", async (data: any) => {
        try {
          const msg = JSON.parse(data.toString()) as unknown[];
          if (!Array.isArray(msg) || msg.length < 2) return;
          const type = msg[0];
          if (type === "EOSE") {
            // End of stored events with no INFO — fall back.
            if (msg[1] === subId) finish(NWC_ENCRYPTION_NIP04);
            return;
          }
          if (type !== "EVENT" || msg.length < 3 || msg[1] !== subId) return;

          const event = msg[2] as Record<string, unknown>;
          if (event["kind"] !== 13194) return;

          // Defence in depth: the INFO event must be published by, and signed
          // by, the wallet pubkey we're talking to.
          const evPubkey =
            typeof event["pubkey"] === "string"
              ? (event["pubkey"] as string).toLowerCase()
              : "";
          if (evPubkey !== this._walletPubkey.toLowerCase()) return;
          if (!(await verifyEventSignature(event, secp256k1))) return;

          let encTagValue: string | null = null;
          const tags = event["tags"];
          if (Array.isArray(tags)) {
            for (const tag of tags) {
              if (
                Array.isArray(tag) &&
                tag.length >= 2 &&
                tag[0] === "encryption"
              ) {
                encTagValue = tag[1] as string;
                break;
              }
            }
          }
          finish(pickEncryptionFromInfoTag(encTagValue));
        } catch {
          // Ignore parse errors; the deadline will fall back to NIP-04.
        }
      });

      ws.on("error", () => finish(NWC_ENCRYPTION_NIP04));
    });
  }
}

// ── Helpers ──

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}
