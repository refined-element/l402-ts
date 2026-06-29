/**
 * NWC (Nostr Wallet Connect) wallet adapter.
 *
 * Requires optional peer dependencies: @noble/secp256k1, ws
 *
 * Connection string format: nostr+walletconnect://<pubkey>?relay=<relay>&secret=<secret>
 */

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
 * verification path (response events) so the two can never drift.
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
 * Verifies that a kind-23195 NIP-47 response event genuinely came from the
 * expected wallet before its (encrypted) content is decrypted and trusted.
 *
 * F-11 — mirrors the MCP server fix shipped in v1.12.8
 * (NwcWalletService.IsResponseEventTrustworthy /
 * nwc_wallet._verify_nostr_event_signature). A relay only proves it relayed an
 * event; it never proves the event is authentic. Without this gate a malicious
 * or compromised relay (or a MITM) can forge a `pay_invoice`/`get_balance`
 * response that matches our subscription filter and feed us a bogus preimage or
 * balance. The NIP-04 ECDH encryption already authenticates the sender
 * implicitly, but verifying the BIP340 signature + claimed pubkey is
 * defence-in-depth: it rejects forged/garbage events up front and stays correct
 * against any future NIP-47 extension that decouples sender identity from the
 * encryption key.
 *
 * Returns true only when ALL of the following hold:
 *   1. `event.pubkey` equals `expectedWalletPubkey` (case-insensitive).
 *   2. The recomputed NIP-01 id matches `event.id` (catches tampered
 *      tags/content/etc).
 *   3. The `sig` is a valid BIP340 Schnorr signature over the id bytes under
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
  try {
    const idHex = typeof event["id"] === "string" ? (event["id"] as string).toLowerCase() : "";
    const pubkeyHex =
      typeof event["pubkey"] === "string" ? (event["pubkey"] as string).toLowerCase() : "";
    const sigHex = typeof event["sig"] === "string" ? (event["sig"] as string).toLowerCase() : "";
    const createdAt = event["created_at"];
    const kind = event["kind"];
    const tags = event["tags"];
    const content = event["content"];

    // 1. Claimed pubkey must be the wallet we're talking to.
    if (pubkeyHex !== expectedWalletPubkey.toLowerCase()) return false;

    // Structural validation before any crypto.
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

    // 1b. This verifier is the gate for NIP-47 *responses* specifically, which
    //     are kind 23195. Rejecting any other kind makes the response contract
    //     explicit: even a validly-signed event from the wallet at the wrong
    //     kind (e.g. a stray 23194 request echo) must not be treated as a
    //     pay_invoice/get_balance response.
    if (kind !== 23195) return false;

    // 2. Recompute the id from the canonical serialization — any tampered
    //    field (including the content the relay might rewrite to inject a bogus
    //    preimage) produces a different id and fails here.
    const recomputedId = await computeNostrEventId(
      pubkeyHex,
      createdAt,
      kind,
      tags,
      content,
    );
    if (recomputedId !== idHex) return false;

    // 3. BIP340 schnorr verify over the raw 32-byte id bytes. All-Uint8Array
    //    arguments (no hex strings) to avoid the 2c1de9b coercion pitfall.
    const verified = await secp256k1.schnorr.verify(
      hexToBytes(sigHex),
      hexToBytes(idHex),
      hexToBytes(pubkeyHex),
    );
    return verified === true;
  } catch {
    // Fail closed: any parse/crypto exception → untrusted.
    return false;
  }
}

export class NwcWallet implements Wallet {
  readonly supportsPreimage = true;

  private _walletPubkey: string;
  private _relay: string;
  private _secret: string;
  private _timeout: number;

  constructor(connectionString: string, timeout: number = 30_000) {
    const url = new URL(connectionString);
    this._walletPubkey = (
      url.hostname || url.pathname.replace(/^\/\//, "")
    ).toLowerCase();
    this._relay = url.searchParams.get("relay") ?? "";
    this._secret = (url.searchParams.get("secret") ?? "").toLowerCase();
    this._timeout = timeout;

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
    // the functions we actually call. For consumers @noble/secp256k1 is an
    // optional peer dependency (not bundled); it's also a devDependency here so
    // the test suite can construct and verify real signatures. The minimal
    // interface still catches regressions where a hex string gets passed into
    // `getSharedSecret`/`schnorr.sign` instead of a Uint8Array (the bug that
    // motivated this version of the code).
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
      throw new Error(
        "NWC wallet requires ws. Install with: npm install ws",
      );
    }

    // Derive keypair from secret
    const secretBytes = hexToBytes(this._secret);
    const pubkeyBytes: Uint8Array = secp256k1.getPublicKey(secretBytes, true);
    const pubkeyHex = bytesToHex(pubkeyBytes).slice(2); // remove 02/03 prefix for nostr

    // Build NIP-47 pay_invoice request
    const content = JSON.stringify({
      method: "pay_invoice",
      params: { invoice: bolt11 },
    });

    // NIP-04 encryption (shared secret + AES-256-CBC).
    // @noble/secp256k1 v2+ requires Uint8Array, not hex strings — passing
    // `"02" + this._walletPubkey` directly here blew up with
    // `expected Uint8Array, got type=string`, breaking NWC for Coinos/CLINK/Alby.
    // Strike and LND paths are unaffected (different wallet implementations).
    const sharedPoint: Uint8Array = secp256k1.getSharedSecret(
      secretBytes,
      hexToBytes("02" + this._walletPubkey),
    );
    const sharedX = sharedPoint.slice(1, 33);

    const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      sharedX,
      { name: "AES-CBC", length: 256 },
      false,
      ["encrypt"],
    );
    const encrypted = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        key,
        new TextEncoder().encode(content),
      ),
    );
    const encryptedContent = `${bytesToBase64(encrypted)}?iv=${bytesToBase64(iv)}`;

    // Build unsigned event (kind 23194 = NWC request)
    const createdAt = Math.floor(Date.now() / 1000);
    const event: Record<string, unknown> = {
      kind: 23194,
      created_at: createdAt,
      tags: [["p", this._walletPubkey]],
      content: encryptedContent,
      pubkey: pubkeyHex,
    };

    // Compute event ID (SHA-256 of serialized event). Shares the exact
    // serialization with verifyNwcResponseEvent so the request and response
    // id derivations can't drift.
    const eventId = await computeNostrEventId(
      pubkeyHex,
      createdAt,
      23194,
      event["tags"],
      encryptedContent,
    );
    event["id"] = eventId;

    // Sign event with Schnorr. schnorr.sign is async in @noble/secp256k1 v1
    // (utils.sha256Sync unset) — it MUST be awaited. The un-awaited Promise
    // previously serialized into `event.sig` as garbage, yielding an event the
    // wallet/relay rejected (the bug nwc-sign.test.ts now guards). Normalize to
    // a fresh Uint8Array so bytesToHex sees real bytes regardless of subtype.
    const sig = new Uint8Array(
      await secp256k1.schnorr.sign(hexToBytes(eventId), secretBytes),
    );
    event["sig"] = bytesToHex(sig);

    // Connect to relay and send
    return new Promise<string>((resolve, reject) => {
      const ws = new WebSocketCtor(this._relay);
      const subId = bytesToHex(globalThis.crypto.getRandomValues(new Uint8Array(8)));
      const timer = setTimeout(() => {
        ws.close();
        reject(new PaymentFailedError("NWC payment timed out", bolt11));
      }, this._timeout);

      ws.on("open", () => {
        ws.send(
          JSON.stringify([
            "REQ",
            subId,
            {
              kinds: [23195],
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
          // relayed an event — it never proves authenticity. Without this a
          // malicious/compromised relay or MITM could forge a pay_invoice
          // response (matching our subscription filter) and feed us a bogus
          // preimage. Drop unverified events and keep waiting for the real one.
          const trusted = await verifyNwcResponseEvent(
            responseEvent,
            this._walletPubkey,
            secp256k1,
          );
          if (!trusted) {
            // Stay subscribed: a forged event must not abort a still-pending
            // legitimate payment. Just ignore this message.
            return;
          }

          // Decrypt response
          const parts = (responseEvent["content"] as string).split("?iv=");
          const ct = base64ToBytes(parts[0]);
          const respIv = base64ToBytes(parts[1]);

          const decryptKey = await globalThis.crypto.subtle.importKey(
            "raw",
            sharedX,
            { name: "AES-CBC", length: 256 },
            false,
            ["decrypt"],
          );
          const decrypted = new TextDecoder().decode(
            await globalThis.crypto.subtle.decrypt(
              { name: "AES-CBC", iv: new Uint8Array(respIv) },
              decryptKey,
              new Uint8Array(ct),
            ),
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

          const preimage = (result["result"] as Record<string, unknown>)?.["preimage"] as
            | string
            | undefined;
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
          // Ignore parse errors, wait for next message
        }
      });

      ws.on("error", (err: Error) => {
        clearTimeout(timer);
        reject(new PaymentFailedError(`NWC WebSocket error: ${err.message}`, bolt11));
      });
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
