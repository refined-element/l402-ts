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
// 64 lowercase hex characters (x-only, no 0x-prefix, no compressed-point byte).
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
interface NobleSecp256k1 {
  getPublicKey: (privateKey: Uint8Array, compressed?: boolean) => Uint8Array;
  getSharedSecret: (
    privateKey: Uint8Array,
    publicKey: Uint8Array,
  ) => Uint8Array;
  schnorr: {
    sign: (message: Uint8Array, privateKey: Uint8Array) => Uint8Array;
  };
}

export class NwcWallet implements Wallet {
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
   * Install them with: `npm install @noble/secp256k1 ws`
   */
  async payInvoice(bolt11: string): Promise<string> {
    // Lazy-import optional dependencies. The `as string` cast on the module
    // specifier forces a dynamic import (bundlers leave it alone), which
    // means TypeScript can't infer the return type — and we deliberately
    // don't take @noble/secp256k1 as a devDependency (it's an optional peer
    // dep for consumers, shouldn't show up in our own node_modules at
    // build time). So we cast the resolved namespace to a minimal local
    // interface that covers only the functions we actually call. That
    // still catches future regressions where a hex string gets passed
    // into `getSharedSecret`/`schnorr.sign` instead of a Uint8Array
    // (exactly the bug that motivated this version of the code).
    let secp256k1: NobleSecp256k1;
    let WebSocketCtor: any;
    try {
      secp256k1 = (await import(
        /* webpackIgnore: true */ "@noble/secp256k1" as string,
      )) as unknown as NobleSecp256k1;
    } catch {
      throw new Error(
        "NWC wallet requires @noble/secp256k1. Install with: npm install @noble/secp256k1",
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

    // Compute event ID (SHA-256 of serialized event)
    const serialized = JSON.stringify([
      0,
      event["pubkey"],
      event["created_at"],
      event["kind"],
      event["tags"],
      event["content"],
    ]);
    const idBytes = new Uint8Array(
      await globalThis.crypto.subtle.digest(
        "SHA-256",
        new TextEncoder().encode(serialized),
      ),
    );
    const eventId = bytesToHex(idBytes);
    event["id"] = eventId;

    // Sign event with Schnorr
    const sig: Uint8Array = secp256k1.schnorr.sign(hexToBytes(eventId), secretBytes);
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
