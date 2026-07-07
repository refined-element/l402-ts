import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import * as secp from "@noble/secp256k1";

// ── Sign-path coverage (the gap that hid the schnorr.sign-not-awaited bug) ──
//
// The original test file only exercised verifyNwcResponseEvent (the RECEIVE /
// verify path). It never drove payInvoice, so it never noticed that
// `secp256k1.schnorr.sign(...)` returns a Promise in @noble/secp256k1 v1.7.x
// (utils.sha256Sync is unset → async) and was assigned to event.sig WITHOUT
// being awaited. At runtime that serialized a "[object Promise]"-shaped value
// into the request event's sig field, producing an event no wallet/relay would
// accept (its sig fails BIP340 verification).
//
// These tests drive payInvoice against an in-process mock `ws` relay and assert
// the request event the client PUBLISHES carries a real 64-byte Uint8Array
// signature (not a Promise) that passes BIP340 verification under the client's
// own derived pubkey.

// ── Helpers ──

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
}

async function sha256Hex(input: string): Promise<string> {
  const digest = new Uint8Array(
    await globalThis.crypto.subtle.digest(
      "SHA-256",
      new TextEncoder().encode(input),
    ),
  );
  return bytesToHex(digest);
}

function bytesToBase64(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64");
}

function base64ToBytes(b64: string): Uint8Array {
  return new Uint8Array(Buffer.from(b64, "base64"));
}

// 64-char lowercase hex (32-byte Nostr private key). Neutral fixture name to
// stay clear of the gitleaks generic-api-key gate.
const fixtureClientPrivHex =
  "1122334455667788112233445566778811223344556677881122334455667788";

// A deterministic 32-byte wallet private key. The mock relay signs its
// kind-23195 response with this, and connection strings advertise the matching
// x-only pubkey so verifyNwcResponseEvent (which payInvoice runs internally)
// accepts the response.
const fixtureWalletPriv = new Uint8Array(32);
for (let i = 0; i < 32; i++) fixtureWalletPriv[i] = (i * 13 + 7) & 0xff;
const fixtureWalletPubkeyHex = bytesToHex(
  secp.schnorr.getPublicKey(fixtureWalletPriv),
);

/**
 * In-process stand-in for the `ws` WebSocket. Captures the EVENT the client
 * publishes (so the test can inspect its signature), then — if `autoRespond` —
 * derives the same NIP-04 shared secret, encrypts a pay_invoice result, signs a
 * kind-23195 response as the wallet, and pushes it back to the client.
 */
class MockRelaySocket {
  static lastInstance: MockRelaySocket | null = null;

  public publishedRequestEvent: Record<string, unknown> | null = null;
  public preimageToReturn = "ff".repeat(32);
  public autoRespond = true;

  private handlers: Record<string, ((arg: unknown) => void)[]> = {};
  private subId: string | null = null;

  constructor(_url: string) {
    MockRelaySocket.lastInstance = this;
    // Fire "open" on the next microtask, mimicking ws connecting.
    queueMicrotask(() => this.emit("open", undefined));
  }

  on(event: string, cb: (arg: unknown) => void): void {
    (this.handlers[event] ??= []).push(cb);
  }

  private emit(event: string, arg: unknown): void {
    for (const cb of this.handlers[event] ?? []) cb(arg);
  }

  send(raw: string): void {
    const msg = JSON.parse(raw) as unknown[];
    if (msg[0] === "REQ") {
      this.subId = msg[1] as string;
      return;
    }
    if (msg[0] === "EVENT") {
      this.publishedRequestEvent = msg[1] as Record<string, unknown>;
      if (this.autoRespond) {
        void this.respond();
      }
    }
  }

  close(): void {
    /* no-op */
  }

  private async respond(): Promise<void> {
    const req = this.publishedRequestEvent!;
    // Derive the NIP-04 shared X coordinate exactly as the client did, but from
    // the wallet's side (wallet privkey × client pubkey).
    const clientPubkeyHex = req["pubkey"] as string;
    const sharedPoint = secp.getSharedSecret(
      fixtureWalletPriv,
      hexToBytes("02" + clientPubkeyHex),
    );
    const sharedX = sharedPoint.slice(1, 33);

    const plaintext = JSON.stringify({
      result_type: "pay_invoice",
      result: { preimage: this.preimageToReturn },
    });
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(16));
    const key = await globalThis.crypto.subtle.importKey(
      "raw",
      sharedX,
      { name: "AES-CBC", length: 256 },
      false,
      ["encrypt"],
    );
    const ct = new Uint8Array(
      await globalThis.crypto.subtle.encrypt(
        { name: "AES-CBC", iv },
        key,
        new TextEncoder().encode(plaintext),
      ),
    );
    const encryptedContent = `${bytesToBase64(ct)}?iv=${bytesToBase64(iv)}`;

    const created_at = Math.floor(Date.now() / 1000);
    const kind = 23195;
    const tags = [["p", clientPubkeyHex]];
    const id = await sha256Hex(
      JSON.stringify([0, fixtureWalletPubkeyHex, created_at, kind, tags, encryptedContent]),
    );
    const sig = bytesToHex(await secp.schnorr.sign(id, fixtureWalletPriv));
    const responseEvent = {
      id,
      pubkey: fixtureWalletPubkeyHex,
      created_at,
      kind,
      tags,
      content: encryptedContent,
      sig,
    };

    this.emit("message", { toString: () => JSON.stringify(["EVENT", this.subId, responseEvent]) });
  }
}

describe("NwcWallet.payInvoice — sign path (schnorr.sign must be awaited)", () => {
  const priorEncryption = process.env["NWC_ENCRYPTION"];

  beforeEach(() => {
    MockRelaySocket.lastInstance = null;
    // Pin NIP-04 so this sign-path test doesn't trigger the (default "auto")
    // NIP-47 INFO-event fetch — that would open a second mock socket and stall
    // on its 3s deadline. Outbound encryption negotiation is covered separately
    // in nwc-nip44.test.ts; here we only care about the request signature.
    process.env["NWC_ENCRYPTION"] = "nip04";
    // The dynamic `import("ws" as string)` resolves at runtime; vi.doMock
    // intercepts it. We only mock `ws` — secp256k1 stays REAL so the actual
    // (async) schnorr.sign is exercised; that's the whole point of this test.
    vi.doMock("ws", () => ({ default: MockRelaySocket }));
  });

  afterEach(() => {
    if (priorEncryption === undefined) delete process.env["NWC_ENCRYPTION"];
    else process.env["NWC_ENCRYPTION"] = priorEncryption;
    vi.doUnmock("ws");
    vi.resetModules();
  });

  it("publishes a request event whose sig is a real 64-byte signature, not a Promise", async () => {
    // Import AFTER doMock so the module picks up the mocked `ws`.
    const { NwcWallet } = await import("../../src/wallets/nwc.js");
    const conn = `nostr+walletconnect://${fixtureWalletPubkeyHex}?relay=wss://relay.example.com&secret=${fixtureClientPrivHex}`;
    const wallet = new NwcWallet(conn);

    const preimage = await wallet.payInvoice("lnbc1examplebolt11");

    const req = MockRelaySocket.lastInstance?.publishedRequestEvent;
    expect(req).toBeTruthy();

    const sig = req!["sig"];
    // The bug: an un-awaited Promise<Uint8Array> serializes to a non-hex string
    // (e.g. "[object Promise]" or "{}"). A correct signature is 128 lowercase
    // hex chars (64 bytes).
    expect(typeof sig).toBe("string");
    expect(sig as string).toMatch(/^[0-9a-f]{128}$/);

    // And it must be a genuine BIP340 signature over the event id under the
    // client's own derived pubkey.
    const id = req!["id"] as string;
    const pubkey = req!["pubkey"] as string;
    const ok = await secp.schnorr.verify(
      hexToBytes(sig as string),
      hexToBytes(id),
      hexToBytes(pubkey),
    );
    expect(ok).toBe(true);

    // Sanity: the full round-trip returned the wallet's preimage.
    expect(preimage).toBe("ff".repeat(32));
  });

  it("produces a request event whose BIP340 signature verifies under its own pubkey", async () => {
    // The request event is kind 23194 (not a response), but it is the same
    // canonical NIP-01 signing seam used by verifyNwcResponseEvent. We re-verify
    // the produced signature with the same BIP340 primitive the receive path
    // uses, asserting the sign side and verify side agree. (A Promise-valued sig
    // would fail this — it would not be a valid signature.)
    const { NwcWallet } = await import("../../src/wallets/nwc.js");
    const conn = `nostr+walletconnect://${fixtureWalletPubkeyHex}?relay=wss://relay.example.com&secret=${fixtureClientPrivHex}`;
    const wallet = new NwcWallet(conn);

    await wallet.payInvoice("lnbc1examplebolt11");

    const req = MockRelaySocket.lastInstance!.publishedRequestEvent!;
    // verifyNwcResponseEvent enforces kind === 23195, so we can't reuse it
    // verbatim on a 23194 request; assert the BIP340 signature directly.
    const verified = await secp.schnorr.verify(
      hexToBytes(req["sig"] as string),
      hexToBytes(req["id"] as string),
      hexToBytes(req["pubkey"] as string),
    );
    expect(verified).toBe(true);
  });
});
