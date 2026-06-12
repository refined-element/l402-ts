import { describe, it, expect } from "vitest";
import * as secp from "@noble/secp256k1";

// F-11 (mirrors the MCP server fix shipped in v1.12.8): NWC kind-23195
// (NIP-47 response) events must be signature-verified before their decrypted
// content is trusted. A malicious/compromised relay or MITM can otherwise
// forge a pay_invoice/get_balance response (a valid filter match) and feed a
// bogus preimage/balance to the client.
//
// `verifyNwcResponseEvent(event, expectedWalletPubkey, secp256k1)` is the pure,
// relay-free gate: it recomputes the NIP-01 event id, verifies the BIP340
// Schnorr signature over that id under the claimed pubkey, AND requires
// event.pubkey === expectedWalletPubkey. These tests exercise it directly.
import { verifyNwcResponseEvent } from "../../src/wallets/nwc.js";

// ── Helpers ──

function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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

interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

/**
 * Build a genuinely BIP340-signed kind-23195 event from `secretBytes`, exactly
 * the way a real NWC wallet would: compute the NIP-01 id over
 * [0, pubkey, created_at, kind, tags, content], then schnorr-sign the id bytes.
 */
async function buildSignedResponseEvent(
  secretBytes: Uint8Array,
  overrides: Partial<Pick<NostrEvent, "content" | "kind" | "created_at" | "tags">> = {},
): Promise<NostrEvent> {
  const pubkeyHex = bytesToHex(secp.schnorr.getPublicKey(secretBytes));
  const created_at = overrides.created_at ?? 1_700_000_000;
  const kind = overrides.kind ?? 23195;
  const tags = overrides.tags ?? [["p", "00".repeat(32)], ["e", "ab".repeat(32)]];
  const content = overrides.content ?? "ciphertext-placeholder?iv=aaaa";

  const serialized = JSON.stringify([0, pubkeyHex, created_at, kind, tags, content]);
  const id = await sha256Hex(serialized);
  const sig = bytesToHex(await secp.schnorr.sign(id, secretBytes));

  return { id, pubkey: pubkeyHex, created_at, kind, tags, content, sig };
}

describe("verifyNwcResponseEvent — F-11 response signature verification", () => {
  // Neutral fixture names (no "secret-" literals — gitleaks generic-api-key gate).
  const fixtureWalletSecret = new Uint8Array(32);
  for (let i = 0; i < 32; i++) fixtureWalletSecret[i] = (i * 7 + 3) & 0xff;

  const attackerSecret = new Uint8Array(32);
  for (let i = 0; i < 32; i++) attackerSecret[i] = (i * 11 + 5) & 0xff;

  it("ACCEPTS a correctly-signed event from the expected wallet pubkey", async () => {
    const walletPubkey = bytesToHex(secp.schnorr.getPublicKey(fixtureWalletSecret));
    const event = await buildSignedResponseEvent(fixtureWalletSecret);

    await expect(
      verifyNwcResponseEvent(event, walletPubkey, secp),
    ).resolves.toBe(true);
  });

  it("REJECTS a forged event whose pubkey is NOT the expected wallet pubkey", async () => {
    // The attacker signs a perfectly valid event with their own key. The
    // signature verifies against the attacker's pubkey, but the pubkey is not
    // the wallet we're talking to — must be rejected. Without the pubkey check,
    // this forged pay_invoice/get_balance response would be trusted.
    const walletPubkey = bytesToHex(secp.schnorr.getPublicKey(fixtureWalletSecret));
    const forged = await buildSignedResponseEvent(attackerSecret);

    expect(forged.pubkey).not.toBe(walletPubkey);
    await expect(
      verifyNwcResponseEvent(forged, walletPubkey, secp),
    ).resolves.toBe(false);
  });

  it("REJECTS an event whose content was tampered after signing (sig no longer matches recomputed id)", async () => {
    const walletPubkey = bytesToHex(secp.schnorr.getPublicKey(fixtureWalletSecret));
    const event = await buildSignedResponseEvent(fixtureWalletSecret);
    // Relay rewrites the (encrypted) content to inject a bogus preimage. The id
    // and sig still reference the original content, so id-recomputation +
    // signature verification must fail.
    const tampered = { ...event, content: "tampered-ciphertext?iv=bbbb" };

    await expect(
      verifyNwcResponseEvent(tampered, walletPubkey, secp),
    ).resolves.toBe(false);
  });

  it("REJECTS an event with a structurally-invalid signature", async () => {
    const walletPubkey = bytesToHex(secp.schnorr.getPublicKey(fixtureWalletSecret));
    const event = await buildSignedResponseEvent(fixtureWalletSecret);
    const badSig = { ...event, sig: "00".repeat(64) };

    await expect(
      verifyNwcResponseEvent(badSig, walletPubkey, secp),
    ).resolves.toBe(false);
  });

  it("REJECTS an event whose claimed id does not match the canonical serialization", async () => {
    // id swapped to an unrelated 32-byte hex — even though pubkey matches and a
    // (now-mismatched) sig is present, recomputation catches the swap.
    const walletPubkey = bytesToHex(secp.schnorr.getPublicKey(fixtureWalletSecret));
    const event = await buildSignedResponseEvent(fixtureWalletSecret);
    const swappedId = { ...event, id: "cd".repeat(32) };

    await expect(
      verifyNwcResponseEvent(swappedId, walletPubkey, secp),
    ).resolves.toBe(false);
  });

  it("REJECTS a validly-signed event from the expected wallet whose kind is NOT 23195", async () => {
    // The wallet signs a perfectly authentic event (correct pubkey, correct id,
    // valid BIP340 sig) but at the wrong kind — e.g. an echoed 23194 request or
    // any other NIP-47 kind. The NIP-47-response contract is kind 23195 only, so
    // verification must fail purely on the kind mismatch even though the
    // signature is genuine.
    const walletPubkey = bytesToHex(secp.schnorr.getPublicKey(fixtureWalletSecret));
    const wrongKind = await buildSignedResponseEvent(fixtureWalletSecret, {
      kind: 23194,
    });

    expect(wrongKind.kind).toBe(23194);
    await expect(
      verifyNwcResponseEvent(wrongKind, walletPubkey, secp),
    ).resolves.toBe(false);
  });

  it("matches the expected pubkey case-insensitively", async () => {
    const walletPubkeyUpper = bytesToHex(
      secp.schnorr.getPublicKey(fixtureWalletSecret),
    ).toUpperCase();
    const event = await buildSignedResponseEvent(fixtureWalletSecret);

    await expect(
      verifyNwcResponseEvent(event, walletPubkeyUpper, secp),
    ).resolves.toBe(true);
  });
});
