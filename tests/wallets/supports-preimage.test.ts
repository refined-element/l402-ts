/**
 * Tests for the `Wallet.supportsPreimage` parity attribute.
 *
 * L402 cannot complete without a preimage, so callers should be able to
 * check `wallet.supportsPreimage` up front instead of attempting a payment
 * and catching the resulting `PaymentFailedError`. This file is a focused
 * contract test for that attribute across every shipped adapter.
 */

import { describe, it, expect } from "vitest";
import { StrikeWallet } from "../../src/wallets/strike.js";
import { LndWallet } from "../../src/wallets/lnd.js";
import { NwcWallet } from "../../src/wallets/nwc.js";
import { OpenNodeWallet } from "../../src/wallets/opennode.js";

describe("Wallet.supportsPreimage parity", () => {
  it("Strike supports preimage", () => {
    const w = new StrikeWallet("test-key");
    expect(w.supportsPreimage).toBe(true);
  });

  it("LND supports preimage", () => {
    const w = new LndWallet("https://localhost:8080", "aabb");
    expect(w.supportsPreimage).toBe(true);
  });

  it("NWC supports preimage", () => {
    const w = new NwcWallet(
      "nostr+walletconnect://" +
        "0".repeat(64) +
        "?relay=wss://example.com&secret=" +
        "1".repeat(64),
    );
    expect(w.supportsPreimage).toBe(true);
  });

  it("OpenNode does NOT support preimage", () => {
    const w = new OpenNodeWallet("test-key");
    expect(w.supportsPreimage).toBe(false);
  });
});
