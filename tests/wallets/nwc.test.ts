import { describe, it, expect } from "vitest";
import { NwcWallet } from "../../src/wallets/nwc.js";

describe("NwcWallet", () => {
  it("parses connection string correctly", () => {
    const conn =
      "nostr+walletconnect://abc123?relay=wss://relay.example.com&secret=deadbeef";
    // Should not throw
    const wallet = new NwcWallet(conn);
    expect(wallet).toBeDefined();
  });

  it("throws for missing relay", () => {
    expect(
      () => new NwcWallet("nostr+walletconnect://abc123?secret=deadbeef"),
    ).toThrow("missing relay");
  });

  it("throws for missing secret", () => {
    expect(
      () =>
        new NwcWallet(
          "nostr+walletconnect://abc123?relay=wss://relay.example.com",
        ),
    ).toThrow("missing secret");
  });
});
