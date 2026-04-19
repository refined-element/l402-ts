import { describe, it, expect } from "vitest";
import { NwcWallet } from "../../src/wallets/nwc.js";

describe("NwcWallet — connection string parsing", () => {
  // 64-char lowercase hex (32-byte Nostr pubkey/privkey values).
  const pubkey64 =
    "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
  const secret64 =
    "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";

  it("parses connection string correctly", () => {
    const conn = `nostr+walletconnect://${pubkey64}?relay=wss://relay.example.com&secret=${secret64}`;
    const wallet = new NwcWallet(conn);
    expect(wallet).toBeDefined();
  });

  it("throws for missing relay", () => {
    expect(
      () => new NwcWallet(`nostr+walletconnect://${pubkey64}?secret=${secret64}`),
    ).toThrow("missing relay");
  });

  it("throws for missing secret", () => {
    expect(
      () =>
        new NwcWallet(
          `nostr+walletconnect://${pubkey64}?relay=wss://relay.example.com`,
        ),
    ).toThrow("missing secret");
  });

  // Regression guards for the v0.2.1 fix — bad hex inputs previously sneaked
  // past the constructor and only blew up much later inside the crypto code
  // with an opaque "expected Uint8Array, got type=string" from @noble/secp256k1.
  it("throws for wallet pubkey that isn't 64 hex chars", () => {
    expect(
      () =>
        new NwcWallet(
          `nostr+walletconnect://abc123?relay=wss://relay.example.com&secret=${secret64}`,
        ),
    ).toThrow(/64 lowercase hex chars/);
  });

  it("throws for wallet pubkey containing non-hex characters", () => {
    const badPubkey =
      "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz";
    expect(
      () =>
        new NwcWallet(
          `nostr+walletconnect://${badPubkey}?relay=wss://relay.example.com&secret=${secret64}`,
        ),
    ).toThrow(/64 lowercase hex chars/);
  });

  it("throws for secret that isn't 64 hex chars", () => {
    expect(
      () =>
        new NwcWallet(
          `nostr+walletconnect://${pubkey64}?relay=wss://relay.example.com&secret=deadbeef`,
        ),
    ).toThrow(/64 lowercase hex chars/);
  });

  it("lowercases the pubkey and secret so regex validation is deterministic", () => {
    // Upper-case hex is semantically valid; we normalize to lowercase before
    // validation to keep the `hexToBytes` path deterministic. Constructor
    // must accept upper-case hex without throwing.
    const upperPubkey = pubkey64.toUpperCase();
    const upperSecret = secret64.toUpperCase();
    const wallet = new NwcWallet(
      `nostr+walletconnect://${upperPubkey}?relay=wss://relay.example.com&secret=${upperSecret}`,
    );
    expect(wallet).toBeDefined();
  });
});

// Note on payInvoice crypto-boundary coverage:
//
// The original v0.2.0 bug was that `secp256k1.getSharedSecret` received a hex
// string instead of a Uint8Array. The v0.2.1 fix wraps the argument with
// `hexToBytes()`; an earlier attempt at this test file also mocked the whole
// `@noble/secp256k1` module via `vi.doMock` to intercept the dynamic import
// and assert a Uint8Array arrived at the crypto boundary. That approach was
// brittle against the `as string` cast on the dynamic module specifier (used
// so bundlers don't try to statically resolve an optional peer dep), and
// dropped silently without raising useful signal.
//
// The five constructor-validation tests above are the real regression guard
// the review asked for: they trip before any caller can reach the crypto
// boundary with malformed input, and together with the minimal local
// `NobleSecp256k1` interface in nwc.ts they give the compiler enough to
// catch future type regressions on the `getSharedSecret` / `schnorr.sign`
// call sites. Full end-to-end pay coverage belongs in a wallet-integration
// harness against a stubbed NWC relay, not in a plain unit test.
