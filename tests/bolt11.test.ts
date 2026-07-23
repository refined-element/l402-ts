import { describe, it, expect } from "vitest";
import { classifyMissingAmount, extractAmountSats } from "../src/bolt11.js";

describe("extractAmountSats", () => {
  it("parses micro-BTC (u) amounts", () => {
    // lnbc10u → 10 * 0.000001 BTC = 0.00001 BTC = 1000 sats
    expect(extractAmountSats("lnbc10u1pxxxxxx")).toBe(1000);
  });

  it("parses milli-BTC (m) amounts", () => {
    // lnbc1m → 1 * 0.001 BTC = 100000 sats
    expect(extractAmountSats("lnbc1m1pxxxxxx")).toBe(100000);
  });

  it("parses nano-BTC (n) amounts", () => {
    // lnbc1000n → 1000 * 0.000000001 BTC = 0.000001 BTC = 100 sats (0.1 sat → rounds)
    expect(extractAmountSats("lnbc1000n1pxxxxxx")).toBe(100);
  });

  it("parses pico-BTC (p) amounts", () => {
    // lnbc1000000p → 1000000 * 1e-12 BTC = 1e-6 BTC = 100 sats (0.1 sat → truncates)
    expect(extractAmountSats("lnbc1000000p1pxxxxxx")).toBe(100);
  });

  it("parses 1 sat correctly", () => {
    // lnbc10n → 10 * 0.000000001 BTC = 0.00000001 BTC = 1 sat
    expect(extractAmountSats("lnbc10n1pxxxxxx")).toBe(1);
  });

  it("parses 500 sats", () => {
    // lnbc5u → 5 * 0.000001 BTC = 0.000005 BTC = 500 sats
    expect(extractAmountSats("lnbc5u1pxxxxxx")).toBe(500);
  });

  it("parses whole BTC amounts", () => {
    // lnbc1 → 1 BTC = 100000000 sats
    expect(extractAmountSats("lnbc11pxxxxxx")).toBe(100000000);
  });

  it("returns null for no-amount invoices", () => {
    // lnbc1pxxxxxx — no amount digits before "1" separator
    expect(extractAmountSats("lnbc1pxxxxxx")).toBeNull();
  });

  it("returns null for empty string", () => {
    expect(extractAmountSats("")).toBeNull();
  });

  it("returns null for invalid input", () => {
    expect(extractAmountSats("not-a-bolt11")).toBeNull();
  });

  it("handles testnet invoices (lntb)", () => {
    // lntb10u → 1000 sats
    expect(extractAmountSats("lntb10u1pxxxxxx")).toBe(1000);
  });

  it("is case-insensitive", () => {
    expect(extractAmountSats("LNBC10U1PXXXXXX")).toBe(1000);
  });

  it("parses 2500 sats (25u)", () => {
    // lnbc25u → 25 * 0.000001 BTC = 2500 sats
    expect(extractAmountSats("lnbc25u1pxxxxxx")).toBe(2500);
  });
});

describe("HRP anchoring (ledger #74)", () => {
  // The amount must be read ONLY from the human-readable part — everything
  // before the LAST "1" separator. The bech32 data charset excludes "1", so the
  // final "1" is always the true separator. A decoder that stops at an EARLIER
  // "1" can lift a small bogus amount out of a crafted stray segment, report a
  // positive number the invoice does not actually encode, and sail through a
  // budget check (which the <= 0 guard cannot catch — it is positive).

  it("does not read an amount before a later separator", () => {
    // First "1" sits right after "9u", so an un-anchored decoder reports
    // 9u = 900 sats. The real separator is the LAST "1", making the true HRP
    // "lnbc9u1qpzq" — not a valid amount HRP — so the amount is unknown.
    expect(
      extractAmountSats("lnbc9u1qpzq1qpzry9x8gf2tvdw0s3jn54khce6mua7l"),
    ).toBeNull();
  });

  it("does not read an amount from inside the data part", () => {
    // Reference examples from le-agent-sdk-python's hardened decoder.
    expect(extractAmountSats("lnbc1pabc9u1def")).toBeNull();
    expect(extractAmountSats("lnbc1pvjl5p1uez")).toBeNull();
  });

  it("classifies a crafted data-part invoice as unparseable, not priced", () => {
    const crafted = "lnbc9u1qpzq1qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    expect(extractAmountSats(crafted)).toBeNull();
    expect(classifyMissingAmount(crafted)).toBe("unparseable");
  });

  it("still decodes legitimate single-separator invoices", () => {
    // HRP anchoring must not over-reject, including amounts whose digits hold "1".
    expect(extractAmountSats("lnbc10u1pdata")).toBe(1000);
    expect(extractAmountSats("lnbc1500n1pdata")).toBe(150);
    expect(extractAmountSats("lnbc1m1pdata")).toBe(100000);
  });
});

describe("classifyMissingAmount", () => {
  // extractAmountSats returns null for two very different reasons. Callers
  // refuse either way, but the distinction tells a user whether the server
  // sent an amountless invoice or something that isn't a BOLT11 at all.

  it("reports a well-formed invoice with no amount", () => {
    expect(classifyMissingAmount("lnbc1pxxxxxx")).toBe("no-amount-encoded");
  });

  it("reports a string that isn't BOLT11 at all", () => {
    expect(classifyMissingAmount("not-a-bolt11")).toBe("unparseable");
  });

  it("reports an empty string as unparseable", () => {
    expect(classifyMissingAmount("")).toBe("unparseable");
  });

  it("is case-insensitive", () => {
    expect(classifyMissingAmount("LNBC1PXXXXXX")).toBe("no-amount-encoded");
  });
});
