import { describe, it, expect } from "vitest";
import { extractAmountSats } from "../src/bolt11.js";

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
