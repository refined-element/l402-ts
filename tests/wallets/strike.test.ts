import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { StrikeWallet } from "../../src/wallets/strike.js";
import { PaymentFailedError } from "../../src/errors.js";

describe("StrikeWallet", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("pays invoice via quote + execute flow", async () => {
    // Mock quote response
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ paymentQuoteId: "quote-123" }),
        { status: 200 },
      ),
    );
    // Mock execute response
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          lightning: { preImage: "abc123preimage" },
        }),
        { status: 200 },
      ),
    );

    const wallet = new StrikeWallet("test-key");
    const preimage = await wallet.payInvoice("lnbc10u1p...");

    expect(preimage).toBe("abc123preimage");
    expect(mockFetch).toHaveBeenCalledTimes(2);

    // Verify quote request
    const quoteCall = mockFetch.mock.calls[0];
    expect(quoteCall[0]).toContain("/v1/payment-quotes/lightning");
    const quoteBody = JSON.parse(quoteCall[1].body);
    expect(quoteBody.sourceCurrency).toBe("BTC");
  });

  it("throws PaymentFailedError on quote failure", async () => {
    mockFetch.mockResolvedValueOnce(
      new Response("Unauthorized", { status: 401 }),
    );

    const wallet = new StrikeWallet("bad-key");
    await expect(wallet.payInvoice("lnbc10u1p...")).rejects.toThrow(
      PaymentFailedError,
    );
  });

  it("throws when preimage is missing", async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ paymentQuoteId: "quote-123" }),
        { status: 200 },
      ),
    );
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({}), { status: 200 }),
    );
    // Mock the payment details fetch (also returns no preimage)
    mockFetch.mockResolvedValueOnce(
      new Response(JSON.stringify({}), { status: 200 }),
    );

    const wallet = new StrikeWallet("test-key");
    await expect(wallet.payInvoice("lnbc10u1p...")).rejects.toThrow(
      PaymentFailedError,
    );
  });

  it("supports custom base URL", async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ paymentQuoteId: "q1" }),
        { status: 200 },
      ),
    );
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ lightning: { preImage: "pre123" } }),
        { status: 200 },
      ),
    );

    const wallet = new StrikeWallet("key", "https://custom.strike.api/");
    await wallet.payInvoice("lnbc1...");

    expect(mockFetch.mock.calls[0][0]).toContain("custom.strike.api");
  });

  it("uses BTC as source currency", async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ paymentQuoteId: "q1" }),
        { status: 200 },
      ),
    );
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({ lightning: { preImage: "pre" } }),
        { status: 200 },
      ),
    );

    const wallet = new StrikeWallet("key");
    await wallet.payInvoice("lnbc1...");

    const body = JSON.parse(mockFetch.mock.calls[0][1].body);
    expect(body.sourceCurrency).toBe("BTC");
  });
});
