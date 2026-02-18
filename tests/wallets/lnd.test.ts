import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { LndWallet } from "../../src/wallets/lnd.js";
import { PaymentFailedError } from "../../src/errors.js";

describe("LndWallet", () => {
  const mockFetch = vi.fn();

  beforeEach(() => {
    vi.stubGlobal("fetch", mockFetch);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("pays invoice and extracts preimage from base64", async () => {
    // "deadbeef" in hex = 3q2+7w== in base64
    const preimageHex = "deadbeef";
    const preimageBytes = new Uint8Array([0xde, 0xad, 0xbe, 0xef]);
    const preimageBase64 = btoa(String.fromCharCode(...preimageBytes));

    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          result: {
            status: "SUCCEEDED",
            payment_preimage: preimageBase64,
          },
        }),
        { status: 200 },
      ),
    );

    const wallet = new LndWallet("https://localhost:8080", "macaroon-hex");
    const result = await wallet.payInvoice("lnbc10u1p...");
    expect(result).toBe(preimageHex);
  });

  it("throws on payment failure", async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          result: {
            status: "FAILED",
            failure_reason: "NO_ROUTE",
          },
        }),
        { status: 200 },
      ),
    );

    const wallet = new LndWallet("https://localhost:8080", "mac");
    await expect(wallet.payInvoice("lnbc...")).rejects.toThrow(
      PaymentFailedError,
    );
  });

  it("throws on connection error", async () => {
    mockFetch.mockRejectedValueOnce(new Error("ECONNREFUSED"));

    const wallet = new LndWallet("https://localhost:8080", "mac");
    await expect(wallet.payInvoice("lnbc...")).rejects.toThrow(
      PaymentFailedError,
    );
  });

  it("sends correct headers and payload", async () => {
    mockFetch.mockResolvedValueOnce(
      new Response(
        JSON.stringify({
          result: { status: "SUCCEEDED", payment_preimage: btoa("\x01\x02") },
        }),
        { status: 200 },
      ),
    );

    const wallet = new LndWallet("https://mynode:8080", "abcdef");
    await wallet.payInvoice("lnbc1...");

    expect(mockFetch.mock.calls[0][0]).toBe(
      "https://mynode:8080/v2/router/send",
    );
    const init = mockFetch.mock.calls[0][1];
    expect(init.headers["Grpc-Metadata-macaroon"]).toBe("abcdef");
    const body = JSON.parse(init.body);
    expect(body.payment_request).toBe("lnbc1...");
  });
});
