import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { L402Client } from "../src/client.js";
import { BudgetController } from "../src/budget.js";
import {
  BudgetExceededError,
  PaymentFailedError,
  NoWalletError,
} from "../src/errors.js";
import type { Wallet } from "../src/types.js";

/** A mock wallet that always returns a fixed preimage. */
function mockWallet(preimage = "abc123preimage"): Wallet {
  return {
    payInvoice: vi.fn().mockResolvedValue(preimage),
  };
}

/** A mock wallet that always fails. */
function failingWallet(message = "payment failed"): Wallet {
  return {
    payInvoice: vi.fn().mockRejectedValue(new Error(message)),
  };
}

/**
 * Build a mock fetch that returns 402 on first call and 200 on retry.
 * The 402 response includes a valid L402 challenge header.
 */
function mockL402Fetch(
  data: unknown = { result: "ok" },
  invoiceAmount = "10u",
) {
  let callCount = 0;
  return vi.fn().mockImplementation(async (url: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    const hasAuth = headers.get("Authorization")?.startsWith("L402 ");

    if (!hasAuth && callCount === 0) {
      callCount++;
      return new Response("Payment Required", {
        status: 402,
        headers: {
          "WWW-Authenticate": `L402 macaroon="mac123", invoice="lnbc${invoiceAmount}1ptest"`,
        },
      });
    }

    return new Response(JSON.stringify(data), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  });
}

describe("L402Client", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  it("returns response directly for non-402", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ ok: true }), { status: 200 }),
    );
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    const response = await client.get("https://api.example.com/free");

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("auto-pays 402 and retries", async () => {
    const fetchMock = mockL402Fetch({ data: "paid" });
    globalThis.fetch = fetchMock;

    const wallet = mockWallet();
    const client = new L402Client({ wallet });
    const response = await client.get("https://api.example.com/paid");

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ data: "paid" });
    expect(wallet.payInvoice).toHaveBeenCalledOnce();
    // First request + retry
    expect(fetchMock).toHaveBeenCalledTimes(2);
  });

  it("sends L402 authorization on retry", async () => {
    const fetchMock = mockL402Fetch();
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet("preimage_hex") });
    await client.get("https://api.example.com/paid");

    // Check the retry request has the L402 auth header
    const retryCall = fetchMock.mock.calls[1];
    const retryHeaders = new Headers(retryCall[1].headers);
    expect(retryHeaders.get("Authorization")).toBe(
      "L402 mac123:preimage_hex",
    );
  });

  it("prevents payment when budget exceeded", async () => {
    const fetchMock = mockL402Fetch({}, "10u"); // 10u = 1000 sats
    globalThis.fetch = fetchMock;

    const client = new L402Client({
      wallet: mockWallet(),
      budget: new BudgetController({ maxSatsPerRequest: 500 }),
    });

    await expect(
      client.get("https://api.example.com/expensive"),
    ).rejects.toThrow(BudgetExceededError);
  });

  it("records payment in spending log", async () => {
    const fetchMock = mockL402Fetch({}, "10u"); // 1000 sats
    globalThis.fetch = fetchMock;

    const client = new L402Client({
      wallet: mockWallet("pre123"),
      budget: new BudgetController({ maxSatsPerRequest: 5000 }),
    });
    await client.get("https://api.example.com/paid");

    expect(client.spendingLog.totalSpent()).toBe(1000);
    expect(client.spendingLog.records).toHaveLength(1);
    expect(client.spendingLog.records[0].preimage).toBe("pre123");
  });

  it("records failed payment in spending log", async () => {
    const fetchMock = mockL402Fetch({}, "10u");
    globalThis.fetch = fetchMock;

    const client = new L402Client({
      wallet: failingWallet(),
      budget: new BudgetController({ maxSatsPerRequest: 5000 }),
    });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toThrow(PaymentFailedError);

    expect(client.spendingLog.records).toHaveLength(1);
    expect(client.spendingLog.records[0].success).toBe(false);
  });

  it("uses cached credentials on subsequent requests", async () => {
    let callCount = 0;
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      const hasAuth = headers.get("Authorization")?.startsWith("L402 ");

      if (!hasAuth && callCount === 0) {
        callCount++;
        return new Response("Payment Required", {
          status: 402,
          headers: {
            "WWW-Authenticate": 'L402 macaroon="mac1", invoice="lnbc10u1ptest"',
          },
        });
      }

      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    globalThis.fetch = fetchMock;

    const wallet = mockWallet();
    const client = new L402Client({ wallet });

    // First request: triggers 402 + payment + retry
    await client.get("https://api.example.com/api/v1/data");
    // Second request to same path prefix: should use cached credential
    await client.get("https://api.example.com/api/v1/other");

    // Wallet should only be called once (first request)
    expect(wallet.payInvoice).toHaveBeenCalledOnce();
  });

  it("returns 402 as-is when no L402 challenge header", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("Payment Required", { status: 402 }),
    );
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    const response = await client.get("https://api.example.com/non-l402");

    expect(response.status).toBe(402);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("works with POST and body", async () => {
    const fetchMock = mockL402Fetch({ created: true });
    globalThis.fetch = fetchMock;

    const client = new L402Client({
      wallet: mockWallet(),
      budget: new BudgetController({ maxSatsPerRequest: 5000 }),
    });
    const response = await client.post("https://api.example.com/create", {
      body: JSON.stringify({ name: "test" }),
      headers: { "Content-Type": "application/json" },
    });

    expect(response.status).toBe(200);
    // Body should be sent in both requests
    const firstBody = fetchMock.mock.calls[0][1].body;
    const retryBody = fetchMock.mock.calls[1][1].body;
    expect(firstBody).toBe(JSON.stringify({ name: "test" }));
    expect(retryBody).toBe(JSON.stringify({ name: "test" }));
  });

  it("disables budget when null", async () => {
    const fetchMock = mockL402Fetch({}, "500u"); // 50,000 sats
    globalThis.fetch = fetchMock;

    const client = new L402Client({
      wallet: mockWallet(),
      budget: null,
    });

    // Would normally exceed default budget, but budget is disabled
    const response = await client.get("https://api.example.com/expensive");
    expect(response.status).toBe(200);
  });

  it("supports all HTTP methods", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("ok", { status: 200 }),
    );
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });

    await client.get("https://example.com/a");
    await client.post("https://example.com/b");
    await client.put("https://example.com/c");
    await client.delete("https://example.com/d");
    await client.patch("https://example.com/e");
    await client.head("https://example.com/f");

    expect(fetchMock).toHaveBeenCalledTimes(6);
    expect(fetchMock.mock.calls[0][1].method).toBe("GET");
    expect(fetchMock.mock.calls[1][1].method).toBe("POST");
    expect(fetchMock.mock.calls[2][1].method).toBe("PUT");
    expect(fetchMock.mock.calls[3][1].method).toBe("DELETE");
    expect(fetchMock.mock.calls[4][1].method).toBe("PATCH");
    expect(fetchMock.mock.calls[5][1].method).toBe("HEAD");
  });
});
