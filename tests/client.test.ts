import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { L402Client } from "../src/client.js";
import { BudgetController } from "../src/budget.js";
import {
  BudgetExceededError,
  PaymentFailedError,
  NoWalletError,
  UnsupportedWalletError,
  InvoiceAmountUnknownError,
} from "../src/errors.js";
import type { Wallet } from "../src/types.js";

/** A mock wallet that always returns a fixed preimage (hex string). */
function mockWallet(preimage = "abc123def456"): Wallet {
  return {
    supportsPreimage: true,
    payInvoice: vi.fn().mockResolvedValue(preimage),
  };
}

/** A mock wallet that always fails. */
function failingWallet(message = "payment failed"): Wallet {
  return {
    supportsPreimage: true,
    payInvoice: vi.fn().mockRejectedValue(new Error(message)),
  };
}

/**
 * Build a mock fetch that returns a 402 carrying a verbatim invoice string.
 *
 * Unlike `mockL402Fetch`, the invoice is not assembled from an amount, so
 * tests can hand the client amountless or malformed invoices. Always answers
 * 402 — the client under test is expected to refuse before any retry.
 */
function mockL402FetchRawInvoice(invoice: string) {
  return vi.fn().mockImplementation(async () => {
    return new Response("Payment Required", {
      status: 402,
      headers: {
        "WWW-Authenticate": `L402 macaroon="mac123", invoice="${invoice}"`,
      },
    });
  });
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

    const client = new L402Client({ wallet: mockWallet("aabbccdd") });
    await client.get("https://api.example.com/paid");

    // Check the retry request has the L402 auth header
    const retryCall = fetchMock.mock.calls[1];
    const retryHeaders = new Headers(retryCall[1].headers);
    expect(retryHeaders.get("Authorization")).toBe(
      "L402 mac123:aabbccdd",
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
      wallet: mockWallet("aabb11"),
      budget: new BudgetController({ maxSatsPerRequest: 5000 }),
    });
    await client.get("https://api.example.com/paid");

    expect(client.spendingLog.totalSpent()).toBe(1000);
    expect(client.spendingLog.records).toHaveLength(1);
    expect(client.spendingLog.records[0].preimage).toBe("aabb11");
    // Macaroon from the parsed 402 challenge is exposed for two-step flows
    expect(client.spendingLog.records[0].macaroon).toBe("mac123");
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
    // Challenge macaroon is still recorded on failure
    expect(client.spendingLog.records[0].macaroon).toBe("mac123");
  });

  it("refuses to pay with a wallet that opts out of preimage", async () => {
    // OpenNode-like adapter: explicit supportsPreimage=false. L402Client must
    // fail fast BEFORE calling payInvoice — otherwise the invoice is paid but
    // the L402 retry can't construct the Authorization header. Funds gone.
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const noPreimageWallet: Wallet = {
      supportsPreimage: false,
      payInvoice,
    };

    const fetchMock = mockL402Fetch({}, "10u");
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: noPreimageWallet });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toThrow(UnsupportedWalletError);

    // The wallet's payInvoice must NOT have been called — that's the whole
    // point of failing fast.
    expect(payInvoice).not.toHaveBeenCalled();
  });

  it("uses a wallet that leaves supportsPreimage undefined (back-compat)", async () => {
    // A pre-existing custom wallet from before supportsPreimage existed has
    // no such property. Strict `=== false` semantics in the client mean
    // these wallets continue to work — only an EXPLICIT false blocks them.
    const fetchMock = mockL402Fetch({ data: "ok" });
    globalThis.fetch = fetchMock;

    const legacyWallet: Wallet = {
      payInvoice: vi.fn().mockResolvedValue("abc123"),
      // supportsPreimage intentionally omitted
    };
    const client = new L402Client({ wallet: legacyWallet });
    const response = await client.get("https://api.example.com/paid");

    expect(response.status).toBe(200);
    expect(legacyWallet.payInvoice).toHaveBeenCalledOnce();
  });

  // ── Invoices whose amount can't be determined ──
  //
  // `extractAmountSats` returns null both for invoices that encode no amount
  // and for invoices it can't parse at all. Reading that null as "no limit
  // applies" let a server hand over an amountless invoice and skip
  // `budget.check` entirely — which is not only the sats limits but the domain
  // allowlist too — and the spend never reached the log, so it stayed invisible
  // to every later budget check as well. An amount we cannot determine is an
  // amount we cannot authorise: refuse before spending.

  it("refuses an invoice that encodes no amount instead of paying it", async () => {
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const wallet: Wallet = { supportsPreimage: true, payInvoice };

    // "lnbc1ptest" — well-formed BOLT11 prefix, no amount encoded.
    globalThis.fetch = mockL402FetchRawInvoice("lnbc1ptest");

    const client = new L402Client({
      wallet,
      budget: new BudgetController({ maxSatsPerRequest: 5000 }),
    });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toThrow(InvoiceAmountUnknownError);

    // Refused BEFORE spending, and nothing recorded as spent.
    expect(payInvoice).not.toHaveBeenCalled();
    expect(client.spendingLog.records).toHaveLength(0);
  });

  it("reports why the amount was unknown", async () => {
    globalThis.fetch = mockL402FetchRawInvoice("lnbc1ptest");
    const client = new L402Client({ wallet: mockWallet() });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toMatchObject({
      name: "InvoiceAmountUnknownError",
      reason: "no-amount-encoded",
      bolt11: "lnbc1ptest",
    });
  });

  it("refuses an invoice that cannot be parsed as BOLT11", async () => {
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const wallet: Wallet = { supportsPreimage: true, payInvoice };

    globalThis.fetch = mockL402FetchRawInvoice("not-a-bolt11-invoice");

    const client = new L402Client({ wallet });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toMatchObject({
      name: "InvoiceAmountUnknownError",
      reason: "unparseable",
    });
    expect(payInvoice).not.toHaveBeenCalled();
  });

  it("refuses an amountless invoice from a domain outside the allowlist", async () => {
    // The allowlist is enforced inside budget.check(), so skipping that call
    // for a null amount disabled the allowlist as well — an amountless invoice
    // from ANY domain got paid.
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const wallet: Wallet = { supportsPreimage: true, payInvoice };

    globalThis.fetch = mockL402FetchRawInvoice("lnbc1ptest");

    const client = new L402Client({
      wallet,
      budget: new BudgetController({
        allowedDomains: new Set(["trusted.example.com"]),
      }),
    });

    await expect(
      client.get("https://evil.example.com/paid"),
    ).rejects.toThrow(InvoiceAmountUnknownError);
    expect(payInvoice).not.toHaveBeenCalled();
  });

  it("refuses an amountless invoice even with budgets disabled", async () => {
    // An unknown amount is refused on its own merits: with `budget: null` the
    // client still cannot tell the caller what it is about to spend.
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const wallet: Wallet = { supportsPreimage: true, payInvoice };

    globalThis.fetch = mockL402FetchRawInvoice("lnbc1ptest");

    const client = new L402Client({ wallet, budget: null });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toThrow(InvoiceAmountUnknownError);
    expect(payInvoice).not.toHaveBeenCalled();
  });

  it("refuses an MPP challenge with amount=0 on an amountless invoice (ledger #42)", async () => {
    // An MPP amount=0 resolving onto an amountless invoice is a blank cheque:
    // the wallet, not the server, would pick the spend. This port refuses it
    // because it prices the request purely from the BOLT11 invoice and does NOT
    // read the MPP `amount` param (adding that is deferred ledger #72), so an
    // amountless invoice is unbounded regardless of the MPP amount. That is the
    // safe outcome for #42. This test pins it EXPLICITLY so the refusal can't
    // silently regress to a 0-sat payment if MPP-amount support is ever added.
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const wallet: Wallet = { supportsPreimage: true, payInvoice };

    globalThis.fetch = vi.fn().mockImplementation(async () => {
      return new Response("Payment Required", {
        status: 402,
        headers: {
          "WWW-Authenticate":
            'Payment realm="api.example.com", method="lightning", invoice="lnbc1ptest", amount="0", currency="sat"',
        },
      });
    });

    const client = new L402Client({
      wallet,
      budget: new BudgetController({ maxSatsPerRequest: 5000 }),
    });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toMatchObject({
      name: "InvoiceAmountUnknownError",
      reason: "no-amount-encoded",
      bolt11: "lnbc1ptest",
    });
    // Refused BEFORE spending, and nothing recorded as spent.
    expect(payInvoice).not.toHaveBeenCalled();
    expect(client.spendingLog.records).toHaveLength(0);
  });

  it("refuses a literal-zero BOLT11 invoice instead of paying it (ledger #42)", async () => {
    // "lnbc0p1..." DECODES to 0, not null — the amount field is present, it is
    // just zero — so a bare null-check lets it through, budget.check(0) passes,
    // and the wallet (not the server) picks the spend. The #42 fix only refused
    // the null case; the resolved amount must be strictly positive too.
    const payInvoice = vi.fn().mockResolvedValue("never-called");
    const wallet: Wallet = { supportsPreimage: true, payInvoice };

    globalThis.fetch = mockL402FetchRawInvoice("lnbc0p1ptest");

    // budget: null so the refusal is on the amount's own merits, budget or not.
    const client = new L402Client({ wallet, budget: null });

    await expect(
      client.get("https://api.example.com/paid"),
    ).rejects.toThrow(InvoiceAmountUnknownError);

    // Refused BEFORE spending, and nothing recorded as spent.
    expect(payInvoice).not.toHaveBeenCalled();
    expect(client.spendingLog.records).toHaveLength(0);
  });

  it("still pays a strictly positive BOLT11 amount (no over-rejection)", async () => {
    // Guard against the zero-amount refusal over-rejecting: lnbc10u = 1000 sats.
    const fetchMock = mockL402Fetch({ data: "paid" });
    globalThis.fetch = fetchMock;

    const wallet = mockWallet();
    const client = new L402Client({ wallet });
    const response = await client.get("https://api.example.com/paid");

    expect(response.status).toBe(200);
    expect(wallet.payInvoice).toHaveBeenCalledTimes(1);
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

  it("auto-pays MPP challenge and retries with Payment header", async () => {
    let callCount = 0;
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      const auth = headers.get("Authorization");
      const hasPaymentAuth = auth?.startsWith("Payment ");

      if (!hasPaymentAuth && callCount === 0) {
        callCount++;
        return new Response("Payment Required", {
          status: 402,
          headers: {
            "WWW-Authenticate":
              'Payment realm="api.example.com", method="lightning", invoice="lnbc10u1ptest", amount="1000", currency="sat"',
          },
        });
      }

      return new Response(JSON.stringify({ data: "paid-mpp" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    globalThis.fetch = fetchMock;

    const wallet = mockWallet("deadbeef0123");
    const client = new L402Client({ wallet, budget: null });
    const response = await client.get("https://api.example.com/mpp-resource");

    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual({ data: "paid-mpp" });
    expect(wallet.payInvoice).toHaveBeenCalledOnce();

    // Check the retry request has the Payment auth header (not L402)
    const retryCall = fetchMock.mock.calls[1];
    const retryHeaders = new Headers(retryCall[1].headers);
    expect(retryHeaders.get("Authorization")).toBe(
      'Payment method="lightning", preimage="deadbeef0123"',
    );

    // MPP challenges carry no macaroon — recorded as empty string
    expect(client.spendingLog.records[0].macaroon).toBe("");
  });

  it("prefers L402 over MPP when both available", async () => {
    let callCount = 0;
    const fetchMock = vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
      const headers = new Headers(init?.headers);
      const hasAuth = headers.get("Authorization")?.startsWith("L402 ");

      if (!hasAuth && callCount === 0) {
        callCount++;
        // Even though this looks like MPP-style, parseChallenge should still try L402 first
        return new Response("Payment Required", {
          status: 402,
          headers: {
            "WWW-Authenticate": 'L402 macaroon="mac_l402", invoice="lnbc10u1ptest"',
          },
        });
      }

      return new Response(JSON.stringify({ ok: true }), { status: 200 });
    });
    globalThis.fetch = fetchMock;

    const wallet = mockWallet("ff00aa11");
    const client = new L402Client({ wallet, budget: null });
    await client.get("https://api.example.com/l402-preferred");

    // Should use L402 format, not Payment format
    const retryCall = fetchMock.mock.calls[1];
    const retryHeaders = new Headers(retryCall[1].headers);
    expect(retryHeaders.get("Authorization")).toBe("L402 mac_l402:ff00aa11");
  });

  it("returns 402 as-is when no recognized payment challenge", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response("Payment Required", {
        status: 402,
        headers: { "WWW-Authenticate": "Bearer realm=api" },
      }),
    );
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    const response = await client.get("https://api.example.com/unknown-scheme");

    expect(response.status).toBe(402);
    expect(fetchMock).toHaveBeenCalledTimes(1);
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
