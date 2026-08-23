import { describe, it, expect, vi, afterEach } from "vitest";
import {
  parseMppDraft00Challenge,
  buildMppDraft00Authorization,
  findPaymentChallenge,
} from "../src/challenge.js";
import { parsePaymentReceipt } from "../src/receipt.js";
import { L402Client } from "../src/client.js";
import {
  ChallengeExpiredError,
  ChallengeParseError,
  L402Error,
} from "../src/errors.js";
import type { MppDraft00Challenge, Wallet } from "../src/types.js";

// ── Fixtures ──
// Deterministic fake values only — no real invoices, preimages, or credentials.
const FIXTURE_PREIMAGE = "a".repeat(64);
const FIXTURE_PAYMENT_HASH = "b".repeat(64);
const FUTURE_EXPIRES = "2099-01-01T00:00:00Z";
const PAST_EXPIRES = "2020-01-01T00:00:00Z";

function b64url(value: string): string {
  return Buffer.from(value, "utf-8").toString("base64url");
}

function decodeB64url(value: string): string {
  return Buffer.from(value, "base64url").toString("utf-8");
}

/** The decoded draft-00 `request` payload (draft-lightning-charge-00). */
function requestPayload(overrides: Record<string, unknown> = {}) {
  return {
    amount: "1000",
    currency: "sat",
    methodDetails: {
      invoice: "lnbc10u1ptest", // 10u = 1000 sats
      paymentHash: FIXTURE_PAYMENT_HASH,
      network: "mainnet",
    },
    ...overrides,
  };
}

/** Encoded `request` param for a valid modern challenge (b64url, no padding). */
function encodedRequest(overrides: Record<string, unknown> = {}): string {
  return b64url(JSON.stringify(requestPayload(overrides)));
}

/** Build a modern draft-00 Payment WWW-Authenticate header. */
function modernHeader(
  opts: {
    request?: string;
    expires?: string | null;
    method?: string;
    intent?: string;
    extraParams?: string;
  } = {},
): string {
  const request = opts.request ?? encodedRequest();
  const expires = opts.expires === undefined ? FUTURE_EXPIRES : opts.expires;
  const method = opts.method ?? "lightning";
  const intent = opts.intent ?? "charge";
  let header =
    `Payment id="fixture-id-1", realm="api.example.com", ` +
    `method="${method}", intent="${intent}", request="${request}"`;
  if (expires !== null) {
    header += `, expires="${expires}"`;
  }
  if (opts.extraParams) {
    header += `, ${opts.extraParams}`;
  }
  return header;
}

describe("parseMppDraft00Challenge", () => {
  it("parses a full modern challenge", () => {
    const request = encodedRequest();
    const result = parseMppDraft00Challenge(modernHeader({ request }));

    expect(result.id).toBe("fixture-id-1");
    expect(result.realm).toBe("api.example.com");
    expect(result.method).toBe("lightning");
    expect(result.intent).toBe("charge");
    expect(result.expires).toBe(FUTURE_EXPIRES);
    // The encoded request string is preserved byte-exact for the echo
    expect(result.request).toBe(request);
    // Fields decoded from the request payload
    expect(result.invoice).toBe("lnbc10u1ptest");
    expect(result.amount).toBe("1000");
    expect(result.currency).toBe("sat");
    expect(result.paymentHash).toBe(FIXTURE_PAYMENT_HASH);
    expect(result.network).toBe("mainnet");
  });

  it("parses optional digest, description, and opaque params", () => {
    const header = modernHeader({
      extraParams:
        'digest="fixture-digest-1", description="Test resource", opaque="fixture-opaque-1"',
    });
    const result = parseMppDraft00Challenge(header);
    expect(result.digest).toBe("fixture-digest-1");
    expect(result.description).toBe("Test resource");
    expect(result.opaque).toBe("fixture-opaque-1");
  });

  it("parses a challenge without expires", () => {
    const result = parseMppDraft00Challenge(modernHeader({ expires: null }));
    expect(result.expires).toBeUndefined();
    expect(result.invoice).toBe("lnbc10u1ptest");
  });

  it("accepts a base64url request with padding", () => {
    // Grow the invoice until the unpadded encoding actually needs padding.
    let invoice = "lnbc10u1ptest";
    let unpadded = b64url(JSON.stringify(requestPayload({ methodDetails: { invoice } })));
    while (unpadded.length % 4 === 0) {
      invoice += "q";
      unpadded = b64url(JSON.stringify(requestPayload({ methodDetails: { invoice } })));
    }
    const padded = unpadded + "=".repeat(4 - (unpadded.length % 4));

    const result = parseMppDraft00Challenge(modernHeader({ request: padded }));
    expect(result.invoice).toBe(invoice);
    // The echoed request is the received string, padding included
    expect(result.request).toBe(padded);
  });

  it("ignores unknown params", () => {
    const header = modernHeader({
      extraParams: 'x-future-param="something", flavor=vanilla',
    });
    const result = parseMppDraft00Challenge(header);
    expect(result.invoice).toBe("lnbc10u1ptest");
  });

  it("parses a superset header, taking amount from the request not the legacy params", () => {
    // Lightning Enable's server sends a SUPERSET header: modern params plus
    // legacy invoice/amount/currency. The legacy params are unknown params to
    // the modern profile — values come from the decoded request only.
    const header = modernHeader({
      extraParams: 'invoice="lnbc-legacy-should-be-ignored", amount="999", currency="sat"',
    });
    const result = parseMppDraft00Challenge(header);
    expect(result.invoice).toBe("lnbc10u1ptest");
    expect(result.amount).toBe("1000");
  });

  it("handles a quoted description containing a comma", () => {
    const header = modernHeader({
      extraParams: 'description="Pay for this, please"',
    });
    const result = parseMppDraft00Challenge(header);
    expect(result.description).toBe("Pay for this, please");
    expect(result.invoice).toBe("lnbc10u1ptest");
  });

  it("finds the modern Payment challenge after an L402 challenge in the same header", () => {
    const header = `L402 macaroon="mac123", invoice="lnbc5u1ptest", ${modernHeader()}`;
    const result = parseMppDraft00Challenge(header);
    expect(result.invoice).toBe("lnbc10u1ptest");
    expect(result.id).toBe("fixture-id-1");
  });

  it("finds the modern Payment challenge after a Bearer challenge", () => {
    const header = `Bearer realm="api", ${modernHeader()}`;
    const result = parseMppDraft00Challenge(header);
    expect(result.invoice).toBe("lnbc10u1ptest");
  });

  it("skips a legacy Payment challenge to find the modern one", () => {
    const header =
      `Payment method="lightning", invoice="lnbc5u1ptest", ` + modernHeader();
    const result = parseMppDraft00Challenge(header);
    expect(result.invoice).toBe("lnbc10u1ptest");
    expect(result.request).not.toBe("");
  });

  it("throws ChallengeParseError for a request that is not base64url", () => {
    expect(() =>
      parseMppDraft00Challenge(modernHeader({ request: "%%%not-base64%%%" })),
    ).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError for a request that decodes to invalid JSON", () => {
    expect(() =>
      parseMppDraft00Challenge(modernHeader({ request: b64url("not json at all") })),
    ).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError when the request is missing the invoice", () => {
    const request = b64url(
      JSON.stringify({ amount: "1000", currency: "sat", methodDetails: {} }),
    );
    expect(() => parseMppDraft00Challenge(modernHeader({ request }))).toThrow(
      ChallengeParseError,
    );
  });

  it("throws ChallengeParseError for a non-lightning method", () => {
    expect(() =>
      parseMppDraft00Challenge(modernHeader({ method: "card" })),
    ).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError for a non-charge intent", () => {
    expect(() =>
      parseMppDraft00Challenge(modernHeader({ intent: "refund" })),
    ).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError for a non-sat currency", () => {
    const request = b64url(
      JSON.stringify(requestPayload({ currency: "usd" })),
    );
    expect(() => parseMppDraft00Challenge(modernHeader({ request }))).toThrow(
      ChallengeParseError,
    );
  });

  it("throws ChallengeParseError for a non-numeric amount", () => {
    const request = b64url(
      JSON.stringify(requestPayload({ amount: "lots" })),
    );
    expect(() => parseMppDraft00Challenge(modernHeader({ request }))).toThrow(
      ChallengeParseError,
    );
  });

  it("tolerates a bare JSON number amount", () => {
    const request = b64url(JSON.stringify(requestPayload({ amount: 1000 })));
    const result = parseMppDraft00Challenge(modernHeader({ request }));
    expect(result.amount).toBe("1000");
  });

  it("throws ChallengeParseError for a legacy-only Payment header (no request param)", () => {
    expect(() =>
      parseMppDraft00Challenge(
        'Payment method="lightning", invoice="lnbc10u1ptest", amount="1000"',
      ),
    ).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError for an empty header", () => {
    expect(() => parseMppDraft00Challenge("")).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError for an invalid expires timestamp", () => {
    expect(() =>
      parseMppDraft00Challenge(modernHeader({ expires: "not-a-timestamp" })),
    ).toThrow(ChallengeParseError);
  });

  it("throws ChallengeExpiredError for an expired challenge", () => {
    expect(() =>
      parseMppDraft00Challenge(modernHeader({ expires: PAST_EXPIRES })),
    ).toThrow(ChallengeExpiredError);
  });
});

describe("findPaymentChallenge (draft-00 precedence)", () => {
  it("returns the modern challenge for a modern-only Payment header", () => {
    const headers = { "www-authenticate": modernHeader() };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("request" in result!).toBe(true);
  });

  it("prefers modern over legacy in a superset header", () => {
    const headers = {
      "www-authenticate": modernHeader({
        extraParams: 'invoice="lnbc-legacy-should-be-ignored", amount="999", currency="sat"',
      }),
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("request" in result!).toBe(true);
    expect(result!.invoice).toBe("lnbc10u1ptest");
  });

  it("prefers modern over legacy across separate Payment challenges", () => {
    const headers = {
      "www-authenticate":
        `Payment method="lightning", invoice="lnbc5u1ptest", ` + modernHeader(),
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("request" in result!).toBe(true);
    expect(result!.invoice).toBe("lnbc10u1ptest");
  });

  it("still returns a legacy challenge for a legacy-only Payment header", () => {
    const headers = {
      "www-authenticate":
        'Payment realm="api.example.com", method="lightning", invoice="lnbc10u1ptest", amount="1000", currency="sat"',
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("request" in result!).toBe(false);
    expect("macaroon" in result!).toBe(false);
    expect(result!.invoice).toBe("lnbc10u1ptest");
  });

  it("still prefers L402 over a modern Payment challenge", () => {
    const headers = {
      "www-authenticate": `L402 macaroon="mac123", invoice="lnbc5u1ptest", ${modernHeader()}`,
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("macaroon" in result!).toBe(true);
  });

  it("returns null for a malformed modern challenge with no legacy fallback", () => {
    // Malformed modern (bad base64url request) and NO legacy invoice= param:
    // must NOT be silently retried as anything else.
    const headers = {
      "www-authenticate": modernHeader({ request: "%%%not-base64%%%" }),
    };
    expect(findPaymentChallenge(headers)).toBeNull();
  });

  it("falls back to legacy when a malformed modern challenge carries legacy params", () => {
    // Superset case: the same header carries legacy invoice= — an intentional
    // fallback provided by the server.
    const headers = {
      "www-authenticate": modernHeader({
        request: "%%%not-base64%%%",
        extraParams: 'invoice="lnbc10u1ptest", amount="1000", currency="sat"',
      }),
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("request" in result!).toBe(false);
    expect(result!.invoice).toBe("lnbc10u1ptest");
  });

  it("propagates ChallengeExpiredError instead of falling back to legacy", () => {
    const headers = {
      "www-authenticate": modernHeader({
        expires: PAST_EXPIRES,
        extraParams: 'invoice="lnbc10u1ptest", amount="1000", currency="sat"',
      }),
    };
    expect(() => findPaymentChallenge(headers)).toThrow(ChallengeExpiredError);
  });
});

describe("buildMppDraft00Authorization", () => {
  function parsedModernChallenge(
    opts: Parameters<typeof modernHeader>[0] = {},
  ): MppDraft00Challenge {
    return parseMppDraft00Challenge(modernHeader(opts));
  }

  it("produces a Payment header with unpadded base64url", () => {
    const auth = buildMppDraft00Authorization(
      parsedModernChallenge(),
      FIXTURE_PREIMAGE,
    );
    expect(auth.startsWith("Payment ")).toBe(true);
    const token = auth.slice("Payment ".length);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/); // b64url charset, no padding
  });

  it("echoes the challenge byte-exact, including the received request string", () => {
    const request = encodedRequest();
    const challenge = parsedModernChallenge({ request });
    const auth = buildMppDraft00Authorization(challenge, FIXTURE_PREIMAGE);
    const decoded = JSON.parse(decodeB64url(auth.slice("Payment ".length)));

    expect(decoded.challenge.id).toBe("fixture-id-1");
    expect(decoded.challenge.realm).toBe("api.example.com");
    expect(decoded.challenge.method).toBe("lightning");
    expect(decoded.challenge.intent).toBe("charge");
    expect(decoded.challenge.expires).toBe(FUTURE_EXPIRES);
    // The load-bearing assertion: the encoded request string is unchanged
    expect(decoded.challenge.request).toBe(request);
    expect(decoded.payload).toEqual({ preimage: FIXTURE_PREIMAGE });
  });

  it("echoes optional params only when they were received", () => {
    const withOptional = parsedModernChallenge({
      extraParams: 'digest="fixture-digest-1", opaque="fixture-opaque-1"',
    });
    const decodedWith = JSON.parse(
      decodeB64url(
        buildMppDraft00Authorization(withOptional, FIXTURE_PREIMAGE).slice(
          "Payment ".length,
        ),
      ),
    );
    expect(decodedWith.challenge.digest).toBe("fixture-digest-1");
    expect(decodedWith.challenge.opaque).toBe("fixture-opaque-1");

    const withoutOptional = parsedModernChallenge();
    const decodedWithout = JSON.parse(
      decodeB64url(
        buildMppDraft00Authorization(withoutOptional, FIXTURE_PREIMAGE).slice(
          "Payment ".length,
        ),
      ),
    );
    expect("digest" in decodedWithout.challenge).toBe(false);
    expect("opaque" in decodedWithout.challenge).toBe(false);
    expect("description" in decodedWithout.challenge).toBe(false);
  });

  it("does not echo legacy superset extras", () => {
    const challenge = parsedModernChallenge({
      extraParams: 'invoice="lnbc-legacy-should-be-ignored", amount="999", currency="sat"',
    });
    const decoded = JSON.parse(
      decodeB64url(
        buildMppDraft00Authorization(challenge, FIXTURE_PREIMAGE).slice(
          "Payment ".length,
        ),
      ),
    );
    expect("invoice" in decoded.challenge).toBe(false);
    expect("amount" in decoded.challenge).toBe(false);
    expect("currency" in decoded.challenge).toBe(false);
  });

  it("lowercases an uppercase preimage", () => {
    const decoded = JSON.parse(
      decodeB64url(
        buildMppDraft00Authorization(
          parsedModernChallenge(),
          FIXTURE_PREIMAGE.toUpperCase(),
        ).slice("Payment ".length),
      ),
    );
    expect(decoded.payload.preimage).toBe(FIXTURE_PREIMAGE);
  });

  it("rejects a non-hex preimage to prevent credential injection", () => {
    expect(() =>
      buildMppDraft00Authorization(parsedModernChallenge(), 'evil"injected'),
    ).toThrow(L402Error);
  });
});

describe("parsePaymentReceipt", () => {
  const receiptJson = {
    challengeId: "fixture-id-1",
    method: "lightning",
    reference: FIXTURE_PAYMENT_HASH,
    status: "settled",
    timestamp: "2026-08-23T00:00:00Z",
  };

  it("parses a valid receipt", () => {
    const headers = new Headers({
      "Payment-Receipt": b64url(JSON.stringify(receiptJson)),
    });
    const receipt = parsePaymentReceipt(headers);
    expect(receipt).toEqual(receiptJson);
  });

  it("accepts standard base64 with padding", () => {
    const headers = {
      "payment-receipt": Buffer.from(JSON.stringify(receiptJson), "utf-8").toString(
        "base64",
      ),
    };
    const receipt = parsePaymentReceipt(headers);
    expect(receipt).toEqual(receiptJson);
  });

  it("returns null when the header is absent", () => {
    expect(parsePaymentReceipt(new Headers())).toBeNull();
    expect(parsePaymentReceipt({ "content-type": "application/json" })).toBeNull();
  });

  it("returns null for invalid base64", () => {
    expect(parsePaymentReceipt({ "payment-receipt": "%%%" })).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    expect(
      parsePaymentReceipt({ "payment-receipt": b64url("not json") }),
    ).toBeNull();
  });

  it("tolerates missing fields", () => {
    const headers = {
      "payment-receipt": b64url(JSON.stringify({ status: "settled" })),
    };
    const receipt = parsePaymentReceipt(headers);
    expect(receipt).not.toBeNull();
    expect(receipt!.status).toBe("settled");
    expect(receipt!.reference).toBeUndefined();
  });
});

describe("L402Client (modern MPP flow)", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.restoreAllMocks();
  });

  function fixtureWallet(preimage = FIXTURE_PREIMAGE): Wallet {
    return {
      supportsPreimage: true,
      payInvoice: vi.fn().mockResolvedValue(preimage),
    };
  }

  /**
   * Mock fetch: 200 whenever the request carries a `Payment` Authorization
   * header, else a 402 with the given WWW-Authenticate challenge.
   */
  function mockModernFetch(
    header: string,
    opts: { data?: unknown; receipt?: string } = {},
  ) {
    return vi
      .fn()
      .mockImplementation(async (_url: string, init?: RequestInit) => {
        const headers = new Headers(init?.headers);
        if (headers.get("Authorization")?.startsWith("Payment ")) {
          const responseHeaders: Record<string, string> = {
            "Content-Type": "application/json",
          };
          if (opts.receipt !== undefined) {
            responseHeaders["Payment-Receipt"] = opts.receipt;
          }
          return new Response(JSON.stringify(opts.data ?? { ok: true }), {
            status: 200,
            headers: responseHeaders,
          });
        }
        return new Response("Payment Required", {
          status: 402,
          headers: { "WWW-Authenticate": header },
        });
      });
  }

  it("auto-pays a modern challenge and retries with the draft-00 credential", async () => {
    const request = encodedRequest();
    const fetchMock = mockModernFetch(modernHeader({ request }), {
      data: { data: "paid-modern" },
    });
    globalThis.fetch = fetchMock;

    const wallet = fixtureWallet();
    const client = new L402Client({ wallet, budget: null });
    const response = await client.get("https://api.example.com/modern");

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ data: "paid-modern" });
    expect(wallet.payInvoice).toHaveBeenCalledOnce();
    expect(wallet.payInvoice).toHaveBeenCalledWith("lnbc10u1ptest");

    // The retry carries the base64url credential, not the legacy format
    const retryAuth = new Headers(fetchMock.mock.calls[1][1].headers).get(
      "Authorization",
    )!;
    expect(retryAuth.startsWith("Payment ")).toBe(true);
    const token = retryAuth.slice("Payment ".length);
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    const decoded = JSON.parse(decodeB64url(token));
    expect(decoded.challenge.request).toBe(request);
    expect(decoded.payload).toEqual({ preimage: FIXTURE_PREIMAGE });
  });

  it("pays a modern challenge from a superset header using the draft-00 credential", async () => {
    const fetchMock = mockModernFetch(
      modernHeader({
        extraParams: 'invoice="lnbc10u1ptest", amount="1000", currency="sat"',
      }),
    );
    globalThis.fetch = fetchMock;

    const wallet = fixtureWallet();
    const client = new L402Client({ wallet, budget: null });
    const response = await client.get("https://api.example.com/superset");

    expect(response.status).toBe(200);
    const retryAuth = new Headers(fetchMock.mock.calls[1][1].headers).get(
      "Authorization",
    )!;
    // Draft-00 credential (base64url token), not the legacy preimage= format
    expect(retryAuth).toMatch(/^Payment [A-Za-z0-9_-]+$/);
  });

  it("refuses an expired modern challenge before paying", async () => {
    const fetchMock = mockModernFetch(modernHeader({ expires: PAST_EXPIRES }));
    globalThis.fetch = fetchMock;

    const wallet = fixtureWallet();
    const client = new L402Client({ wallet, budget: null });

    await expect(
      client.get("https://api.example.com/expired"),
    ).rejects.toThrow(ChallengeExpiredError);

    expect(wallet.payInvoice).not.toHaveBeenCalled();
    expect(client.spendingLog.records).toHaveLength(0);
  });

  it("refuses a modern challenge whose amount disagrees with the invoice", async () => {
    // Request declares 5 sats but the invoice encodes 1000 sats. The server
    // is telling the agent one price and the wallet another — refuse.
    const request = b64url(JSON.stringify(requestPayload({ amount: "5" })));
    const fetchMock = mockModernFetch(modernHeader({ request }));
    globalThis.fetch = fetchMock;

    const wallet = fixtureWallet();
    const client = new L402Client({ wallet, budget: null });

    await expect(
      client.get("https://api.example.com/mismatch"),
    ).rejects.toThrow(L402Error);

    expect(wallet.payInvoice).not.toHaveBeenCalled();
    expect(client.spendingLog.records).toHaveLength(0);
  });

  it("does not cache modern credentials (single-use server-side)", async () => {
    const fetchMock = mockModernFetch(modernHeader());
    globalThis.fetch = fetchMock;

    const wallet = fixtureWallet();
    const client = new L402Client({ wallet, budget: null });

    await client.get("https://api.example.com/api/v1/data");
    await client.get("https://api.example.com/api/v1/data");

    // Each request triggers a fresh 402 → pay → retry cycle: the credential
    // is single-use server-side, so replaying it would just earn another 402.
    expect(wallet.payInvoice).toHaveBeenCalledTimes(2);
    // 402 + retry, twice
    expect(fetchMock).toHaveBeenCalledTimes(4);
    // Neither initial request carried a cached Authorization header
    expect(new Headers(fetchMock.mock.calls[0][1].headers).get("Authorization")).toBeNull();
    expect(new Headers(fetchMock.mock.calls[2][1].headers).get("Authorization")).toBeNull();
  });

  it("exposes the Payment-Receipt header on the result", async () => {
    const receiptJson = {
      challengeId: "fixture-id-1",
      method: "lightning",
      reference: FIXTURE_PAYMENT_HASH,
      status: "settled",
      timestamp: "2026-08-23T00:00:00Z",
    };
    const fetchMock = mockModernFetch(modernHeader(), {
      receipt: b64url(JSON.stringify(receiptJson)),
    });
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: fixtureWallet(), budget: null });
    const response = await client.get("https://api.example.com/receipt");

    expect(response.status).toBe(200);
    expect(response.paymentReceipt).toEqual(receiptJson);
  });

  it("does not fail the successful payment on a malformed receipt", async () => {
    const fetchMock = mockModernFetch(modernHeader(), { receipt: "%%%" });
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: fixtureWallet(), budget: null });
    const response = await client.get("https://api.example.com/bad-receipt");

    expect(response.status).toBe(200);
    expect(response.paymentReceipt).toBeUndefined();
  });

  it("records the modern payment in the spending log with no macaroon", async () => {
    globalThis.fetch = mockModernFetch(modernHeader());

    const client = new L402Client({ wallet: fixtureWallet(), budget: null });
    await client.get("https://api.example.com/logged");

    expect(client.spendingLog.records).toHaveLength(1);
    expect(client.spendingLog.records[0].amountSats).toBe(1000);
    expect(client.spendingLog.records[0].success).toBe(true);
    expect(client.spendingLog.records[0].macaroon).toBe("");
  });
});
