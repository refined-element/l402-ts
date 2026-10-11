import { readFileSync } from "node:fs";
import { describe, it, expect, vi, afterEach } from "vitest";
import { L402Client } from "../src/client.js";
import { USER_AGENT, isBrowserLike } from "../src/user-agent.js";
import { LndWallet } from "../src/wallets/lnd.js";
import { OpenNodeWallet } from "../src/wallets/opennode.js";
import { StrikeWallet } from "../src/wallets/strike.js";
import type { Wallet } from "../src/types.js";

const pkg = JSON.parse(
  readFileSync(new URL("../package.json", import.meta.url), "utf8"),
) as { version: string };

function mockWallet(): Wallet {
  return {
    supportsPreimage: true,
    payInvoice: vi.fn().mockResolvedValue("abc123def456"),
  };
}

/** 402 on the first (unauthenticated) call, 200 once L402 auth is present. */
function mockL402Fetch() {
  return vi.fn().mockImplementation(async (_url: string, init?: RequestInit) => {
    const headers = new Headers(init?.headers);
    if (headers.get("Authorization")?.startsWith("L402 ")) {
      return new Response("{}", { status: 200 });
    }
    return new Response("Payment Required", {
      status: 402,
      headers: {
        "WWW-Authenticate": `L402 macaroon="mac123", invoice="lnbc10u1ptest"`,
      },
    });
  });
}

function sentUserAgent(
  fetchMock: ReturnType<typeof vi.fn>,
  call: number,
): string | null {
  const init = fetchMock.mock.calls[call][1] as RequestInit | undefined;
  return new Headers(init?.headers).get("User-Agent");
}

describe("User-Agent", () => {
  const originalFetch = globalThis.fetch;

  afterEach(() => {
    globalThis.fetch = originalFetch;
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("is l402-ts/<package.json version>", () => {
    expect(USER_AGENT).toMatch(/^l402-ts\/\d+\.\d+\.\d+$/);
    expect(USER_AGENT).toBe(`l402-ts/${pkg.version}`);
  });

  it("is sent on the request that receives the 402 and on the paid retry", async () => {
    const fetchMock = mockL402Fetch();
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    const response = await client.get("https://api.example.com/paid");

    expect(response.status).toBe(200);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    expect(sentUserAgent(fetchMock, 0)).toBe(USER_AGENT);
    expect(sentUserAgent(fetchMock, 1)).toBe(USER_AGENT);
  });

  it("is sent on a request that never sees a 402", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(new Response("{}", { status: 200 }));
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    await client.get("https://api.example.com/free");

    expect(sentUserAgent(fetchMock, 0)).toBe(USER_AGENT);
  });

  it("lets a caller-supplied User-Agent win on both requests", async () => {
    const fetchMock = mockL402Fetch();
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    await client.get("https://api.example.com/paid", {
      headers: { "user-agent": "my-agent/1.0" },
    });

    expect(sentUserAgent(fetchMock, 0)).toBe("my-agent/1.0");
    expect(sentUserAgent(fetchMock, 1)).toBe("my-agent/1.0");
  });

  it("lets a User-Agent from default fetchOptions win", async () => {
    const fetchMock = mockL402Fetch();
    globalThis.fetch = fetchMock;

    const client = new L402Client({
      wallet: mockWallet(),
      fetchOptions: { headers: { "User-Agent": "configured-agent/2.0" } },
    });
    await client.get("https://api.example.com/paid");

    expect(sentUserAgent(fetchMock, 0)).toBe("configured-agent/2.0");
    expect(sentUserAgent(fetchMock, 1)).toBe("configured-agent/2.0");
  });

  it("is skipped, without throwing, in a browser-like environment", async () => {
    vi.stubGlobal("window", {});
    const fetchMock = mockL402Fetch();
    globalThis.fetch = fetchMock;

    const client = new L402Client({ wallet: mockWallet() });
    const response = await client.get("https://api.example.com/paid");

    expect(response.status).toBe(200);
    expect(sentUserAgent(fetchMock, 0)).toBeNull();
    expect(sentUserAgent(fetchMock, 1)).toBeNull();
  });

  describe("isBrowserLike", () => {
    it("is false in Node", () => {
      expect(isBrowserLike()).toBe(false);
    });

    it("is true when a window global is present", () => {
      expect(
        isBrowserLike({ window: {}, process: { versions: { node: "22.0.0" } } }),
      ).toBe(true);
    });

    it("is true when process.versions.node is absent", () => {
      expect(isBrowserLike({})).toBe(true);
      expect(isBrowserLike({ process: { versions: {} } })).toBe(true);
    });
  });

  describe("wallet requests", () => {
    it("LndWallet sends it", async () => {
      const fetchMock = vi.fn().mockResolvedValue(
        new Response(
          JSON.stringify({
            result: { status: "SUCCEEDED", payment_preimage: "3q2+7w==" },
          }),
          { status: 200 },
        ),
      );
      vi.stubGlobal("fetch", fetchMock);

      await new LndWallet("https://localhost:8080", "macaroon-hex").payInvoice(
        "lnbc10u1ptest",
      );

      expect(sentUserAgent(fetchMock, 0)).toBe(USER_AGENT);
    });

    it("OpenNodeWallet sends it", async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValue(
          new Response(JSON.stringify({ data: { id: "w-1" } }), { status: 200 }),
        );
      vi.stubGlobal("fetch", fetchMock);

      // OpenNode can't surface a preimage, so the call may reject after the
      // request is sent; only the outgoing header matters here.
      await new OpenNodeWallet("fixture-string-opennode")
        .payInvoice("lnbc10u1ptest")
        .catch(() => undefined);

      expect(fetchMock).toHaveBeenCalled();
      expect(sentUserAgent(fetchMock, 0)).toBe(USER_AGENT);
    });

    it("StrikeWallet sends it on every call", async () => {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ paymentQuoteId: "q-1" }), {
            status: 200,
          }),
        )
        .mockResolvedValueOnce(
          new Response(JSON.stringify({ lightning: { preImage: "abc123" } }), {
            status: 200,
          }),
        );
      vi.stubGlobal("fetch", fetchMock);

      await new StrikeWallet("fixture-string-strike").payInvoice(
        "lnbc10u1ptest",
      );

      expect(fetchMock).toHaveBeenCalledTimes(2);
      expect(sentUserAgent(fetchMock, 0)).toBe(USER_AGENT);
      expect(sentUserAgent(fetchMock, 1)).toBe(USER_AGENT);
    });
  });
});
