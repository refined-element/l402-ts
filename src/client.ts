/**
 * L402 HTTP client — auto-pays Lightning invoices on 402 responses.
 *
 * Drop-in enhancement to fetch(). Any API behind an L402 paywall just works.
 */

import { extractAmountSats } from "./bolt11.js";
import { BudgetController } from "./budget.js";
import { findL402Challenge } from "./challenge.js";
import { CredentialCache } from "./credential-cache.js";
import { L402Error, PaymentFailedError } from "./errors.js";
import { SpendingLog } from "./spending-log.js";
import type { Wallet, L402Options } from "./types.js";
import { autoDetectWallet } from "./wallets/index.js";

/** Body type compatible with fetch's RequestInit.body. */
type FetchBody = NonNullable<RequestInit["body"]>;

export class L402Client {
  private _wallet: Wallet | undefined;
  private _budget: BudgetController | null;
  private _cache: CredentialCache;
  private _fetchOptions: RequestInit;
  readonly spendingLog: SpendingLog;

  constructor(options: L402Options = {}) {
    this._wallet = options.wallet;

    // Budget: undefined → default, null → disabled, BudgetController → use it
    if (options.budget === undefined) {
      this._budget = new BudgetController();
    } else {
      this._budget = options.budget;
    }

    this._cache = options.credentialCache ?? new CredentialCache();
    this._fetchOptions = options.fetchOptions ?? {};
    this.spendingLog = new SpendingLog();
  }

  private async _getWallet(): Promise<Wallet> {
    if (!this._wallet) {
      this._wallet = await autoDetectWallet();
    }
    return this._wallet;
  }

  /**
   * Make an HTTP request, auto-paying L402 challenges.
   *
   * Accepts the same arguments as global fetch(). If the server returns
   * a 402 with an L402 challenge, the invoice is paid and the request
   * is retried automatically.
   */
  async fetch(url: string | URL, init?: RequestInit): Promise<Response> {
    const urlStr = url.toString();
    const parsed = new URL(urlStr);
    const domain = parsed.hostname;

    // Merge default fetch options with per-request options
    const mergedInit = { ...this._fetchOptions, ...init };
    const headers = new Headers(mergedInit.headers);

    // Buffer the body for potential retry (fetch body is one-use)
    let bodyBuffer: FetchBody | null = null;
    if (mergedInit.body != null) {
      bodyBuffer = await bufferBody(mergedInit.body);
    }

    // Try cached credential first
    const cachedCred = this._cache.get(domain, parsed.pathname);
    if (cachedCred) {
      headers.set("Authorization", CredentialCache.authorizationHeader(cachedCred));
    }

    const response = await globalThis.fetch(urlStr, {
      ...mergedInit,
      headers,
      body: bodyBuffer,
    });

    if (response.status !== 402) {
      return response;
    }

    // Parse L402 challenge
    const challenge = findL402Challenge(response.headers);
    if (challenge === null) {
      return response; // 402 but not L402 — return as-is
    }

    // Extract amount and check budget
    const amountSats = extractAmountSats(challenge.invoice);

    if (this._budget && amountSats !== null) {
      this._budget.check(amountSats, domain);
    }

    // Pay the invoice
    const wallet = await this._getWallet();
    let preimage: string;
    try {
      preimage = await wallet.payInvoice(challenge.invoice);
    } catch (e) {
      if (amountSats !== null) {
        this.spendingLog.record(domain, parsed.pathname, amountSats, "", false);
      }
      if (e instanceof L402Error) throw e;
      throw new PaymentFailedError(
        String(e instanceof Error ? e.message : e),
        challenge.invoice,
      );
    }

    // Record successful payment
    if (amountSats !== null) {
      if (this._budget) {
        this._budget.recordPayment(amountSats);
      }
      this.spendingLog.record(
        domain,
        parsed.pathname,
        amountSats,
        preimage,
        true,
      );
    }

    // Cache the credential
    this._cache.put(
      domain,
      parsed.pathname,
      challenge.macaroon,
      preimage,
    );

    // Retry with L402 authorization
    const retryHeaders = new Headers(mergedInit.headers);
    retryHeaders.set(
      "Authorization",
      `L402 ${challenge.macaroon}:${preimage}`,
    );

    const retryResponse = await globalThis.fetch(urlStr, {
      ...mergedInit,
      headers: retryHeaders,
      body: bodyBuffer,
    });

    return retryResponse;
  }

  async get(url: string, init?: RequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: "GET" });
  }

  async post(url: string, init?: RequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: "POST" });
  }

  async put(url: string, init?: RequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: "PUT" });
  }

  async delete(url: string, init?: RequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: "DELETE" });
  }

  async patch(url: string, init?: RequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: "PATCH" });
  }

  async head(url: string, init?: RequestInit): Promise<Response> {
    return this.fetch(url, { ...init, method: "HEAD" });
  }
}

/**
 * Buffer a request body so it can be replayed after a 402 retry.
 * fetch() Request bodies are one-use streams; this consumes the body
 * and returns a reusable form (string, ArrayBuffer, or Uint8Array).
 */
async function bufferBody(body: FetchBody): Promise<FetchBody> {
  if (typeof body === "string") return body;
  if (body instanceof ArrayBuffer) return body;
  if (body instanceof Uint8Array) return body;
  if (body instanceof Blob) return await body.arrayBuffer();
  if (body instanceof ReadableStream) {
    const reader = body.getReader();
    const chunks: Uint8Array[] = [];
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(value);
    }
    const totalLen = chunks.reduce((acc, c) => acc + c.length, 0);
    const result = new Uint8Array(totalLen);
    let offset = 0;
    for (const chunk of chunks) {
      result.set(chunk, offset);
      offset += chunk.length;
    }
    return result;
  }
  // URLSearchParams, FormData — convert to string
  if (body instanceof URLSearchParams) return body.toString();
  // FormData: not bufferable in a simple way, pass through
  return body;
}
