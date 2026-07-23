/**
 * L402 HTTP client — auto-pays Lightning invoices on 402 responses.
 *
 * Drop-in enhancement to fetch(). Any API behind an L402 paywall just works.
 */

import { classifyMissingAmount, extractAmountSats } from "./bolt11.js";
import { BudgetController } from "./budget.js";
import { findPaymentChallenge } from "./challenge.js";
import { CredentialCache } from "./credential-cache.js";
import {
  InvoiceAmountUnknownError,
  L402Error,
  PaymentFailedError,
  UnsupportedWalletError,
} from "./errors.js";
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

    // Parse L402 or MPP challenge
    const challenge = findPaymentChallenge(response.headers);
    if (challenge === null) {
      return response; // 402 but no recognized payment challenge — return as-is
    }

    // Extract amount and check budget
    const amountSats = extractAmountSats(challenge.invoice);

    // Macaroon from the parsed challenge, recorded at payment time so
    // two-step flows can rebuild `L402 {macaroon}:{preimage}` later.
    // Use "macaroon" in challenge for natural type narrowing instead of
    // casting; MPP challenges carry no macaroon.
    const macaroonValue = "macaroon" in challenge ? challenge.macaroon : null;

    // An amount we can't determine is an amount we can't authorise. Paying
    // anyway would skip `budget.check` entirely — and that call is not just the
    // per-request/hour/day sats limits but the domain allowlist too — while the
    // spend would also never reach the log below, hiding it from every LATER
    // budget check. A server that wants a blank cheque only has to send an
    // amountless invoice. Refuse instead, before any funds move.
    //
    // `<= 0` is refused alongside null: a literal-zero invoice ("lnbc0p1...")
    // DECODES to 0, not null — the amount field is present, it is just zero — so
    // a bare null-check waves it through, budget.check(0) passes, and the wallet
    // (not the server) then picks the spend. The resolved amount must be
    // strictly positive, the same blank-cheque hole ledger #42 closes for MPP.
    if (amountSats === null || amountSats <= 0) {
      throw new InvoiceAmountUnknownError(
        classifyMissingAmount(challenge.invoice),
        challenge.invoice,
      );
    }

    if (this._budget) {
      this._budget.check(amountSats, domain);
    }

    // Pay the invoice
    const wallet = await this._getWallet();

    // Fail fast on wallets that EXPLICITLY can't surface the preimage — the
    // L402 retry can't construct the Authorization header without one, so
    // paying the invoice would spend funds for no access. Strict `=== false`
    // check (not `!supportsPreimage`) so pre-existing custom wallets that
    // pre-date the property are treated as preimage-capable by default and
    // we only block adapters that opted out explicitly. Throws
    // UnsupportedWalletError (NOT PaymentFailedError) since no payment is
    // attempted — callers that distinguish payment failures from config
    // failures can catch the two separately.
    if (wallet.supportsPreimage === false) {
      throw new UnsupportedWalletError(
        "configured wallet does not return Lightning payment preimages, " +
          "which L402 requires. Use Strike, LND, or a compatible NWC " +
          "wallet (CoinOS, CLINK, Alby Hub) instead.",
      );
    }

    let preimage: string;
    try {
      preimage = await wallet.payInvoice(challenge.invoice);
    } catch (e) {
      this.spendingLog.record(
        domain,
        parsed.pathname,
        amountSats,
        "",
        false,
        macaroonValue ?? "",
      );
      if (e instanceof L402Error) throw e;
      throw new PaymentFailedError(
        String(e instanceof Error ? e.message : e),
        challenge.invoice,
      );
    }

    // Record successful payment. `amountSats` is always known by this point —
    // unknown amounts were refused above — so every payment the client makes
    // lands in the budget and the log, with no silent gaps.
    if (this._budget) {
      this._budget.recordPayment(amountSats);
    }
    this.spendingLog.record(
      domain,
      parsed.pathname,
      amountSats,
      preimage,
      true,
      macaroonValue ?? "",
    );

    // Cache the credential and reuse CredentialCache.authorizationHeader() for retry
    const credential = this._cache.put(domain, parsed.pathname, macaroonValue, preimage);

    // Retry with appropriate authorization header (delegated to CredentialCache)
    const retryHeaders = new Headers(mergedInit.headers);
    retryHeaders.set("Authorization", CredentialCache.authorizationHeader(credential));

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
