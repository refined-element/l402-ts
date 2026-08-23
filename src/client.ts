/**
 * L402 HTTP client — auto-pays Lightning invoices on 402 responses.
 *
 * Drop-in enhancement to fetch(). Any API behind an L402 paywall just works.
 */

import { classifyMissingAmount, extractAmountSats } from "./bolt11.js";
import { BudgetController } from "./budget.js";
import {
  buildMppDraft00Authorization,
  findPaymentChallenge,
} from "./challenge.js";
import { CredentialCache } from "./credential-cache.js";
import {
  InvoiceAmountUnknownError,
  L402Error,
  PaymentFailedError,
  UnsupportedWalletError,
} from "./errors.js";
import { parsePaymentReceipt } from "./receipt.js";
import { SpendingLog } from "./spending-log.js";
import type { Wallet, L402Options, L402Response } from "./types.js";
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
  async fetch(url: string | URL, init?: RequestInit): Promise<L402Response> {
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

    // Modern draft-00 sanity check: when the decoded request declares an
    // amount, it must agree with what the BOLT11 invoice actually encodes.
    // A mismatch means the server is telling the agent one price and the
    // wallet another — refuse before any funds move. (Legacy MPP `amount`
    // params stay advisory-only, unchanged.)
    if ("request" in challenge && challenge.amount !== undefined) {
      const declaredSats = Number(challenge.amount);
      if (declaredSats !== amountSats) {
        throw new L402Error(
          `Refusing to pay: the Payment challenge declares ${declaredSats} ` +
            `sats but the invoice encodes ${amountSats} sats`,
        );
      }
    }

    // Reserve the spend SYNCHRONOUSLY — before any `await` yields to the event
    // loop for the payment. The reservation counts against the window limits
    // immediately, so a concurrent fetch() cannot also pass its budget check
    // while this payment is still settling. This closes the old
    // check → await payInvoice → recordPayment TOCTOU race, where two
    // concurrent calls both passed check() against the not-yet-recorded total
    // and both settled, blowing the cap. reserve() throws (DomainNotAllowed /
    // BudgetExceeded) before recording anything, so a refused reservation
    // leaves no state to unwind. On success we commit(), on any failure we
    // release() — see the try/catch below.
    let reservationId: string | null = null;
    if (this._budget) {
      reservationId = this._budget.reserve(amountSats, domain);
    }

    let preimage: string;
    try {
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
    } catch (e) {
      // Anything between reserve and commit failed (unsupported wallet, wallet
      // resolution, or the payment itself). Release the reservation so it stops
      // counting against the budget, then propagate.
      if (this._budget && reservationId !== null) {
        this._budget.release(reservationId);
      }
      throw e;
    }

    // Payment settled. Commit the reservation as a real spend. `amountSats` is
    // always known by this point — unknown amounts were refused above — so
    // every payment the client makes lands in the budget and the log, with no
    // silent gaps. The Wallet interface surfaces only the preimage, not the
    // routing fee, so we commit the invoice principal; if a wallet ever exposes
    // the fee, commit `amountSats + fee` here instead.
    if (this._budget && reservationId !== null) {
      this._budget.commit(reservationId, amountSats);
    }
    this.spendingLog.record(
      domain,
      parsed.pathname,
      amountSats,
      preimage,
      true,
      macaroonValue ?? "",
    );

    // Build the retry Authorization. Modern draft-00 credentials are
    // SINGLE-USE server-side, so they are never cached — replaying one would
    // just earn another 402. Legacy L402/MPP credentials keep the existing
    // cache-and-reuse behavior.
    let authorization: string;
    if ("request" in challenge) {
      authorization = buildMppDraft00Authorization(challenge, preimage);
    } else {
      const credential = this._cache.put(
        domain,
        parsed.pathname,
        macaroonValue,
        preimage,
      );
      authorization = CredentialCache.authorizationHeader(credential);
    }

    const retryHeaders = new Headers(mergedInit.headers);
    retryHeaders.set("Authorization", authorization);

    const retryResponse: L402Response = await globalThis.fetch(urlStr, {
      ...mergedInit,
      headers: retryHeaders,
      body: bodyBuffer,
    });

    // Surface the Payment-Receipt header (MPP draft-00) when present. Parsed
    // tolerantly: a missing or malformed receipt never fails the payment that
    // already succeeded. The receipt carries only the payment hash, never the
    // preimage, so it is safe to expose and store.
    const receipt = parsePaymentReceipt(retryResponse.headers);
    if (receipt !== null) {
      retryResponse.paymentReceipt = receipt;
    }

    return retryResponse;
  }

  async get(url: string, init?: RequestInit): Promise<L402Response> {
    return this.fetch(url, { ...init, method: "GET" });
  }

  async post(url: string, init?: RequestInit): Promise<L402Response> {
    return this.fetch(url, { ...init, method: "POST" });
  }

  async put(url: string, init?: RequestInit): Promise<L402Response> {
    return this.fetch(url, { ...init, method: "PUT" });
  }

  async delete(url: string, init?: RequestInit): Promise<L402Response> {
    return this.fetch(url, { ...init, method: "DELETE" });
  }

  async patch(url: string, init?: RequestInit): Promise<L402Response> {
    return this.fetch(url, { ...init, method: "PATCH" });
  }

  async head(url: string, init?: RequestInit): Promise<L402Response> {
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
