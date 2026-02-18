/**
 * Strike REST API wallet adapter.
 *
 * Quote + execute flow with preimage extraction.
 */

import type { Wallet } from "../types.js";
import { PaymentFailedError } from "../errors.js";

export class StrikeWallet implements Wallet {
  private _apiKey: string;
  private _baseUrl: string;

  static readonly BASE_URL = "https://api.strike.me";

  constructor(apiKey: string, baseUrl?: string) {
    this._apiKey = apiKey;
    this._baseUrl = (baseUrl ?? StrikeWallet.BASE_URL).replace(/\/+$/, "");
  }

  /**
   * Pay via Strike's quote + execute flow.
   *
   * 1. POST /v1/payment-quotes/lightning — create quote from bolt11
   * 2. PATCH /v1/payment-quotes/{id}/execute — execute the payment
   * 3. Extract preimage from completed payment
   */
  async payInvoice(bolt11: string): Promise<string> {
    const headers = {
      Authorization: `Bearer ${this._apiKey}`,
      "Content-Type": "application/json",
    };

    // Step 1: Create payment quote
    let quoteResp: Response;
    try {
      quoteResp = await fetch(
        `${this._baseUrl}/v1/payment-quotes/lightning`,
        {
          method: "POST",
          headers,
          body: JSON.stringify({
            lnInvoice: bolt11,
            sourceCurrency: "BTC",
          }),
        },
      );
    } catch (e) {
      throw new PaymentFailedError(
        `Strike connection error: ${e}`,
        bolt11,
      );
    }

    if (quoteResp.status !== 200 && quoteResp.status !== 201) {
      const text = await quoteResp.text();
      throw new PaymentFailedError(
        `Strike quote failed (${quoteResp.status}): ${text}`,
        bolt11,
      );
    }

    const quote = (await quoteResp.json()) as Record<string, unknown>;
    const quoteId = quote["paymentQuoteId"] as string | undefined;
    if (!quoteId) {
      throw new PaymentFailedError(
        "Strike quote missing paymentQuoteId",
        bolt11,
      );
    }

    // Step 2: Execute payment
    let execResp: Response;
    try {
      execResp = await fetch(
        `${this._baseUrl}/v1/payment-quotes/${quoteId}/execute`,
        { method: "PATCH", headers },
      );
    } catch (e) {
      throw new PaymentFailedError(
        `Strike execution error: ${e}`,
        bolt11,
      );
    }

    if (execResp.status !== 200 && execResp.status !== 201) {
      const text = await execResp.text();
      throw new PaymentFailedError(
        `Strike execution failed (${execResp.status}): ${text}`,
        bolt11,
      );
    }

    const payment = (await execResp.json()) as Record<string, unknown>;

    // Extract preimage from Lightning payment details
    const lightning = payment["lightning"] as Record<string, unknown> | undefined;
    let preimage =
      lightning?.["preImage"] as string | undefined ??
      lightning?.["preimage"] as string | undefined ??
      payment["preimage"] as string | undefined;

    if (!preimage) {
      // Try fetching payment details
      const paymentId =
        (payment["paymentId"] as string | undefined) ??
        (payment["paymentQuoteId"] as string | undefined);
      if (paymentId) {
        preimage = await this._fetchPreimage(headers, paymentId);
      }
    }

    if (!preimage) {
      throw new PaymentFailedError(
        "Strike payment succeeded but no preimage returned. " +
          "This may happen with older Strike API versions.",
        bolt11,
      );
    }

    return preimage;
  }

  private async _fetchPreimage(
    headers: Record<string, string>,
    paymentId: string,
  ): Promise<string | undefined> {
    try {
      const resp = await fetch(
        `${this._baseUrl}/v1/payments/${paymentId}`,
        { headers },
      );
      if (resp.status === 200) {
        const data = (await resp.json()) as Record<string, unknown>;
        const lightning = data["lightning"] as Record<string, unknown> | undefined;
        return (
          (lightning?.["preImage"] as string | undefined) ??
          (lightning?.["preimage"] as string | undefined)
        );
      }
    } catch {
      // ignore
    }
    return undefined;
  }
}
