/**
 * OpenNode REST API wallet adapter.
 *
 * Note: OpenNode does not return preimages in withdrawal responses,
 * which limits L402 functionality. For full L402 support, prefer
 * Strike, LND, or compatible NWC wallets.
 */

import type { Wallet } from "../types.js";
import { PaymentFailedError } from "../errors.js";

export class OpenNodeWallet implements Wallet {
  private _apiKey: string;
  private _baseUrl: string;

  static readonly BASE_URL = "https://api.opennode.com";

  constructor(apiKey: string, baseUrl?: string) {
    this._apiKey = apiKey;
    this._baseUrl = (baseUrl ?? OpenNodeWallet.BASE_URL).replace(/\/+$/, "");
  }

  /**
   * Pay via OpenNode's withdrawal endpoint.
   *
   * Warning: OpenNode typically does not return the preimage, which
   * means L402 token construction will fail.
   */
  async payInvoice(bolt11: string): Promise<string> {
    let resp: Response;
    try {
      resp = await fetch(`${this._baseUrl}/v2/withdrawals`, {
        method: "POST",
        headers: {
          Authorization: this._apiKey,
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          type: "ln",
          address: bolt11,
        }),
      });
    } catch (e) {
      throw new PaymentFailedError(
        `OpenNode connection error: ${e}`,
        bolt11,
      );
    }

    if (resp.status !== 200 && resp.status !== 201) {
      const text = await resp.text();
      throw new PaymentFailedError(
        `OpenNode withdrawal failed (${resp.status}): ${text}`,
        bolt11,
      );
    }

    const body = (await resp.json()) as Record<string, unknown>;
    const data = (body["data"] as Record<string, unknown>) ?? body;
    const preimage =
      (data["preimage"] as string | undefined) ??
      (data["payment_preimage"] as string | undefined);

    if (!preimage) {
      throw new PaymentFailedError(
        "OpenNode payment succeeded but no preimage returned. " +
          "OpenNode does not support preimage extraction. " +
          "For L402, use Strike, LND, or a compatible NWC wallet.",
        bolt11,
      );
    }

    return preimage;
  }
}
