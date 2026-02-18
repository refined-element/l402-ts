/**
 * LND REST wallet adapter.
 *
 * Uses /v2/router/send for synchronous payment with streaming JSON response.
 */

import type { Wallet } from "../types.js";
import { PaymentFailedError } from "../errors.js";

export class LndWallet implements Wallet {
  private _host: string;
  private _macaroonHex: string;

  constructor(host: string, macaroonHex: string) {
    this._host = host.replace(/\/+$/, "");
    this._macaroonHex = macaroonHex;
  }

  /**
   * Pay via LND's /v2/router/send (streaming JSON response).
   * Extracts preimage from the final SUCCEEDED update.
   */
  async payInvoice(bolt11: string): Promise<string> {
    const headers: Record<string, string> = {
      "Grpc-Metadata-macaroon": this._macaroonHex,
      "Content-Type": "application/json",
    };

    let response: Response;
    try {
      response = await fetch(`${this._host}/v2/router/send`, {
        method: "POST",
        headers,
        body: JSON.stringify({
          payment_request: bolt11,
          timeout_seconds: 60,
          fee_limit_sat: 100,
        }),
      });
    } catch (e) {
      throw new PaymentFailedError(`LND connection error: ${e}`, bolt11);
    }

    if (response.status !== 200) {
      const text = await response.text();
      throw new PaymentFailedError(
        `LND returned ${response.status}: ${text}`,
        bolt11,
      );
    }

    // v2/router/send returns newline-delimited JSON stream
    // Parse the last complete JSON object for the final payment state
    const text = await response.text();
    let lastUpdate: Record<string, unknown> | null = null;

    for (const line of text.trim().split("\n")) {
      const trimmed = line.trim();
      if (trimmed) {
        try {
          lastUpdate = JSON.parse(trimmed);
        } catch {
          continue;
        }
      }
    }

    if (!lastUpdate) {
      throw new PaymentFailedError("No response from LND router", bolt11);
    }

    const result = (lastUpdate["result"] as Record<string, unknown>) ?? lastUpdate;
    const status = result["status"] as string ?? "";

    if (status === "SUCCEEDED") {
      const preimage = result["payment_preimage"] as string | undefined;
      if (!preimage) {
        throw new PaymentFailedError(
          "LND payment succeeded but no preimage returned",
          bolt11,
        );
      }
      // LND returns base64-encoded preimage, convert to hex
      try {
        const bytes = new Uint8Array(Buffer.from(preimage, "base64"));
        return Array.from(bytes)
          .map((b) => b.toString(16).padStart(2, "0"))
          .join("");
      } catch {
        // Already hex
        return preimage;
      }
    } else if (status === "FAILED") {
      const reason = (result["failure_reason"] as string) ?? "unknown";
      throw new PaymentFailedError(`LND payment failed: ${reason}`, bolt11);
    } else {
      throw new PaymentFailedError(
        `LND unexpected status: ${status}`,
        bolt11,
      );
    }
  }
}
