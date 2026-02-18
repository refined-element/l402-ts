/**
 * Payment history tracker for L402 spending introspection.
 */

import type { PaymentRecord } from "./types.js";

export class SpendingLog {
  private _records: PaymentRecord[] = [];

  /** Record a payment attempt. */
  record(
    domain: string,
    path: string,
    amountSats: number,
    preimage: string,
    success: boolean = true,
  ): PaymentRecord {
    const entry: PaymentRecord = {
      domain,
      path,
      amountSats,
      preimage,
      timestamp: Date.now(),
      success,
    };
    this._records.push(entry);
    return entry;
  }

  /** All recorded payments. */
  get records(): PaymentRecord[] {
    return [...this._records];
  }

  /** Total sats spent across all successful payments. */
  totalSpent(): number {
    return this._records
      .filter((r) => r.success)
      .reduce((sum, r) => sum + r.amountSats, 0);
  }

  /** Total sats spent in the last hour. */
  spentLastHour(): number {
    const cutoff = Date.now() - 3_600_000;
    return this._records
      .filter((r) => r.success && r.timestamp >= cutoff)
      .reduce((sum, r) => sum + r.amountSats, 0);
  }

  /** Total sats spent in the last 24 hours. */
  spentToday(): number {
    const cutoff = Date.now() - 86_400_000;
    return this._records
      .filter((r) => r.success && r.timestamp >= cutoff)
      .reduce((sum, r) => sum + r.amountSats, 0);
  }

  /** Total sats spent per domain. */
  byDomain(): Record<string, number> {
    const totals: Record<string, number> = {};
    for (const r of this._records) {
      if (r.success) {
        totals[r.domain] = (totals[r.domain] ?? 0) + r.amountSats;
      }
    }
    return totals;
  }

  /** Serialize all records to JSON. */
  toJSON(): string {
    return JSON.stringify(this._records, null, 2);
  }

  /** Number of recorded payments. */
  get length(): number {
    return this._records.length;
  }
}
