/**
 * Budget controls for L402 payments.
 *
 * Enforces per-request, hourly, and daily spending limits. Safety-first:
 * budgets are enabled by default so users don't accidentally overspend.
 */

import { BudgetExceededError, DomainNotAllowedError } from "./errors.js";
import type { BudgetOptions } from "./types.js";

export class BudgetController {
  readonly maxSatsPerRequest: number;
  readonly maxSatsPerHour: number;
  readonly maxSatsPerDay: number;
  readonly allowedDomains: Set<string> | null;

  private _payments: Array<{ timestamp: number; amount: number }> = [];

  constructor(options: BudgetOptions = {}) {
    this.maxSatsPerRequest = options.maxSatsPerRequest ?? 1_000;
    this.maxSatsPerHour = options.maxSatsPerHour ?? 10_000;
    this.maxSatsPerDay = options.maxSatsPerDay ?? 50_000;
    this.allowedDomains = options.allowedDomains ?? null;
  }

  /**
   * Verify a payment is within budget. Throws if not.
   *
   * @throws {DomainNotAllowedError} If domain is not in allowed_domains.
   * @throws {BudgetExceededError} If any budget limit would be exceeded.
   */
  check(amountSats: number, domain?: string): void {
    if (this.allowedDomains !== null && domain) {
      const lowerDomains = new Set(
        [...this.allowedDomains].map((d) => d.toLowerCase()),
      );
      if (!lowerDomains.has(domain.toLowerCase())) {
        throw new DomainNotAllowedError(domain);
      }
    }

    // Per-request limit
    if (amountSats > this.maxSatsPerRequest) {
      throw new BudgetExceededError(
        "per_request",
        this.maxSatsPerRequest,
        0,
        amountSats,
      );
    }

    const now = Date.now();
    this._prune(now);

    // Hourly limit
    const hourAgo = now - 3_600_000;
    const spentHour = this._payments
      .filter((p) => p.timestamp >= hourAgo)
      .reduce((sum, p) => sum + p.amount, 0);
    if (spentHour + amountSats > this.maxSatsPerHour) {
      throw new BudgetExceededError(
        "per_hour",
        this.maxSatsPerHour,
        spentHour,
        amountSats,
      );
    }

    // Daily limit
    const dayAgo = now - 86_400_000;
    const spentDay = this._payments
      .filter((p) => p.timestamp >= dayAgo)
      .reduce((sum, p) => sum + p.amount, 0);
    if (spentDay + amountSats > this.maxSatsPerDay) {
      throw new BudgetExceededError(
        "per_day",
        this.maxSatsPerDay,
        spentDay,
        amountSats,
      );
    }
  }

  /** Record a successful payment against the budget. */
  recordPayment(amountSats: number): void {
    this._payments.push({ timestamp: Date.now(), amount: amountSats });
  }

  /** Total sats spent in the last hour. */
  spentLastHour(): number {
    const now = Date.now();
    this._prune(now);
    const hourAgo = now - 3_600_000;
    return this._payments
      .filter((p) => p.timestamp >= hourAgo)
      .reduce((sum, p) => sum + p.amount, 0);
  }

  /** Total sats spent in the last 24 hours. */
  spentLastDay(): number {
    const now = Date.now();
    this._prune(now);
    const dayAgo = now - 86_400_000;
    return this._payments
      .filter((p) => p.timestamp >= dayAgo)
      .reduce((sum, p) => sum + p.amount, 0);
  }

  /** Remove payments older than 24 hours. */
  private _prune(now: number): void {
    const cutoff = now - 86_400_000;
    while (this._payments.length > 0 && this._payments[0].timestamp < cutoff) {
      this._payments.shift();
    }
  }
}
