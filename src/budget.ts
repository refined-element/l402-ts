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

  /**
   * In-flight reservations, keyed by id. A reservation is an amount that has
   * passed the budget check and is about to be paid but has not yet settled.
   * It counts against the window limits so a concurrent `reserve()` cannot also
   * pass while the first payment is still awaiting the wallet — closing the
   * check-then-pay-then-record TOCTOU race.
   */
  private _reservations = new Map<string, number>();
  private _reservationSeq = 0;

  constructor(options: BudgetOptions = {}) {
    this.maxSatsPerRequest = options.maxSatsPerRequest ?? 1_000;
    this.maxSatsPerHour = options.maxSatsPerHour ?? 10_000;
    this.maxSatsPerDay = options.maxSatsPerDay ?? 50_000;
    this.allowedDomains = options.allowedDomains ?? null;
  }

  /**
   * Verify a payment is within budget. Throws if not.
   *
   * Does not account for in-flight reservations — prefer `reserve()`/`commit()`
   * for the pay path, which is race-safe. Kept for backward compatibility.
   *
   * @throws {DomainNotAllowedError} If domain is not in allowed_domains.
   * @throws {BudgetExceededError} If any budget limit would be exceeded.
   */
  check(amountSats: number, domain?: string): void {
    this._enforceLimits(amountSats, domain, 0);
  }

  /**
   * Atomically reserve budget for a payment about to be made, returning a
   * reservation id. Evaluates the window limits INCLUDING all active
   * reservations, then records this reservation — all synchronously, with no
   * `await` in between. Because JS is single-threaded, a concurrent `reserve()`
   * cannot interleave with this check-and-insert, so two racing payments whose
   * sum exceeds a limit cannot both pass.
   *
   * The caller MUST subsequently `commit(id, actualAmount)` on success or
   * `release(id)` on failure so the reservation does not linger.
   *
   * @throws {DomainNotAllowedError} If domain is not in allowed_domains.
   * @throws {BudgetExceededError} If any budget limit would be exceeded.
   */
  reserve(amountSats: number, domain?: string): string {
    this._enforceLimits(amountSats, domain, this._reservedTotal());
    const id = String(++this._reservationSeq);
    this._reservations.set(id, amountSats);
    return id;
  }

  /**
   * Settle a reservation as a completed payment of `actualAmountSats`, dropping
   * the reservation and recording the real spend against the window. Pass the
   * amount actually paid (principal, plus routing fee if the wallet surfaces
   * one). Unknown ids are ignored.
   */
  commit(reservationId: string, actualAmountSats: number): void {
    if (!this._reservations.delete(reservationId)) return;
    this._payments.push({ timestamp: Date.now(), amount: actualAmountSats });
  }

  /**
   * Drop a reservation without recording any spend (payment failed or was
   * never attempted). Unknown ids are ignored.
   */
  release(reservationId: string): void {
    this._reservations.delete(reservationId);
  }

  /** Sum of all in-flight reservations. */
  private _reservedTotal(): number {
    let total = 0;
    for (const amount of this._reservations.values()) total += amount;
    return total;
  }

  /**
   * Shared limit enforcement for `check()` and `reserve()`. `pendingReserved`
   * is the total of in-flight reservations to count against the window limits
   * (0 for a plain `check`). Throws before returning if any limit is exceeded.
   */
  private _enforceLimits(
    amountSats: number,
    domain: string | undefined,
    pendingReserved: number,
  ): void {
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

    // Hourly limit — settled spend in the window plus in-flight reservations.
    const hourAgo = now - 3_600_000;
    const spentHour =
      this._payments
        .filter((p) => p.timestamp >= hourAgo)
        .reduce((sum, p) => sum + p.amount, 0) + pendingReserved;
    if (spentHour + amountSats > this.maxSatsPerHour) {
      throw new BudgetExceededError(
        "per_hour",
        this.maxSatsPerHour,
        spentHour,
        amountSats,
      );
    }

    // Daily limit — settled spend in the window plus in-flight reservations.
    const dayAgo = now - 86_400_000;
    const spentDay =
      this._payments
        .filter((p) => p.timestamp >= dayAgo)
        .reduce((sum, p) => sum + p.amount, 0) + pendingReserved;
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
