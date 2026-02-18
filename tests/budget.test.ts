import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { BudgetController } from "../src/budget.js";
import { BudgetExceededError, DomainNotAllowedError } from "../src/errors.js";

describe("BudgetController", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-15T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("allows payment within per-request limit", () => {
    const budget = new BudgetController({ maxSatsPerRequest: 1000 });
    expect(() => budget.check(500)).not.toThrow();
  });

  it("rejects payment exceeding per-request limit", () => {
    const budget = new BudgetController({ maxSatsPerRequest: 1000 });
    expect(() => budget.check(1500)).toThrow(BudgetExceededError);
  });

  it("rejects payment exceeding hourly limit", () => {
    const budget = new BudgetController({
      maxSatsPerRequest: 5000,
      maxSatsPerHour: 10000,
    });
    budget.recordPayment(8000);
    expect(() => budget.check(3000)).toThrow(BudgetExceededError);
  });

  it("rejects payment exceeding daily limit", () => {
    const budget = new BudgetController({
      maxSatsPerRequest: 50000,
      maxSatsPerHour: 100000,
      maxSatsPerDay: 50000,
    });
    budget.recordPayment(40000);
    expect(() => budget.check(15000)).toThrow(BudgetExceededError);
  });

  it("resets hourly window after 1 hour", () => {
    const budget = new BudgetController({
      maxSatsPerRequest: 5000,
      maxSatsPerHour: 10000,
    });
    budget.recordPayment(8000);

    // Advance 61 minutes
    vi.advanceTimersByTime(61 * 60 * 1000);

    expect(() => budget.check(3000)).not.toThrow();
  });

  it("tracks spent_last_hour correctly", () => {
    const budget = new BudgetController();
    budget.recordPayment(500);
    budget.recordPayment(300);
    expect(budget.spentLastHour()).toBe(800);
  });

  it("tracks spent_last_day correctly", () => {
    const budget = new BudgetController();
    budget.recordPayment(500);

    // Advance 2 hours
    vi.advanceTimersByTime(2 * 60 * 60 * 1000);
    budget.recordPayment(300);

    expect(budget.spentLastDay()).toBe(800);
    expect(budget.spentLastHour()).toBe(300);
  });

  it("enforces domain allowlist", () => {
    const budget = new BudgetController({
      allowedDomains: new Set(["api.example.com"]),
    });
    expect(() => budget.check(100, "api.example.com")).not.toThrow();
    expect(() => budget.check(100, "evil.com")).toThrow(DomainNotAllowedError);
  });

  it("domain allowlist is case-insensitive", () => {
    const budget = new BudgetController({
      allowedDomains: new Set(["API.Example.COM"]),
    });
    expect(() => budget.check(100, "api.example.com")).not.toThrow();
  });

  it("uses sensible defaults", () => {
    const budget = new BudgetController();
    expect(budget.maxSatsPerRequest).toBe(1000);
    expect(budget.maxSatsPerHour).toBe(10000);
    expect(budget.maxSatsPerDay).toBe(50000);
  });

  it("BudgetExceededError contains details", () => {
    const budget = new BudgetController({ maxSatsPerRequest: 100 });
    try {
      budget.check(500);
      expect.unreachable("should have thrown");
    } catch (e) {
      expect(e).toBeInstanceOf(BudgetExceededError);
      const err = e as BudgetExceededError;
      expect(err.limitType).toBe("per_request");
      expect(err.limitSats).toBe(100);
      expect(err.invoiceSats).toBe(500);
    }
  });
});
