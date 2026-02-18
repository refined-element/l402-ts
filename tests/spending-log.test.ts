import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { SpendingLog } from "../src/spending-log.js";

describe("SpendingLog", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-15T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("records payments and tracks total", () => {
    const log = new SpendingLog();
    log.record("a.com", "/api", 500, "pre1");
    log.record("b.com", "/api", 300, "pre2");
    expect(log.totalSpent()).toBe(800);
    expect(log.length).toBe(2);
  });

  it("excludes failed payments from totals", () => {
    const log = new SpendingLog();
    log.record("a.com", "/api", 500, "pre1", true);
    log.record("b.com", "/api", 300, "", false);
    expect(log.totalSpent()).toBe(500);
  });

  it("tracks spending by domain", () => {
    const log = new SpendingLog();
    log.record("a.com", "/api", 500, "pre1");
    log.record("a.com", "/api/v2", 200, "pre2");
    log.record("b.com", "/api", 300, "pre3");

    const byDomain = log.byDomain();
    expect(byDomain["a.com"]).toBe(700);
    expect(byDomain["b.com"]).toBe(300);
  });

  it("tracks hourly spending", () => {
    const log = new SpendingLog();
    log.record("a.com", "/api", 500, "pre1");

    // Advance 2 hours
    vi.advanceTimersByTime(2 * 60 * 60 * 1000);
    log.record("a.com", "/api", 300, "pre2");

    expect(log.spentLastHour()).toBe(300);
    expect(log.spentToday()).toBe(800);
  });

  it("serializes to JSON", () => {
    const log = new SpendingLog();
    log.record("a.com", "/api", 500, "pre1");
    const json = log.toJSON();
    const parsed = JSON.parse(json);
    expect(parsed).toHaveLength(1);
    expect(parsed[0].domain).toBe("a.com");
    expect(parsed[0].amountSats).toBe(500);
  });

  it("returns copies of records", () => {
    const log = new SpendingLog();
    log.record("a.com", "/api", 500, "pre1");
    const records = log.records;
    expect(records).toHaveLength(1);
    // Modifying the copy should not affect the log
    records.pop();
    expect(log.records).toHaveLength(1);
  });
});
