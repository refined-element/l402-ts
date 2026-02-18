import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { CredentialCache } from "../src/credential-cache.js";

describe("CredentialCache", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(new Date("2026-01-15T12:00:00Z"));
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("stores and retrieves credentials", () => {
    const cache = new CredentialCache();
    cache.put("example.com", "/api/v1/data", "mac123", "pre456");
    const cred = cache.get("example.com", "/api/v1/data");
    expect(cred).not.toBeNull();
    expect(cred!.macaroon).toBe("mac123");
    expect(cred!.preimage).toBe("pre456");
  });

  it("returns null for missing credentials", () => {
    const cache = new CredentialCache();
    expect(cache.get("example.com", "/api/v1/data")).toBeNull();
  });

  it("groups paths by first two segments", () => {
    const cache = new CredentialCache();
    cache.put("example.com", "/api/v1/foo", "mac1", "pre1");
    // /api/v1/bar should use the same cached credential
    const cred = cache.get("example.com", "/api/v1/bar");
    expect(cred).not.toBeNull();
    expect(cred!.macaroon).toBe("mac1");
  });

  it("expires credentials after TTL", () => {
    const cache = new CredentialCache({ defaultTtlMs: 60_000 }); // 1 minute
    cache.put("example.com", "/api", "mac", "pre");
    expect(cache.get("example.com", "/api")).not.toBeNull();

    // Advance past TTL
    vi.advanceTimersByTime(61_000);
    expect(cache.get("example.com", "/api")).toBeNull();
  });

  it("evicts oldest when over capacity", () => {
    const cache = new CredentialCache({ maxSize: 2 });
    cache.put("a.com", "/x", "mac1", "pre1");
    cache.put("b.com", "/x", "mac2", "pre2");
    cache.put("c.com", "/x", "mac3", "pre3"); // should evict a.com

    expect(cache.get("a.com", "/x")).toBeNull();
    expect(cache.get("b.com", "/x")).not.toBeNull();
    expect(cache.get("c.com", "/x")).not.toBeNull();
  });

  it("moves accessed items to end (LRU)", () => {
    const cache = new CredentialCache({ maxSize: 2 });
    cache.put("a.com", "/x", "mac1", "pre1");
    cache.put("b.com", "/x", "mac2", "pre2");

    // Access a.com to make it recently used
    cache.get("a.com", "/x");

    // Add new entry, should evict b.com (least recently used)
    cache.put("c.com", "/x", "mac3", "pre3");
    expect(cache.get("a.com", "/x")).not.toBeNull();
    expect(cache.get("b.com", "/x")).toBeNull();
  });

  it("builds authorization header", () => {
    const cred = {
      macaroon: "mac123",
      preimage: "pre456",
      createdAt: Date.now(),
      expiresAt: null,
    };
    expect(CredentialCache.authorizationHeader(cred)).toBe(
      "L402 mac123:pre456",
    );
  });

  it("tracks size correctly", () => {
    const cache = new CredentialCache();
    expect(cache.size).toBe(0);
    cache.put("a.com", "/x", "mac", "pre");
    expect(cache.size).toBe(1);
    cache.clear();
    expect(cache.size).toBe(0);
  });
});
