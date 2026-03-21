import { describe, it, expect } from "vitest";
import {
  parseChallenge,
  findL402Challenge,
  parseMppChallenge,
  findPaymentChallenge,
} from "../src/challenge.js";
import { ChallengeParseError } from "../src/errors.js";

describe("parseChallenge", () => {
  it("parses L402 with quoted values", () => {
    const header = 'L402 macaroon="abc123", invoice="lnbc10u1p..."';
    const result = parseChallenge(header);
    expect(result.macaroon).toBe("abc123");
    expect(result.invoice).toBe("lnbc10u1p...");
  });

  it("parses L402 with unquoted values", () => {
    const header = "L402 macaroon=abc123, invoice=lnbc10u1p...";
    const result = parseChallenge(header);
    expect(result.macaroon).toBe("abc123");
    expect(result.invoice).toBe("lnbc10u1p...");
  });

  it("parses LSAT for backwards compatibility", () => {
    const header = 'LSAT macaroon="abc123", invoice="lnbc10u1p..."';
    const result = parseChallenge(header);
    expect(result.macaroon).toBe("abc123");
    expect(result.invoice).toBe("lnbc10u1p...");
  });

  it("is case-insensitive for scheme", () => {
    const header = 'l402 macaroon="abc123", invoice="lnbc10u1p..."';
    const result = parseChallenge(header);
    expect(result.macaroon).toBe("abc123");
  });

  it("throws ChallengeParseError for empty header", () => {
    expect(() => parseChallenge("")).toThrow(ChallengeParseError);
  });

  it("throws ChallengeParseError for non-L402 header", () => {
    expect(() => parseChallenge("Bearer token=abc")).toThrow(
      ChallengeParseError,
    );
  });

  it("throws ChallengeParseError for incomplete challenge", () => {
    expect(() => parseChallenge('L402 macaroon="abc123"')).toThrow(
      ChallengeParseError,
    );
  });
});

describe("findL402Challenge", () => {
  it("finds challenge in Headers object", () => {
    const headers = new Headers({
      "www-authenticate": 'L402 macaroon="mac123", invoice="lnbc1..."',
    });
    const result = findL402Challenge(headers);
    expect(result).not.toBeNull();
    expect(result!.macaroon).toBe("mac123");
  });

  it("finds challenge in plain object (case-insensitive)", () => {
    const headers = {
      "WWW-Authenticate": 'L402 macaroon="mac123", invoice="lnbc1..."',
    };
    const result = findL402Challenge(headers);
    expect(result).not.toBeNull();
    expect(result!.macaroon).toBe("mac123");
  });

  it("returns null when no www-authenticate header", () => {
    const headers = { "content-type": "application/json" };
    expect(findL402Challenge(headers)).toBeNull();
  });
});

describe("parseMppChallenge", () => {
  it("parses valid Payment header with all fields", () => {
    const header =
      'Payment realm="api.example.com", method="lightning", invoice="lnbc100n1pjtest", amount="100", currency="sat"';
    const result = parseMppChallenge(header);
    expect(result.invoice).toBe("lnbc100n1pjtest");
    expect(result.amount).toBe("100");
    expect(result.realm).toBe("api.example.com");
  });

  it("parses minimal header (method + invoice only)", () => {
    const result = parseMppChallenge(
      'Payment method="lightning", invoice="lnbc100n1pjtest"',
    );
    expect(result.invoice).toBe("lnbc100n1pjtest");
    expect(result.amount).toBeUndefined();
    expect(result.realm).toBeUndefined();
  });

  it("is case-insensitive for scheme and method", () => {
    const header =
      'PAYMENT METHOD="LIGHTNING", invoice="lnbc100n1pjtest"';
    const result = parseMppChallenge(header);
    expect(result.invoice).toBe("lnbc100n1pjtest");
  });

  it("rejects non-lightning method", () => {
    expect(() =>
      parseMppChallenge(
        'Payment method="stripe", invoice="lnbc100n1pjtest"',
      ),
    ).toThrow(ChallengeParseError);
  });

  it("rejects missing invoice", () => {
    expect(() =>
      parseMppChallenge('Payment method="lightning", amount="100"'),
    ).toThrow(ChallengeParseError);
  });

  it("rejects empty header", () => {
    expect(() => parseMppChallenge("")).toThrow(ChallengeParseError);
  });

  it("rejects null/undefined header", () => {
    expect(() => parseMppChallenge(null as unknown as string)).toThrow(
      ChallengeParseError,
    );
    expect(() => parseMppChallenge(undefined as unknown as string)).toThrow(
      ChallengeParseError,
    );
  });

  it("handles field ordering variations", () => {
    const header =
      'Payment invoice="lnbc200n1pjtest", method="lightning", realm="test.com", amount="200"';
    const result = parseMppChallenge(header);
    expect(result.invoice).toBe("lnbc200n1pjtest");
    expect(result.amount).toBe("200");
    expect(result.realm).toBe("test.com");
  });

  it("parses unquoted param values", () => {
    const header =
      "Payment method=lightning, invoice=lnbc300n1pjtest, amount=300";
    const result = parseMppChallenge(header);
    expect(result.invoice).toBe("lnbc300n1pjtest");
    expect(result.amount).toBe("300");
  });

  it("parses Payment challenge from comma-concatenated header", () => {
    const header =
      'Bearer realm="api", Payment method="lightning", invoice="lnbc400n1pjtest"';
    const result = parseMppChallenge(header);
    expect(result.invoice).toBe("lnbc400n1pjtest");
  });
});

describe("findPaymentChallenge", () => {
  it("prefers L402 when header contains L402 challenge", () => {
    const headers = {
      "www-authenticate":
        'L402 macaroon="abc", invoice="lnbc100n1pjtest"',
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("macaroon" in result!).toBe(true);
  });

  it("falls back to MPP when L402 not present", () => {
    const headers = {
      "www-authenticate":
        'Payment method="lightning", invoice="lnbc100n1pjtest"',
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("macaroon" in result!).toBe(false);
    expect(result!.invoice).toBe("lnbc100n1pjtest");
  });

  it("returns null for unknown scheme", () => {
    const headers = { "www-authenticate": "Bearer token123" };
    expect(findPaymentChallenge(headers)).toBeNull();
  });

  it("returns null when no www-authenticate header", () => {
    const headers = { "content-type": "application/json" };
    expect(findPaymentChallenge(headers)).toBeNull();
  });

  it("works with Headers object for L402", () => {
    const headers = new Headers({
      "www-authenticate":
        'L402 macaroon="mac123", invoice="lnbc1..."',
    });
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("macaroon" in result!).toBe(true);
  });

  it("works with Headers object for MPP", () => {
    const headers = new Headers({
      "www-authenticate":
        'Payment method="lightning", invoice="lnbc1..."',
    });
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect("macaroon" in result!).toBe(false);
  });

  it("handles case-insensitive header keys in plain objects", () => {
    const headers = {
      "WWW-Authenticate":
        'Payment method="lightning", invoice="lnbc100n1pjtest"',
    };
    const result = findPaymentChallenge(headers);
    expect(result).not.toBeNull();
    expect(result!.invoice).toBe("lnbc100n1pjtest");
  });
});
