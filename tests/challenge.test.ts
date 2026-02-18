import { describe, it, expect } from "vitest";
import { parseChallenge, findL402Challenge } from "../src/challenge.js";
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
