# Changelog

## 0.8.0

**MPP draft-00 client support** (draft-httpauth-payment-00 + draft-lightning-charge-00), additive interop with third-party MPP servers. Existing L402 and legacy `Payment` handling are unchanged.

- **Modern challenge parsing** — `parseMppDraft00Challenge` parses `Payment` challenges carrying a base64url `request` param (`id`/`realm`/`method`/`intent`/`request`/`expires` plus optional `digest`/`description`/`opaque`), including superset headers that also carry legacy `invoice=`/`amount=`/`currency=` params and multi-challenge `WWW-Authenticate` headers. Unknown params are ignored.
- **Precedence** — `findPaymentChallenge` still prefers L402 first, then a modern draft-00 challenge, then the legacy `Payment` profile. A malformed modern challenge only falls back to legacy when the same header carries a legacy `invoice=` param.
- **Modern credential** — `buildMppDraft00Authorization` builds `Authorization: Payment <base64url(JSON)>` with a byte-exact challenge echo and a lowercase-hex preimage payload. `L402Client` uses it on the retry; legacy challenges keep the legacy formats.
- **Receipts** — the `Payment-Receipt` response header is parsed tolerantly (`parsePaymentReceipt`) and exposed as `paymentReceipt` on the returned response.
- **Single-use** — modern credentials are never cached (they are single-use server-side); L402 credential caching is unchanged.
- **Funds safety** — an expired modern challenge throws `ChallengeExpiredError` before any payment, and a modern challenge whose declared amount disagrees with the BOLT11 invoice amount is refused.

## 0.6.1

**Security fix — upgrade recommended.** Completes 0.6.0's "refuse an invoice whose amount can't be positively bounded" guarantee by closing two remaining ways an unbounded or ambiguous invoice could still be paid:

- **Literal-zero invoices.** A BOLT11 invoice encoding a literal `0` amount (e.g. `lnbc0p1...`) decoded to `0`, which slipped past the "no amount" check, passed the budget check, and reached the wallet as an effectively-amountless invoice (the wallet then chooses the actual spend). The resolved amount must now be **strictly positive from every source** (BOLT11 decode and MPP fallback); `0` or negative is refused.
- **Decoder amount injection (HRP-anchoring).** The amount regex was terminated by the first `1`, so a crafted invoice could smuggle digits from the bech32 data part and decode to a bogus positive that passed the budget check with a fabricated number. The amount is now read **only from the human-readable part** (isolated at the true last-`1` separator), so data-part digits can't influence it.

## 0.6.0

**Security fix — upgrade recommended.** An invoice whose amount could not be read was treated as "no amount to check" and paid anyway, skipping `budget.check()` altogether. That went well beyond the sats limits:

- **The domain allowlist was bypassed.** `allowedDomains` is enforced inside the same `check()` call the missing amount skipped, so an amountless invoice was paid from *any* domain, allowlisted or not.
- **The spend was never recorded.** It never reached the `SpendingLog`, so it stayed out of every later budget check and out of any audit of what the client had already spent — you cannot reconstruct that exposure from the log after the fact.

A server that wanted a blank cheque only had to send an invoice with no amount.

**Breaking:** invoices with no readable amount now throw `InvoiceAmountUnknownError` instead of being paid. If you relied on paying amountless invoices, this release stops that.
