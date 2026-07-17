# Changelog

## 0.6.0

**Security fix — upgrade recommended.** An invoice whose amount could not be read was treated as "no amount to check" and paid anyway, skipping `budget.check()` altogether. That went well beyond the sats limits:

- **The domain allowlist was bypassed.** `allowedDomains` is enforced inside the same `check()` call the missing amount skipped, so an amountless invoice was paid from *any* domain, allowlisted or not.
- **The spend was never recorded.** It never reached the `SpendingLog`, so it stayed out of every later budget check and out of any audit of what the client had already spent — you cannot reconstruct that exposure from the log after the fact.

A server that wanted a blank cheque only had to send an invoice with no amount.

**Breaking:** invoices with no readable amount now throw `InvoiceAmountUnknownError` instead of being paid. If you relied on paying amountless invoices, this release stops that.
