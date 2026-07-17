# Changelog

## 0.6.0

- Fixes budget limits being skipped for invoices with no parseable amount — upgrade recommended. Such invoices are now refused with `InvoiceAmountUnknownError` instead of paid.
