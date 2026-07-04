# MyInvois integration notes (ported knowledge from dev_mly_einvoice_sync_v11)

Extracted 2026-07-04 from the proven Odoo module. The Rust port keeps
this domain knowledge, replaces the architecture (durable jobs,
encrypted secrets, FileStore evidence, golden-file tests).

## Endpoints
- Identity/API base: prod `https://api.myinvois.hasil.gov.my`,
  sandbox `https://preprod-api.myinvois.hasil.gov.my`
- Portal (validation/QR links): prod `https://myinvois.hasil.gov.my/`,
  preprod `https://preprod.myinvois.hasil.gov.my/`
- OAuth: `POST {base}/connect/token`, x-www-form-urlencoded:
  client_id, client_secret, grant_type=client_credentials,
  scope=InvoicingAPI. Token valid 60min — refresh at 55.
  Intermediary mode: header `onbehalfof: <taxpayer TIN>`.
- Submit: `POST {base}/api/v1.0/documentsubmissions/` — body
  `{"documents":[{"format":"XML","codeNumber":<doc number>,
  "document":<base64 of UTF-8 XML>,"documentHash":<SHA-256 HEX of the
  RAW bytes — not base64, not minified>}]}`. Success = HTTP 202
  (async). Response: submissionUid (casing varies!), accepted/
  rejectedDocuments.
- Poll: `GET /api/v1.0/documentsubmissions/{submissionUid}` →
  overallStatus (InProgress|Valid|Invalid|Partial) + documentSummary[]
  {uuid, longId, status, internalId, error}. ~3s interval, ~30 tries.
- Details (rejection reasons): `GET /api/v1.0/documents/{uuid}/details`
  → validationResults.validationSteps[].error{code,message,
  propertyPath,innerError[]}.
- Raw: `GET /api/v1.0/documents/{uuid}/raw`; search:
  `/api/v1.0/documents/search`; recent: `/api/v1.0/documents/recent`
  (pageSize cap 100, dates `%Y-%m-%dT00:00:00Z`).
- TIN validate: `GET /api/v1.0/taxpayer/validate/{tin}?idType&idValue`.
- **Cancellation NOT in the Odoo module** — greenfield:
  `PUT /api/v1.0/documents/state/{uuid}/state` {status:"cancelled",
  reason}, 72h window.
- Retry: 429 → honor Retry-After (default 60s); 401/403 → refresh
  token once; 5xx → backoff (our job queue provides this). Limits:
  login 12/min, submit 100/min, GetSubmission 300/min.

## Document rules (v1.0, UNSIGNED — the proven path)
- XML UBL 2.1; `listVersionID="1.0"` on cbc:InvoiceTypeCode. v1.1
  requires XAdES RSA-SHA256/PKCS1v15 + C14N11 + cert from Malaysian CA
  (Pos Digicert / MSC Trustgate / Digicert Sdn Bhd; TIN in X.509 OID
  2.5.4.97, BRN in serialNumber) — the Odoo module's signing code was
  never exercised; treat as spec reference only.
- **IssueDate/IssueTime = CURRENT UTC at submission** (Z suffix), NOT
  the accounting date — stale timestamps are rejected.
- Doc type codes: 01 invoice, 02 credit note, 03 debit note, 04 refund
  note, 11–14 self-billed variants (self-billed = swap supplier/buyer).
- Supplier: TIN + second PartyIdentification (schemeID = BRN|NRIC|
  PASSPORT|ARMY), MSIC (IndustryClassificationCode + name=desc),
  address (CountrySubentityCode = LHDN state code, default '17'
  unknown; country listID="ISO3166-1" listAgencyID="6" e.g. MYS),
  phone regex-stripped to [\d+], email.
- Buyer mirror; consolidated B2C buyer: TIN `EI00000000010`, ID type
  BRN value `NA`, name "General Public", postal 00000, state 17,
  monthly one doc with InvoicePeriod.
- Taxes: per-line + doc TaxTotal/TaxSubtotal per (code, rate);
  TaxCategory/ID codes: 01 Sales Tax, 02 Service Tax, E/06 exempt/
  not-applicable; TaxScheme/ID = OTH schemeID="UN/ECE 5153"
  schemeAgencyID="6". Rate-based fallback: 5/10%→01, 6/8%→02, 0%→06.
- Lines: InvoicedQuantity unitCode (C62 fallback; real UN/ECE Rec20
  later), CommodityClassification twice (listID PTC and CLASS, same
  value), OriginCountry MYS, Price/PriceAmount, ItemPriceExtension.
- Totals: LineExtension/TaxExclusive/TaxInclusive/Payable + zero
  Allowance/Charge/PayableRounding, all %.2f w/ currencyID; exchange
  rate block always emitted (CalculationRate 2dp).
- Omit empty optional blocks (Delivery, PaymentMeans, PaymentTerms,
  PrepaidPayment) on normal invoices.
- Validation link = portal_base + uuid + "/share/" + longId (longId
  only exists after Valid).

## Code tables (fetch from https://sdk.myinvois.hasil.gov.my/files/)
ClassificationCodes.json, EInvoiceTypes.json, MSICSubCategoryCodes.json,
PaymentMethods.json, TaxTypes.json, UnitTypes.json, CountryCodes.json,
StateCodes.json. ID types static: BRN, NRIC, PASSPORT, ARMY.
TIN formats seen: companies C###########, individuals IG###########.

## Status mapping (ours)
draft → ready → submitted → valid | invalid (resubmittable after
clearing uuid/submission ids) | cancelled. Keep raw LHDN status +
dateTimeReceived/Validated/cancelDateTime.
