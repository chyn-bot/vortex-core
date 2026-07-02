# vortex-accounting — Generic Accounting Base

The platform's double-entry accounting primitive. Other modules (purchase, inventory
valuation, highway tenancy billing, future verticals) **adopt** it through a small
service API instead of inventing their own charge/invoice tables.

Fills the gap the commerce module explicitly deferred ("no journal entries, no chart
of accounts — that's a Finance plugin"). Composes: commerce (currencies, taxes),
core `contacts` (customers/vendors), sequences, WORM audit, list framework, reports.

## Design decisions

1. **Unified move model (Odoo-proven).** One `acc_move` table is *both* the journal
   entry and the AR/AP document — an invoice is a move with `move_type =
   'customer_invoice'` plus partner/due-date/total columns. One posting engine, one
   numbering scheme, one immutability rule; AR/AP never drifts from the GL.
2. **Posted = immutable; corrections are reversals.** DB triggers reject
   UPDATE/DELETE on posted moves/lines (allow-list: payment/reconciliation
   bookkeeping columns). `reverse_move()` creates the counter-entry. Aligned with the
   WORM/regulated-industry posture — no Odoo-style "reset to draft".
3. **Balance enforced at posting, in one transaction.** `post_move()` validates
   Σdebit = Σcredit (and ≥ 2 lines), assigns the journal-type sequence number
   (`SAL/2026/00042`), flips state, writes the WORM audit entry.
4. **Flat chart of accounts** (no hierarchy), typed by `account_type` (drives
   P&L/balance-sheet grouping and AR/AP resolution). Generic ~20-account CoA +
   5 journals (SAL/PUR/BNK/CSH/GEN) seeded idempotently, tenant-editable.
5. **Company-currency amounts in v1.** `debit`/`credit` are company-currency;
   `currency_id`/`amount_currency` columns exist on lines for display and future FX;
   commerce `convert_amount` is the hook. No revaluation in v1.
6. **Reconciliation via `acc_partial_reconcile`** (debit-line ↔ credit-line, amount) —
   Phase 2, powers payment allocation, `amount_residual`, aged AR/AP.
7. **No fiscal periods in v1** — a per-company `lock_date` in `acc_config` blocks
   posting/reversal on or before it. Full period tables can come later.

## Schema (prefix `acc_`)

| Table | Purpose | Phase |
|---|---|---|
| `acc_account` | CoA: code, name, `account_type` (13 CHECK values), `reconcile` flag, active | 1 |
| `acc_journal` | code, name, `journal_type` (sale/purchase/cash/bank/general), default accounts | 1 |
| `acc_move` | number, journal, date, ref, narration, `state` draft/posted/cancelled, `move_type` (entry/customer_invoice/customer_credit_note/vendor_bill/vendor_credit_note/payment), partner_id, invoice_date, due_date, currency_id, untaxed/tax/total, amount_residual, payment_state | 1 (+invoice cols used in 2) |
| `acc_move_line` | move FK, account, partner, label, debit ≥ 0, credit ≥ 0 (not both), tax_id, reconciled flag | 1 |
| `acc_config` | per-company defaults: AR/AP/tax/income/expense accounts, lock_date | 1 |
| `acc_invoice_line` | document lines (qty × price × tax) that expand into GL lines on posting | 2 |
| `acc_partial_reconcile` | debit_line ↔ credit_line, amount | 2 |

Integrity in SQL: `chk_debit_credit` (one side only, both ≥ 0), posted-immutability
triggers, `uq_acc_move_number (company_id, number)`, runtime-role grants, registry
migration for `/api/v1` + webhooks.

## Service API (what other modules call)

```rust
// Phase 1 — GL
pub struct MoveLine { account_id, partner_id, name, debit, credit }
create_move(pool, company, user, journal_code, date, ref, narration, &[MoveLine]) -> Uuid   // draft
post_move(pool, audit?, db_name, move_id, user) -> String                                   // number
create_and_post(...) -> (Uuid, String)
reverse_move(pool, ..., move_id, date, user) -> Uuid
account_by_type(pool, company, "asset_receivable") -> Uuid                                  // config-first lookup

// Phase 2 — documents
create_invoice(pool, company, user, partner, move_type, journal_code, dates, currency, &[InvoiceLine]) -> Uuid
post_invoice(...)            // expands doc lines → AR/AP + income/expense + tax GL lines, posts
register_payment(pool, ..., partner, journal_code, amount, date, allocate: &[Uuid]) -> Uuid // payment move + reconcile
```

Adoption examples: highway `hwy_tenancy_charge` → `create_invoice(customer_invoice)`;
purchase vendor bill → `create_invoice(vendor_bill)`; inventory valuation → plain
`create_and_post` on GEN.

## UI & reports

- Phase 1: `/accounting` journal-entries list · manual entry form (header + add-line
  + post, purchase-style) · move detail w/ audit trail · CoA + Journals config pages.
- Phase 3: Trial Balance, General Ledger (account drill), Aged Receivables/Payables,
  P&L + Balance Sheet (grouped by `account_type`) as `ReportDef`s (HTML/CSV, PDF via
  feature).

## Phases

1. **GL core** — migration 001 (+seed), posting service, entries/CoA/journals UI,
   registration in server.rs + db.rs. *(this build)*
2. **AR/AP** — invoice/bill/credit-note documents, payments, reconciliation,
   payment_state/residual, partner ledger.
3. **Reports + API** — the five reports, registry migration, translations (en/ms).

Sequences: const specs per journal type — `accounting.move.sal` → `SAL/2026/#####`
(yearly scope), etc. Roles: reuse platform roles for now; an `accounting_manager`
role gate on post/reverse can layer on via StageActions later if needed.
