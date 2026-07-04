//! End-to-end lifecycle test against a live Postgres database.
//!
//! Skipped unless `ACC_TEST_DATABASE_URL` is set (point it at a tenant DB
//! that has core + accounting migrations applied, e.g. the `acc_test`
//! scratch database):
//!
//! ```sh
//! ACC_TEST_DATABASE_URL=postgres://remicle:…@localhost/acc_test \
//!     cargo test -p vortex-accounting --test lifecycle
//! ```
//!
//! Covers: GL create→post→number, posted immutability, reversal, invoice
//! create→post (GL expansion incl. tax), partial + final payment with
//! reconciliation, and the lock-date gate.

use vortex_accounting::documents::{
    self, InvoiceLine, NewInvoice, NewPayment, PaymentDirection,
};
use vortex_accounting::service::{self, MoveLine, NewMove};
use vortex_plugin_sdk::chrono::Utc;
use vortex_plugin_sdk::orm::connection::{ConnectionPool, DatabaseConfig};
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use rust_decimal_macros::dec;

async fn setup() -> Option<(PgPool, ConnectionPool, Uuid, Uuid)> {
    let Ok(url) = std::env::var("ACC_TEST_DATABASE_URL") else {
        eprintln!("ACC_TEST_DATABASE_URL not set — skipping accounting lifecycle test");
        return None;
    };
    let db = PgPool::connect(&url).await.expect("connect PgPool");
    let seq_pool = ConnectionPool::new(DatabaseConfig {
        url: url.clone(),
        min_connections: 1,
        max_connections: 4,
        ..DatabaseConfig::default()
    })
    .await
    .expect("connect ConnectionPool");

    // A user to attribute writes to (any existing user, else a seeded one).
    let user_id: Uuid = match vortex_plugin_sdk::sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM users LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .expect("query users")
    {
        Some(u) => u,
        None => vortex_plugin_sdk::sqlx::query_scalar(
            "INSERT INTO users (username, email, password_hash) \
             VALUES ('acc_test', 'acc_test@example.com', 'x') RETURNING id",
        )
        .fetch_one(&db)
        .await
        .expect("seed user"),
    };

    // A fresh partner per run keeps assertions isolated. contacts.company_id
    // is NOT NULL, so attach it to the first company (seeded by core).
    let company_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM companies ORDER BY created_at LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .expect("default company");
    let suffix = &Uuid::new_v4().simple().to_string()[..8];
    let partner_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO contacts (name, contact_type, company_id, active) \
         VALUES ($1, 'customer', $2, TRUE) RETURNING id",
    )
    .bind(format!("Lifecycle Tenant {suffix}"))
    .bind(company_id)
    .fetch_one(&db)
    .await
    .expect("seed partner");

    Some((db, seq_pool, user_id, partner_id))
}

async fn line_sums(db: &PgPool, move_id: Uuid) -> (Decimal, Decimal, i64) {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(SUM(debit),0) AS d, COALESCE(SUM(credit),0) AS c, COUNT(*) AS n \
         FROM acc_move_line WHERE move_id = $1",
    )
    .bind(move_id)
    .fetch_one(db)
    .await
    .unwrap();
    (row.get("d"), row.get("c"), row.get("n"))
}

async fn move_field<T>(db: &PgPool, move_id: Uuid, field: &str) -> T
where
    T: for<'r> vortex_plugin_sdk::sqlx::Decode<'r, vortex_plugin_sdk::sqlx::Postgres>
        + vortex_plugin_sdk::sqlx::Type<vortex_plugin_sdk::sqlx::Postgres>
        + Send
        + Unpin,
{
    vortex_plugin_sdk::sqlx::query_scalar(&format!(
        "SELECT {field} FROM acc_move WHERE id = $1"
    ))
    .bind(move_id)
    .fetch_one(db)
    .await
    .unwrap()
}

#[tokio::test]
async fn full_gl_and_document_lifecycle() {
    let Some((db, seq_pool, user_id, partner_id)) = setup().await else {
        return;
    };
    let today = Utc::now().date_naive();
    let expense = service::account_by_code(&db, None, "6100").await.unwrap().unwrap();
    let inventory = service::account_by_code(&db, None, "1300").await.unwrap().unwrap();

    // ── 1. GL: create + post a balanced entry ────────────────────────────
    let (entry_id, number) = service::create_and_post(
        &db,
        &seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: today,
            move_type: "entry",
            ref_: Some("TEST/GL"),
            narration: Some("Lifecycle test entry"),
            partner_id: None,
            origin_ref: Some("lifecycle_test:gl"),
            company_id: None,
            lines: vec![
                MoveLine::debit(expense, dec!(150.00), Some("Parts")),
                MoveLine::credit(inventory, dec!(150.00), Some("Parts")),
            ],
        },
    )
    .await
    .expect("create_and_post");
    assert!(number.starts_with("GEN/"), "unexpected number {number}");
    let state: String = move_field(&db, entry_id, "state").await;
    assert_eq!(state, "posted");

    // ── 2. Unbalanced entries must not post ──────────────────────────────
    let err = service::create_and_post(
        &db,
        &seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: today,
            move_type: "entry",
            ref_: None,
            narration: None,
            partner_id: None,
            origin_ref: None,
            company_id: None,
            lines: vec![
                MoveLine::debit(expense, dec!(100.00), None),
                MoveLine::credit(inventory, dec!(99.00), None),
            ],
        },
    )
    .await;
    assert!(err.is_err(), "unbalanced entry must be rejected");

    // ── 3. Posted entries are immutable at the DB level ──────────────────
    let tamper = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move_line SET debit = debit + 1 WHERE move_id = $1 AND debit > 0",
    )
    .bind(entry_id)
    .execute(&db)
    .await;
    assert!(tamper.is_err(), "posted line edit must be rejected by trigger");

    // ── 4. Reversal creates a posted counter-entry ───────────────────────
    let reversal_id = service::reverse_move(&db, &seq_pool, entry_id, today, user_id)
        .await
        .expect("reverse_move");
    let (rd, rc, rn) = line_sums(&db, reversal_id).await;
    assert_eq!(rn, 2);
    assert_eq!(rd, dec!(150.00));
    assert_eq!(rc, dec!(150.00));
    let orig_payment_state: String = move_field(&db, entry_id, "payment_state").await;
    assert_eq!(orig_payment_state, "reversed");

    // ── 5. Invoice: two lines, one taxed at 10% ──────────────────────────
    let tax_id: Uuid = match vortex_plugin_sdk::sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM taxes WHERE name = 'Lifecycle 10%'",
    )
    .fetch_optional(&db)
    .await
    .unwrap()
    {
        Some(t) => t,
        None => vortex_plugin_sdk::sqlx::query_scalar(
            "INSERT INTO taxes (name, amount_type, amount, type_tax_use, price_include, active) \
             VALUES ('Lifecycle 10%', 'percent', 10, 'sale', FALSE, TRUE) RETURNING id",
        )
        .fetch_one(&db)
        .await
        .expect("seed tax"),
    };

    let invoice_id = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: today,
            due_date: Some(today),
            journal_code: None,
            currency_id: None,
            origin_ref: Some("lifecycle_test:invoice"),
            narration: None,
            company_id: None,
            lines: vec![
                InvoiceLine::new("Monthly rent", dec!(1), dec!(3000.00)),
                InvoiceLine::new("Utilities recharge", dec!(1), dec!(500.00)).with_tax(tax_id),
            ],
        },
    )
    .await
    .expect("create_invoice");

    // untaxed 3500, tax 50, total 3550
    let untaxed: Decimal = move_field(&db, invoice_id, "untaxed_amount").await;
    let tax: Decimal = move_field(&db, invoice_id, "tax_amount").await;
    let total: Decimal = move_field(&db, invoice_id, "total_amount").await;
    assert_eq!(untaxed, dec!(3500.00));
    assert_eq!(tax, dec!(50.00));
    assert_eq!(total, dec!(3550.00));

    let inv_number = documents::post_invoice(&db, &seq_pool, invoice_id, user_id)
        .await
        .expect("post_invoice");
    assert!(inv_number.starts_with("SAL/"), "unexpected number {inv_number}");

    // GL expansion: AR debit 3550 | income credits 3500 | tax credit 50
    let (d, c, n) = line_sums(&db, invoice_id).await;
    assert_eq!(d, dec!(3550.00));
    assert_eq!(c, dec!(3550.00));
    assert_eq!(n, 4); // AR + 2 income + tax
    let residual: Decimal = move_field(&db, invoice_id, "amount_residual").await;
    assert_eq!(residual, dec!(3550.00));
    let pstate: String = move_field(&db, invoice_id, "payment_state").await;
    assert_eq!(pstate, "not_paid");

    // ── 6. Partial payment ───────────────────────────────────────────────
    documents::register_payment(
        &db,
        &seq_pool,
        user_id,
        &NewPayment {
            partner_id,
            direction: PaymentDirection::Inbound,
            journal_code: "BNK",
            currency_code: None,
            amount: dec!(2000.00),
            payment_date: today,
            memo: Some("First instalment"),
            company_id: None,
            allocate_to: vec![invoice_id],
        },
    )
    .await
    .expect("partial payment");
    let residual: Decimal = move_field(&db, invoice_id, "amount_residual").await;
    assert_eq!(residual, dec!(1550.00));
    let pstate: String = move_field(&db, invoice_id, "payment_state").await;
    assert_eq!(pstate, "partial");

    // ── 7. Final payment settles the document ────────────────────────────
    documents::register_payment(
        &db,
        &seq_pool,
        user_id,
        &NewPayment {
            partner_id,
            direction: PaymentDirection::Inbound,
            journal_code: "BNK",
            currency_code: None,
            amount: dec!(1550.00),
            payment_date: today,
            memo: Some("Balance"),
            company_id: None,
            allocate_to: vec![invoice_id],
        },
    )
    .await
    .expect("final payment");
    let residual: Decimal = move_field(&db, invoice_id, "amount_residual").await;
    assert_eq!(residual, dec!(0.00));
    let pstate: String = move_field(&db, invoice_id, "payment_state").await;
    assert_eq!(pstate, "paid");
    let reconciled: bool = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT l.reconciled FROM acc_move_line l JOIN acc_account a ON a.id = l.account_id \
         WHERE l.move_id = $1 AND a.reconcile",
    )
    .bind(invoice_id)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(reconciled, "settled AR line must be flagged reconciled");

    // ── 8. Lock date blocks back-dated posting ───────────────────────────
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_config SET lock_date = CURRENT_DATE WHERE company_id IS NULL",
    )
    .execute(&db)
    .await
    .unwrap();
    let locked = service::create_and_post(
        &db,
        &seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: today, // == lock_date → must be rejected
            move_type: "entry",
            ref_: None,
            narration: None,
            partner_id: None,
            origin_ref: None,
            company_id: None,
            lines: vec![
                MoveLine::debit(expense, dec!(10.00), None),
                MoveLine::credit(inventory, dec!(10.00), None),
            ],
        },
    )
    .await;
    assert!(locked.is_err(), "posting on the lock date must be rejected");
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_config SET lock_date = NULL WHERE company_id IS NULL",
    )
    .execute(&db)
    .await
    .unwrap();

    println!("lifecycle OK: entry {number}, reversal {reversal_id}, invoice {inv_number}");
}

// ═════════════════════════════════════════════════════════════════════════
// Phase 1: Malaysian tax engine + fiscal calendar
// ═════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn malaysian_tax_engine() {
    let Some((db, seq_pool, user_id, partner_id)) = setup().await else {
        return;
    };
    // The sibling test opens a lock_date == today window; everything here
    // is dated tomorrow / far-future so the two tests cannot interfere.
    let today = Utc::now().date_naive();
    let doc_date = today + vortex_plugin_sdk::chrono::Duration::days(1);

    // ── Multi-rate invoice: one GL tax line PER TAX, with base ──────────
    let st8: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM taxes WHERE name = 'Service Tax 8%'",
    )
    .fetch_one(&db)
    .await
    .expect("Service Tax 8% seeded by migration 004");
    let st6: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM taxes WHERE name = 'Service Tax 6%'",
    )
    .fetch_one(&db)
    .await
    .expect("Service Tax 6% seeded");

    let inv = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: doc_date,
            due_date: None,
            journal_code: None,
            currency_id: None,
            origin_ref: Some("test_mytax:multirate"),
            narration: None,
            company_id: None,
            lines: vec![
                InvoiceLine::new("Consulting", dec!(1), dec!(1000.00)).with_tax(st8),
                InvoiceLine::new("Logistics", dec!(1), dec!(500.00)).with_tax(st6),
                InvoiceLine::new("Untaxed disbursement", dec!(1), dec!(100.00)),
            ],
        },
    )
    .await
    .expect("create multi-rate invoice");
    documents::post_invoice(&db, &seq_pool, inv, user_id)
        .await
        .expect("post multi-rate invoice");

    // Header: 1600 untaxed + 80 + 30 tax = 1710 total.
    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT untaxed_amount, tax_amount, total_amount FROM acc_move WHERE id = $1",
    )
    .bind(inv)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(head.get::<Decimal, _>("untaxed_amount"), dec!(1600.00));
    assert_eq!(head.get::<Decimal, _>("tax_amount"), dec!(110.00));
    assert_eq!(head.get::<Decimal, _>("total_amount"), dec!(1710.00));

    // GL: AR + 3 revenue lines + 2 tax lines = 6, balanced.
    let (d, c, n) = line_sums(&db, inv).await;
    assert_eq!(n, 6, "AR + 3 doc lines + 2 per-tax lines");
    assert_eq!(d, c, "balanced");

    // Tax lines carry tax_id + tax_base_amount and hit the SST account.
    let tax_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT t.name, l.credit, l.tax_base_amount, a.code AS account_code \
         FROM acc_move_line l JOIN taxes t ON t.id = l.tax_id \
         JOIN acc_account a ON a.id = l.account_id \
         WHERE l.move_id = $1 ORDER BY t.name",
    )
    .bind(inv)
    .fetch_all(&db)
    .await
    .unwrap();
    assert_eq!(tax_lines.len(), 2);
    assert_eq!(tax_lines[0].get::<String, _>("name"), "Service Tax 6%");
    assert_eq!(tax_lines[0].get::<Decimal, _>("credit"), dec!(30.00));
    assert_eq!(tax_lines[0].get::<Option<Decimal>, _>("tax_base_amount"), Some(dec!(500.00)));
    assert_eq!(tax_lines[0].get::<String, _>("account_code"), "2110");
    assert_eq!(tax_lines[1].get::<String, _>("name"), "Service Tax 8%");
    assert_eq!(tax_lines[1].get::<Decimal, _>("credit"), dec!(80.00));
    assert_eq!(tax_lines[1].get::<Option<Decimal>, _>("tax_base_amount"), Some(dec!(1000.00)));

    // ── SST-02 aggregation reads it back off the GL ─────────────────────
    let rows = vortex_accounting::tax::sst_return(&db, None, doc_date, doc_date)
        .await
        .expect("sst_return");
    let st8_row = rows
        .iter()
        .find(|r| r.sst_category == "service_tax_8" && r.direction == "output")
        .expect("service_tax_8 output row");
    assert!(st8_row.taxable_value >= dec!(1000.00));
    assert!(st8_row.tax_amount >= dec!(80.00));

    // ── Closed fiscal year blocks posting ────────────────────────────────
    // Far future: outside any lock_date the sibling test sets.
    let fy_from = today + vortex_plugin_sdk::chrono::Duration::days(3650);
    let fy_to = today + vortex_plugin_sdk::chrono::Duration::days(3656);
    let fy_post_date = today + vortex_plugin_sdk::chrono::Duration::days(3652);
    let fy_code = format!("FYTEST{}", &Uuid::new_v4().simple().to_string()[..6]);
    let fy_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_fiscal_year (code, date_from, date_to, state) \
         VALUES ($1, $2, $3, 'closed') RETURNING id",
    )
    .bind(&fy_code)
    .bind(fy_from)
    .bind(fy_to)
    .fetch_one(&db)
    .await
    .unwrap();

    let suspense: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '9999' LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let sales: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '4000' LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();

    let blocked = service::create_and_post(
        &db,
        &seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: fy_post_date,
            move_type: "entry",
            ref_: Some("should be blocked"),
            narration: None,
            partner_id: None,
            origin_ref: None,
            company_id: None,
            lines: vec![
                MoveLine::debit(suspense, dec!(10), Some("test")),
                MoveLine::credit(sales, dec!(10), Some("test")),
            ],
        },
    )
    .await;
    assert!(blocked.is_err(), "posting into a closed fiscal year must fail");
    let msg = format!("{:?}", blocked.err());
    assert!(msg.contains("closed"), "error should name the closed year: {msg}");

    // Reopen so later tests in this DB aren't blocked, then verify posting works.
    vortex_plugin_sdk::sqlx::query("UPDATE acc_fiscal_year SET state = 'open' WHERE id = $1")
        .bind(fy_id)
        .execute(&db)
        .await
        .unwrap();
    service::create_and_post(
        &db,
        &seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: fy_post_date,
            move_type: "entry",
            ref_: Some("open year posts fine"),
            narration: None,
            partner_id: None,
            origin_ref: None,
            company_id: None,
            lines: vec![
                MoveLine::debit(suspense, dec!(10), Some("test")),
                MoveLine::credit(sales, dec!(10), Some("test")),
            ],
        },
    )
    .await
    .expect("posting into an open year succeeds");
}

// ═════════════════════════════════════════════════════════════════════════
// Phase 2: MyInvois e-invoicing (portal path, DB-only — no LHDN creds)
// ═════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn einvoice_payload_and_lifecycle() {
    let Some((db, seq_pool, user_id, partner_id)) = setup().await else {
        return;
    };
    let today = Utc::now().date_naive();
    let doc_date = today + vortex_plugin_sdk::chrono::Duration::days(1);

    // Company + partner tax identity (what Settings/Profiles capture).
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_config SET company_tin = 'C1234567890', company_id_type = 'BRN', \
                company_id_value = '202301012345', company_msic_code = '62010', \
                company_business_activity = 'Software', company_city = 'Kuala Lumpur', \
                company_postcode = '50480', company_state_code = '14' \
         WHERE company_id IS NULL",
    )
    .execute(&db)
    .await
    .unwrap();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_partner_tax_profile (contact_id, tin, id_type, id_value, state_code) \
         VALUES ($1, 'C9876543210', 'BRN', '201501054321', '10') \
         ON CONFLICT DO NOTHING",
    )
    .bind(partner_id)
    .execute(&db)
    .await
    .unwrap();

    let st8: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM taxes WHERE name = 'Service Tax 8%'",
    )
    .fetch_one(&db)
    .await
    .unwrap();

    let inv = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: doc_date,
            due_date: None,
            journal_code: None,
            currency_id: None,
            origin_ref: Some("test_einvoice:1"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Consulting", dec!(1), dec!(1000.00)).with_tax(st8)],
        },
    )
    .await
    .unwrap();
    let number = documents::post_invoice(&db, &seq_pool, inv, user_id).await.unwrap();

    // ensure → row in 'ready'
    let einv = vortex_accounting::einvois::flow::ensure_einvoice(&db, inv)
        .await
        .unwrap()
        .expect("customer invoice is e-invoiceable");
    let status: String = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT status FROM acc_einvoice WHERE id = $1",
    )
    .bind(einv)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(status, "ready");

    // payload → UBL XML with the ledger's numbers and identities
    let (_, doc) = vortex_accounting::einvois::flow::payload_for(&db, inv).await.unwrap();
    assert_eq!(doc.doc_type_code, "01");
    assert_eq!(doc.number, number);
    assert_eq!(doc.supplier.tin, "C1234567890");
    assert_eq!(doc.buyer.tin, "C9876543210");
    assert_eq!(doc.tax_subtotals.len(), 1);
    assert_eq!(doc.tax_subtotals[0].code, "02"); // service tax
    let xml = vortex_accounting::einvois::ubl::build_xml(&doc);
    assert!(xml.contains(&format!("<cbc:ID>{number}</cbc:ID>")));
    assert!(xml.contains(r#"listVersionID="1.0""#));
    assert!(xml.contains(r#"<cbc:TaxInclusiveAmount currencyID="MYR">1080.00</cbc:TaxInclusiveAmount>"#));
    // documentHash convention: sha256 hex of the raw bytes
    let hash = vortex_accounting::einvois::sha256_hex(xml.as_bytes());
    assert_eq!(hash.len(), 64);

    // Partner opt-out routes to consolidated (no individual e-invoice)
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_partner_tax_profile SET einvoice_optout = true WHERE contact_id = $1",
    )
    .bind(partner_id)
    .execute(&db)
    .await
    .unwrap();
    let inv2 = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: doc_date,
            due_date: None,
            journal_code: None,
            currency_id: None,
            origin_ref: Some("test_einvoice:2"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Opt-out sale", dec!(1), dec!(50.00))],
        },
    )
    .await
    .unwrap();
    documents::post_invoice(&db, &seq_pool, inv2, user_id).await.unwrap();
    let none = vortex_accounting::einvois::flow::ensure_einvoice(&db, inv2).await.unwrap();
    assert!(none.is_none(), "opted-out partners get no individual e-invoice");

    // restore for other tests
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_partner_tax_profile SET einvoice_optout = false WHERE contact_id = $1",
    )
    .bind(partner_id)
    .execute(&db)
    .await
    .unwrap();
}

// ═════════════════════════════════════════════════════════════════════════
// Phase 3: Multi-currency (MFRS 121)
// ═════════════════════════════════════════════════════════════════════════

#[tokio::test]
async fn multicurrency_fx_lifecycle() {
    let Some((db, seq_pool, user_id, partner_id)) = setup().await else {
        return;
    };
    let today = Utc::now().date_naive();
    let doc_date = today + vortex_plugin_sdk::chrono::Duration::days(2);
    let pay_date = today + vortex_plugin_sdk::chrono::Duration::days(4);

    // USD currency + rates: 1 USD = RM 4.70 on doc date, RM 4.60 on pay date.
    // Commerce stores units-per-MYR: 1/4.70 and 1/4.60.
    let usd: Uuid = match vortex_plugin_sdk::sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM currencies WHERE code = 'USD'",
    )
    .fetch_optional(&db)
    .await
    .unwrap()
    {
        Some(id) => id,
        None => vortex_plugin_sdk::sqlx::query_scalar(
            "INSERT INTO currencies (code, name, symbol, decimal_places, rounding, active) \
             VALUES ('USD', 'US Dollar', '$', 2, 0.01, TRUE) RETURNING id",
        )
        .fetch_one(&db)
        .await
        .unwrap(),
    };
    for (date, myr_per_usd) in [(doc_date, "4.70"), (pay_date, "4.60")] {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO currency_rates (currency_id, rate, rate_date) \
             VALUES ($1, 1.0 / $2::numeric, $3) \
             ON CONFLICT (currency_id, rate_date) DO UPDATE SET rate = EXCLUDED.rate",
        )
        .bind(usd)
        .bind(date_rate(myr_per_usd))
        .bind(date)
        .execute(&db)
        .await
        .unwrap();
    }

    // USD 1,000 invoice → MYR 4,700 booked.
    let inv = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: doc_date,
            due_date: None,
            journal_code: None,
            currency_id: Some(usd),
            origin_ref: Some("test_fx:1"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Export consulting", dec!(1), dec!(1000.00))],
        },
    )
    .await
    .unwrap();
    documents::post_invoice(&db, &seq_pool, inv, user_id).await.unwrap();

    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT total_amount, amount_residual, amount_residual_currency, currency_rate \
         FROM acc_move WHERE id = $1",
    )
    .bind(inv)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(head.get::<Decimal, _>("total_amount"), dec!(1000.00), "header in USD");
    assert_eq!(head.get::<Decimal, _>("amount_residual"), dec!(4700.00), "MYR residual");
    assert_eq!(
        head.get::<Option<Decimal>, _>("amount_residual_currency"),
        Some(dec!(1000.0000)),
        "USD residual"
    );
    let rate: Decimal = head.get::<Option<Decimal>, _>("currency_rate").unwrap();
    assert_eq!(rate.round_dp(2), dec!(4.70));

    // GL lines are MYR and carry amount_currency.
    let (d, c, _) = line_sums(&db, inv).await;
    assert_eq!(d, dec!(4700.00));
    assert_eq!(d, c);

    // Full payment of USD 1,000 at 4.60 → realized LOSS of MYR 100.
    documents::register_payment(
        &db,
        &seq_pool,
        user_id,
        &NewPayment {
            partner_id,
            direction: PaymentDirection::Inbound,
            journal_code: "BNK",
            currency_code: Some("USD"),
            amount: dec!(1000.00),
            payment_date: pay_date,
            memo: Some("USD wire"),
            company_id: None,
            allocate_to: vec![inv],
        },
    )
    .await
    .unwrap();

    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT payment_state, amount_residual, amount_residual_currency FROM acc_move WHERE id = $1",
    )
    .bind(inv)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(head.get::<String, _>("payment_state"), "paid");
    assert_eq!(head.get::<Option<Decimal>, _>("amount_residual_currency"), Some(dec!(0.0000)));

    // The realized-FX move exists, is linked, and books a 100 MYR loss.
    let fx = vortex_plugin_sdk::sqlx::query(
        "SELECT pr.exchange_move_id, \
                (SELECT SUM(l.debit) FROM acc_move_line l \
                 JOIN acc_account a ON a.id = l.account_id \
                 WHERE l.move_id = pr.exchange_move_id AND a.code = '6950') AS loss_debit \
         FROM acc_partial_reconcile pr \
         WHERE pr.exchange_move_id IS NOT NULL \
         ORDER BY pr.created_at DESC LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(fx.get::<Option<Uuid>, _>("exchange_move_id").is_some());
    assert_eq!(fx.get::<Option<Decimal>, _>("loss_debit"), Some(dec!(100.00)));

    // Revaluation: a second open USD invoice, rate moves, revalue.
    let inv2 = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: doc_date,
            due_date: None,
            journal_code: None,
            currency_id: Some(usd),
            origin_ref: Some("test_fx:2"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Second export", dec!(1), dec!(500.00))],
        },
    )
    .await
    .unwrap();
    documents::post_invoice(&db, &seq_pool, inv2, user_id).await.unwrap();

    let result = vortex_accounting::currency::revalue_open_items(
        &db, &seq_pool, user_id, None, pay_date,
    )
    .await
    .unwrap();
    let (reval, reversal) = result.expect("open USD item to revalue");
    // 500 USD booked at 4.70 = 2350; at 4.60 = 2300 → unrealized loss 50.
    // Assert on THIS invoice's per-item line — the batch may also carry
    // leftovers from earlier runs against a reused test DB.
    let inv2_number: String = move_field(&db, inv2, "number").await;
    let item_credit: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT l.credit FROM acc_move_line l \
         WHERE l.move_id = $1 AND l.name = $2",
    )
    .bind(reval)
    .bind(format!("Revaluation {inv2_number} USD"))
    .fetch_one(&db)
    .await
    .expect("per-item revaluation line for inv2");
    assert_eq!(item_credit, dec!(50.00));
    // The batch loss on 6960 covers at least this item.
    let loss: Option<Decimal> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT SUM(l.debit) FROM acc_move_line l \
         JOIN acc_account a ON a.id = l.account_id \
         WHERE l.move_id = $1 AND a.code = '6960'",
    )
    .bind(reval)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(loss.unwrap_or_default() >= dec!(50.00));
    // The reversal exists and is posted.
    let rev_state: String =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM acc_move WHERE id = $1")
            .bind(reversal)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(rev_state, "posted");

    // Guard: amount_currency on a posted line is immutable.
    let tamper = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move_line SET amount_currency = 999 \
         WHERE move_id = $1 AND amount_currency IS NOT NULL",
    )
    .bind(inv2)
    .execute(&db)
    .await;
    assert!(tamper.is_err(), "posted amount_currency must be immutable");
}

fn date_rate(s: &str) -> Decimal {
    s.parse().unwrap()
}

/// Phase 5: dimensions on GL lines (tag + posted immutability),
/// fixed-asset confirm → depreciate → dispose, recurring generation.
#[tokio::test]
async fn dimensions_assets_recurring_lifecycle() {
    let Some((db, seq_pool, user_id, partner_id)) = setup().await else {
        return;
    };
    let _ = partner_id;
    use vortex_accounting::{assets, recurring};
    let today = Utc::now().date_naive();
    let op_date = today + vortex_plugin_sdk::chrono::Duration::days(1);
    let suffix = Uuid::new_v4().simple().to_string()[..6].to_string();

    // ── Dimension tagging + guard ────────────────────────────────────────
    let project: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_dimension (dim_type, code, name) VALUES ('project', $1, 'Test Project') \
         RETURNING id",
    )
    .bind(format!("PRJ{suffix}"))
    .fetch_one(&db)
    .await
    .expect("seed project dimension");
    let acc_expense: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '6000'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let acc_bank: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '1100'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let (tagged_move, _) = service::create_and_post(
        &db,
        &seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: op_date,
            move_type: "entry",
            ref_: Some("dimension tag test"),
            narration: None,
            partner_id: None,
            origin_ref: None,
            company_id: None,
            lines: vec![
                MoveLine::debit(acc_expense, dec!(120.00), Some("Tagged expense"))
                    .with_dimensions(Some(project), None),
                MoveLine::credit(acc_bank, dec!(120.00), Some("Tagged expense")),
            ],
        },
    )
    .await
    .expect("post tagged entry");
    let stored: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT project_id FROM acc_move_line WHERE move_id = $1 AND debit > 0",
    )
    .bind(tagged_move)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(stored, Some(project));
    let retag = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move_line SET project_id = NULL WHERE move_id = $1",
    )
    .bind(tagged_move)
    .execute(&db)
    .await;
    assert!(retag.is_err(), "posted dimension tags must be immutable");

    // ── Fixed asset: confirm → schedule → post periods → dispose ────────
    let acc_1500: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '1500'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let acc_1600: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '1600'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let acc_7000: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '7000'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    // Start tomorrow: period 1 lands at month-end, safely past the
    // lock_date == today window the sibling test opens.
    let start = op_date;
    let asset: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_asset (name, asset_account_id, depreciation_account_id, \
             expense_account_id, cost, salvage_value, life_months, start_date, created_by) \
         VALUES ($1, $2, $3, $4, 12000.00, 0, 24, $5, $6) RETURNING id",
    )
    .bind(format!("Test Server {suffix}"))
    .bind(acc_1500)
    .bind(acc_1600)
    .bind(acc_7000)
    .bind(start)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .expect("seed asset");
    let periods = assets::confirm_asset(&db, asset).await.expect("confirm asset");
    assert_eq!(periods, 24);
    assets::confirm_asset(&db, asset).await.expect_err("cannot confirm twice");
    // Post exactly the first period (due at the first month-end).
    let first_due = assets::month_end(start);
    let posted = assets::post_due_depreciation(&db, &seq_pool, user_id, first_due)
        .await
        .expect("depreciation run");
    assert!(posted >= 1, "at least one period should post");
    let (dep_posted, dep_sum): (i64, Decimal) = {
        let r = vortex_plugin_sdk::sqlx::query(
            "SELECT COUNT(*) AS n, COALESCE(SUM(amount), 0) AS s \
             FROM acc_asset_depreciation WHERE asset_id = $1 AND state = 'posted'",
        )
        .bind(asset)
        .fetch_one(&db)
        .await
        .unwrap();
        (r.get("n"), r.get("s"))
    };
    // `posted` may include leftover assets from earlier runs against a
    // reused DB; THIS asset has exactly one period due at first_due.
    assert_eq!(dep_posted, 1);
    assert_eq!(dep_sum, dec!(500.00), "12000/24 = 500/mo");
    // Dispose at NBV + 100 → gain of 100 on 4970.
    let proceeds = dec!(12000.00) - dep_sum + dec!(100.00);
    let disposal = assets::dispose_asset(&db, &seq_pool, user_id, asset, proceeds, op_date)
        .await
        .expect("dispose");
    let gain: Option<Decimal> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT SUM(l.credit) FROM acc_move_line l \
         JOIN acc_account a ON a.id = l.account_id \
         WHERE l.move_id = $1 AND a.code = '4970'",
    )
    .bind(disposal)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(gain, Some(dec!(100.00)));
    let (d, c, _) = line_sums(&db, disposal).await;
    assert_eq!(d, c, "disposal move balanced");
    let asset_state: String =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM acc_asset WHERE id = $1")
            .bind(asset)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(asset_state, "disposed");
    let planned_left: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_asset_depreciation WHERE asset_id = $1 AND state = 'planned'",
    )
    .bind(asset)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(planned_left, 0, "disposal drops remaining planned periods");

    // ── Recurring: auto-post occurrence + advance ────────────────────────
    let template = vortex_plugin_sdk::serde_json::json!([
        {"account_code": "6000", "name": "Rent", "debit": 2500, "credit": 0},
        {"account_code": "1100", "name": "Rent", "debit": 0, "credit": 2500}
    ]);
    let rec: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_recurring (name, interval_months, next_date, auto_post, lines, created_by) \
         VALUES ($1, 1, $2, TRUE, $3, $4) RETURNING id",
    )
    .bind(format!("Rent {suffix}"))
    .bind(op_date)
    .bind(&template)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .expect("seed recurring");
    let rec_move = recurring::generate_occurrence(&db, &seq_pool, user_id, rec, op_date)
        .await
        .expect("generate occurrence");
    assert_eq!(move_field::<String>(&db, rec_move, "state").await, "posted");
    let (d, c, n) = line_sums(&db, rec_move).await;
    assert_eq!(n, 2);
    assert_eq!(d, dec!(2500.00));
    assert_eq!(c, dec!(2500.00));
    let next: vortex_plugin_sdk::chrono::NaiveDate = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT next_date FROM acc_recurring WHERE id = $1",
    )
    .bind(rec)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(next, recurring::advance_months(op_date, 1));
}

/// Phase 4: PDC lifecycle, bank statement import → match → finalize,
/// AR↔AP contra, and credit-limit enforcement.
#[tokio::test]
async fn banking_and_arap_lifecycle() {
    let Some((db, seq_pool, user_id, partner_id)) = setup().await else {
        return;
    };
    use vortex_accounting::banking;
    // The sibling test opens a lock_date == today window; post tomorrow.
    let today = Utc::now().date_naive();
    let op_date = today + vortex_plugin_sdk::chrono::Duration::days(1);
    // Amounts unique to this test so statement matching can't collide
    // with GL lines written by the parallel tests.
    let pdc_amount = dec!(5137.42);
    let charges = dec!(-10.53);

    // ── PDC received: holding entry, then clear to bank ────────────────
    let cheque = format!("MBB{}", &Uuid::new_v4().simple().to_string()[..6]);
    let pdc = banking::record_pdc(
        &db, &seq_pool, user_id, None, "received", partner_id, &cheque,
        Some("Maybank"), pdc_amount, op_date, None, op_date,
    )
    .await
    .expect("record received PDC");
    let holding: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT holding_move_id FROM acc_pdc WHERE id = $1",
    )
    .bind(pdc)
    .fetch_one(&db)
    .await
    .unwrap();
    let (d, c, n) = line_sums(&db, holding).await;
    assert_eq!(n, 2, "holding entry: PDC account vs AR");
    assert_eq!(d, pdc_amount);
    assert_eq!(c, pdc_amount);
    let clearing = banking::clear_pdc(&db, &seq_pool, user_id, pdc, op_date)
        .await
        .expect("clear PDC");
    let state: String =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM acc_pdc WHERE id = $1")
            .bind(pdc)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(state, "cleared");
    banking::clear_pdc(&db, &seq_pool, user_id, pdc, op_date)
        .await
        .expect_err("cleared PDC cannot clear twice");

    // ── PDC issued: bounce reverses the holding entry ───────────────────
    let cheque2 = format!("PBB{}", &Uuid::new_v4().simple().to_string()[..6]);
    let pdc2 = banking::record_pdc(
        &db, &seq_pool, user_id, None, "issued", partner_id, &cheque2,
        None, dec!(1200.00), op_date, None, op_date,
    )
    .await
    .expect("record issued PDC");
    banking::bounce_pdc(&db, &seq_pool, user_id, pdc2, op_date)
        .await
        .expect("bounce PDC");
    let state2: String =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM acc_pdc WHERE id = $1")
            .bind(pdc2)
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(state2, "bounced");

    // ── Statement import → auto-match → quick counterpart → finalize ────
    let csv = format!(
        "date,description,amount\n\
         {op_date},PDC {cheque} BANKED IN,{pdc_amount}\n\
         {op_date},BANK SERVICE CHARGES,{charges}\n"
    );
    let parsed = banking::parse_statement_csv(&csv).expect("parse CSV");
    assert_eq!(parsed.len(), 2);
    let journal_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_journal WHERE code = 'BNK'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let sid: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_bank_statement (journal_id, name, statement_date, created_by) \
         VALUES ($1, 'Lifecycle import', $2, $3) RETURNING id",
    )
    .bind(journal_id)
    .bind(op_date)
    .bind(user_id)
    .fetch_one(&db)
    .await
    .unwrap();
    for (date, desc, amount) in &parsed {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_bank_statement_line (statement_id, line_date, description, amount) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(sid)
        .bind(date)
        .bind(desc)
        .bind(amount)
        .execute(&db)
        .await
        .unwrap();
    }
    banking::finalize_statement(&db, sid)
        .await
        .expect_err("unmatched lines must block finalize");
    let suggestions = banking::auto_match_suggestions(&db, sid).await.expect("suggestions");
    // The clearing move debited the bank for exactly pdc_amount on op_date.
    let clearing_bank_line: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT l.id FROM acc_move_line l WHERE l.move_id = $1 AND l.debit = $2",
    )
    .bind(clearing)
    .bind(pdc_amount)
    .fetch_one(&db)
    .await
    .unwrap();
    let hit = suggestions
        .iter()
        .find(|(_, gl, _)| *gl == clearing_bank_line)
        .expect("auto-match must propose the PDC clearing bank line");
    assert_eq!(hit.2, 100, "same amount + same date = perfect score");
    banking::match_line(&db, hit.0, clearing_bank_line, user_id)
        .await
        .expect("match line");
    // Bank charges: quick counterpart into an expense account.
    let expense: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '6000'",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let charges_line: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_bank_statement_line \
         WHERE statement_id = $1 AND matched_line_id IS NULL",
    )
    .bind(sid)
    .fetch_one(&db)
    .await
    .unwrap();
    let charge_move = banking::quick_counterpart(&db, &seq_pool, user_id, charges_line, expense)
        .await
        .expect("quick counterpart for bank charges");
    let (d, c, _) = line_sums(&db, charge_move).await;
    assert_eq!(d, charges.abs());
    assert_eq!(c, charges.abs());
    banking::finalize_statement(&db, sid).await.expect("finalize");
    let st_state: String = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT state FROM acc_bank_statement WHERE id = $1",
    )
    .bind(sid)
    .fetch_one(&db)
    .await
    .unwrap();
    assert_eq!(st_state, "reconciled");

    // ── Contra: 800 AR vs 300 AP nets to 300, bill fully settled ────────
    let inv = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id,
            invoice_date: op_date,
            due_date: None,
            journal_code: None,
            currency_id: None,
            origin_ref: Some("test_banking:contra_ar"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Services", dec!(1), dec!(800.00))],
        },
    )
    .await
    .expect("create AR invoice");
    documents::post_invoice(&db, &seq_pool, inv, user_id).await.expect("post AR");
    let bill = documents::create_invoice(
        &db,
        user_id,
        &NewInvoice {
            move_type: "vendor_bill",
            partner_id,
            invoice_date: op_date,
            due_date: None,
            journal_code: None,
            currency_id: None,
            origin_ref: Some("test_banking:contra_ap"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Subcontract", dec!(1), dec!(300.00))],
        },
    )
    .await
    .expect("create AP bill");
    documents::post_invoice(&db, &seq_pool, bill, user_id).await.expect("post AP");
    let contra_move =
        banking::contra(&db, &seq_pool, user_id, None, partner_id, &[inv], &[bill], op_date)
            .await
            .expect("contra");
    let (d, c, n) = line_sums(&db, contra_move).await;
    assert_eq!(n, 2);
    assert_eq!(d, dec!(300.00));
    assert_eq!(c, dec!(300.00));
    assert_eq!(move_field::<String>(&db, bill, "payment_state").await, "paid");
    assert_eq!(move_field::<String>(&db, inv, "payment_state").await, "partial");
    assert_eq!(move_field::<Decimal>(&db, inv, "amount_residual").await, dec!(500.00));

    // ── Credit control: block over the limit, warn posts anyway ─────────
    let company_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM companies ORDER BY created_at LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .unwrap();
    let risky: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO contacts (name, contact_type, company_id, active, credit_limit) \
         VALUES ($1, 'customer', $2, TRUE, 100.00) RETURNING id",
    )
    .bind(format!("Risky {}", &Uuid::new_v4().simple().to_string()[..6]))
    .bind(company_id)
    .fetch_one(&db)
    .await
    .expect("seed risky partner");
    vortex_plugin_sdk::sqlx::query("UPDATE acc_config SET credit_limit_policy = 'block'")
        .execute(&db)
        .await
        .unwrap();
    let post_for = |amount: Decimal| {
        let db = db.clone();
        let seq_pool = seq_pool.clone();
        async move {
            let doc = documents::create_invoice(
                &db,
                user_id,
                &NewInvoice {
                    move_type: "customer_invoice",
                    partner_id: risky,
                    invoice_date: op_date,
                    due_date: None,
                    journal_code: None,
                    currency_id: None,
                    origin_ref: Some("test_banking:credit"),
                    narration: None,
                    company_id: None,
                    lines: vec![InvoiceLine::new("Goods", dec!(1), amount)],
                },
            )
            .await
            .expect("create credit-test invoice");
            documents::post_invoice(&db, &seq_pool, doc, user_id).await
        }
    };
    post_for(dec!(50.00)).await.expect("within limit posts");
    post_for(dec!(80.00))
        .await
        .expect_err("50 exposure + 80 new > 100 limit must block");
    vortex_plugin_sdk::sqlx::query("UPDATE acc_config SET credit_limit_policy = 'warn'")
        .execute(&db)
        .await
        .unwrap();
    post_for(dec!(80.00)).await.expect("warn policy posts anyway");
    vortex_plugin_sdk::sqlx::query("UPDATE acc_config SET credit_limit_policy = 'off'")
        .execute(&db)
        .await
        .unwrap();
}
