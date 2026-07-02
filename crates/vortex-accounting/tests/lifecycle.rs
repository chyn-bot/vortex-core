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
