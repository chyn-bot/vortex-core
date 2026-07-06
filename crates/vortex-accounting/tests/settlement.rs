//! Payment-allocation lifecycle: `documents::settle_documents` across the
//! shapes a real AR/AP desk needs — partial payment, one payment over many
//! invoices, partial allocation over many, payment plus credit-note knock-off,
//! and a pure (cash-free) credit-note application.
//!
//! Skipped unless `ACC_TEST_DATABASE_URL` is set (a tenant DB with core +
//! accounting migrations applied):
//!
//! ```sh
//! ACC_TEST_DATABASE_URL=postgres://vortex:vortex@localhost/acc_dev \
//!     cargo test -p vortex-accounting --test settlement
//! ```

use vortex_accounting::documents::{
    self, Allocation, InvoiceLine, NewInvoice, NewPayment, PaymentDirection, WriteOff,
};
use vortex_plugin_sdk::chrono::Utc;
use vortex_plugin_sdk::orm::connection::{ConnectionPool, DatabaseConfig};
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::PgPool;
use vortex_plugin_sdk::uuid::Uuid;

use rust_decimal_macros::dec;

async fn setup() -> Option<(PgPool, ConnectionPool, Uuid, Uuid)> {
    let url = std::env::var("ACC_TEST_DATABASE_URL").ok()?;
    let db = PgPool::connect(&url).await.expect("connect PgPool");
    let seq_pool = ConnectionPool::new(DatabaseConfig {
        url: url.clone(),
        min_connections: 1,
        max_connections: 4,
        ..DatabaseConfig::default()
    })
    .await
    .expect("connect ConnectionPool");

    let user_id: Uuid =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM users LIMIT 1")
            .fetch_one(&db)
            .await
            .expect("a user");
    let company_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM companies ORDER BY created_at LIMIT 1",
    )
    .fetch_one(&db)
    .await
    .expect("default company");
    let suffix = &Uuid::new_v4().simple().to_string()[..8];
    let partner_id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO contacts (name, contact_type, company_id, active) \
         VALUES ($1, 'both', $2, TRUE) RETURNING id",
    )
    .bind(format!("Settle Test {suffix}"))
    .bind(company_id)
    .fetch_one(&db)
    .await
    .expect("seed partner");

    Some((db, seq_pool, user_id, partner_id))
}

/// Create + post a single-line, tax-free document of `amount`, return its id.
async fn mk_doc(
    db: &PgPool,
    seq: &ConnectionPool,
    user: Uuid,
    partner: Uuid,
    move_type: &str,
    amount: Decimal,
) -> Uuid {
    let today = Utc::now().date_naive();
    let id = documents::create_invoice(
        db,
        user,
        &NewInvoice {
            move_type,
            partner_id: partner,
            invoice_date: today,
            due_date: Some(today),
            journal_code: None,
            currency_id: None,
            origin_ref: Some("settlement_test"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Test line", dec!(1), amount)],
        },
    )
    .await
    .expect("create doc");
    documents::post_invoice(db, seq, id, user).await.expect("post doc");
    id
}

async fn state(db: &PgPool, id: Uuid) -> (Decimal, String) {
    let row = vortex_plugin_sdk::sqlx::query_as::<_, (Decimal, String)>(
        "SELECT amount_residual, payment_state FROM acc_move WHERE id = $1",
    )
    .bind(id)
    .fetch_one(db)
    .await
    .unwrap();
    row
}

/// Total posted 'payment' moves for a partner (count, sum) — proves how much
/// real cash was booked.
async fn payments_for(db: &PgPool, partner: Uuid) -> (i64, Decimal) {
    vortex_plugin_sdk::sqlx::query_as::<_, (i64, Decimal)>(
        "SELECT COUNT(*), COALESCE(SUM(total_amount),0) FROM acc_move \
         WHERE partner_id = $1 AND move_type = 'payment'",
    )
    .bind(partner)
    .fetch_one(db)
    .await
    .unwrap()
}

#[tokio::test]
async fn partial_payment_one_invoice() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("part"), None,
        &[Allocation { doc_id: inv, amount: dec!(400.00) }],
    )
    .await
    .expect("settle");
    assert!(pid.is_some(), "cash payment expected");

    let (res, st) = state(&db, inv).await;
    assert_eq!(res, dec!(600.00), "residual after partial");
    assert_eq!(st, "partial");
    let (_, paid) = payments_for(&db, partner).await;
    assert_eq!(paid, dec!(400.00), "only the allocated cash booked");
}

#[tokio::test]
async fn one_payment_across_many_invoices() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let a = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;
    let b = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        &[
            Allocation { doc_id: a, amount: dec!(1000.00) },
            Allocation { doc_id: b, amount: dec!(500.00) },
        ],
    )
    .await
    .expect("settle");
    assert!(pid.is_some());
    assert_eq!(state(&db, a).await.1, "paid");
    assert_eq!(state(&db, b).await.1, "paid");
    let (cnt, paid) = payments_for(&db, partner).await;
    assert_eq!(cnt, 1, "a single payment move");
    assert_eq!(paid, dec!(1500.00));
}

#[tokio::test]
async fn partial_allocation_across_many_invoices() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let a = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;
    let b = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;

    documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        &[
            Allocation { doc_id: a, amount: dec!(700.00) }, // partial
            Allocation { doc_id: b, amount: dec!(500.00) }, // full
        ],
    )
    .await
    .expect("settle");

    let (res_a, st_a) = state(&db, a).await;
    assert_eq!(res_a, dec!(300.00));
    assert_eq!(st_a, "partial");
    assert_eq!(state(&db, b).await.1, "paid");
    assert_eq!(payments_for(&db, partner).await.1, dec!(1200.00));
}

#[tokio::test]
async fn payment_plus_credit_note_knockoff() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;
    let cn = mk_doc(&db, &seq, user, partner, "customer_credit_note", dec!(300.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("cn+cash"), None,
        &[
            Allocation { doc_id: inv, amount: dec!(1000.00) },
            Allocation { doc_id: cn, amount: dec!(300.00) },
        ],
    )
    .await
    .expect("settle");
    assert!(pid.is_some(), "net cash 700 → a payment");

    assert_eq!(state(&db, inv).await.1, "paid", "invoice cleared by CN + cash");
    assert_eq!(state(&db, cn).await.1, "paid", "credit note consumed");
    // Only the NET cash (1000 − 300) hits the bank.
    assert_eq!(payments_for(&db, partner).await.1, dec!(700.00));
}

#[tokio::test]
async fn pure_credit_note_application_no_cash() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;
    let cn = mk_doc(&db, &seq, user, partner, "customer_credit_note", dec!(500.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        &[
            Allocation { doc_id: inv, amount: dec!(500.00) },
            Allocation { doc_id: cn, amount: dec!(500.00) },
        ],
    )
    .await
    .expect("settle");
    assert!(pid.is_none(), "no cash → no payment move");

    assert_eq!(state(&db, inv).await.1, "paid");
    assert_eq!(state(&db, cn).await.1, "paid");
    assert_eq!(payments_for(&db, partner).await.0, 0, "no payment posted");
}

#[tokio::test]
async fn credit_notes_exceeding_invoices_is_rejected() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(200.00)).await;
    let cn = mk_doc(&db, &seq, user, partner, "customer_credit_note", dec!(500.00)).await;

    let err = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        &[
            Allocation { doc_id: inv, amount: dec!(200.00) },
            Allocation { doc_id: cn, amount: dec!(500.00) },
        ],
    )
    .await;
    assert!(err.is_err(), "negative net cash must be refused");
    // Nothing was settled.
    assert_eq!(state(&db, inv).await.1, "not_paid");
}

#[tokio::test]
async fn vendor_bill_outbound_payment() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let bill = mk_doc(&db, &seq, user, partner, "vendor_bill", dec!(800.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, false, "BNK", Utc::now().date_naive(), Some("pay vendor"), None,
        &[Allocation { doc_id: bill, amount: dec!(800.00) }],
    )
    .await
    .expect("settle");
    assert!(pid.is_some());
    assert_eq!(state(&db, bill).await.1, "paid");
    assert_eq!(payments_for(&db, partner).await.1, dec!(800.00));
}

/// Register an unallocated advance for a partner (a customer deposit or a
/// prepayment to a vendor) — no invoice involved.
async fn deposit(
    db: &PgPool,
    seq: &ConnectionPool,
    user: Uuid,
    partner: Uuid,
    inbound: bool,
    amount: Decimal,
) -> Uuid {
    documents::register_payment(
        db,
        seq,
        user,
        &NewPayment {
            partner_id: partner,
            direction: if inbound {
                PaymentDirection::Inbound
            } else {
                PaymentDirection::Outbound
            },
            journal_code: "BNK",
            currency_code: None,
            amount,
            payment_date: Utc::now().date_naive(),
            memo: Some("Advance"),
            company_id: None,
            allocate_to: Vec::new(),
        },
    )
    .await
    .expect("deposit")
}

#[tokio::test]
async fn customer_advance_deposit_stays_open() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let dep = deposit(&db, &seq, user, partner, true, dec!(500.00)).await;
    let (res, st) = state(&db, dep).await;
    assert_eq!(res, dec!(500.00), "the whole deposit sits open as credit");
    assert_eq!(st, "not_paid");
    // It is a real bank receipt.
    assert_eq!(payments_for(&db, partner).await.1, dec!(500.00));
}

#[tokio::test]
async fn apply_deposit_to_later_invoice_no_cash() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    // Customer paid a 500 deposit up front...
    let dep = deposit(&db, &seq, user, partner, true, dec!(500.00)).await;
    // ...later a 500 invoice is raised and the deposit clears it, no new cash.
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        &[
            Allocation { doc_id: inv, amount: dec!(500.00) },
            Allocation { doc_id: dep, amount: dec!(500.00) },
        ],
    )
    .await
    .expect("apply deposit");
    assert!(pid.is_none(), "deposit fully covers the invoice — no new payment");
    assert_eq!(state(&db, inv).await.1, "paid");
    assert_eq!(state(&db, dep).await.1, "paid", "deposit consumed");
    // Still just the one original 500 receipt — no double counting.
    assert_eq!(payments_for(&db, partner).await, (1, dec!(500.00)));
}

#[tokio::test]
async fn apply_partial_deposit_plus_cash() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let dep = deposit(&db, &seq, user, partner, true, dec!(300.00)).await;
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;

    let pid = documents::settle_documents(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        &[
            Allocation { doc_id: inv, amount: dec!(1000.00) },
            Allocation { doc_id: dep, amount: dec!(300.00) },
        ],
    )
    .await
    .expect("settle");
    assert!(pid.is_some(), "700 cash still owed after the 300 deposit");
    assert_eq!(state(&db, inv).await.1, "paid");
    assert_eq!(state(&db, dep).await.1, "paid");
    // 300 deposit + 700 new receipt = two payment moves totalling 1000.
    assert_eq!(payments_for(&db, partner).await, (2, dec!(1000.00)));
}

#[tokio::test]
async fn vendor_advance_prepayment_stays_open() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let dep = deposit(&db, &seq, user, partner, false, dec!(750.00)).await;
    let (res, st) = state(&db, dep).await;
    assert_eq!(res, dec!(750.00));
    assert_eq!(st, "not_paid");
}

// ── apply_payment: the amount-received + pick-invoices flow ──────────

/// Like `mk_doc`, but back-dates the invoice so FIFO ordering is testable.
async fn mk_doc_dated(
    db: &PgPool,
    seq: &ConnectionPool,
    user: Uuid,
    partner: Uuid,
    move_type: &str,
    amount: Decimal,
    days_ago: i64,
) -> Uuid {
    let date = Utc::now().date_naive() - vortex_plugin_sdk::chrono::Duration::days(days_ago);
    let id = documents::create_invoice(
        db,
        user,
        &NewInvoice {
            move_type,
            partner_id: partner,
            invoice_date: date,
            due_date: Some(date),
            journal_code: None,
            currency_id: None,
            origin_ref: Some("settlement_test"),
            narration: None,
            company_id: None,
            lines: vec![InvoiceLine::new("Test line", dec!(1), amount)],
        },
    )
    .await
    .expect("create dated doc");
    documents::post_invoice(db, seq, id, user).await.expect("post doc");
    id
}

#[tokio::test]
async fn apply_payment_fifo_oldest_first() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    // Newest first in the picked slice — apply_payment must still clear the
    // oldest invoice before touching the newer one.
    let newer = mk_doc_dated(&db, &seq, user, partner, "customer_invoice", dec!(500.00), 1).await;
    let older = mk_doc_dated(&db, &seq, user, partner, "customer_invoice", dec!(1000.00), 10).await;

    let pid = documents::apply_payment(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("fifo"), None,
        dec!(1200.00), &[newer, older],
    )
    .await
    .expect("apply");
    assert!(pid.is_some());

    // 1200 clears the 1000 oldest in full, 200 spills onto the newer one.
    assert_eq!(state(&db, older).await.1, "paid", "oldest fully paid first");
    let (res_new, st_new) = state(&db, newer).await;
    assert_eq!(res_new, dec!(300.00), "newer invoice partly paid");
    assert_eq!(st_new, "partial");
    assert_eq!(payments_for(&db, partner).await, (1, dec!(1200.00)));
}

#[tokio::test]
async fn apply_payment_excess_becomes_advance() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;

    let pid = documents::apply_payment(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("over"), None,
        dec!(800.00), &[inv],
    )
    .await
    .expect("apply")
    .expect("cash payment posted");

    assert_eq!(state(&db, inv).await.1, "paid", "invoice cleared");
    // The 300 overpayment stays open on the payment as an advance credit.
    let (res_pay, _st_pay) = state(&db, pid).await;
    assert_eq!(res_pay, dec!(300.00), "overpayment kept as advance");
    assert_eq!(payments_for(&db, partner).await.1, dec!(800.00));
}

#[tokio::test]
async fn apply_payment_with_credit_note_and_cash() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;
    let cn = mk_doc(&db, &seq, user, partner, "customer_credit_note", dec!(300.00)).await;

    // Customer owes 1000, has a 300 credit note, pays 700 cash for the rest.
    let pid = documents::apply_payment(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("cn+cash"), None,
        dec!(700.00), &[inv, cn],
    )
    .await
    .expect("apply");
    assert!(pid.is_some());
    assert_eq!(state(&db, inv).await.1, "paid");
    assert_eq!(state(&db, cn).await.1, "paid", "credit note consumed");
    assert_eq!(payments_for(&db, partner).await.1, dec!(700.00));
}

#[tokio::test]
async fn apply_payment_pure_advance_no_documents() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    // No invoices picked — a standalone deposit.
    let pid = documents::apply_payment(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("deposit"), None,
        dec!(500.00), &[],
    )
    .await
    .expect("apply")
    .expect("deposit payment posted");

    let (res, st) = state(&db, pid).await;
    assert_eq!(res, dec!(500.00), "whole deposit sits open as credit");
    assert_eq!(st, "not_paid");
}

#[tokio::test]
async fn apply_payment_shortfall_leaves_invoice_open() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;

    // Only 400 cash against a 1000 invoice — partial, no advance.
    let pid = documents::apply_payment(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), None, None,
        dec!(400.00), &[inv],
    )
    .await
    .expect("apply");
    assert!(pid.is_some());
    let (res, st) = state(&db, inv).await;
    assert_eq!(res, dec!(600.00));
    assert_eq!(st, "partial");
    // No leftover on the payment.
    assert_eq!(state(&db, pid.unwrap()).await.0, dec!(0.00), "cash fully applied");
}

// ── post_settlement: directed allocation + write-off difference ─────

async fn account_by_code(db: &PgPool, code: &str) -> Uuid {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM acc_account WHERE code = $1")
        .bind(code)
        .fetch_one(db)
        .await
        .expect("account by code")
}

#[tokio::test]
async fn post_settlement_directed_split_not_fifo() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    // A is older and larger; B is newer. FIFO would clear A first — but the
    // caller directs 100 to A and the full 500 to B instead.
    let a = mk_doc_dated(&db, &seq, user, partner, "customer_invoice", dec!(1000.00), 10).await;
    let b = mk_doc_dated(&db, &seq, user, partner, "customer_invoice", dec!(500.00), 1).await;

    let pid = documents::post_settlement(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("directed"), None,
        dec!(600.00),
        &[
            Allocation { doc_id: a, amount: dec!(100.00) },
            Allocation { doc_id: b, amount: dec!(500.00) },
        ],
        None,
    )
    .await
    .expect("settle");
    assert!(pid.is_some());

    let (res_a, st_a) = state(&db, a).await;
    assert_eq!(res_a, dec!(900.00), "only the directed 100 hit the older invoice");
    assert_eq!(st_a, "partial");
    assert_eq!(state(&db, b).await.1, "paid", "newer invoice fully paid by direction");
    assert_eq!(payments_for(&db, partner).await, (1, dec!(600.00)));
}

#[tokio::test]
async fn post_settlement_early_payment_discount() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;
    let discount = account_by_code(&db, "4900").await; // Other Income (stand-in discount account)

    // Customer settles a 1000 invoice with 980 cash and a 20 early-payment
    // discount written off — the invoice must show fully paid.
    let pid = documents::post_settlement(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("disc"), None,
        dec!(980.00),
        &[Allocation { doc_id: inv, amount: dec!(1000.00) }],
        Some(WriteOff { account_id: discount, amount: dec!(20.00) }),
    )
    .await
    .expect("settle")
    .expect("cash payment");

    let (res, st) = state(&db, inv).await;
    assert_eq!(res, dec!(0.00), "invoice cleared by cash + discount");
    assert_eq!(st, "paid");
    assert_eq!(state(&db, pid).await.0, dec!(0.00), "cash fully applied, no advance");
    // Only 980 of real cash was booked; the 20 is a write-off, not a receipt.
    assert_eq!(payments_for(&db, partner).await.1, dec!(980.00));
    // The write-off posted a difference entry hitting the discount account.
    let hits: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_move_line WHERE account_id = $1 AND debit = 20.00",
    )
    .bind(discount)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(hits >= 1, "discount account debited 20");
}

#[tokio::test]
async fn post_settlement_splits_one_payment_over_two_invoices() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    // The exact shape that regressed: 500 cash, 250 directed to each of two
    // 500 invoices. Both must end up half-paid — not left fully open.
    let a = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;
    let b = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;

    let pid = documents::post_settlement(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("split"), None,
        dec!(500.00),
        &[
            Allocation { doc_id: a, amount: dec!(250.00) },
            Allocation { doc_id: b, amount: dec!(250.00) },
        ],
        None,
    )
    .await
    .expect("settle")
    .expect("cash payment");

    assert_eq!(state(&db, a).await, (dec!(250.00), "partial".into()), "A half-paid");
    assert_eq!(state(&db, b).await, (dec!(250.00), "partial".into()), "B half-paid");
    assert_eq!(state(&db, pid).await.0, dec!(0.00), "cash fully applied, no advance");
    assert_eq!(payments_for(&db, partner).await, (1, dec!(500.00)));
}

#[tokio::test]
async fn post_settlement_vendor_directed_split_with_discount() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    // The vendor (outbound) mirror of the customer flow: two bills, a directed
    // split, and a discount-received write-off — exercising the opposite GL
    // sign (debit payable, credit income).
    let a = mk_doc(&db, &seq, user, partner, "vendor_bill", dec!(500.00)).await;
    let b = mk_doc(&db, &seq, user, partner, "vendor_bill", dec!(500.00)).await;
    let disc = account_by_code(&db, "4900").await; // income stand-in (discount received)

    // Owe 1000; pay 750 cash + 250 discount, directed to clear both bills.
    let pid = documents::post_settlement(
        &db, &seq, user, partner, false, "BNK", Utc::now().date_naive(), Some("vendor"), None,
        dec!(750.00),
        &[
            Allocation { doc_id: a, amount: dec!(500.00) },
            Allocation { doc_id: b, amount: dec!(500.00) },
        ],
        Some(WriteOff { account_id: disc, amount: dec!(250.00) }),
    )
    .await
    .expect("settle")
    .expect("cash payment");

    assert_eq!(state(&db, a).await.1, "paid", "bill A cleared");
    assert_eq!(state(&db, b).await.1, "paid", "bill B cleared");
    assert_eq!(state(&db, pid).await.0, dec!(0.00), "cash fully applied");
    // Outbound write-off credits the discount income account.
    let credited: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_move_line WHERE account_id = $1 AND credit = 250.00",
    )
    .bind(disc)
    .fetch_one(&db)
    .await
    .unwrap();
    assert!(credited >= 1, "discount income credited 250");
    // Only 750 of real cash left the bank.
    assert_eq!(payments_for(&db, partner).await.1, dec!(750.00));
}

#[tokio::test]
async fn post_settlement_overpay_leaves_advance() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;

    // Directed 500 to the invoice but 800 cash arrived — 300 is an advance.
    let pid = documents::post_settlement(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("over"), None,
        dec!(800.00),
        &[Allocation { doc_id: inv, amount: dec!(500.00) }],
        None,
    )
    .await
    .expect("settle")
    .expect("payment");

    assert_eq!(state(&db, inv).await.1, "paid");
    assert_eq!(state(&db, pid).await.0, dec!(300.00), "overpayment kept as advance on the payment");
}

// ── reset a posted payment to draft (auto-unallocate) ───────────────

async fn move_state(db: &PgPool, id: Uuid) -> String {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM acc_move WHERE id = $1")
        .bind(id)
        .fetch_one(db)
        .await
        .unwrap()
}

async fn reconciles_touching(db: &PgPool, move_id: Uuid) -> i64 {
    vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_partial_reconcile pr \
         JOIN acc_move_line l ON l.id IN (pr.debit_line_id, pr.credit_line_id) \
         WHERE l.move_id = $1",
    )
    .bind(move_id)
    .fetch_one(db)
    .await
    .unwrap()
}

#[tokio::test]
async fn reset_payment_to_draft_reopens_invoices() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let a = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;
    let b = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;
    let pid = documents::post_settlement(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("both"), None,
        dec!(1000.00),
        &[
            Allocation { doc_id: a, amount: dec!(500.00) },
            Allocation { doc_id: b, amount: dec!(500.00) },
        ],
        None,
    )
    .await
    .expect("settle")
    .expect("payment");
    assert_eq!(state(&db, a).await.1, "paid");
    assert_eq!(state(&db, b).await.1, "paid");

    // Reset the payment to draft — both invoices must reopen.
    let reopened = documents::reset_payment_to_draft(&db, user, pid).await.expect("reset");
    assert_eq!(reopened, 2, "both invoices reported reopened");
    assert_eq!(state(&db, a).await, (dec!(500.00), "not_paid".into()), "A fully reopened");
    assert_eq!(state(&db, b).await, (dec!(500.00), "not_paid".into()), "B fully reopened");
    assert_eq!(move_state(&db, pid).await, "draft", "payment is back to draft");
    assert_eq!(reconciles_touching(&db, pid).await, 0, "no reconciliations remain");
    // The draft can be re-posted (number kept) and re-applied afterwards.
    vortex_accounting::service::post_move(&db, &seq, pid, user)
        .await
        .expect("repost draft payment");
    assert_eq!(move_state(&db, pid).await, "posted");
}

#[tokio::test]
async fn reset_partial_payment_to_draft_reopens_fully() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(1000.00)).await;
    let pid = documents::post_settlement(
        &db, &seq, user, partner, true, "BNK", Utc::now().date_naive(), Some("part"), None,
        dec!(400.00),
        &[Allocation { doc_id: inv, amount: dec!(400.00) }],
        None,
    )
    .await
    .expect("settle")
    .expect("payment");
    assert_eq!(state(&db, inv).await, (dec!(600.00), "partial".into()));

    let reopened = documents::reset_payment_to_draft(&db, user, pid).await.expect("reset");
    assert_eq!(reopened, 1);
    assert_eq!(state(&db, inv).await, (dec!(1000.00), "not_paid".into()), "invoice fully reopened");
    assert_eq!(move_state(&db, pid).await, "draft");
}

#[tokio::test]
async fn reset_to_draft_rejects_non_payment() {
    let Some((db, seq, user, partner)) = setup().await else { return };
    let inv = mk_doc(&db, &seq, user, partner, "customer_invoice", dec!(500.00)).await;
    let err = documents::reset_payment_to_draft(&db, user, inv).await;
    assert!(err.is_err(), "an invoice is not a payment");
}
