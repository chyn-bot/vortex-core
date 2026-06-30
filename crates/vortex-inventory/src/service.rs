//! Public stock-movement API for **other modules** to build on.
//!
//! Purchasing receipts, manufacturing consumption, sales deliveries —
//! any module that needs goods to flow through the ledger calls
//! [`post_move`] rather than touching `stock_move` / `stock_quant`
//! directly. This keeps the double-entry invariant (every on-hand
//! change is backed by a validated move) owned in one place.

use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::PgPool;
use vortex_plugin_sdk::uuid::Uuid;

use crate::handlers::adjust_quant;

/// Find the lot named `name` for `product_id`, creating it (typed
/// `lot_type`) if absent. Returns the lot id. Exposed so modules that
/// receive tracked goods (e.g. purchasing) can register lots the same
/// way the inventory UI does.
pub async fn resolve_lot(
    db: &PgPool,
    product_id: Uuid,
    name: &str,
    lot_type: &str,
    company_id: Option<Uuid>,
    user_id: Uuid,
) -> Result<Uuid, vortex_plugin_sdk::sqlx::Error> {
    crate::handlers::resolve_lot(db, product_id, name, lot_type, company_id, user_id).await
}

/// The stock-move reference sequence spec (`MOV/000001`). Exposed so
/// callers can mint a move reference through the core sequence service
/// before calling [`post_move`].
pub fn move_sequence() -> vortex_plugin_sdk::orm::sequence::SequenceSpec {
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("inventory.move", "MOV").with_padding(6)
}

/// Post a **validated** stock move (`state = done`) and update on-hand
/// for the source and destination locations, atomically.
///
/// `qty` must be positive; it is debited from `source_location_id` and
/// credited to `dest_location_id`. `lot_id` is required by the caller's
/// own rules for tracked products (this function does not enforce
/// tracking — it trusts the lot it is given). Returns the new move id.
#[allow(clippy::too_many_arguments)]
pub async fn post_move(
    pool: &PgPool,
    reference: &str,
    company_id: Option<Uuid>,
    user_id: Uuid,
    product_id: Uuid,
    lot_id: Option<Uuid>,
    uom_id: Option<Uuid>,
    qty: Decimal,
    source_location_id: Uuid,
    dest_location_id: Uuid,
    reference_doc: Option<&str>,
) -> Result<Uuid, vortex_plugin_sdk::sqlx::Error> {
    let mut tx = pool.begin().await?;

    let move_id = Uuid::now_v7();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_move \
         (id, reference, product_id, quantity, uom_id, lot_id, \
          source_location_id, dest_location_id, state, done_at, \
          reference_doc, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'done',NOW(),$9,$10,$11)",
    )
    .bind(move_id)
    .bind(reference)
    .bind(product_id)
    .bind(qty)
    .bind(uom_id)
    .bind(lot_id)
    .bind(source_location_id)
    .bind(dest_location_id)
    .bind(reference_doc)
    .bind(company_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    for (loc, delta) in [(source_location_id, -qty), (dest_location_id, qty)] {
        adjust_quant(&mut tx, product_id, loc, lot_id, delta, company_id).await?;
    }

    tx.commit().await?;
    Ok(move_id)
}
