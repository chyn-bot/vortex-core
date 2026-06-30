//! Purchase-order handlers — vendors → orders → receipts. Receiving a
//! confirmed order posts validated stock moves into inventory through
//! `vortex_inventory::post_move`, keeping on-hand backed by the ledger.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

/// Purchase-order number sequence — `PO/000001`.
const PO_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("purchase.order", "PO").with_padding(6);

pub fn purchase_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/purchase", get(list_orders))
        .route("/purchase/orders/new", get(new_order_form))
        .route("/purchase/orders/create", post(create_order))
        .route("/purchase/orders/{id}", get(edit_order))
        .route("/purchase/orders/{id}", post(update_order))
        .route("/purchase/orders/{id}/lines", post(add_line))
        .route("/purchase/orders/{id}/lines/{line_id}/delete", post(delete_line))
        .route("/purchase/orders/{id}/confirm", post(confirm_order))
        .route("/purchase/orders/{id}/cancel", post(cancel_order))
        .route("/purchase/orders/{id}/receive", get(receive_form))
        .route("/purchase/orders/{id}/receive", post(process_receipt))
}

// ─────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────

fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden">
<button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square">
<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
</button>
<a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">vor</span><span class="opacity-60">tex</span></a>
</div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
{content}
</main></div></body></html>"##,
        title = title,
        sidebar = sidebar,
        content = content,
    )
}

fn render_sidebar(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    vortex_plugin_sdk::framework::build_sidebar(
        "purchase",
        display_name,
        &initials,
        &db_ctx.installed_modules,
        user.roles.contains(&"system_administrator".to_string()),
        &state.plugin_registry,
        &user.roles,
    )
}

async fn default_company(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

fn opt_uuid(form: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    form.get(key).filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
}

fn dec_or(form: &HashMap<String, String>, key: &str, default: Decimal) -> Decimal {
    form.get(key)
        .and_then(|s| s.trim().parse::<Decimal>().ok())
        .unwrap_or(default)
}

/// Format a money amount to 2 decimal places.
fn money(d: Decimal) -> String {
    d.round_dp(2).to_string()
}

/// Badge markup for a PO state.
fn state_badge(state: &str) -> &'static str {
    match state {
        "draft" => r#"<span class="badge badge-ghost">Draft</span>"#,
        "confirmed" => r#"<span class="badge badge-info">Confirmed</span>"#,
        "received" => r#"<span class="badge badge-success">Received</span>"#,
        "cancelled" => r#"<span class="badge badge-error">Cancelled</span>"#,
        _ => r#"<span class="badge">?</span>"#,
    }
}

/// `<option>` list of vendor contacts (supplier or both).
async fn vendor_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, code FROM contacts \
         WHERE active AND contact_type IN ('supplier','both') ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Vendor --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        let code: Option<String> = r.try_get("code").ok();
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{name}{code}</option>"#,
            id = id, sel = sel,
            name = esc(&name),
            code = code.filter(|c| !c.is_empty()).map(|c| format!(" ({})", esc(&c))).unwrap_or_default(),
        ));
    }
    out
}

/// `<option>` list of purchasable products (active, not a service).
async fn product_options(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM stock_product \
         WHERE active AND product_type <> 'service' ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Product --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        out.push_str(&format!(
            r#"<option value="{id}">{code} · {name}</option>"#,
            id = id, code = esc(&code), name = esc(&name)
        ));
    }
    out
}

/// `<option>` list of internal receiving locations.
async fn location_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM stock_location \
         WHERE active AND location_type = 'internal' ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Receiving Location --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{code} · {name}</option>"#,
            id = id, sel = sel, code = esc(&code), name = esc(&name)
        ));
    }
    out
}

/// `<option>` list of active currencies.
async fn currency_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query("SELECT id, code, name FROM currencies WHERE active ORDER BY code")
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Currency --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{code} — {name}</option>"#,
            id = id, sel = sel, code = esc(&code), name = esc(&name)
        ));
    }
    out
}

/// Recompute and persist a PO's untaxed/tax/total from its lines.
async fn recompute_totals(db: &vortex_plugin_sdk::sqlx::PgPool, order_id: Uuid) {
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order po SET \
            untaxed_amount = t.untaxed, \
            tax_amount     = t.tax, \
            total_amount   = t.untaxed + t.tax, \
            updated_at = NOW() \
         FROM ( \
            SELECT \
                COALESCE(SUM(quantity * unit_price), 0) AS untaxed, \
                COALESCE(SUM(quantity * unit_price * tax_percent / 100), 0) AS tax \
            FROM purchase_order_line WHERE order_id = $1 \
         ) t \
         WHERE po.id = $1",
    )
    .bind(order_id)
    .execute(db)
    .await;
}

// ─────────────────────────────────────────────────────────────────────────
// Order list + create
// ─────────────────────────────────────────────────────────────────────────

async fn list_orders(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("Purchase Orders", "purchase_order")
        .custom_from("purchase_order po JOIN contacts v ON v.id = po.vendor_id")
        .custom_select(
            "po.id, po.number, v.name AS vendor_name, po.order_date::text AS order_date, \
             po.total_amount::text AS total_amount, po.state",
        )
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("po.number"))
        .column(ListColumn::new("vendor_name", "Vendor").sortable().searchable().sql_expr("v.name"))
        .column(ListColumn::new("order_date", "Order Date").sortable().sql_expr("po.order_date"))
        .column(ListColumn::new("total_amount", "Total").sortable().sql_expr("po.total_amount"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("draft", "Draft"),
                    ("confirmed", "Confirmed"),
                    ("received", "Received"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("draft", "Draft", "badge-ghost"),
                    ("confirmed", "Confirmed", "badge-info"),
                    ("received", "Received", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("po.state"),
        )
        .detail_url("/purchase/orders/{id}")
        .create("New Purchase Order", "/purchase/orders/new")
        .pivot_url("/pivot/purchase_order?rows=state")
        .default_sort("number")
        .group_by_options(&[("vendor_name", "Vendor"), ("state", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "purchase orders list query failed");
            return Html("<h1>Failed to load purchase orders</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/purchase");
    Html(page_shell(&sidebar, "Purchase Orders", &list_html)).into_response()
}

async fn new_order_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let vendors = vendor_options(&db, None).await;
    let locations = location_options(&db, None).await;
    let currencies = currency_options(&db, None).await;

    let content = format!(
        r#"<div class="max-w-2xl">
<a href="/purchase" class="btn btn-ghost btn-sm mb-4">← Back to Purchase Orders</a>
<h1 class="text-2xl font-bold mb-6">New Purchase Order</h1>
<form method="POST" action="/purchase/orders/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Vendor *</span></label>
<select name="vendor_id" class="select select-bordered select-sm" required>{vendors}</select>
<label class="label"><span class="label-text-alt text-base-content/50">Vendors are contacts of type Supplier or Both.</span></label>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Order Date</span></label>
<input name="order_date" type="date" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Expected Date</span></label>
<input name="expected_date" type="date" class="input input-bordered input-sm"/>
</div>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Receiving Location</span></label>
<select name="dest_location_id" class="select select-bordered select-sm">{locations}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Currency</span></label>
<select name="currency_id" class="select select-bordered select-sm">{currencies}</select>
</div>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Note</span></label>
<textarea name="note" class="textarea textarea-bordered" rows="2"></textarea>
</div>
<div class="flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Create</button>
<a href="/purchase" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        vendors = vendors,
        locations = locations,
        currencies = currencies,
    );

    Html(page_shell(&sidebar, "New Purchase Order", &content)).into_response()
}

async fn create_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let Some(vendor_id) = opt_uuid(&form, "vendor_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Vendor is required").into_response();
    };

    let number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &PO_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "PO sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate PO number").into_response();
        }
    };
    let company_id = default_company(&db).await;

    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("order_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("expected_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());

    let order_id = Uuid::now_v7();
    // order_date column defaults to CURRENT_DATE; pass COALESCE via Option.
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO purchase_order \
         (id, number, vendor_id, order_date, expected_date, currency_id, dest_location_id, note, company_id, created_by) \
         VALUES ($1,$2,$3,COALESCE($4, CURRENT_DATE),$5,$6,$7,$8,$9,$10)",
    )
    .bind(order_id)
    .bind(&number)
    .bind(vendor_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(opt_uuid(&form, "currency_id"))
    .bind(opt_uuid(&form, "dest_location_id"))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "PO insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create order: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("purchase_order", order_id.to_string())
    .with_resource_name(&number)
    .with_details(json!({ "number": number }));
    let _ = state.audit.log(audit_entry).await;

    info!(number = %number, "purchase order created");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{order_id}")).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Order detail / edit
// ─────────────────────────────────────────────────────────────────────────

async fn edit_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT po.number, po.vendor_id, v.name AS vendor_name, \
                po.order_date::text AS order_date, po.expected_date::text AS expected_date, \
                po.state, po.currency_id, po.dest_location_id, \
                dl.name AS dest_name, c.code AS currency_code, po.note, \
                po.untaxed_amount, po.tax_amount, po.total_amount \
         FROM purchase_order po \
         JOIN contacts v ON v.id = po.vendor_id \
         LEFT JOIN stock_location dl ON dl.id = po.dest_location_id \
         LEFT JOIN currencies c ON c.id = po.currency_id \
         WHERE po.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Order not found").into_response(),
        Err(e) => {
            error!(error = %e, "PO fetch failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let number: String = row.get("number");
    let vendor_id: Uuid = row.get("vendor_id");
    let vendor_name: String = row.get("vendor_name");
    let order_date: Option<String> = row.try_get("order_date").ok();
    let expected_date: Option<String> = row.try_get("expected_date").ok();
    let po_state: String = row.get("state");
    let currency_id: Option<Uuid> = row.try_get("currency_id").ok();
    let dest_location_id: Option<Uuid> = row.try_get("dest_location_id").ok();
    let dest_name: Option<String> = row.try_get("dest_name").ok();
    let currency_code: Option<String> = row.try_get("currency_code").ok();
    let note: Option<String> = row.try_get("note").ok();
    let untaxed: Decimal = row.try_get("untaxed_amount").unwrap_or(Decimal::ZERO);
    let tax: Decimal = row.try_get("tax_amount").unwrap_or(Decimal::ZERO);
    let total: Decimal = row.try_get("total_amount").unwrap_or(Decimal::ZERO);
    let is_draft = po_state == "draft";
    let cur = currency_code.clone().unwrap_or_default();

    // ── Lines table ──
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, p.code AS product_code, p.name AS product_name, l.description, \
                l.quantity, l.unit_price, l.tax_percent, l.qty_received \
         FROM purchase_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut lines_html = String::new();
    for r in &line_rows {
        let lid: Uuid = r.get("id");
        let pcode: String = r.get("product_code");
        let pname: String = r.get("product_name");
        let desc: Option<String> = r.try_get("description").ok();
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        let price: Decimal = r.try_get("unit_price").unwrap_or(Decimal::ZERO);
        let tax_pct: Decimal = r.try_get("tax_percent").unwrap_or(Decimal::ZERO);
        let recv: Decimal = r.try_get("qty_received").unwrap_or(Decimal::ZERO);
        let subtotal = qty * price;
        let del = if is_draft {
            format!(
                r#"<form method="POST" action="/purchase/orders/{id}/lines/{lid}/delete" onsubmit="return confirm('Remove this line?')"><button class="btn btn-ghost btn-xs text-error">✕</button></form>"#,
                id = id, lid = lid
            )
        } else {
            String::new()
        };
        lines_html.push_str(&format!(
            r#"<tr><td class="font-mono">{pcode}</td><td>{pname}{desc}</td>
<td class="text-right">{qty}</td><td class="text-right">{price}</td>
<td class="text-right">{tax_pct}%</td><td class="text-right">{subtotal}</td>
<td class="text-right">{recv}</td><td class="text-right">{del}</td></tr>"#,
            pcode = esc(&pcode),
            pname = esc(&pname),
            desc = desc.filter(|d| !d.is_empty()).map(|d| format!(r#"<br><span class="text-xs text-base-content/50">{}</span>"#, esc(&d))).unwrap_or_default(),
            qty = qty,
            price = money(price),
            tax_pct = tax_pct.normalize(),
            subtotal = money(subtotal),
            recv = recv,
            del = del,
        ));
    }
    if lines_html.is_empty() {
        lines_html.push_str(r#"<tr><td colspan="8" class="text-base-content/50">No lines yet — add one below.</td></tr>"#);
    }

    // ── Add-line form (draft only) ──
    let add_line_form = if is_draft {
        let products = product_options(&db).await;
        format!(
            r#"<form method="POST" action="/purchase/orders/{id}/lines" class="mt-4">
<div class="grid grid-cols-12 gap-2 items-end">
<div class="form-control col-span-4"><label class="label py-1"><span class="label-text text-xs">Product</span></label>
<select name="product_id" class="select select-bordered select-sm" required>{products}</select></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Qty</span></label>
<input name="quantity" type="number" step="0.0001" min="0.0001" value="1" class="input input-bordered input-sm" required/></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Unit Price</span></label>
<input name="unit_price" type="number" step="0.0001" min="0" value="0" class="input input-bordered input-sm"/></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Tax %</span></label>
<input name="tax_percent" type="number" step="0.01" min="0" value="0" class="input input-bordered input-sm"/></div>
<div class="col-span-2"><button class="btn btn-primary btn-sm w-full">Add Line</button></div>
</div>
<div class="form-control mt-2"><input name="description" class="input input-bordered input-sm" placeholder="Description (optional)"/></div>
</form>"#,
            id = id, products = products
        )
    } else {
        String::new()
    };

    // ── Header (editable in draft, read-only otherwise) ──
    let header = if is_draft {
        let vendors = vendor_options(&db, Some(vendor_id)).await;
        let locations = location_options(&db, dest_location_id).await;
        let currencies = currency_options(&db, currency_id).await;
        format!(
            r#"<form method="POST" action="/purchase/orders/{id}">
<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
<div class="form-control"><label class="label"><span class="label-text">Vendor *</span></label>
<select name="vendor_id" class="select select-bordered select-sm" required>{vendors}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Receiving Location</span></label>
<select name="dest_location_id" class="select select-bordered select-sm">{locations}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Order Date</span></label>
<input name="order_date" type="date" value="{order_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Expected Date</span></label>
<input name="expected_date" type="date" value="{expected_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Currency</span></label>
<select name="currency_id" class="select select-bordered select-sm">{currencies}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Note</span></label>
<input name="note" value="{note}" class="input input-bordered input-sm"/></div>
</div>
<div class="mt-3"><button class="btn btn-primary btn-sm">Save Header</button></div>
</form>"#,
            id = id,
            vendors = vendors,
            locations = locations,
            currencies = currencies,
            order_date = esc(order_date.as_deref().unwrap_or("")),
            expected_date = esc(expected_date.as_deref().unwrap_or("")),
            note = esc(note.as_deref().unwrap_or("")),
        )
    } else {
        format!(
            r#"<div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
<div><div class="text-base-content/50">Vendor</div><div class="font-medium">{vendor}</div></div>
<div><div class="text-base-content/50">Order Date</div><div class="font-medium">{order_date}</div></div>
<div><div class="text-base-content/50">Expected</div><div class="font-medium">{expected}</div></div>
<div><div class="text-base-content/50">Receiving</div><div class="font-medium">{dest}</div></div>
</div>{note}"#,
            vendor = esc(&vendor_name),
            order_date = esc(order_date.as_deref().unwrap_or("—")),
            expected = esc(expected_date.as_deref().unwrap_or("—")),
            dest = esc(dest_name.as_deref().unwrap_or("—")),
            note = note.filter(|n| !n.is_empty()).map(|n| format!(r#"<div class="mt-3 text-sm text-base-content/70">{}</div>"#, esc(&n))).unwrap_or_default(),
        )
    };

    // ── Action buttons by state ──
    let has_lines = !line_rows.is_empty();
    let mut actions = String::new();
    match po_state.as_str() {
        "draft" => {
            if has_lines {
                actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/confirm" class="inline"><button class="btn btn-primary btn-sm">Confirm Order</button></form>"#, id = id));
            }
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this order?')"><button class="btn btn-ghost btn-sm">Cancel Order</button></form>"#, id = id));
        }
        "confirmed" => {
            actions.push_str(&format!(r#"<a href="/purchase/orders/{id}/receive" class="btn btn-success btn-sm">Receive Goods</a>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this order?')"><button class="btn btn-ghost btn-sm">Cancel Order</button></form>"#, id = id));
        }
        _ => {}
    }

    let content = format!(
        r#"<div class="flex items-center justify-between mb-4">
<div>
<a href="/purchase" class="btn btn-ghost btn-sm mb-2">← Back to Purchase Orders</a>
<h1 class="text-2xl font-bold">{number} {badge}</h1>
</div>
<div>{actions}</div>
</div>

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg mb-3">Details</h2>
{header}
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-3">Lines</h2>
<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Code</th><th>Product</th><th class="text-right">Qty</th><th class="text-right">Unit Price</th><th class="text-right">Tax</th><th class="text-right">Subtotal</th><th class="text-right">Received</th><th></th></tr></thead>
<tbody>{lines}</tbody>
</table>
</div>
{add_line}
<div class="flex justify-end mt-4">
<table class="text-sm">
<tr><td class="text-base-content/60 pr-6">Untaxed</td><td class="text-right font-mono">{untaxed} {cur}</td></tr>
<tr><td class="text-base-content/60 pr-6">Tax</td><td class="text-right font-mono">{tax} {cur}</td></tr>
<tr><td class="font-semibold pr-6">Total</td><td class="text-right font-mono font-semibold">{total} {cur}</td></tr>
</table>
</div>
</div></div>"#,
        number = esc(&number),
        badge = state_badge(&po_state),
        actions = actions,
        header = header,
        lines = lines_html,
        add_line = add_line_form,
        untaxed = money(untaxed),
        tax = money(tax),
        total = money(total),
        cur = esc(&cur),
    );

    Html(page_shell(&sidebar, &format!("PO {}", number), &content)).into_response()
}

async fn update_order(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if !is_state(&db, id, "draft").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only draft orders can be edited").into_response();
    }
    let Some(vendor_id) = opt_uuid(&form, "vendor_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Vendor is required").into_response();
    };
    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("order_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("expected_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());

    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET \
            vendor_id = $1, order_date = COALESCE($2, order_date), expected_date = $3, \
            currency_id = $4, dest_location_id = $5, note = $6, \
            updated_by = $7, updated_at = NOW() \
         WHERE id = $8 AND state = 'draft'",
    )
    .bind(vendor_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(opt_uuid(&form, "currency_id"))
    .bind(opt_uuid(&form, "dest_location_id"))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "PO header update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update: {e}")).into_response();
    }
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}

/// True iff the order is currently in `want` state.
async fn is_state(db: &vortex_plugin_sdk::sqlx::PgPool, id: Uuid, want: &str) -> bool {
    let s: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM purchase_order WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
    s.as_deref() == Some(want)
}

// ─────────────────────────────────────────────────────────────────────────
// Lines
// ─────────────────────────────────────────────────────────────────────────

async fn add_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if !is_state(&db, id, "draft").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Lines can only be edited on draft orders").into_response();
    }
    let Some(product_id) = opt_uuid(&form, "product_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product is required").into_response();
    };
    let quantity = dec_or(&form, "quantity", Decimal::ONE);
    if quantity <= Decimal::ZERO {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Quantity must be greater than zero").into_response();
    }
    let unit_price = dec_or(&form, "unit_price", Decimal::ZERO);
    let tax_percent = dec_or(&form, "tax_percent", Decimal::ZERO);
    let company_id = default_company(&db).await;

    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO purchase_order_line \
         (id, order_id, product_id, description, quantity, unit_price, tax_percent, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .bind(product_id)
    .bind(form.get("description").filter(|s| !s.is_empty()))
    .bind(quantity)
    .bind(unit_price)
    .bind(tax_percent)
    .bind(company_id)
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "PO line insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to add line: {e}")).into_response();
    }
    recompute_totals(&db, id).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}

async fn delete_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path((id, line_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if !is_state(&db, id, "draft").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Lines can only be edited on draft orders").into_response();
    }
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM purchase_order_line WHERE id = $1 AND order_id = $2")
        .bind(line_id)
        .bind(id)
        .execute(&db)
        .await;
    recompute_totals(&db, id).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Confirm / cancel
// ─────────────────────────────────────────────────────────────────────────

async fn confirm_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let line_count: i64 = vortex_plugin_sdk::sqlx::query_scalar("SELECT COUNT(*) FROM purchase_order_line WHERE order_id = $1")
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap_or(0);
    if line_count == 0 {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Add at least one line before confirming").into_response();
    }

    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET state = 'confirmed', updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state = 'draft'",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only draft orders can be confirmed").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "PO confirm failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to confirm").into_response();
        }
    }

    audit_po(&state, &db_ctx, &db, user.id, &user.username, id, "confirmed").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}

async fn cancel_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET state = 'cancelled', updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state IN ('draft','confirmed')",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only draft or confirmed orders can be cancelled").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "PO cancel failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to cancel").into_response();
        }
    }

    audit_po(&state, &db_ctx, &db, user.id, &user.username, id, "cancelled").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}

async fn audit_po(
    state: &AppState,
    db_ctx: &DatabaseContext,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user_id: Uuid,
    username: &str,
    id: Uuid,
    action: &str,
) {
    let number: String = vortex_plugin_sdk::sqlx::query_scalar("SELECT number FROM purchase_order WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user_id))
    .with_username(username)
    .with_database(&db_ctx.db_name)
    .with_resource("purchase_order", id.to_string())
    .with_resource_name(&number)
    .with_details(json!({ "action": action }));
    let _ = state.audit.log(entry).await;
}

// ─────────────────────────────────────────────────────────────────────────
// Receiving
// ─────────────────────────────────────────────────────────────────────────

async fn receive_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let po = vortex_plugin_sdk::sqlx::query("SELECT number, state, dest_location_id FROM purchase_order WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
    let Some(po) = po else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Order not found").into_response();
    };
    let number: String = po.get("number");
    let po_state: String = po.get("state");
    let dest_location_id: Option<Uuid> = po.try_get("dest_location_id").ok();
    if po_state != "confirmed" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can be received").into_response();
    }
    if dest_location_id.is_none() {
        return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "Set a receiving location on the order before receiving.").into_response();
    }

    // Outstanding lines (quantity > qty_received).
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, p.code AS product_code, p.name AS product_name, p.tracking, \
                l.quantity, l.qty_received, (l.quantity - l.qty_received) AS remaining \
         FROM purchase_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.quantity > l.qty_received ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if lines.is_empty() {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response();
    }

    let mut rows = String::new();
    for r in &lines {
        let lid: Uuid = r.get("id");
        let pcode: String = r.get("product_code");
        let pname: String = r.get("product_name");
        let tracking: String = r.get("tracking");
        let remaining: Decimal = r.try_get("remaining").unwrap_or(Decimal::ZERO);
        let lot_input = if tracking == "none" {
            r#"<span class="text-base-content/40 text-xs">—</span>"#.to_string()
        } else {
            format!(
                r#"<input name="lot_{lid}" class="input input-bordered input-xs w-40" placeholder="{tracking} number" required/>"#,
                lid = lid, tracking = esc(&tracking)
            )
        };
        rows.push_str(&format!(
            r#"<tr><td class="font-mono">{pcode}</td><td>{pname}</td>
<td class="text-right">{remaining}</td>
<td><input name="qty_{lid}" type="number" step="0.0001" min="0" max="{remaining}" value="{remaining}" class="input input-bordered input-xs w-28 text-right"/></td>
<td>{lot_input}</td></tr>"#,
            pcode = esc(&pcode), pname = esc(&pname),
            remaining = remaining, lid = lid, lot_input = lot_input,
        ));
    }

    let content = format!(
        r#"<div class="max-w-3xl">
<a href="/purchase/orders/{id}" class="btn btn-ghost btn-sm mb-4">← Back to {number}</a>
<h1 class="text-2xl font-bold mb-2">Receive Goods — {number}</h1>
<p class="text-base-content/60 mb-6">Enter the quantity received per line. Lot/serial-tracked products require a number. Receiving posts validated stock moves from the Vendors location into the receiving location.</p>
<form method="POST" action="/purchase/orders/{id}/receive">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Code</th><th>Product</th><th class="text-right">Outstanding</th><th>Receive Qty</th><th>Lot / Serial</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<div class="flex gap-2 mt-4">
<button type="submit" class="btn btn-success btn-sm">Post Receipt</button>
<a href="/purchase/orders/{id}" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        id = id, number = esc(&number), rows = rows,
    );

    Html(page_shell(&sidebar, &format!("Receive {}", number), &content)).into_response()
}

async fn process_receipt(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    // Re-read the PO and guard state + destination.
    let po = vortex_plugin_sdk::sqlx::query("SELECT number, state, dest_location_id, company_id FROM purchase_order WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
    let Some(po) = po else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Order not found").into_response();
    };
    let number: String = po.get("number");
    let po_state: String = po.get("state");
    let company_id: Option<Uuid> = po.try_get("company_id").ok();
    let Some(dest_location_id): Option<Uuid> = po.try_get("dest_location_id").ok() else {
        return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No receiving location set.").into_response();
    };
    if po_state != "confirmed" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can be received").into_response();
    }

    // The Vendors (supplier) source location.
    let Some(vendor_location): Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM stock_location WHERE location_type = 'supplier' AND active ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No supplier-type location exists for receipts.").into_response();
    };

    // Outstanding lines.
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.product_id, p.tracking, p.uom_id, (l.quantity - l.qty_received) AS remaining \
         FROM purchase_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.quantity > l.qty_received",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut received_any = false;
    for r in &lines {
        let lid: Uuid = r.get("id");
        let product_id: Uuid = r.get("product_id");
        let tracking: String = r.get("tracking");
        let uom_id: Option<Uuid> = r.try_get("uom_id").ok();
        let remaining: Decimal = r.try_get("remaining").unwrap_or(Decimal::ZERO);

        let want = form
            .get(&format!("qty_{lid}"))
            .and_then(|s| s.trim().parse::<Decimal>().ok())
            .unwrap_or(Decimal::ZERO);
        if want <= Decimal::ZERO {
            continue;
        }
        let qty = if want > remaining { remaining } else { want };

        // Resolve lot for tracked products.
        let lot_id: Option<Uuid> = if tracking == "none" {
            None
        } else {
            let lot_name = form.get(&format!("lot_{lid}")).map(|s| s.trim()).unwrap_or("");
            if lot_name.is_empty() {
                return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "A lot/serial number is required for a tracked product line.").into_response();
            }
            if tracking == "serial" && qty != Decimal::ONE {
                return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Serial-tracked lines must be received one unit at a time.").into_response();
            }
            match vortex_inventory::service::resolve_lot(&db, product_id, lot_name, &tracking, company_id, user.id).await {
                Ok(lot) => Some(lot),
                Err(e) => {
                    error!(error = %e, "lot resolve failed");
                    return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve lot").into_response();
                }
            }
        };

        // Mint a move reference and post the receipt through inventory.
        let reference = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &vortex_inventory::move_sequence()).await {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "move sequence failed");
                return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate move reference").into_response();
            }
        };
        if let Err(e) = vortex_inventory::post_move(
            &db, &reference, company_id, user.id, product_id, lot_id, uom_id, qty,
            vendor_location, dest_location_id, Some(&number),
        )
        .await
        {
            error!(error = %e, "receipt move post failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to post receipt: {e}")).into_response();
        }

        let _ = vortex_plugin_sdk::sqlx::query("UPDATE purchase_order_line SET qty_received = qty_received + $1 WHERE id = $2")
            .bind(qty)
            .bind(lid)
            .execute(&db)
            .await;
        received_any = true;
    }

    if !received_any {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response();
    }

    // Flip to 'received' once every line is fully received.
    let outstanding: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM purchase_order_line WHERE order_id = $1 AND quantity > qty_received",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(0);
    if outstanding == 0 {
        let _ = vortex_plugin_sdk::sqlx::query("UPDATE purchase_order SET state = 'received', updated_by = $1, updated_at = NOW() WHERE id = $2")
            .bind(user.id)
            .bind(id)
            .execute(&db)
            .await;
    }

    audit_po(&state, &db_ctx, &db, user.id, &user.username, id, "received").await;
    info!(number = %number, "purchase receipt posted");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}
