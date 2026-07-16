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
/// RFQ number sequence — assigned at creation; the PO number is only
/// minted at confirmation.
const RFQ_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("purchase.rfq", "RFQ").with_padding(6);

pub fn purchase_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/purchase", get(list_orders))
        .route("/purchase/rfqs", get(list_rfqs))
        .route("/purchase/orders/new", get(new_order_form))
        .route("/purchase/orders/create", post(create_order))
        .route("/purchase/orders/{id}", get(edit_order))
        .route("/purchase/orders/{id}", post(update_order))
        .route("/purchase/orders/{id}/lines", post(add_line))
        .route("/purchase/orders/{id}/lines/{line_id}/delete", post(delete_line))
        .route("/purchase/orders/{id}/confirm", post(confirm_order))
        .route("/purchase/orders/{id}/send", post(mark_sent))
        .route("/purchase/orders/{id}/revise", post(revise_rfq))
        .route("/purchase/orders/{id}/duplicate", post(duplicate_order))
        .route("/purchase/orders/{id}/print-rfq", get(print_rfq))
        .route("/purchase/orders/{id}/cancel", post(cancel_order))
        .route("/purchase/orders/{id}/receive", get(receive_form))
        .route("/purchase/orders/{id}/receive", post(process_receipt))
        .route("/purchase/orders/{id}/create-bill", post(create_vendor_bill))
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
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=20" rel="stylesheet"/>
<script src="/static/vortex.js?v=20" defer></script>
<link href="/static/tailwind.css?v=21" rel="stylesheet"/>
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
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
        &db_ctx.custom_apps_html,
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
        "rfq" => r#"<span class="badge badge-ghost">RFQ</span>"#,
        "sent" => r#"<span class="badge badge-info badge-outline">Sent</span>"#,
        "superseded" => r#"<span class="badge badge-ghost badge-outline">Superseded</span>"#,
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

/// Display identity: PO number once confirmed, the RFQ number (with
/// revision suffix past rev 1) before that.
fn doc_identity(number: Option<&str>, rfq_number: Option<&str>, revision: i32) -> String {
    match number.filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => {
            let q = rfq_number.unwrap_or("(unnumbered)");
            if revision > 1 { format!("{q} (Rev {revision})") } else { q.to_string() }
        }
    }
}

async fn list_orders(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    // Confirmed purchases only — the pre-order pipeline lives on the
    // RFQs list. (Cancelled POs carry a number; cancelled RFQs don't.)
    let config = ListConfig::new("Purchase Orders", "purchase_order")
        .custom_from(
            "(SELECT * FROM purchase_order WHERE state IN ('confirmed','received') \
              OR (state = 'cancelled' AND number IS NOT NULL)) po \
             JOIN contacts v ON v.id = po.vendor_id",
        )
        .custom_select(
            "po.id, po.number, po.rfq_number, v.name AS vendor_name, po.order_date::text AS order_date, \
             po.total_amount::text AS total_amount, po.state",
        )
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("po.number"))
        .column(ListColumn::new("rfq_number", "RFQ").sortable().code().sql_expr("po.rfq_number"))
        .column(ListColumn::new("vendor_name", "Vendor").sortable().searchable().sql_expr("v.name"))
        .column(ListColumn::new("order_date", "Order Date").sortable().sql_expr("po.order_date"))
        .column(ListColumn::new("total_amount", "Total").sortable().sql_expr("po.total_amount"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("confirmed", "Confirmed"),
                    ("received", "Received"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("confirmed", "Confirmed", "badge-info"),
                    ("received", "Received", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("po.state"),
        )
        .detail_url("/purchase/orders/{id}")
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

/// The pre-order pipeline: every RFQ revision from open to cancelled.
async fn list_rfqs(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("RFQs", "purchase_order")
        .custom_from(
            "(SELECT * FROM purchase_order WHERE state IN ('rfq','sent','superseded') \
              OR (state = 'cancelled' AND number IS NULL)) po \
             JOIN contacts v ON v.id = po.vendor_id",
        )
        .custom_select(
            "po.id, po.rfq_number, po.revision::text AS revision, v.name AS vendor_name, \
             po.order_date::text AS order_date, po.respond_by::text AS respond_by, \
             po.total_amount::text AS total_amount, po.state",
        )
        .column(ListColumn::new("rfq_number", "Number").sortable().code().sql_expr("po.rfq_number"))
        .column(ListColumn::new("revision", "Rev").sortable().sql_expr("po.revision"))
        .column(ListColumn::new("vendor_name", "Vendor").sortable().searchable().sql_expr("v.name"))
        .column(ListColumn::new("order_date", "Date").sortable().sql_expr("po.order_date"))
        .column(ListColumn::new("respond_by", "Respond By").sortable().sql_expr("po.respond_by"))
        .column(ListColumn::new("total_amount", "Est. Total").sortable().sql_expr("po.total_amount"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("rfq", "Open"),
                    ("sent", "Sent"),
                    ("superseded", "Superseded"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("rfq", "Open", "badge-ghost"),
                    ("sent", "Sent", "badge-info"),
                    ("superseded", "Superseded", "badge-ghost"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("po.state"),
        )
        .detail_url("/purchase/orders/{id}")
        .create("New RFQ", "/purchase/orders/new")
        .default_sort("rfq_number")
        .group_by_options(&[("vendor_name", "Vendor"), ("state", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "RFQ list query failed");
            return Html("<h1>Failed to load RFQs</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/purchase/rfqs");
    Html(page_shell(&sidebar, "RFQs", &list_html)).into_response()
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

    // Field groups — identical field markup to before, now composed as one flat
    // Odoo-style sheet section (see vortex_plugin_sdk::framework::form_section_raw)
    // instead of a floating card. The submit/cancel buttons move to the sheet footer.
    let fields = format!(
        r#"<p class="text-base-content/60 text-sm mb-4">Every purchase starts as a request for quotation — it gets its PO number when confirmed.</p>
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
<div class="form-control mb-3">
<label class="label"><span class="label-text">Respond By</span></label>
<input name="respond_by" type="date" class="input input-bordered input-sm"/>
<label class="label"><span class="label-text-alt text-base-content/50">Optional reply-by date for the supplier's quote.</span></label>
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
</div>"#,
        vendors = vendors,
        locations = locations,
        currencies = currencies,
    );

    let inner = vortex_plugin_sdk::framework::form_section_raw("", &fields);

    let content = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/purchase/rfqs",
        control_row: "",
        form_attrs: r#"method="POST" action="/purchase/orders/create""#,
        title: "New RFQ",
        inner: &inner,
        footer: r#"<a href="/purchase" class="btn btn-ghost btn-sm">Cancel</a><button type="submit" class="btn btn-primary btn-sm">Create</button>"#,
        below: "",
    });

    Html(page_shell(&sidebar, "New RFQ", &content)).into_response()
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

    // Every purchase starts life as an RFQ: RFQ number now, PO number
    // only at confirmation.
    let rfq_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &RFQ_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "RFQ sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate RFQ number").into_response();
        }
    };
    let company_id = default_company(&db).await;

    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("order_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("expected_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let respond_by: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("respond_by").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());

    let order_id = Uuid::now_v7();
    // order_date column defaults to CURRENT_DATE; pass COALESCE via Option.
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO purchase_order \
         (id, rfq_number, revision, root_rfq_id, respond_by, vendor_id, order_date, \
          expected_date, currency_id, dest_location_id, note, company_id, created_by) \
         VALUES ($1,$2,1,$1,$11,$3,COALESCE($4, CURRENT_DATE),$5,$6,$7,$8,$9,$10)",
    )
    .bind(order_id)
    .bind(&rfq_number)
    .bind(vendor_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(opt_uuid(&form, "currency_id"))
    .bind(opt_uuid(&form, "dest_location_id"))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(company_id)
    .bind(user.id)
    .bind(respond_by)
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "RFQ insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create RFQ: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("purchase_order", order_id.to_string())
    .with_resource_name(&rfq_number)
    .with_details(json!({ "rfq_number": rfq_number }));
    let _ = state.audit.log(audit_entry).await;

    info!(number = %rfq_number, "RFQ created");
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
        "SELECT po.number, po.rfq_number, po.revision, po.root_rfq_id, \
                po.respond_by::text AS respond_by, \
                po.vendor_id, v.name AS vendor_name, \
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

    let number: Option<String> = row.try_get("number").ok().flatten();
    let rfq_number: Option<String> = row.try_get("rfq_number").ok().flatten();
    let revision: i32 = row.try_get("revision").unwrap_or(1);
    let root_rfq_id: Option<Uuid> = row.try_get("root_rfq_id").ok().flatten();
    let respond_by: Option<String> = row.try_get("respond_by").ok().flatten();
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
    let is_draft = po_state == "rfq";
    let is_rfq_stage = matches!(po_state.as_str(), "rfq" | "sent" | "superseded");
    let identity = doc_identity(number.as_deref(), rfq_number.as_deref(), revision);
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
<div class="form-control"><label class="label"><span class="label-text">Respond By</span></label>
<input name="respond_by" type="date" value="{respond_by}" class="input input-bordered input-sm"/></div>
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
            respond_by = esc(respond_by.as_deref().unwrap_or("")),
            note = esc(note.as_deref().unwrap_or("")),
        )
    } else {
        format!(
            r#"<div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
<div><div class="text-base-content/50">Vendor</div><div class="font-medium">{vendor}</div></div>
<div><div class="text-base-content/50">Order Date</div><div class="font-medium">{order_date}</div></div>
<div><div class="text-base-content/50">Expected</div><div class="font-medium">{expected}</div></div>
<div><div class="text-base-content/50">Receiving</div><div class="font-medium">{dest}</div></div>
<div><div class="text-base-content/50">RFQ</div><div class="font-medium">{rfq_no}</div></div>
<div><div class="text-base-content/50">Respond By</div><div class="font-medium">{respond}</div></div>
</div>{note}"#,
            vendor = esc(&vendor_name),
            order_date = esc(order_date.as_deref().unwrap_or("—")),
            expected = esc(expected_date.as_deref().unwrap_or("—")),
            dest = esc(dest_name.as_deref().unwrap_or("—")),
            rfq_no = {
                let q = rfq_number.as_deref().unwrap_or("—");
                if revision > 1 { format!("{} (Rev {})", esc(q), revision) } else { esc(q).to_string() }
            },
            respond = esc(respond_by.as_deref().unwrap_or("—")),
            note = note.filter(|n| !n.is_empty()).map(|n| format!(r#"<div class="mt-3 text-sm text-base-content/70">{}</div>"#, esc(&n))).unwrap_or_default(),
        )
    };

    // ── Action buttons by state ──
    let has_lines = !line_rows.is_empty();
    let mut actions = String::new();
    match po_state.as_str() {
        "rfq" => {
            actions.push_str(&format!(r#"<a href="/purchase/orders/{id}/print-rfq" target="_blank" class="btn btn-outline btn-sm">Print RFQ</a>"#, id = id));
            if has_lines {
                actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/send" class="inline ml-2"><button class="btn btn-primary btn-sm" title="Freezes this revision — the supplier now holds a copy">Mark as Sent</button></form>"#, id = id));
                actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/confirm" class="inline ml-2"><button class="btn btn-success btn-sm">Confirm Order</button></form>"#, id = id));
            }
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this RFQ?')"><button class="btn btn-ghost btn-sm">Cancel</button></form>"#, id = id));
        }
        "sent" => {
            actions.push_str(&format!(r#"<a href="/purchase/orders/{id}/print-rfq" target="_blank" class="btn btn-outline btn-sm">Print RFQ</a>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/confirm" class="inline ml-2"><button class="btn btn-primary btn-sm">Confirm Order</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/revise" class="inline ml-2"><button class="btn btn-outline btn-sm" title="Creates the next revision; this one stays exactly as the supplier received it">Revise</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this RFQ?')"><button class="btn btn-ghost btn-sm">Cancel</button></form>"#, id = id));
        }
        "cancelled" if number.is_none() => {
            actions.push_str(&format!(r#"<a href="/purchase/orders/{id}/print-rfq" target="_blank" class="btn btn-outline btn-sm">Print RFQ</a>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/revise" class="inline ml-2"><button class="btn btn-primary btn-sm">Revise</button></form>"#, id = id));
        }
        "superseded" => {
            actions.push_str(&format!(r#"<a href="/purchase/orders/{id}/print-rfq" target="_blank" class="btn btn-outline btn-sm">Print RFQ</a>"#, id = id));
        }
        "confirmed" => {
            actions.push_str(&format!(r#"<a href="/purchase/orders/{id}/receive" class="btn btn-success btn-sm">Receive Goods</a>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/purchase/orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this order?')"><button class="btn btn-ghost btn-sm">Cancel Order</button></form>"#, id = id));
        }
        _ => {}
    }
    // Accounting bridge: bill a confirmed/received order once.
    if has_lines && matches!(po_state.as_str(), "confirmed" | "received") {
        let bill: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT vendor_bill_move_id FROM purchase_order WHERE id = $1",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .ok()
        .flatten();
        match bill {
            Some(bill_id) => actions.push_str(&format!(
                r#"<a href="/accounting/documents/{bill_id}" class="btn btn-outline btn-sm ml-2">View Vendor Bill</a>"#
            )),
            None => actions.push_str(&format!(
                r#"<form method="POST" action="/purchase/orders/{id}/create-bill" class="inline ml-2"><button class="btn btn-outline btn-sm">Create Vendor Bill</button></form>"#
            )),
        }
    }
    // Duplicate — available in every state: any document, however far
    // along, can seed a fresh editable RFQ.
    actions.push_str(&format!(
        r#"<span class="inline ml-2">{}</span>"#,
        duplicate_button(&format!("/purchase/orders/{id}/duplicate")),
    ));

    // ── Revision chain ──
    let revisions_card = if let Some(root) = root_rfq_id {
        let revs = vortex_plugin_sdk::sqlx::query(
            "SELECT id, revision, state, number, total_amount FROM purchase_order \
             WHERE root_rfq_id = $1 ORDER BY revision",
        )
        .bind(root)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        if revs.len() < 2 {
            String::new()
        } else {
            let mut rows_html = String::new();
            for r in &revs {
                let rid: Uuid = r.get("id");
                let rev: i32 = r.get("revision");
                let rstate: String = r.get("state");
                let rnum: Option<String> = r.try_get("number").ok().flatten();
                let rtotal: Decimal = r.try_get("total_amount").unwrap_or(Decimal::ZERO);
                let this_marker = if rid == id { r#" <span class="text-xs opacity-60">(this)</span>"# } else { "" };
                rows_html.push_str(&format!(
                    r#"<tr><td>Rev {rev}{this_marker}</td><td>{badge}</td><td class="font-mono">{po}</td>
<td class="text-right font-mono">{total}</td>
<td class="text-right"><a href="/purchase/orders/{rid}" class="btn btn-ghost btn-xs">Open</a></td></tr>"#,
                    rev = rev,
                    this_marker = this_marker,
                    badge = state_badge(&rstate),
                    po = rnum.filter(|n| !n.is_empty()).map(|n| esc(&n).to_string()).unwrap_or_else(|| "—".into()),
                    total = money(rtotal),
                    rid = rid,
                ));
            }
            format!(
                r#"<div class="card bg-base-100 shadow mt-6"><div class="card-body">
<h2 class="card-title text-lg mb-3">Revisions</h2>
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Revision</th><th>Status</th><th>Purchase Order</th><th class="text-right">Total</th><th class="text-right"></th></tr></thead>
<tbody>{rows_html}</tbody></table></div>
</div></div>"#
            )
        }
    } else {
        String::new()
    };
    let rfq_ref = if number.is_some() && rfq_number.is_some() {
        format!(
            r#" <span class="text-sm opacity-60 font-normal">from {}</span>"#,
            esc(rfq_number.as_deref().unwrap_or(""))
        )
    } else {
        String::new()
    };

    // Activity stream: schedule/assign/complete tasks, messages, attachments.
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("purchase_order", id);

    let content = format!(
        r#"<div class="flex items-center justify-between mb-4">
<div>
<a href="{back_url}" class="btn btn-ghost btn-sm mb-2">← Back to {back_label}</a>
<h1 class="text-2xl font-bold">{number}{rfq_ref} {badge}</h1>
</div>
<div class="vortex-actions">{actions}</div>
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
</div></div>

{revisions_card}
<div class="mt-6">{activity_panel}</div>"#,
        back_url = if is_rfq_stage { "/purchase/rfqs" } else { "/purchase" },
        back_label = if is_rfq_stage { "RFQs" } else { "Purchase Orders" },
        number = esc(&identity),
        rfq_ref = rfq_ref,
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

    Html(page_shell(&sidebar, &identity, &content)).into_response()
}

async fn update_order(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    if !is_state(&db, id, "rfq").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open RFQs can be edited").into_response();
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
            currency_id = $4, dest_location_id = $5, note = $6, respond_by = $9, \
            updated_by = $7, updated_at = NOW() \
         WHERE id = $8 AND state = 'rfq'",
    )
    .bind(vendor_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(opt_uuid(&form, "currency_id"))
    .bind(opt_uuid(&form, "dest_location_id"))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(user.id)
    .bind(id)
    .bind(form.get("respond_by").filter(|s| !s.is_empty()).and_then(|s| s.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok()))
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
    if !is_state(&db, id, "rfq").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Lines can only be edited on open RFQs").into_response();
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
    if !is_state(&db, id, "rfq").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Lines can only be edited on open RFQs").into_response();
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

    // The confirmed order receives its PO number here; the RFQ keeps
    // its identity for traceability.
    let po_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &PO_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "PO sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate PO number").into_response();
        }
    };
    // The partial unique index on root_rfq_id backstops this UPDATE.
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET state = 'confirmed', number = $3, updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state IN ('rfq', 'sent')",
    )
    .bind(user.id)
    .bind(id)
    .bind(&po_number)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open or sent RFQs can be confirmed").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "PO confirm failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Failed to confirm — another revision of this RFQ may already be confirmed.").into_response();
        }
    }

    // Every other open revision of the family is now superseded.
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET state = 'superseded', updated_by = $1, updated_at = NOW() \
         WHERE root_rfq_id = (SELECT root_rfq_id FROM purchase_order WHERE id = $2) \
           AND id <> $2 AND state IN ('rfq', 'sent')",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

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
         WHERE id = $2 AND state IN ('rfq','sent','confirmed')",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open RFQs or confirmed orders can be cancelled").into_response(),
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

/// rfq → sent: the RFQ is now with the supplier; changes require a
/// revision.
async fn mark_sent(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET state = 'sent', updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state = 'rfq'",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open RFQs can be marked sent").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "RFQ send failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to mark sent").into_response();
        }
    }
    audit_po(&state, &db_ctx, &db, user.id, &user.username, id, "sent").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{id}")).into_response()
}

/// Clone a frozen RFQ into the next revision. The source stays exactly
/// as the supplier received it (sent → superseded, cancelled keeps its
/// state); the clone reopens as an editable RFQ.
async fn revise_rfq(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let src = vortex_plugin_sdk::sqlx::query(
        "SELECT rfq_number, root_rfq_id, state FROM purchase_order WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(src) = src else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "RFQ not found").into_response();
    };
    let src_state: String = src.get("state");
    if !matches!(src_state.as_str(), "sent" | "cancelled") {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only sent or cancelled RFQs can be revised — open RFQs are edited directly.").into_response();
    }
    let root: Uuid = src.get("root_rfq_id");
    let live: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM purchase_order WHERE root_rfq_id = $1 \
         AND state NOT IN ('rfq','sent','superseded','cancelled')",
    )
    .bind(root)
    .fetch_one(&db)
    .await
    .unwrap_or(0);
    if live > 0 {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "This RFQ already has a confirmed purchase order — revise is not available.").into_response();
    }
    let next_rev: i32 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COALESCE(MAX(revision), 0) + 1 FROM purchase_order WHERE root_rfq_id = $1",
    )
    .bind(root)
    .fetch_one(&db)
    .await
    .unwrap_or(2);

    let new_id = Uuid::now_v7();
    let rfq_number: String = src.get("rfq_number");
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO purchase_order \
         (id, rfq_number, revision, root_rfq_id, respond_by, vendor_id, order_date, \
          expected_date, currency_id, dest_location_id, note, company_id, created_by) \
         SELECT $1, rfq_number, $3, root_rfq_id, respond_by, vendor_id, CURRENT_DATE, \
                expected_date, currency_id, dest_location_id, note, company_id, $4 \
         FROM purchase_order WHERE id = $2",
    )
    .bind(new_id)
    .bind(id)
    .bind(next_rev)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "RFQ revision insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to create revision").into_response();
    }
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO purchase_order_line \
         (id, order_id, sequence, product_id, description, quantity, unit_price, tax_percent, company_id) \
         SELECT uuid_generate_v4(), $1, sequence, product_id, description, quantity, unit_price, tax_percent, company_id \
         FROM purchase_order_line WHERE order_id = $2",
    )
    .bind(new_id)
    .bind(id)
    .execute(&db)
    .await;
    recompute_totals(&db, new_id).await;

    if src_state == "sent" {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE purchase_order SET state = 'superseded', updated_by = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(user.id)
        .bind(id)
        .execute(&db)
        .await;
    }

    audit_po(&state, &db_ctx, &db, user.id, &user.username, new_id, "revised").await;
    info!(rfq = %rfq_number, revision = next_rev, "RFQ revised");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{new_id}")).into_response()
}

/// POST /purchase/orders/{id}/duplicate — copy any document, whatever its
/// state, into a fresh editable RFQ that starts its own revision family:
/// new RFQ number, revision 1, no PO number, nothing received or billed.
/// (Contrast with revise, which stays inside the source's RFQ family.)
async fn duplicate_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // Every purchase document is born as an RFQ: the copy draws a fresh
    // RFQ number now; its PO number is only minted at confirmation.
    let rfq_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &RFQ_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "RFQ sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate RFQ number").into_response();
        }
    };

    let new_id = Uuid::now_v7();
    let spec = DuplicateSpec::new("purchase_order")
        .with_id(new_id)
        .set("rfq_number", json!(rfq_number))
        .set("root_rfq_id", json!(new_id)) // the copy roots its own RFQ family
        .skip("revision") // default 1
        .skip("number") // PO number arrives at confirmation
        .skip("state") // default 'rfq'
        .skip("order_date") // default CURRENT_DATE — today
        .skip("respond_by") // the source's reply-by date is stale here
        .skip("updated_by") // nobody has touched the copy yet
        .skip("vendor_bill_move_id") // never inherit the source's vendor bill
        .skip("untaxed_amount") // recomputed from the copied lines below
        .skip("tax_amount")
        .skip("total_amount")
        .child(
            ChildCopy::new("purchase_order_line", "order_id")
                .set("qty_received", json!(0)), // nothing received yet
        );
    if let Err(e) = spec.execute(&db, id, Some(user.id)).await {
        error!(error = %e, "PO duplicate failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Duplicate failed: {e}")).into_response();
    }
    recompute_totals(&db, new_id).await;

    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("purchase_order", new_id.to_string())
    .with_resource_name(&rfq_number)
    .with_details(json!({ "duplicated_from": id, "rfq_number": rfq_number }));
    let _ = state.audit.log(entry).await;

    info!(number = %rfq_number, "purchase order duplicated");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/purchase/orders/{new_id}")).into_response()
}

/// Printable RFQ — deliberately price-free: it asks the supplier to
/// quote. Quantities, UoM and required-by dates only.
async fn print_rfq(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT o.rfq_number, o.revision, o.state, o.order_date, o.respond_by, o.expected_date, o.note, \
                v.name AS vendor_name, v.street, v.street2, v.city, v.zip, \
                v.phone AS vendor_phone, v.email AS vendor_email \
         FROM purchase_order o \
         JOIN contacts v ON v.id = o.vendor_id \
         WHERE o.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(head) = head else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "RFQ not found").into_response();
    };
    let company = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(co.name, 'Company') AS name, c.company_address1, c.company_address2, \
                c.company_city, c.company_postcode, c.company_phone, c.company_email \
         FROM acc_config c LEFT JOIN companies co ON co.id = c.company_id \
         ORDER BY c.company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT p.code, COALESCE(NULLIF(l.description, ''), p.name) AS description, \
                l.quantity, u.code AS uom_code \
         FROM purchase_order_line l \
         JOIN stock_product p ON p.id = l.product_id \
         LEFT JOIN uoms u ON u.id = p.uom_id \
         WHERE l.order_id = $1 ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let hval = |k: &str| -> String {
        head.try_get::<Option<String>, _>(k).ok().flatten().map(|v| esc(&v)).unwrap_or_default()
    };
    let cval = |k: &str| -> String {
        company
            .as_ref()
            .and_then(|c| c.try_get::<Option<String>, _>(k).ok().flatten())
            .map(|v| esc(&v))
            .unwrap_or_default()
    };
    let company_name = company
        .as_ref()
        .map(|c| esc(&c.get::<String, _>("name")))
        .unwrap_or_else(|| "Company".into());
    let logo_html = match state.files.get(&db_ctx.db_name, "company/logo").await {
        Ok(Some(data)) => {
            use base64::Engine;
            let ct = if data.starts_with(&[0xFF, 0xD8, 0xFF]) { "image/jpeg" } else { "image/png" };
            format!(
                r#"<img src="data:{ct};base64,{}" alt="" style="max-height:64px;max-width:220px;margin-bottom:6px"/>"#,
                base64::engine::general_purpose::STANDARD.encode(&data),
            )
        }
        _ => String::new(),
    };
    let revision: i32 = head.try_get("revision").unwrap_or(1);
    let rfq_state: String = head.get("state");
    let display_number = {
        let q = hval("rfq_number");
        if revision > 1 { format!("{q} (Rev {revision})") } else { q }
    };
    let status_mark = match rfq_state.as_str() {
        "superseded" => r#"<div class="watermark">SUPERSEDED</div>"#,
        "cancelled" => r#"<div class="watermark">CANCELLED</div>"#,
        _ => "",
    };
    let mut line_trs = String::new();
    for (i, l) in lines.iter().enumerate() {
        let qty: Decimal = l.get("quantity");
        line_trs.push_str(&format!(
            r#"<tr><td class="num">{n}</td><td class="mono-code">{code}</td><td>{desc}</td><td class="num">{qty}</td><td>{uom}</td><td></td><td></td></tr>"#,
            n = i + 1,
            code = esc(&l.get::<String, _>("code")),
            desc = esc(&l.get::<String, _>("description")),
            qty = qty.normalize(),
            uom = l.try_get::<Option<String>, _>("uom_code").ok().flatten().map(|u| esc(&u).to_string()).unwrap_or_default(),
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{number} — REQUEST FOR QUOTATION</title>
<style>{css}
body {{ max-width: 21cm; margin: 1.2cm auto; position: relative; }}
@page {{ size: A4; margin: 0; }}
@media print {{
  body {{ max-width: none; margin: 0; padding: 1.2cm 1.4cm; }}
}}
.head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.2em; }}
.head h1 {{ font-size: 1.3em; letter-spacing: 0.06em; }}
.seller p, .buyer p {{ margin: 1px 0; font-size: 0.85em; }}
.seller .name {{ font-size: 1.1em; font-weight: 700; }}
.meta td {{ padding: 1px 8px 1px 0; font-size: 0.85em; border: none; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono-code {{ font-family: monospace; }}
.sig {{ margin-top: 3em; display: flex; gap: 3em; }}
.sig div {{ flex: 1; border-top: 1px solid #333; padding-top: 0.4em; font-size: 0.8em; }}
.footer {{ margin-top: 2em; font-size: 0.75em; color: #666; }}
.watermark {{ position: absolute; top: 35%; left: 15%; font-size: 5em; color: rgba(200,0,0,0.12); transform: rotate(-25deg); pointer-events: none; }}
.printbar {{ text-align: right; margin-bottom: 1em; }}
.printbar button {{ padding: 0.4em 1.2em; cursor: pointer; }}
@media print {{ .printbar {{ display: none; }} }}
</style></head><body>
{status_mark}
<div class="printbar"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="head">
  <div class="seller">
    {logo_html}
    <p class="name">{company_name}</p>
    <p>{addr1}</p><p>{addr2}</p><p>{postcode} {city}</p>
    <p>{cphone} · {cemail}</p>
  </div>
  <div style="text-align:right">
    <h1>REQUEST FOR QUOTATION</h1>
    <table class="meta" style="margin-left:auto">
      <tr><td>Number</td><td><b>{number}</b></td></tr>
      <tr><td>Date</td><td>{date}</td></tr>
      <tr><td>Respond By</td><td>{respond_by}</td></tr>
      <tr><td>Goods Required By</td><td>{expected}</td></tr>
    </table>
  </div>
</div>
<div class="buyer" style="margin-bottom:1em">
  <p style="font-size:0.75em;color:#666">TO (SUPPLIER)</p>
  <p><b>{vendor}</b></p>
  <p>{pstreet}</p><p>{pstreet2}</p><p>{pzip} {pcity}</p>
  <p>{pphone} {pemail}</p>
</div>
<p style="font-size:0.85em">Please quote your best price, lead time and validity for the items below.</p>
<table class="table table-sm" style="table-layout:fixed;width:100%">
<colgroup><col style="width:2.5rem"/><col style="width:7rem"/><col/><col style="width:4.5rem"/><col style="width:4rem"/><col style="width:8rem"/><col style="width:8rem"/></colgroup>
<thead><tr><th class="num">#</th><th>Code</th><th>Description</th><th class="num">Qty</th><th>UoM</th><th>Your Unit Price</th><th>Lead Time</th></tr></thead>
<tbody>{line_trs}</tbody>
</table>
<div class="sig">
  <div>Requested by<br><br>Name:<br>Date:</div>
  <div>Quoted by (supplier)<br><br>Name, company stamp:<br>Date:</div>
</div>
<div class="footer">This is a request for quotation, not a purchase order — no commitment is implied. {note}</div>
</body></html>"##,
        css = vortex_plugin_sdk::framework::user_reports::REPORT_CSS,
        status_mark = status_mark,
        number = display_number,
        logo_html = logo_html,
        company_name = company_name,
        addr1 = cval("company_address1"),
        addr2 = cval("company_address2"),
        postcode = cval("company_postcode"),
        city = cval("company_city"),
        cphone = cval("company_phone"),
        cemail = cval("company_email"),
        date = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("order_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_default(),
        respond_by = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("respond_by")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "—".into()),
        expected = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("expected_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "—".into()),
        vendor = hval("vendor_name"),
        pstreet = hval("street"),
        pstreet2 = hval("street2"),
        pzip = hval("zip"),
        pcity = hval("city"),
        pphone = hval("vendor_phone"),
        pemail = hval("vendor_email"),
        line_trs = line_trs,
        note = hval("note"),
    );
    Html(html).into_response()
}

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
    let number: String = po.try_get::<Option<String>, _>("number").ok().flatten().unwrap_or_default();
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

    // Receipt entry table — identical markup to before, now composed as one flat
    // Odoo-style sheet section instead of a floating card; buttons move to the footer.
    let fields = format!(
        r#"<p class="text-base-content/60 mb-6">Enter the quantity received per line. Lot/serial-tracked products require a number. Receiving posts validated stock moves from the Vendors location into the receiving location.</p>
<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Code</th><th>Product</th><th class="text-right">Outstanding</th><th>Receive Qty</th><th>Lot / Serial</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>"#,
        rows = rows,
    );

    let inner = vortex_plugin_sdk::framework::form_section_raw("", &fields);

    let content = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: &format!("/purchase/orders/{id}"),
        control_row: "",
        form_attrs: &format!(r#"method="POST" action="/purchase/orders/{id}/receive""#),
        title: &format!("Receive Goods — {}", number),
        inner: &inner,
        footer: &format!(
            r#"<a href="/purchase/orders/{id}" class="btn btn-ghost btn-sm">Cancel</a><button type="submit" class="btn btn-success btn-sm">Post Receipt</button>"#
        ),
        below: "",
    });

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
    let number: String = po.try_get::<Option<String>, _>("number").ok().flatten().unwrap_or_default();
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

// ─────────────────────────────────────────────────────────────────────────
// Accounting bridge — vendor bill from a purchase order
// ─────────────────────────────────────────────────────────────────────────

/// Create (and post) an accounting vendor bill from a confirmed or
/// received order. Idempotent: refuses when the PO is already billed.
/// Line taxes map by matching the PO line's tax_percent against an
/// active purchase tax; unmatched rates bill untaxed with the amount
/// already folded into the PO total (flagged in the bill narration).
async fn create_vendor_bill(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    use vortex_accounting::documents::{self, InvoiceLine, NewInvoice};

    let po = vortex_plugin_sdk::sqlx::query(
        "SELECT number, state, vendor_id, order_date, company_id, vendor_bill_move_id \
         FROM purchase_order WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(po) = po else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Order not found").into_response();
    };
    let number: String = po.try_get::<Option<String>, _>("number").ok().flatten().unwrap_or_default();
    let po_state: String = po.get("state");
    if !matches!(po_state.as_str(), "confirmed" | "received") {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed or received orders can be billed").into_response();
    }
    if po.get::<Option<Uuid>, _>("vendor_bill_move_id").is_some() {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "This order already has a vendor bill").into_response();
    }
    let vendor_id: Uuid = po.get("vendor_id");
    let company_id: Option<Uuid> = po.try_get("company_id").ok().flatten();
    let order_date: vortex_plugin_sdk::chrono::NaiveDate = po
        .try_get("order_date")
        .unwrap_or_else(|_| vortex_plugin_sdk::chrono::Utc::now().date_naive());

    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(NULLIF(l.description, ''), NULLIF(p.purchase_description, ''), p.name) AS name, \
                l.quantity, l.unit_price, l.tax_percent \
         FROM purchase_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 ORDER BY l.sequence",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    if line_rows.is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "Order has no lines").into_response();
    }

    let mut lines = Vec::new();
    let mut unmatched_rates = Vec::new();
    for r in &line_rows {
        let name: String = r.get("name");
        let quantity: Decimal = r.get("quantity");
        let unit_price: Decimal = r.get("unit_price");
        let tax_percent: Decimal = r.get("tax_percent");
        let mut line = InvoiceLine::new(&name, quantity, unit_price);
        if tax_percent > Decimal::ZERO {
            let tax: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT id FROM taxes WHERE active AND type_tax_use IN ('purchase', 'both') \
                   AND amount_type = 'percent' AND amount = $1 \
                 ORDER BY name LIMIT 1",
            )
            .bind(tax_percent)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();
            match tax {
                Some(t) => line = line.with_tax(t),
                None => unmatched_rates.push(tax_percent.normalize().to_string()),
            }
        }
        lines.push(line);
    }
    let narration = if unmatched_rates.is_empty() {
        None
    } else {
        Some(format!(
            "PO tax rate(s) {}% had no matching purchase tax — billed untaxed; review before posting SST.",
            unmatched_rates.join("%, ")
        ))
    };

    let origin = format!("purchase_order:{id}");
    let bill = match documents::create_invoice(
        &db,
        user.id,
        &NewInvoice {
            move_type: "vendor_bill",
            partner_id: vendor_id,
            invoice_date: order_date,
            due_date: None,
            journal_code: None,
            currency_id: None,
            origin_ref: Some(&origin),
            narration: narration.as_deref(),
            company_id,
            lines,
        },
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "vendor bill create failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY, format!("Failed to create bill: {e}")).into_response();
        }
    };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE purchase_order SET vendor_bill_move_id = $2, updated_by = $3, updated_at = NOW() \
         WHERE id = $1 AND vendor_bill_move_id IS NULL",
    )
    .bind(id)
    .bind(bill)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "vendor bill link failed");
    }
    audit_po(&state, &db_ctx, &db, user.id, &user.username, id, "billed").await;
    info!(number = %number, bill = %bill, "vendor bill created from purchase order");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/accounting/documents/{bill}")).into_response()
}
