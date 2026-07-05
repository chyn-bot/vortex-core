//! Sales-order handlers — customers → orders → deliveries. Delivering a
//! confirmed order posts validated stock moves OUT of inventory through
//! `vortex_inventory::post_move`, keeping on-hand backed by the ledger.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

/// Quotation number sequence — `QT/000001` (assigned at creation;
/// the SO number is only minted at confirmation).
const QT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sales.quote", "QT").with_padding(6);
/// Sales-order number sequence — `SO/000001`.
const SO_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sales.order", "SO").with_padding(6);
/// Delivery-order number sequence — `DO/000001`.
const DO_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sales.delivery", "DO").with_padding(6);
/// Service-confirmation number sequence — `SC/000001`.
const SC_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("sales.service_confirmation", "SC").with_padding(6);

pub fn sales_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/sales", get(list_orders))
        .route("/sales/quotes", get(list_quotes))
        .route("/sales/orders/new", get(new_order_form))
        .route("/sales/orders/create", post(create_order))
        .route("/sales/orders/{id}", get(edit_order))
        .route("/sales/orders/{id}", post(update_order))
        .route("/sales/orders/{id}/lines", post(add_line))
        .route("/sales/orders/{id}/lines/{line_id}/delete", post(delete_line))
        .route("/sales/orders/{id}/confirm", post(confirm_order))
        .route("/sales/orders/{id}/send", post(mark_sent))
        .route("/sales/orders/{id}/revise", post(revise_quote))
        .route("/sales/orders/{id}/lost", post(mark_lost))
        .route("/sales/orders/{id}/print-quote", get(print_quote))
        .route("/sales/orders/{id}/cancel", post(cancel_order))
        .route("/sales/orders/{id}/deliver", get(deliver_form))
        .route("/sales/orders/{id}/deliver", post(process_delivery))
        .route("/sales/orders/{id}/confirm-services", get(service_form))
        .route("/sales/orders/{id}/confirm-services", post(process_service_confirmation))
        .route("/sales/deliveries/{id}/print", get(print_delivery))
        .route("/sales/orders/{id}/create-invoice", post(create_customer_invoice))
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
<link href="/static/vortex.css?v=4" rel="stylesheet"/>
<script src="/static/vortex.js?v=4" defer></script>
<script src="/static/vendor/tailwind.js"></script>
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
        "sales",
        display_name,
        &initials,
        &db_ctx.installed_modules,
        user.is_admin(),
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

/// Badge markup for a sales-order state.
fn state_badge(state: &str) -> &'static str {
    match state {
        "quotation" => r#"<span class="badge badge-ghost">Quotation</span>"#,
        "sent" => r#"<span class="badge badge-info badge-outline">Sent</span>"#,
        "confirmed" => r#"<span class="badge badge-info">Confirmed</span>"#,
        "delivered" => r#"<span class="badge badge-success">Delivered</span>"#,
        "cancelled" => r#"<span class="badge badge-error">Cancelled</span>"#,
        "superseded" => r#"<span class="badge badge-ghost badge-outline">Superseded</span>"#,
        "lost" => r#"<span class="badge badge-error badge-outline">Lost</span>"#,
        "expired" => r#"<span class="badge badge-warning badge-outline">Expired</span>"#,
        _ => r#"<span class="badge">?</span>"#,
    }
}

/// The document's display identity: SO number once confirmed, the
/// quotation number (with revision suffix past rev 1) before that.
fn doc_identity(number: Option<&str>, quote_number: Option<&str>, revision: i32) -> String {
    match number.filter(|n| !n.is_empty()) {
        Some(n) => n.to_string(),
        None => {
            let q = quote_number.unwrap_or("(unnumbered)");
            if revision > 1 { format!("{q} (Rev {revision})") } else { q.to_string() }
        }
    }
}

/// `<option>` list of customer contacts (customer or both).
async fn customer_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, code FROM contacts \
         WHERE active AND contact_type IN ('customer','both') ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Customer --</option>"#);
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

/// `<option>` list of sellable products — services included; the
/// product type decides fulfilment later (stockable → stock move,
/// consumable → delivery without stock, service → confirmation).
/// Each option carries a `data-fill` JSON payload so picking a
/// product autofills the line with the master's sales description,
/// list price, sales tax and LHDN classification.
async fn product_options(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, product_type, \
                COALESCE(NULLIF(sales_description, ''), name) AS side_desc, \
                CASE WHEN list_price > 0 THEN list_price ELSE cost END AS side_price, \
                sales_tax_id, classification_code \
         FROM stock_product \
         WHERE active ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Product --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        let desc: String = r.get("side_desc");
        let price: Decimal = r.try_get("side_price").unwrap_or(Decimal::ZERO);
        let mut fill = json!({
            "description": desc,
            "unit_price": price.round_dp(2).to_string(),
        });
        if let Ok(Some(t)) = r.try_get::<Option<Uuid>, _>("sales_tax_id") {
            fill["tax_id"] = json!(t.to_string());
        }
        if let Ok(Some(c)) = r.try_get::<Option<String>, _>("classification_code") {
            fill["classification_code"] = json!(c);
        }
        let ptype: String = r.get("product_type");
        let suffix = if ptype == "service" { " [service]" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}" data-fill="{fill}">{code} · {name}{suffix}</option>"#,
            id = id,
            fill = esc(&fill.to_string()),
            code = esc(&code),
            name = esc(&name),
            suffix = suffix
        ));
    }
    out
}

/// `<option>` list of active sale-side taxes.
async fn sale_tax_options(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name FROM taxes WHERE active AND type_tax_use IN ('sale', 'none') ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">— no tax —</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        out.push_str(&format!(r#"<option value="{id}">{name}</option>"#, id = id, name = esc(&name)));
    }
    out
}

/// `<option>` list of internal ship-from locations.
async fn location_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM stock_location \
         WHERE active AND location_type = 'internal' ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Ship-From Location --</option>"#);
    // With exactly one internal location there is nothing to choose —
    // preselect it so orders don't get confirmed without a ship-from.
    let effective = selected.or_else(|| if rows.len() == 1 { rows[0].try_get("id").ok() } else { None });
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        let sel = if effective == Some(id) { " selected" } else { "" };
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

/// Recompute and persist an order's untaxed/tax/total from its lines,
/// using the same tax engine the customer invoice will post with.
async fn recompute_totals(db: &vortex_plugin_sdk::sqlx::PgPool, order_id: Uuid) {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT quantity, unit_price, tax_id FROM sales_order_line WHERE order_id = $1",
    )
    .bind(order_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let lines: Vec<(Decimal, Decimal, Option<Uuid>)> = rows
        .iter()
        .map(|r| (r.get("quantity"), r.get("unit_price"), r.try_get("tax_id").ok().flatten()))
        .collect();
    let Ok((untaxed, tax, total)) =
        vortex_accounting::documents::compute_document_totals(db, &lines).await
    else {
        error!(order = %order_id, "sales order total recompute failed");
        return;
    };
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET untaxed_amount = $2, tax_amount = $3, \
            total_amount = $4, updated_at = NOW() WHERE id = $1",
    )
    .bind(order_id)
    .bind(untaxed)
    .bind(tax)
    .bind(total)
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

    // Confirmed sales only — the pipeline before confirmation lives
    // on the Quotations list.
    let config = ListConfig::new("Sales Orders", "sales_order")
        .custom_from(
            "(SELECT * FROM sales_order WHERE state IN ('confirmed','delivered','cancelled')) po \
             JOIN contacts v ON v.id = po.customer_id",
        )
        .custom_select(
            "po.id, po.number, po.quote_number, v.name AS customer_name, po.order_date::text AS order_date, \
             po.total_amount::text AS total_amount, po.state",
        )
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("po.number"))
        .column(ListColumn::new("quote_number", "Quotation").sortable().code().sql_expr("po.quote_number"))
        .column(ListColumn::new("customer_name", "Customer").sortable().searchable().sql_expr("v.name"))
        .column(ListColumn::new("order_date", "Order Date").sortable().sql_expr("po.order_date"))
        .column(ListColumn::new("total_amount", "Total").sortable().sql_expr("po.total_amount"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("confirmed", "Confirmed"),
                    ("delivered", "Delivered"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("confirmed", "Confirmed", "badge-info"),
                    ("delivered", "Delivered", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("po.state"),
        )
        .detail_url("/sales/orders/{id}")
        .pivot_url("/pivot/sales_order?rows=state")
        .default_sort("number")
        .group_by_options(&[("customer_name", "Customer"), ("state", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "sales orders list query failed");
            return Html("<h1>Failed to load sales orders</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/sales");
    Html(page_shell(&sidebar, "Sales Orders", &list_html)).into_response()
}

/// The pre-sale pipeline: every revision from open to lost.
async fn list_quotes(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("Quotations", "sales_order")
        .custom_from(
            "(SELECT * FROM sales_order WHERE state IN ('quotation','sent','superseded','lost','expired')) po \
             JOIN contacts v ON v.id = po.customer_id",
        )
        .custom_select(
            "po.id, po.quote_number, po.revision::text AS revision, v.name AS customer_name, \
             po.order_date::text AS order_date, po.validity_date::text AS validity_date, \
             po.total_amount::text AS total_amount, po.state",
        )
        .column(ListColumn::new("quote_number", "Number").sortable().code().sql_expr("po.quote_number"))
        .column(ListColumn::new("revision", "Rev").sortable().sql_expr("po.revision"))
        .column(ListColumn::new("customer_name", "Customer").sortable().searchable().sql_expr("v.name"))
        .column(ListColumn::new("order_date", "Date").sortable().sql_expr("po.order_date"))
        .column(ListColumn::new("validity_date", "Valid Until").sortable().sql_expr("po.validity_date"))
        .column(ListColumn::new("total_amount", "Total").sortable().sql_expr("po.total_amount"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("quotation", "Open"),
                    ("sent", "Sent"),
                    ("superseded", "Superseded"),
                    ("lost", "Lost"),
                    ("expired", "Expired"),
                ])
                .badge(&[
                    ("quotation", "Open", "badge-ghost"),
                    ("sent", "Sent", "badge-info"),
                    ("superseded", "Superseded", "badge-ghost"),
                    ("lost", "Lost", "badge-error"),
                    ("expired", "Expired", "badge-warning"),
                ])
                .sql_expr("po.state"),
        )
        .detail_url("/sales/orders/{id}")
        .create("New Quotation", "/sales/orders/new")
        .default_sort("quote_number")
        .group_by_options(&[("customer_name", "Customer"), ("state", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "quotations list query failed");
            return Html("<h1>Failed to load quotations</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/sales/quotes");
    Html(page_shell(&sidebar, "Quotations", &list_html)).into_response()
}

async fn new_order_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let customers = customer_options(&db, None).await;
    let locations = location_options(&db, None).await;
    let currencies = currency_options(&db, None).await;

    let content = format!(
        r#"<div class="max-w-2xl">
<a href="/sales/quotes" class="btn btn-ghost btn-sm mb-4">← Back to Quotations</a>
<h1 class="text-2xl font-bold mb-6">New Quotation</h1>
<p class="text-base-content/60 text-sm mb-4">Every sale starts as a quotation — it gets its SO number when confirmed.</p>
<form method="POST" action="/sales/orders/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Customer *</span></label>
<select name="customer_id" class="select select-bordered select-sm" required>{customers}</select>
<label class="label"><span class="label-text-alt text-base-content/50">Customers are contacts of type Customer or Both.</span></label>
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
<label class="label"><span class="label-text">Valid Until</span></label>
<input name="validity_date" type="date" class="input input-bordered input-sm"/>
<label class="label"><span class="label-text-alt text-base-content/50">Blank = 30 days from today. Sent quotations expire past this date.</span></label>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Ship-From Location</span></label>
<select name="source_location_id" class="select select-bordered select-sm">{locations}</select>
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
<a href="/sales" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        customers = customers,
        locations = locations,
        currencies = currencies,
    );

    Html(page_shell(&sidebar, "New Sales Order", &content)).into_response()
}

async fn create_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let Some(customer_id) = opt_uuid(&form, "customer_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Customer is required").into_response();
    };

    // Every sale starts life as a quotation: QT number now, SO number
    // only at confirmation.
    let quote_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &QT_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "QT sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate quotation number").into_response();
        }
    };
    let company_id = default_company(&db).await;

    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("order_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("expected_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    // Default validity: 30 days from today.
    let validity_date: vortex_plugin_sdk::chrono::NaiveDate = form
        .get("validity_date")
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            vortex_plugin_sdk::chrono::Utc::now().date_naive()
                + vortex_plugin_sdk::chrono::Duration::days(30)
        });

    let order_id = Uuid::now_v7();
    // order_date column defaults to CURRENT_DATE; pass COALESCE via Option.
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_order \
         (id, quote_number, revision, root_quote_id, validity_date, customer_id, order_date, \
          expected_date, currency_id, source_location_id, note, company_id, created_by) \
         VALUES ($1,$2,1,$1,$3,$4,COALESCE($5, CURRENT_DATE),$6,$7,$8,$9,$10,$11)",
    )
    .bind(order_id)
    .bind(&quote_number)
    .bind(validity_date)
    .bind(customer_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(opt_uuid(&form, "currency_id"))
    .bind(opt_uuid(&form, "source_location_id"))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "quotation insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create quotation: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("sales_order", order_id.to_string())
    .with_resource_name(&quote_number)
    .with_details(json!({ "quote_number": quote_number }));
    let _ = state.audit.log(audit_entry).await;

    info!(number = %quote_number, "quotation created");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{order_id}")).into_response()
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
        "SELECT po.number, po.quote_number, po.revision, po.root_quote_id, \
                po.validity_date::text AS validity_date, po.lost_reason, \
                po.customer_id, v.name AS customer_name, \
                po.order_date::text AS order_date, po.expected_date::text AS expected_date, \
                po.state, po.currency_id, po.source_location_id, \
                dl.name AS dest_name, c.code AS currency_code, po.note, \
                po.untaxed_amount, po.tax_amount, po.total_amount \
         FROM sales_order po \
         JOIN contacts v ON v.id = po.customer_id \
         LEFT JOIN stock_location dl ON dl.id = po.source_location_id \
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
            error!(error = %e, "SO fetch failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let number: Option<String> = row.try_get("number").ok().flatten();
    let quote_number: Option<String> = row.try_get("quote_number").ok().flatten();
    let revision: i32 = row.try_get("revision").unwrap_or(1);
    let root_quote_id: Option<Uuid> = row.try_get("root_quote_id").ok().flatten();
    let validity_date: Option<String> = row.try_get("validity_date").ok().flatten();
    let lost_reason: Option<String> = row.try_get("lost_reason").ok().flatten();
    let customer_id: Uuid = row.get("customer_id");
    let customer_name: String = row.get("customer_name");
    let order_date: Option<String> = row.try_get("order_date").ok();
    let expected_date: Option<String> = row.try_get("expected_date").ok();
    let po_state: String = row.get("state");
    let currency_id: Option<Uuid> = row.try_get("currency_id").ok();
    let source_location_id: Option<Uuid> = row.try_get("source_location_id").ok();
    let dest_name: Option<String> = row.try_get("dest_name").ok();
    let currency_code: Option<String> = row.try_get("currency_code").ok();
    let note: Option<String> = row.try_get("note").ok();
    let untaxed: Decimal = row.try_get("untaxed_amount").unwrap_or(Decimal::ZERO);
    let tax: Decimal = row.try_get("tax_amount").unwrap_or(Decimal::ZERO);
    let total: Decimal = row.try_get("total_amount").unwrap_or(Decimal::ZERO);
    let is_draft = po_state == "quotation";
    let is_quote_stage = matches!(po_state.as_str(), "quotation" | "sent" | "superseded" | "lost" | "expired");
    let identity = doc_identity(number.as_deref(), quote_number.as_deref(), revision);
    let cur = currency_code.clone().unwrap_or_default();

    // ── Lines table ──
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, p.code AS product_code, p.name AS product_name, l.description, \
                l.quantity, l.unit_price, t.name AS tax_name, \
                l.classification_code, l.qty_delivered, l.qty_invoiced \
         FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
         LEFT JOIN taxes t ON t.id = l.tax_id \
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
        let tax_name: Option<String> = r.try_get("tax_name").ok().flatten();
        let classification: Option<String> = r.try_get("classification_code").ok().flatten();
        let recv: Decimal = r.try_get("qty_delivered").unwrap_or(Decimal::ZERO);
        let invoiced: Decimal = r.try_get("qty_invoiced").unwrap_or(Decimal::ZERO);
        let backorder = qty - recv;
        let subtotal = qty * price;
        let del = if is_draft {
            format!(
                r#"<form method="POST" action="/sales/orders/{id}/lines/{lid}/delete" onsubmit="return confirm('Remove this line?')"><button class="btn btn-ghost btn-xs text-error">✕</button></form>"#,
                id = id, lid = lid
            )
        } else {
            String::new()
        };
        lines_html.push_str(&format!(
            r#"<tr><td class="font-mono">{pcode}{cls}</td><td>{pname}{desc}</td>
<td class="text-right">{qty}</td><td class="text-right">{price}</td>
<td>{tax}</td><td class="text-right">{subtotal}</td>
<td class="text-right">{recv}</td><td class="text-right">{invoiced}</td>
<td class="text-right">{backorder}</td><td class="text-right">{del}</td></tr>"#,
            pcode = esc(&pcode),
            cls = classification.filter(|c| !c.is_empty()).map(|c| format!(r#"<br><span class="text-xs text-base-content/40">{}</span>"#, esc(&c))).unwrap_or_default(),
            pname = esc(&pname),
            desc = desc.filter(|d| !d.is_empty()).map(|d| format!(r#"<br><span class="text-xs text-base-content/50">{}</span>"#, esc(&d))).unwrap_or_default(),
            qty = qty,
            price = money(price),
            tax = tax_name.map(|t| esc(&t).to_string()).unwrap_or_else(|| "—".into()),
            subtotal = money(subtotal),
            recv = recv,
            invoiced = invoiced,
            backorder = if backorder > Decimal::ZERO {
                format!(r#"<span class="text-warning font-medium">{}</span>"#, backorder.normalize())
            } else {
                "—".into()
            },
            del = del,
        ));
    }
    if lines_html.is_empty() {
        lines_html.push_str(r#"<tr><td colspan="10" class="text-base-content/50">No lines yet — add one below.</td></tr>"#);
    }

    // ── Add-line form (draft only) ──
    let add_line_form = if is_draft {
        let products = product_options(&db).await;
        let taxes = sale_tax_options(&db).await;
        format!(
            r#"<form method="POST" action="/sales/orders/{id}/lines" class="mt-4">
<div class="grid grid-cols-12 gap-2 items-end">
<div class="form-control col-span-4"><label class="label py-1"><span class="label-text text-xs">Product</span></label>
<select name="product_id" data-vortex-autofill class="select select-bordered select-sm" required>{products}</select></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Qty</span></label>
<input name="quantity" type="number" step="0.0001" min="0.0001" value="1" class="input input-bordered input-sm" required/></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Unit Price</span></label>
<input name="unit_price" type="number" step="0.0001" min="0" class="input input-bordered input-sm" placeholder="list price"/></div>
<div class="form-control col-span-2"><label class="label py-1"><span class="label-text text-xs">Tax</span></label>
<select name="tax_id" class="select select-bordered select-sm">{taxes}</select></div>
<div class="col-span-2"><button class="btn btn-primary btn-sm w-full">Add Line</button></div>
</div>
<div class="grid grid-cols-12 gap-2 mt-2">
<div class="form-control col-span-9"><input name="description" class="input input-bordered input-sm" placeholder="Description (from product if blank)"/></div>
<div class="form-control col-span-3"><input name="classification_code" class="input input-bordered input-sm" placeholder="LHDN class"/></div>
</div>
</form>"#,
            id = id, products = products, taxes = taxes
        )
    } else {
        String::new()
    };

    // ── Header (editable in draft, read-only otherwise) ──
    let header = if is_draft {
        let customers = customer_options(&db, Some(customer_id)).await;
        let locations = location_options(&db, source_location_id).await;
        let currencies = currency_options(&db, currency_id).await;
        format!(
            r#"<form method="POST" action="/sales/orders/{id}">
<div class="grid grid-cols-1 md:grid-cols-2 gap-3">
<div class="form-control"><label class="label"><span class="label-text">Customer *</span></label>
<select name="customer_id" class="select select-bordered select-sm" required>{customers}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Ship-From Location</span></label>
<select name="source_location_id" class="select select-bordered select-sm">{locations}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Order Date</span></label>
<input name="order_date" type="date" value="{order_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Expected Date</span></label>
<input name="expected_date" type="date" value="{expected_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Valid Until</span></label>
<input name="validity_date" type="date" value="{validity_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label"><span class="label-text">Currency</span></label>
<select name="currency_id" class="select select-bordered select-sm">{currencies}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Note</span></label>
<input name="note" value="{note}" class="input input-bordered input-sm"/></div>
</div>
<div class="mt-3"><button class="btn btn-primary btn-sm">Save Header</button></div>
</form>"#,
            id = id,
            customers = customers,
            locations = locations,
            currencies = currencies,
            order_date = esc(order_date.as_deref().unwrap_or("")),
            expected_date = esc(expected_date.as_deref().unwrap_or("")),
            validity_date = esc(validity_date.as_deref().unwrap_or("")),
            note = esc(note.as_deref().unwrap_or("")),
        )
    } else {
        format!(
            r#"<div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
<div><div class="text-base-content/50">Customer</div><div class="font-medium">{customer}</div></div>
<div><div class="text-base-content/50">Order Date</div><div class="font-medium">{order_date}</div></div>
<div><div class="text-base-content/50">Expected</div><div class="font-medium">{expected}</div></div>
<div><div class="text-base-content/50">Ship-From</div><div class="font-medium">{dest}</div></div>
<div><div class="text-base-content/50">Quotation</div><div class="font-medium">{quote_no}</div></div>
<div><div class="text-base-content/50">Valid Until</div><div class="font-medium">{validity}</div></div>
</div>{note}"#,
            customer = esc(&customer_name),
            order_date = esc(order_date.as_deref().unwrap_or("—")),
            expected = esc(expected_date.as_deref().unwrap_or("—")),
            dest = esc(dest_name.as_deref().unwrap_or("—")),
            quote_no = {
                let q = quote_number.as_deref().unwrap_or("—");
                if revision > 1 { format!("{} (Rev {})", esc(q), revision) } else { esc(q).to_string() }
            },
            validity = esc(validity_date.as_deref().unwrap_or("—")),
            note = note.filter(|n| !n.is_empty()).map(|n| format!(r#"<div class="mt-3 text-sm text-base-content/70">{}</div>"#, esc(&n))).unwrap_or_default(),
        )
    };

    // ── Action buttons by state ──
    let has_lines = !line_rows.is_empty();
    let mut actions = String::new();
    match po_state.as_str() {
        "quotation" => {
            actions.push_str(&format!(r#"<a href="/sales/orders/{id}/print-quote" target="_blank" class="btn btn-outline btn-sm">Print Quotation</a>"#, id = id));
            if has_lines {
                actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/send" class="inline ml-2"><button class="btn btn-primary btn-sm" title="Freezes this revision — the customer now holds a copy">Mark as Sent</button></form>"#, id = id));
                actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/confirm" class="inline ml-2"><button class="btn btn-success btn-sm">Confirm Order</button></form>"#, id = id));
            }
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/lost" class="inline ml-2" onsubmit="return confirm('Mark this quotation as lost?')"><button class="btn btn-ghost btn-sm">Mark Lost</button></form>"#, id = id));
        }
        "sent" => {
            actions.push_str(&format!(r#"<a href="/sales/orders/{id}/print-quote" target="_blank" class="btn btn-outline btn-sm">Print Quotation</a>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/confirm" class="inline ml-2"><button class="btn btn-primary btn-sm">Confirm Order</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/revise" class="inline ml-2"><button class="btn btn-outline btn-sm" title="Creates the next revision; this one stays exactly as the customer received it">Revise</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/lost" class="inline ml-2" onsubmit="return confirm('Mark this quotation as lost?')"><button class="btn btn-ghost btn-sm">Mark Lost</button></form>"#, id = id));
        }
        "expired" | "lost" => {
            actions.push_str(&format!(r#"<a href="/sales/orders/{id}/print-quote" target="_blank" class="btn btn-outline btn-sm">Print Quotation</a>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/revise" class="inline ml-2"><button class="btn btn-primary btn-sm">Revise</button></form>"#, id = id));
        }
        "superseded" => {
            actions.push_str(&format!(r#"<a href="/sales/orders/{id}/print-quote" target="_blank" class="btn btn-outline btn-sm">Print Quotation</a>"#, id = id));
        }
        "confirmed" => {
            // Fulfilment splits by product type: goods (stockable +
            // consumable) go through delivery, services through a
            // service confirmation — no delivery order needed.
            let counts = vortex_plugin_sdk::sqlx::query(
                "SELECT \
                    COUNT(*) FILTER (WHERE p.product_type <> 'service' AND l.quantity > l.qty_delivered) AS goods_open, \
                    COUNT(*) FILTER (WHERE p.product_type = 'service' AND l.quantity > l.qty_delivered) AS services_open \
                 FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
                 WHERE l.order_id = $1",
            )
            .bind(id)
            .fetch_one(&db)
            .await
            .ok();
            let goods_open: i64 = counts.as_ref().and_then(|r| r.try_get("goods_open").ok()).unwrap_or(0);
            let services_open: i64 = counts.as_ref().and_then(|r| r.try_get("services_open").ok()).unwrap_or(0);
            if goods_open > 0 {
                actions.push_str(&format!(r#"<a href="/sales/orders/{id}/deliver" class="btn btn-success btn-sm">Deliver Goods</a>"#, id = id));
            }
            if services_open > 0 {
                actions.push_str(&format!(r#"<a href="/sales/orders/{id}/confirm-services" class="btn btn-success btn-sm ml-2">Confirm Services</a>"#, id = id));
            }
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/cancel" class="inline ml-2" onsubmit="return confirm('Cancel this order?')"><button class="btn btn-ghost btn-sm">Cancel Order</button></form>"#, id = id));
        }
        _ => {}
    }
    // Accounting bridge: billing follows delivery. The button appears
    // whenever delivered (or service-confirmed) quantity awaits
    // invoicing — partial deliveries bill progressively.
    if has_lines && matches!(po_state.as_str(), "confirmed" | "delivered") {
        let billable: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT COALESCE(SUM(GREATEST(qty_delivered - qty_invoiced, 0)), 0) \
             FROM sales_order_line WHERE order_id = $1",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap_or(Decimal::ZERO);
        if billable > Decimal::ZERO {
            actions.push_str(&format!(
                r#"<form method="POST" action="/sales/orders/{id}/create-invoice" class="inline ml-2"><button class="btn btn-outline btn-sm">Create Invoice</button></form>"#
            ));
        }
    }

    // ── Fulfilment documents (DO / service confirmations) ──
    let deliveries = vortex_plugin_sdk::sqlx::query(
        "SELECT id, number, kind, delivery_date FROM sales_delivery \
         WHERE order_id = $1 ORDER BY created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let deliveries_card = if deliveries.is_empty() {
        String::new()
    } else {
        let mut rows_html = String::new();
        for d in &deliveries {
            let did: Uuid = d.get("id");
            let dnum: String = d.get("number");
            let kind: String = d.get("kind");
            let ddate: vortex_plugin_sdk::chrono::NaiveDate = d.get("delivery_date");
            rows_html.push_str(&format!(
                r#"<tr><td class="font-mono">{dnum}</td><td>{label}</td><td>{ddate}</td>
<td class="text-right"><a href="/sales/deliveries/{did}/print" target="_blank" class="btn btn-outline btn-xs">Print</a></td></tr>"#,
                dnum = esc(&dnum),
                label = if kind == "service" { "Service Confirmation" } else { "Delivery Order" },
                ddate = ddate,
                did = did,
            ));
        }
        format!(
            r#"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg mb-3">Deliveries</h2>
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Number</th><th>Type</th><th>Date</th><th class="text-right"></th></tr></thead>
<tbody>{rows_html}</tbody></table></div>
</div></div>"#
        )
    };

    // ── Invoices raised from this order ──
    let inv_origin = format!("sales_order:{id}");
    let invoices = vortex_plugin_sdk::sqlx::query(
        "SELECT id, number, state, invoice_date, total_amount FROM acc_move \
         WHERE origin_ref = $1 ORDER BY created_at",
    )
    .bind(&inv_origin)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let invoices_card = if invoices.is_empty() {
        String::new()
    } else {
        let mut rows_html = String::new();
        for m in &invoices {
            let mid: Uuid = m.get("id");
            let mnum: Option<String> = m.try_get("number").ok().flatten();
            let mstate: String = m.get("state");
            let mdate: Option<vortex_plugin_sdk::chrono::NaiveDate> = m.try_get("invoice_date").ok().flatten();
            let mtotal: Decimal = m.try_get("total_amount").unwrap_or(Decimal::ZERO);
            rows_html.push_str(&format!(
                r#"<tr><td class="font-mono">{num}</td><td>{date}</td><td>{state}</td>
<td class="text-right font-mono">{total}</td>
<td class="text-right"><a href="/accounting/documents/{mid}" class="btn btn-outline btn-xs">Open</a></td></tr>"#,
                num = mnum.filter(|n| !n.is_empty()).map(|n| esc(&n).to_string()).unwrap_or_else(|| "(draft)".into()),
                date = mdate.map(|d| d.to_string()).unwrap_or_default(),
                state = esc(&mstate),
                total = money(mtotal),
                mid = mid,
            ));
        }
        format!(
            r#"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg mb-3">Invoices</h2>
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Number</th><th>Date</th><th>Status</th><th class="text-right">Total</th><th class="text-right"></th></tr></thead>
<tbody>{rows_html}</tbody></table></div>
</div></div>"#
        )
    };

    // ── Revision chain (only shown when the family has siblings) ──
    let revisions_card = if let Some(root) = root_quote_id {
        let revs = vortex_plugin_sdk::sqlx::query(
            "SELECT id, revision, state, number, total_amount FROM sales_order \
             WHERE root_quote_id = $1 ORDER BY revision",
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
                    r#"<tr><td>Rev {rev}{this_marker}</td><td>{badge}</td><td class="font-mono">{so}</td>
<td class="text-right font-mono">{total}</td>
<td class="text-right"><a href="/sales/orders/{rid}" class="btn btn-ghost btn-xs">Open</a></td></tr>"#,
                    rev = rev,
                    this_marker = this_marker,
                    badge = state_badge(&rstate),
                    so = rnum.filter(|n| !n.is_empty()).map(|n| esc(&n).to_string()).unwrap_or_else(|| "—".into()),
                    total = money(rtotal),
                    rid = rid,
                ));
            }
            format!(
                r#"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg mb-3">Revisions</h2>
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Revision</th><th>Status</th><th>Sales Order</th><th class="text-right">Total</th><th class="text-right"></th></tr></thead>
<tbody>{rows_html}</tbody></table></div>
</div></div>"#
            )
        }
    } else {
        String::new()
    };
    let lost_banner = lost_reason
        .filter(|r| !r.is_empty())
        .map(|r| format!(r#"<div class="alert alert-warning mb-4 text-sm">Lost: {}</div>"#, esc(&r)))
        .unwrap_or_default();
    let quote_ref = if number.is_some() && quote_number.is_some() {
        format!(
            r#" <span class="text-sm opacity-60 font-normal">from {}</span>"#,
            esc(quote_number.as_deref().unwrap_or(""))
        )
    } else {
        String::new()
    };

    let content = format!(
        r#"<div class="flex items-center justify-between mb-4">
<div>
<a href="{back_url}" class="btn btn-ghost btn-sm mb-2">← Back to {back_label}</a>
<h1 class="text-2xl font-bold">{number}{quote_ref} {badge}</h1>
</div>
<div class="vortex-actions">{actions}</div>
</div>
{lost_banner}

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title text-lg mb-3">Details</h2>
{header}
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-3">Lines</h2>
<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Code</th><th>Product</th><th class="text-right">Qty</th><th class="text-right">Unit Price</th><th class="text-right">Tax</th><th class="text-right">Subtotal</th><th class="text-right">Delivered</th><th class="text-right">Invoiced</th><th class="text-right">Backorder</th><th></th></tr></thead>
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

{deliveries_card}
{invoices_card}
{revisions_card}"#,
        back_url = if is_quote_stage { "/sales/quotes" } else { "/sales" },
        back_label = if is_quote_stage { "Quotations" } else { "Sales Orders" },
        number = esc(&identity),
        quote_ref = quote_ref,
        lost_banner = lost_banner,
        badge = state_badge(&po_state),
        actions = actions,
        header = header,
        lines = lines_html,
        add_line = add_line_form,
        untaxed = money(untaxed),
        tax = money(tax),
        total = money(total),
        cur = esc(&cur),
        deliveries_card = deliveries_card,
        invoices_card = invoices_card,
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
    if !is_state(&db, id, "quotation").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open quotations can be edited").into_response();
    }
    let Some(customer_id) = opt_uuid(&form, "customer_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Customer is required").into_response();
    };
    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("order_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        form.get("expected_date").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());

    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET \
            customer_id = $1, order_date = COALESCE($2, order_date), expected_date = $3, \
            currency_id = $4, source_location_id = $5, note = $6, validity_date = $9, \
            updated_by = $7, updated_at = NOW() \
         WHERE id = $8 AND state = 'quotation'",
    )
    .bind(customer_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(opt_uuid(&form, "currency_id"))
    .bind(opt_uuid(&form, "source_location_id"))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(user.id)
    .bind(id)
    .bind(form.get("validity_date").filter(|s| !s.is_empty()).and_then(|s| s.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok()))
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "SO header update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update: {e}")).into_response();
    }
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

/// True iff the order is currently in `want` state.
async fn is_state(db: &vortex_plugin_sdk::sqlx::PgPool, id: Uuid, want: &str) -> bool {
    let s: Option<String> = vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM sales_order WHERE id = $1")
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
    if !is_state(&db, id, "quotation").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Lines can only be edited on open quotations").into_response();
    }
    let Some(product_id) = opt_uuid(&form, "product_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product is required").into_response();
    };
    let quantity = dec_or(&form, "quantity", Decimal::ONE);
    if quantity <= Decimal::ZERO {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Quantity must be greater than zero").into_response();
    }
    let company_id = default_company(&db).await;

    // Product-master defaults fill whatever the form left blank — the
    // same values the client-side autofill seeds, applied server-side
    // so the behaviour holds without JS.
    let product = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(NULLIF(sales_description, ''), name) AS side_desc, \
                CASE WHEN list_price > 0 THEN list_price ELSE cost END AS side_price, \
                sales_tax_id, classification_code \
         FROM stock_product WHERE id = $1",
    )
    .bind(product_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(product) = product else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Unknown product").into_response();
    };
    let description = form
        .get("description")
        .filter(|s| !s.trim().is_empty())
        .cloned()
        .unwrap_or_else(|| product.get("side_desc"));
    let unit_price = match form.get("unit_price").map(|s| s.trim()) {
        Some(v) if !v.is_empty() => v.parse::<Decimal>().unwrap_or(Decimal::ZERO),
        _ => product.try_get("side_price").unwrap_or(Decimal::ZERO),
    };
    let tax_id = opt_uuid(&form, "tax_id")
        .or_else(|| product.try_get::<Option<Uuid>, _>("sales_tax_id").ok().flatten());
    let classification = form
        .get("classification_code")
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| product.try_get::<Option<String>, _>("classification_code").ok().flatten());

    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_order_line \
         (id, order_id, product_id, description, quantity, unit_price, tax_id, classification_code, company_id) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(Uuid::now_v7())
    .bind(id)
    .bind(product_id)
    .bind(&description)
    .bind(quantity)
    .bind(unit_price)
    .bind(tax_id)
    .bind(classification)
    .bind(company_id)
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "SO line insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to add line: {e}")).into_response();
    }
    recompute_totals(&db, id).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

async fn delete_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path((id, line_id)): Path<(Uuid, Uuid)>,
) -> Response {
    if !is_state(&db, id, "quotation").await {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Lines can only be edited on open quotations").into_response();
    }
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM sales_order_line WHERE id = $1 AND order_id = $2")
        .bind(line_id)
        .bind(id)
        .execute(&db)
        .await;
    recompute_totals(&db, id).await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
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
    let line_count: i64 = vortex_plugin_sdk::sqlx::query_scalar("SELECT COUNT(*) FROM sales_order_line WHERE order_id = $1")
        .bind(id)
        .fetch_one(&db)
        .await
        .unwrap_or(0);
    if line_count == 0 {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Add at least one line before confirming").into_response();
    }

    // The confirmed sale receives its SO number here; the quotation
    // keeps its QT identity for traceability.
    let so_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &SO_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "SO sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate SO number").into_response();
        }
    };
    // The partial unique index on root_quote_id backstops this UPDATE:
    // even racing confirmations cannot yield two live sales per family.
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET state = 'confirmed', number = $3, updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state IN ('quotation', 'sent')",
    )
    .bind(user.id)
    .bind(id)
    .bind(&so_number)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open or sent quotations can be confirmed").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "SO confirm failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Failed to confirm — another revision of this quotation may already be confirmed.").into_response();
        }
    }

    // Every other open revision of the family is now superseded.
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET state = 'superseded', updated_by = $1, updated_at = NOW() \
         WHERE root_quote_id = (SELECT root_quote_id FROM sales_order WHERE id = $2) \
           AND id <> $2 AND state IN ('quotation', 'sent', 'expired')",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "confirmed").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

/// quotation → sent: freezes the document (the customer now holds a
/// copy); further changes require a revision.
async fn mark_sent(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET state = 'sent', updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state = 'quotation'",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open quotations can be marked sent").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "quote send failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to mark sent").into_response();
        }
    }
    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "sent").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

/// quotation/sent/expired → lost.
async fn mark_lost(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    body: vortex_plugin_sdk::axum::body::Bytes,
) -> Response {
    // Reason arrives urlencoded from the UI form; the button variant
    // posts an empty body. Parsed by hand so both are accepted.
    let reason = std::str::from_utf8(&body)
        .ok()
        .and_then(|b| {
            b.split('&').find_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                if k != "reason" {
                    return None;
                }
                // Minimal decode: '+' → space is the common case for
                // free-text notes; exotic percent-escapes pass through.
                Some(v.replace('+', " "))
            })
        })
        .map(|r| r.trim().to_string())
        .filter(|r| !r.is_empty());
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET state = 'lost', lost_reason = $3, updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state IN ('quotation', 'sent', 'expired')",
    )
    .bind(user.id)
    .bind(id)
    .bind(reason)
    .execute(&db)
    .await;
    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only open quotations can be marked lost").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "quote lost failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to mark lost").into_response();
        }
    }
    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "lost").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

/// Clone a frozen quotation into the next revision. The source stays
/// exactly as the customer received it (sent/expired → superseded,
/// lost keeps its state); the clone reopens as an editable quotation.
async fn revise_quote(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let src = vortex_plugin_sdk::sqlx::query(
        "SELECT quote_number, root_quote_id, state, customer_id, order_date, expected_date, \
                currency_id, source_location_id, note, company_id \
         FROM sales_order WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(src) = src else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Quotation not found").into_response();
    };
    let src_state: String = src.get("state");
    if !matches!(src_state.as_str(), "sent" | "expired" | "lost") {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only sent, expired or lost quotations can be revised — open quotations are edited directly.").into_response();
    }
    let root: Uuid = src.get("root_quote_id");
    // Refuse when the family already has a live sale.
    let live: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_order WHERE root_quote_id = $1 \
         AND state NOT IN ('quotation','sent','superseded','lost','expired','cancelled')",
    )
    .bind(root)
    .fetch_one(&db)
    .await
    .unwrap_or(0);
    if live > 0 {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "This quotation already has a confirmed sales order — revise is not available.").into_response();
    }
    let next_rev: i32 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COALESCE(MAX(revision), 0) + 1 FROM sales_order WHERE root_quote_id = $1",
    )
    .bind(root)
    .fetch_one(&db)
    .await
    .unwrap_or(2);

    let new_id = Uuid::now_v7();
    let quote_number: String = src.get("quote_number");
    let validity = vortex_plugin_sdk::chrono::Utc::now().date_naive()
        + vortex_plugin_sdk::chrono::Duration::days(30);
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_order \
         (id, quote_number, revision, root_quote_id, validity_date, customer_id, order_date, \
          expected_date, currency_id, source_location_id, note, company_id, created_by) \
         SELECT $1, quote_number, $3, root_quote_id, $4, customer_id, CURRENT_DATE, \
                expected_date, currency_id, source_location_id, note, company_id, $5 \
         FROM sales_order WHERE id = $2",
    )
    .bind(new_id)
    .bind(id)
    .bind(next_rev)
    .bind(validity)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "quote revision insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to create revision").into_response();
    }
    // Clone the commercial lines; fulfilment counters restart at zero.
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_order_line \
         (id, order_id, sequence, product_id, description, quantity, unit_price, tax_id, classification_code, company_id) \
         SELECT uuid_generate_v4(), $1, sequence, product_id, description, quantity, unit_price, tax_id, classification_code, company_id \
         FROM sales_order_line WHERE order_id = $2",
    )
    .bind(new_id)
    .bind(id)
    .execute(&db)
    .await;
    recompute_totals(&db, new_id).await;

    // The revised document is replaced; a lost one keeps its verdict.
    if src_state != "lost" {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE sales_order SET state = 'superseded', updated_by = $1, updated_at = NOW() WHERE id = $2",
        )
        .bind(user.id)
        .bind(id)
        .execute(&db)
        .await;
    }

    audit_so(&state, &db_ctx, &db, user.id, &user.username, new_id, "revised").await;
    info!(quote = %quote_number, revision = next_rev, "quotation revised");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{new_id}")).into_response()
}

async fn cancel_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET state = 'cancelled', updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state = 'confirmed'",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can be cancelled").into_response(),
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "SO cancel failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to cancel").into_response();
        }
    }

    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "cancelled").await;
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

async fn audit_so(
    state: &AppState,
    db_ctx: &DatabaseContext,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user_id: Uuid,
    username: &str,
    id: Uuid,
    action: &str,
) {
    let number: String = vortex_plugin_sdk::sqlx::query_scalar("SELECT number FROM sales_order WHERE id = $1")
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
    .with_resource("sales_order", id.to_string())
    .with_resource_name(&number)
    .with_details(json!({ "action": action }));
    let _ = state.audit.log(entry).await;
}

// ─────────────────────────────────────────────────────────────────────────
// Delivery
// ─────────────────────────────────────────────────────────────────────────

async fn deliver_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let po = vortex_plugin_sdk::sqlx::query("SELECT number, state, source_location_id FROM sales_order WHERE id = $1")
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
    let source_location_id: Option<Uuid> = po.try_get("source_location_id").ok();
    if po_state != "confirmed" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can be delivered").into_response();
    }
    // Outstanding GOODS lines (services fulfil via confirmation, not
    // delivery). Consumables ride the delivery but post no stock move.
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, p.code AS product_code, p.name AS product_name, p.tracking, p.product_type, \
                l.quantity, l.qty_delivered, (l.quantity - l.qty_delivered) AS remaining \
         FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.quantity > l.qty_delivered AND p.product_type <> 'service' \
         ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if lines.is_empty() {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response();
    }

    let any_stockable = lines
        .iter()
        .any(|r| r.get::<String, _>("product_type") == "stockable");
    // No ship-from on the order (created before one was picked, or the
    // picker was skipped): choose it here instead of dead-ending. Only
    // stockable lines move stock, so consumable-only deliveries skip it.
    let location_picker = if source_location_id.is_none() && any_stockable {
        let locations = location_options(&db, None).await;
        format!(
            r#"<div class="form-control mb-4 max-w-sm">
<label class="label"><span class="label-text">Ship-From Location</span></label>
<select name="source_location_id" class="select select-bordered select-sm" required>{locations}</select>
</div>"#
        )
    } else {
        String::new()
    };

    let mut rows = String::new();
    for r in &lines {
        let lid: Uuid = r.get("id");
        let pcode: String = r.get("product_code");
        let pname: String = r.get("product_name");
        let tracking: String = r.get("tracking");
        let ptype: String = r.get("product_type");
        let remaining: Decimal = r.try_get("remaining").unwrap_or(Decimal::ZERO);
        let lot_input = if tracking == "none" || ptype == "consumable" {
            r#"<span class="text-base-content/40 text-xs">—</span>"#.to_string()
        } else {
            format!(
                r#"<input name="lot_{lid}" class="input input-bordered input-xs w-40" placeholder="{tracking} number" required/>"#,
                lid = lid, tracking = esc(&tracking)
            )
        };
        let type_badge = if ptype == "consumable" {
            r#" <span class="badge badge-ghost badge-xs" title="Not stock-holding — no stock move posts">consumable</span>"#
        } else {
            ""
        };
        rows.push_str(&format!(
            r#"<tr><td class="font-mono">{pcode}</td><td>{pname}{type_badge}</td>
<td class="text-right">{remaining}</td>
<td><input name="qty_{lid}" type="number" step="0.0001" min="0" max="{remaining}" value="{remaining}" class="input input-bordered input-xs w-28 text-right"/></td>
<td>{lot_input}</td></tr>"#,
            pcode = esc(&pcode), pname = esc(&pname), type_badge = type_badge,
            remaining = remaining, lid = lid, lot_input = lot_input,
        ));
    }

    let content = format!(
        r#"<div class="max-w-3xl">
<a href="/sales/orders/{id}" class="btn btn-ghost btn-sm mb-4">← Back to {number}</a>
<h1 class="text-2xl font-bold mb-2">Deliver Goods — {number}</h1>
<p class="text-base-content/60 mb-6">Enter the quantity to deliver per line. Lot/serial-tracked products require a number. Posting moves validated stock out of the ship-from location to the Customers location.</p>
<form method="POST" action="/sales/orders/{id}/deliver">
<div class="card bg-base-100 shadow"><div class="card-body">
{location_picker}<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Code</th><th>Product</th><th class="text-right">Outstanding</th><th>Deliver Qty</th><th>Lot / Serial</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<div class="flex gap-2 mt-4">
<button type="submit" class="btn btn-success btn-sm">Post Delivery</button>
<a href="/sales/orders/{id}" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        id = id, number = esc(&number), rows = rows, location_picker = location_picker,
    );

    Html(page_shell(&sidebar, &format!("Deliver {}", number), &content)).into_response()
}

async fn process_delivery(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    // Re-read the order and guard state + source.
    let po = vortex_plugin_sdk::sqlx::query("SELECT number, state, source_location_id, company_id FROM sales_order WHERE id = $1")
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
    if po_state != "confirmed" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can be delivered").into_response();
    }

    // Outstanding GOODS lines. Services never appear on a delivery.
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.product_id, l.description, p.tracking, p.uom_id, p.product_type, \
                (l.quantity - l.qty_delivered) AS remaining \
         FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.quantity > l.qty_delivered AND p.product_type <> 'service'",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Only stockable lines move stock, so the ship-from and Customers
    // locations are required only when one actually ships this posting.
    let needs_stock = lines.iter().any(|r| {
        r.get::<String, _>("product_type") == "stockable"
            && form
                .get(&format!("qty_{}", r.get::<Uuid, _>("id")))
                .and_then(|s| s.trim().parse::<Decimal>().ok())
                .unwrap_or(Decimal::ZERO)
                > Decimal::ZERO
    });

    // Order value wins; otherwise take the picker submitted with the
    // delivery (validated against internal locations) and persist it.
    let order_location: Option<Uuid> = po.try_get("source_location_id").ok();
    let source_location_id = match (order_location, needs_stock) {
        (Some(l), _) => Some(l),
        (None, false) => None,
        (None, true) => {
            let Some(picked) = opt_uuid(&form, "source_location_id") else {
                return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No ship-from location set.").into_response();
            };
            let valid: bool = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM stock_location WHERE id = $1 AND active AND location_type = 'internal')",
            )
            .bind(picked)
            .fetch_one(&db)
            .await
            .unwrap_or(false);
            if !valid {
                return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Ship-from must be an active internal location.").into_response();
            }
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE sales_order SET source_location_id = $1, updated_by = $2, updated_at = NOW() WHERE id = $3",
            )
            .bind(picked)
            .bind(user.id)
            .bind(id)
            .execute(&db)
            .await;
            Some(picked)
        }
    };

    let customer_location: Option<Uuid> = if needs_stock {
        let loc: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT id FROM stock_location WHERE location_type = 'customer' AND active ORDER BY created_at LIMIT 1",
        )
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
        if loc.is_none() {
            return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No customer-type location exists for deliveries.").into_response();
        }
        loc
    } else {
        None
    };

    let mut delivered_any = false;
    // What actually ships this posting — becomes the delivery order.
    let mut shipped: Vec<(Uuid, Uuid, Option<String>, Decimal, Option<String>)> = Vec::new();
    for r in &lines {
        let lid: Uuid = r.get("id");
        let product_id: Uuid = r.get("product_id");
        let line_desc: Option<String> = r.try_get("description").ok().flatten();
        let tracking: String = r.get("tracking");
        let ptype: String = r.get("product_type");
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

        // Consumables are not stock-holding: fulfil the line without
        // posting to the stock ledger.
        if ptype == "consumable" {
            let _ = vortex_plugin_sdk::sqlx::query("UPDATE sales_order_line SET qty_delivered = qty_delivered + $1 WHERE id = $2")
                .bind(qty)
                .bind(lid)
                .execute(&db)
                .await;
            shipped.push((lid, product_id, line_desc, qty, None));
            delivered_any = true;
            continue;
        }
        let (Some(src), Some(dst)) = (source_location_id, customer_location) else {
            return (vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED, "No ship-from location set.").into_response();
        };

        // Resolve lot for tracked products.
        let lot_id: Option<Uuid> = if tracking == "none" {
            None
        } else {
            let lot_name = form.get(&format!("lot_{lid}")).map(|s| s.trim()).unwrap_or("");
            if lot_name.is_empty() {
                return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "A lot/serial number is required for a tracked product line.").into_response();
            }
            if tracking == "serial" && qty != Decimal::ONE {
                return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Serial-tracked lines must be delivered one unit at a time.").into_response();
            }
            match vortex_inventory::service::resolve_lot(&db, product_id, lot_name, &tracking, company_id, user.id).await {
                Ok(lot) => Some(lot),
                Err(e) => {
                    error!(error = %e, "lot resolve failed");
                    return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve lot").into_response();
                }
            }
        };

        // Mint a move reference and post the delivery through inventory.
        let reference = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &vortex_inventory::move_sequence()).await {
            Ok(n) => n,
            Err(e) => {
                error!(error = %e, "move sequence failed");
                return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate move reference").into_response();
            }
        };
        if let Err(e) = vortex_inventory::post_move(
            &db, &reference, company_id, user.id, product_id, lot_id, uom_id, qty,
            src, dst, Some(&number),
        )
        .await
        {
            error!(error = %e, "delivery move post failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to post delivery: {e}")).into_response();
        }

        let _ = vortex_plugin_sdk::sqlx::query("UPDATE sales_order_line SET qty_delivered = qty_delivered + $1 WHERE id = $2")
            .bind(qty)
            .bind(lid)
            .execute(&db)
            .await;
        shipped.push((
            lid,
            product_id,
            line_desc,
            qty,
            form.get(&format!("lot_{lid}")).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()),
        ));
        delivered_any = true;
    }

    if !delivered_any {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response();
    }

    // Mint the printable delivery order for exactly what shipped.
    let _ = create_fulfilment_doc(
        &state, &db, id, "goods", &DO_SEQ, source_location_id, company_id, user.id, &shipped,
    )
    .await;

    // Flip to 'delivered' once every line is fully delivered.
    let outstanding: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_order_line WHERE order_id = $1 AND quantity > qty_delivered",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(0);
    if outstanding == 0 {
        let _ = vortex_plugin_sdk::sqlx::query("UPDATE sales_order SET state = 'delivered', updated_by = $1, updated_at = NOW() WHERE id = $2")
            .bind(user.id)
            .bind(id)
            .execute(&db)
            .await;
    }

    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "delivered").await;
    info!(number = %number, "sales delivery posted");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Quotation print
// ─────────────────────────────────────────────────────────────────────────

/// Printable quotation — self-contained A4 page with prices, taxes,
/// validity and an acceptance block. Reprintable for any revision,
/// exactly as issued.
async fn print_quote(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT o.quote_number, o.revision, o.number, o.state, o.order_date, o.validity_date, \
                o.note, o.untaxed_amount, o.tax_amount, o.total_amount, \
                cu.code AS currency_code, \
                c.name AS customer_name, c.street, c.street2, c.city, c.zip, \
                c.phone AS customer_phone, c.email AS customer_email \
         FROM sales_order o \
         JOIN contacts c ON c.id = o.customer_id \
         LEFT JOIN currencies cu ON cu.id = o.currency_id \
         WHERE o.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(head) = head else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Quotation not found").into_response();
    };
    let company = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(co.name, 'Company') AS name, c.company_id_value, \
                c.company_address1, c.company_address2, \
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
                l.quantity, l.unit_price, t.name AS tax_name \
         FROM sales_order_line l \
         JOIN stock_product p ON p.id = l.product_id \
         LEFT JOIN taxes t ON t.id = l.tax_id \
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
    let quote_state: String = head.get("state");
    let display_number = {
        let q = hval("quote_number");
        if revision > 1 { format!("{q} (Rev {revision})") } else { q }
    };
    let cur = hval("currency_code");
    let cur = if cur.is_empty() { "MYR".to_string() } else { cur };
    // A superseded/lost/expired print carries its status; a confirmed
    // family's quote print points at the SO.
    let status_mark = match quote_state.as_str() {
        "superseded" => r#"<div class="watermark">SUPERSEDED</div>"#.to_string(),
        "lost" => r#"<div class="watermark">LOST</div>"#.to_string(),
        "expired" => r#"<div class="watermark">EXPIRED</div>"#.to_string(),
        _ => String::new(),
    };

    let mut line_trs = String::new();
    for l in &lines {
        let qty: Decimal = l.get("quantity");
        let price: Decimal = l.try_get("unit_price").unwrap_or(Decimal::ZERO);
        line_trs.push_str(&format!(
            r#"<tr><td class="mono-code">{code}</td><td>{desc}</td><td class="num">{qty}</td><td class="num">{price}</td><td>{tax}</td><td class="num">{amount}</td></tr>"#,
            code = esc(&l.get::<String, _>("code")),
            desc = esc(&l.get::<String, _>("description")),
            qty = qty.normalize(),
            price = money(price),
            tax = l.try_get::<Option<String>, _>("tax_name").ok().flatten().map(|t| esc(&t).to_string()).unwrap_or_else(|| "—".into()),
            amount = money((qty * price).round_dp(2)),
        ));
    }

    let html = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{number} — QUOTATION</title>
<style>{css}
body {{ max-width: 21cm; margin: 1.2cm auto; position: relative; }}
@page {{ size: A4; margin: 0; }}
@media print {{
  body {{ max-width: none; margin: 0; padding: 1.2cm 1.4cm; }}
}}
.head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.2em; }}
.head h1 {{ font-size: 1.5em; letter-spacing: 0.06em; }}
.seller p, .buyer p {{ margin: 1px 0; font-size: 0.85em; }}
.seller .name {{ font-size: 1.1em; font-weight: 700; }}
.meta td {{ padding: 1px 8px 1px 0; font-size: 0.85em; border: none; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono-code {{ font-family: monospace; }}
.totals td {{ font-weight: 600; }}
.accept {{ margin-top: 3em; display: flex; gap: 3em; }}
.accept div {{ flex: 1; border-top: 1px solid #333; padding-top: 0.4em; font-size: 0.8em; }}
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
    <h1>QUOTATION</h1>
    <table class="meta" style="margin-left:auto">
      <tr><td>Number</td><td><b>{number}</b></td></tr>
      <tr><td>Date</td><td>{date}</td></tr>
      <tr><td>Valid Until</td><td>{validity}</td></tr>
    </table>
  </div>
</div>
<div class="buyer" style="margin-bottom:1em">
  <p style="font-size:0.75em;color:#666">TO</p>
  <p><b>{customer}</b></p>
  <p>{pstreet}</p><p>{pstreet2}</p><p>{pzip} {pcity}</p>
  <p>{pphone} {pemail}</p>
</div>
<table class="table table-sm" style="table-layout:fixed;width:100%">
<colgroup><col style="width:7rem"/><col/><col style="width:4.5rem"/><col style="width:7rem"/><col style="width:8rem"/><col style="width:8.5rem"/></colgroup>
<thead><tr><th>Code</th><th>Description</th><th class="num">Qty</th><th class="num">Unit Price</th><th>Tax</th><th class="num">Amount ({cur})</th></tr></thead>
<tbody>{line_trs}</tbody>
<tfoot>
<tr><td colspan="5" class="num">Subtotal</td><td class="num">{untaxed}</td></tr>
<tr><td colspan="5" class="num">Tax</td><td class="num">{tax}</td></tr>
<tr class="totals"><td colspan="5" class="num">TOTAL</td><td class="num">{total}</td></tr>
</tfoot>
</table>
<div class="accept">
  <div>Issued by<br><br>Name:<br>Date:</div>
  <div>Accepted by (customer)<br><br>Name, company stamp:<br>Date:</div>
</div>
<div class="footer">Prices are valid until the date stated above. This quotation is not an invoice. {note}</div>
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
        validity = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("validity_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_else(|| "—".into()),
        customer = hval("customer_name"),
        pstreet = hval("street"),
        pstreet2 = hval("street2"),
        pzip = hval("zip"),
        pcity = hval("city"),
        pphone = hval("customer_phone"),
        pemail = hval("customer_email"),
        cur = cur,
        line_trs = line_trs,
        untaxed = money(head.try_get("untaxed_amount").unwrap_or(Decimal::ZERO)),
        tax = money(head.try_get("tax_amount").unwrap_or(Decimal::ZERO)),
        total = money(head.try_get("total_amount").unwrap_or(Decimal::ZERO)),
        note = hval("note"),
    );
    Html(html).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Fulfilment documents — printable DO / service confirmation
// ─────────────────────────────────────────────────────────────────────────

/// Mint a fulfilment document (delivery order or service confirmation)
/// for exactly the lines posted in one fulfilment action. `lines` is
/// `(order_line_id, product_id, description, quantity, lot_name)`.
#[allow(clippy::too_many_arguments)]
async fn create_fulfilment_doc(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    order_id: Uuid,
    kind: &str,
    seq: &vortex_plugin_sdk::orm::sequence::SequenceSpec,
    source_location_id: Option<Uuid>,
    company_id: Option<Uuid>,
    user_id: Uuid,
    lines: &[(Uuid, Uuid, Option<String>, Decimal, Option<String>)],
) -> Option<Uuid> {
    let number = vortex_plugin_sdk::orm::sequence::next(&state.pool, seq)
        .await
        .map_err(|e| error!(error = %e, "fulfilment doc sequence failed"))
        .ok()?;
    let doc_id = Uuid::now_v7();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_delivery (id, number, order_id, kind, source_location_id, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(doc_id)
    .bind(&number)
    .bind(order_id)
    .bind(kind)
    .bind(source_location_id)
    .bind(company_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| error!(error = %e, "fulfilment doc insert failed"))
    .ok()?;
    for (line_id, product_id, desc, qty, lot) in lines {
        let _ = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO sales_delivery_line (delivery_id, order_line_id, product_id, description, quantity, lot_name) \
             VALUES ($1,$2,$3,$4,$5,$6)",
        )
        .bind(doc_id)
        .bind(line_id)
        .bind(product_id)
        .bind(desc)
        .bind(qty)
        .bind(lot)
        .execute(db)
        .await;
    }
    Some(doc_id)
}

/// Print view for a delivery order / service confirmation — a fully
/// self-contained A4 page (logo embedded as a data URI) with signature
/// blocks; no prices, it is a fulfilment document, not an invoice.
async fn print_delivery(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT d.number, d.kind, d.delivery_date, d.note, \
                o.number AS order_number, o.order_date, \
                sl.code AS loc_code, sl.name AS loc_name, \
                c.name AS customer_name, c.street, c.street2, c.city, c.zip, \
                c.phone AS customer_phone, c.email AS customer_email \
         FROM sales_delivery d \
         JOIN sales_order o ON o.id = d.order_id \
         JOIN contacts c ON c.id = o.customer_id \
         LEFT JOIN stock_location sl ON sl.id = d.source_location_id \
         WHERE d.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(head) = head else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Delivery not found").into_response();
    };
    // Company block from the accounting settings (sales depends on
    // accounting, so the table exists; fields may simply be empty).
    let company = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(co.name, 'Company') AS name, c.company_id_value, \
                c.company_address1, c.company_address2, \
                c.company_city, c.company_postcode, c.company_phone, c.company_email \
         FROM acc_config c LEFT JOIN companies co ON co.id = c.company_id \
         ORDER BY c.company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT p.code, p.name, dl.description, dl.quantity, dl.lot_name, u.code AS uom_code \
         FROM sales_delivery_line dl \
         JOIN stock_product p ON p.id = dl.product_id \
         LEFT JOIN uoms u ON u.id = p.uom_id \
         WHERE dl.delivery_id = $1 ORDER BY dl.id",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let kind: String = head.get("kind");
    let is_service = kind == "service";
    let title = if is_service { "SERVICE CONFIRMATION" } else { "DELIVERY ORDER" };
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
    // Logo embedded as a data URI so the page is self-contained.
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

    let mut line_trs = String::new();
    for (i, l) in lines.iter().enumerate() {
        let qty: Decimal = l.get("quantity");
        line_trs.push_str(&format!(
            r#"<tr><td class="num">{n}</td><td class="mono-code">{code}</td><td>{name}{desc}</td><td class="num">{qty}</td><td>{uom}</td><td>{lot}</td></tr>"#,
            n = i + 1,
            code = esc(&l.get::<String, _>("code")),
            name = esc(&l.get::<String, _>("name")),
            desc = l
                .try_get::<Option<String>, _>("description")
                .ok()
                .flatten()
                .filter(|d| !d.is_empty())
                .map(|d| format!(r#"<br><span style="font-size:0.85em;color:#555">{}</span>"#, esc(&d)))
                .unwrap_or_default(),
            qty = qty.normalize(),
            uom = l.try_get::<Option<String>, _>("uom_code").ok().flatten().map(|u| esc(&u).to_string()).unwrap_or_default(),
            lot = l.try_get::<Option<String>, _>("lot_name").ok().flatten().map(|v| esc(&v).to_string()).unwrap_or_else(|| "—".into()),
        ));
    }

    let ack_line = if is_service {
        "The services listed above have been performed and accepted."
    } else {
        "Received the above goods in good order and condition."
    };
    let ship_from = {
        let code = hval("loc_code");
        let name = hval("loc_name");
        if code.is_empty() { name } else { format!("{code} · {name}") }
    };

    let html = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{number} — {title}</title>
<style>{css}
body {{ max-width: 21cm; margin: 1.2cm auto; position: relative; }}
@page {{ size: A4; margin: 0; }}
@media print {{
  body {{ max-width: none; margin: 0; padding: 1.2cm 1.4cm; }}
}}
.head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.2em; }}
.head h1 {{ font-size: 1.4em; letter-spacing: 0.06em; }}
.seller p, .buyer p {{ margin: 1px 0; font-size: 0.85em; }}
.seller .name {{ font-size: 1.1em; font-weight: 700; }}
.meta td {{ padding: 1px 8px 1px 0; font-size: 0.85em; border: none; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono-code {{ font-family: monospace; }}
.sig {{ display: flex; gap: 3em; margin-top: 4em; }}
.sig div {{ flex: 1; border-top: 1px solid #333; padding-top: 0.4em; font-size: 0.8em; }}
.ack {{ margin-top: 2em; font-size: 0.85em; }}
.footer {{ margin-top: 2em; font-size: 0.75em; color: #666; }}
.printbar {{ text-align: right; margin-bottom: 1em; }}
.printbar button {{ padding: 0.4em 1.2em; cursor: pointer; }}
@media print {{ .printbar {{ display: none; }} }}
</style></head><body>
<div class="printbar"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="head">
  <div class="seller">
    {logo_html}
    <p class="name">{company_name}</p>
    <p>{addr1}</p><p>{addr2}</p><p>{postcode} {city}</p>
    <p>{cphone} · {cemail}</p>
  </div>
  <div style="text-align:right">
    <h1>{title}</h1>
    <table class="meta" style="margin-left:auto">
      <tr><td>Number</td><td><b>{number}</b></td></tr>
      <tr><td>Date</td><td>{date}</td></tr>
      <tr><td>Order Ref</td><td>{order_number}</td></tr>
      {ship_from_row}
    </table>
  </div>
</div>
<div class="buyer" style="margin-bottom:1em">
  <p style="font-size:0.75em;color:#666">{party_label}</p>
  <p><b>{customer}</b></p>
  <p>{pstreet}</p><p>{pstreet2}</p><p>{pzip} {pcity}</p>
  <p>{pphone} {pemail}</p>
</div>
<table class="table table-sm" style="table-layout:fixed;width:100%">
<colgroup><col style="width:2.5rem"/><col style="width:7rem"/><col/><col style="width:5rem"/><col style="width:4.5rem"/><col style="width:9rem"/></colgroup>
<thead><tr><th class="num">#</th><th>Code</th><th>Description</th><th class="num">Qty</th><th>UoM</th><th>Lot / Serial</th></tr></thead>
<tbody>{line_trs}</tbody>
</table>
<p class="ack">{ack_line}</p>
<div class="sig">
  <div>Prepared by<br><br>Name:<br>Date:</div>
  <div>{deliver_sig}<br><br>Name:<br>Date:</div>
  <div>Received / Accepted by<br><br>Name, company stamp:<br>Date:</div>
</div>
<div class="footer">This is a fulfilment document — not an invoice. {note}</div>
</body></html>"##,
        css = vortex_plugin_sdk::framework::user_reports::REPORT_CSS,
        number = hval("number"),
        title = title,
        logo_html = logo_html,
        company_name = company_name,
        addr1 = cval("company_address1"),
        addr2 = cval("company_address2"),
        postcode = cval("company_postcode"),
        city = cval("company_city"),
        cphone = cval("company_phone"),
        cemail = cval("company_email"),
        date = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("delivery_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_default(),
        order_number = hval("order_number"),
        ship_from_row = if ship_from.is_empty() || is_service {
            String::new()
        } else {
            format!("<tr><td>Ship From</td><td>{ship_from}</td></tr>")
        },
        party_label = if is_service { "CUSTOMER" } else { "DELIVER TO" },
        customer = hval("customer_name"),
        pstreet = hval("street"),
        pstreet2 = hval("street2"),
        pzip = hval("zip"),
        pcity = hval("city"),
        pphone = hval("customer_phone"),
        pemail = hval("customer_email"),
        line_trs = line_trs,
        ack_line = ack_line,
        deliver_sig = if is_service { "Performed by" } else { "Delivered by" },
        note = hval("note"),
    );
    Html(html).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Service confirmation — fulfilment for service lines
// ─────────────────────────────────────────────────────────────────────────

/// Confirmation form for outstanding service lines. Services are not
/// stock-holding and need no delivery order — performing the work is
/// confirmed here instead.
async fn service_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let po = vortex_plugin_sdk::sqlx::query("SELECT number, state FROM sales_order WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
    let Some(po) = po else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Order not found").into_response();
    };
    let number: String = po.try_get::<Option<String>, _>("number").ok().flatten().unwrap_or_default();
    if po.get::<String, _>("state") != "confirmed" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can have services confirmed").into_response();
    }

    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, p.code AS product_code, p.name AS product_name, l.description, \
                (l.quantity - l.qty_delivered) AS remaining \
         FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.quantity > l.qty_delivered AND p.product_type = 'service' \
         ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    if lines.is_empty() {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response();
    }

    let mut rows = String::new();
    for r in &lines {
        let lid: Uuid = r.get("id");
        let pcode: String = r.get("product_code");
        let pname: String = r.get("product_name");
        let desc: Option<String> = r.try_get("description").ok();
        let remaining: Decimal = r.try_get("remaining").unwrap_or(Decimal::ZERO);
        rows.push_str(&format!(
            r#"<tr><td class="font-mono">{pcode}</td><td>{pname}{desc}</td>
<td class="text-right">{remaining}</td>
<td><input name="qty_{lid}" type="number" step="0.0001" min="0" max="{remaining}" value="{remaining}" class="input input-bordered input-xs w-28 text-right"/></td></tr>"#,
            pcode = esc(&pcode),
            pname = esc(&pname),
            desc = desc.filter(|d| !d.is_empty()).map(|d| format!(r#"<br><span class="text-xs text-base-content/50">{}</span>"#, esc(&d))).unwrap_or_default(),
            remaining = remaining,
            lid = lid,
        ));
    }

    let content = format!(
        r#"<div class="max-w-3xl">
<a href="/sales/orders/{id}" class="btn btn-ghost btn-sm mb-4">← Back to {number}</a>
<h1 class="text-2xl font-bold mb-2">Confirm Services — {number}</h1>
<p class="text-base-content/60 mb-6">Enter the quantity performed per service line. Confirming records fulfilment — no delivery order or stock move is involved.</p>
<form method="POST" action="/sales/orders/{id}/confirm-services">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="overflow-x-auto">
<table class="table table-sm">
<thead><tr><th>Code</th><th>Service</th><th class="text-right">Outstanding</th><th>Confirm Qty</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
<div class="flex gap-2 mt-4">
<button type="submit" class="btn btn-success btn-sm">Confirm Services</button>
<a href="/sales/orders/{id}" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        id = id, number = esc(&number), rows = rows,
    );

    Html(page_shell(&sidebar, &format!("Confirm Services {}", number), &content)).into_response()
}

async fn process_service_confirmation(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let po = vortex_plugin_sdk::sqlx::query("SELECT number, state FROM sales_order WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
    let Some(po) = po else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Order not found").into_response();
    };
    let number: String = po.try_get::<Option<String>, _>("number").ok().flatten().unwrap_or_default();
    if po.get::<String, _>("state") != "confirmed" {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed orders can have services confirmed").into_response();
    }

    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.product_id, l.description, (l.quantity - l.qty_delivered) AS remaining \
         FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.quantity > l.qty_delivered AND p.product_type = 'service'",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut confirmed_any = false;
    let mut performed: Vec<(Uuid, Uuid, Option<String>, Decimal, Option<String>)> = Vec::new();
    for r in &lines {
        let lid: Uuid = r.get("id");
        let product_id: Uuid = r.get("product_id");
        let line_desc: Option<String> = r.try_get("description").ok().flatten();
        let remaining: Decimal = r.try_get("remaining").unwrap_or(Decimal::ZERO);
        let want = form
            .get(&format!("qty_{lid}"))
            .and_then(|s| s.trim().parse::<Decimal>().ok())
            .unwrap_or(Decimal::ZERO);
        if want <= Decimal::ZERO {
            continue;
        }
        let qty = if want > remaining { remaining } else { want };
        let _ = vortex_plugin_sdk::sqlx::query("UPDATE sales_order_line SET qty_delivered = qty_delivered + $1 WHERE id = $2")
            .bind(qty)
            .bind(lid)
            .execute(&db)
            .await;
        performed.push((lid, product_id, line_desc, qty, None));
        confirmed_any = true;
    }

    if !confirmed_any {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response();
    }

    // Mint the printable service confirmation.
    let company_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT company_id FROM sales_order WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(None);
    let _ = create_fulfilment_doc(
        &state, &db, id, "service", &SC_SEQ, None, company_id, user.id, &performed,
    )
    .await;

    // Same completion rule as delivery: the order is fulfilled when
    // every line — goods and services — is fully delivered/confirmed.
    let outstanding: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM sales_order_line WHERE order_id = $1 AND quantity > qty_delivered",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(0);
    if outstanding == 0 {
        let _ = vortex_plugin_sdk::sqlx::query("UPDATE sales_order SET state = 'delivered', updated_by = $1, updated_at = NOW() WHERE id = $2")
            .bind(user.id)
            .bind(id)
            .execute(&db)
            .await;
    }

    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "services_confirmed").await;
    info!(number = %number, "sales services confirmed");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Accounting bridge — customer invoice from a sales order
// ─────────────────────────────────────────────────────────────────────────

/// Create a draft accounting customer invoice for the delivered (or
/// service-confirmed) quantities not yet invoiced — billing follows
/// delivery, so partial deliveries bill progressively and a fully
/// invoiced order simply has nothing left to bill. Lines carry their
/// real tax reference, LHDN classification and product soft-link
/// straight through; the income account comes from the product master
/// when set.
async fn create_customer_invoice(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    use vortex_accounting::documents::{self, InvoiceLine, NewInvoice};

    let po = vortex_plugin_sdk::sqlx::query(
        "SELECT number, state, customer_id, order_date, company_id, customer_invoice_move_id \
         FROM sales_order WHERE id = $1",
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
    if !matches!(po_state.as_str(), "confirmed" | "delivered") {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only confirmed or delivered orders can be invoiced").into_response();
    }
    let customer_id: Uuid = po.get("customer_id");
    let company_id: Option<Uuid> = po.try_get("company_id").ok().flatten();
    let invoice_date = vortex_plugin_sdk::chrono::Utc::now().date_naive();

    let currency_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT currency_id FROM sales_order WHERE id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(None);

    // Bill what has been delivered/confirmed but not yet invoiced.
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, COALESCE(NULLIF(l.description, ''), NULLIF(p.sales_description, ''), p.name) AS name, \
                GREATEST(l.qty_delivered - l.qty_invoiced, 0) AS billable, \
                l.unit_price, l.tax_id, l.product_id, \
                COALESCE(l.classification_code, p.classification_code) AS classification_code, \
                p.income_account_id \
         FROM sales_order_line l JOIN stock_product p ON p.id = l.product_id \
         WHERE l.order_id = $1 AND l.qty_delivered - l.qty_invoiced > 0 \
         ORDER BY l.sequence",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    if line_rows.is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Nothing to invoice — no delivered or confirmed quantity is awaiting billing.").into_response();
    }

    let mut lines = Vec::new();
    let mut billed: Vec<(Uuid, Decimal)> = Vec::new();
    for r in &line_rows {
        let line_id: Uuid = r.get("id");
        let name: String = r.get("name");
        let quantity: Decimal = r.get("billable");
        let unit_price: Decimal = r.get("unit_price");
        billed.push((line_id, quantity));
        let mut line = InvoiceLine::new(&name, quantity, unit_price);
        if let Ok(Some(t)) = r.try_get::<Option<Uuid>, _>("tax_id") {
            line = line.with_tax(t);
        }
        if let Ok(Some(a)) = r.try_get::<Option<Uuid>, _>("income_account_id") {
            line = line.with_account(a);
        }
        if let Ok(Some(c)) = r.try_get::<Option<String>, _>("classification_code") {
            line = line.with_classification(c);
        }
        if let Ok(Some(pid)) = r.try_get::<Option<Uuid>, _>("product_id") {
            line = line.with_product(pid);
        }
        lines.push(line);
    }

    let origin = format!("sales_order:{id}");
    let narration = format!("From sales order {number} — delivered quantities");
    let invoice = match documents::create_invoice(
        &db,
        user.id,
        &NewInvoice {
            move_type: "customer_invoice",
            partner_id: customer_id,
            invoice_date,
            due_date: None,
            journal_code: None,
            currency_id,
            origin_ref: Some(&origin),
            narration: Some(&narration),
            company_id,
            lines,
        },
    )
    .await
    {
        Ok(b) => b,
        Err(e) => {
            error!(error = %e, "customer invoice create failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY, format!("Failed to create invoice: {e}")).into_response();
        }
    };
    // Advance the invoiced quantity on each billed line, and keep the
    // latest-invoice pointer for quick reference.
    for (line_id, qty) in &billed {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE sales_order_line SET qty_invoiced = qty_invoiced + $1 WHERE id = $2",
        )
        .bind(qty)
        .bind(line_id)
        .execute(&db)
        .await;
    }
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET customer_invoice_move_id = $2, updated_by = $3, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(invoice)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "customer invoice link failed");
    }
    audit_so(&state, &db_ctx, &db, user.id, &user.username, id, "invoiced").await;
    info!(number = %number, invoice = %invoice, "customer invoice created from sales order");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/accounting/documents/{invoice}")).into_response()
}
