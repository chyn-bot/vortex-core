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
        .route("/sales/orders/{id}/edit", get(edit_quote_form))
        .route("/sales/orders/{id}/save", post(save_quote))
        .route("/sales/orders/{id}/lines", post(add_line))
        .route("/sales/orders/{id}/lines/{line_id}/delete", post(delete_line))
        .route("/sales/orders/{id}/confirm", post(confirm_order))
        .route("/sales/orders/{id}/send", post(mark_sent))
        .route("/sales/orders/{id}/revise", post(revise_quote))
        .route("/sales/orders/{id}/duplicate", post(duplicate_order))
        .route("/sales/orders/{id}/lost", post(mark_lost))
        .route("/sales/orders/{id}/print-quote", get(print_quote))
        .route("/sales/orders/{id}/cancel", post(cancel_order))
        .route("/sales/orders/{id}/deliver", get(deliver_form))
        .route("/sales/orders/{id}/deliver", post(process_delivery))
        .route("/sales/orders/{id}/confirm-services", get(service_form))
        .route("/sales/orders/{id}/confirm-services", post(process_service_confirmation))
        .route("/sales/deliveries/{id}/print", get(print_delivery))
        .route("/sales/orders/{id}/create-invoice", post(create_customer_invoice))
        // Notes / Terms template library (Sales ▸ Configuration)
        .route("/sales/note-templates", get(list_note_templates))
        .route("/sales/note-templates/new", get(new_note_template_form))
        .route("/sales/note-templates/create", post(create_note_template))
        .route("/sales/note-templates/{id}", get(edit_note_template))
        .route("/sales/note-templates/{id}", post(update_note_template))
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
        "sales",
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

/// A display-only status bar for the order pipeline
/// (Quotation → Sent → Confirmed → Delivered). Terminal states
/// (cancelled / lost / expired / superseded) are appended only when the
/// record is actually in one, so the happy path stays uncluttered.
fn order_statusbar(state: &str) -> String {
    use vortex_plugin_sdk::framework::{StageColor, StatusBar};
    let mut bar = StatusBar::new("sales_order", "state")
        .stage("quotation", "Quotation", StageColor::Neutral)
        .stage("sent", "Sent", StageColor::Info)
        .stage("confirmed", "Confirmed", StageColor::Primary)
        .stage("delivered", "Delivered", StageColor::Success);
    bar = match state {
        "cancelled" => bar.stage("cancelled", "Cancelled", StageColor::Error),
        "lost" => bar.stage("lost", "Lost", StageColor::Error),
        "expired" => bar.stage("expired", "Expired", StageColor::Warning),
        "superseded" => bar.stage("superseded", "Superseded", StageColor::Neutral),
        _ => bar,
    };
    bar.render(state, "")
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


/// JSON map of customer context (address + credit limit), keyed for the
/// editor's client so picking a customer can surface where they are and how
/// much credit they have — without a round-trip.
async fn customers_json(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT c.id, c.street, c.street2, c.city, c.country, c.credit_limit, \
                tp.payment_term_id \
         FROM contacts c \
         LEFT JOIN LATERAL ( \
             SELECT payment_term_id FROM acc_partner_tax_profile \
             WHERE contact_id = c.id ORDER BY company_id NULLS LAST LIMIT 1 \
         ) tp ON TRUE \
         WHERE c.active AND c.contact_type IN ('customer','both')",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let parts: Vec<String> = ["street", "street2", "city", "country"]
                .iter()
                .filter_map(|c| r.try_get::<Option<String>, _>(*c).ok().flatten())
                .filter(|s| !s.trim().is_empty())
                .collect();
            let credit: Option<Decimal> = r.try_get("credit_limit").ok().flatten();
            json!({
                "id": id.to_string(),
                "address": parts.join(", "),
                "credit_limit": credit.filter(|c| *c > Decimal::ZERO).map(|c| c.round_dp(2).to_string()),
                "payment_term_id": r.try_get::<Option<Uuid>, _>("payment_term_id").ok().flatten().map(|u| u.to_string()),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

/// The company's base currency id, used to preselect the currency on a new
/// quote instead of forcing the user to pick every time.
async fn company_currency_id(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query(
        "SELECT c.currency_id FROM companies c \
         WHERE c.currency_id IS NOT NULL ORDER BY c.created_at LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .and_then(|r| r.try_get::<Option<Uuid>, _>("currency_id").ok().flatten())
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
/// The uniform factor a whole-quote discount applies to every line's net.
/// `subtotal` (sum of per-line-discounted nets) is only consulted for a fixed
/// amount. Returns 1 (no-op) for no/unknown discount. Clamped to [0, 1] so a
/// discount can never make a line negative.
fn global_factor(discount_type: Option<&str>, value: Decimal, subtotal: Decimal) -> Decimal {
    let hundred = Decimal::from(100);
    match discount_type {
        Some("percent") => (hundred - value.clamp(Decimal::ZERO, hundred)) / hundred,
        Some("fixed") if subtotal > Decimal::ZERO => {
            (subtotal - value.clamp(Decimal::ZERO, subtotal)) / subtotal
        }
        _ => Decimal::ONE,
    }
}

/// Read an order's whole-quote discount (type, value).
async fn order_global_discount(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    order_id: Uuid,
) -> (Option<String>, Decimal) {
    vortex_plugin_sdk::sqlx::query(
        "SELECT global_discount_type, global_discount_value FROM sales_order WHERE id = $1",
    )
    .bind(order_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .map(|r| {
        (
            r.try_get::<Option<String>, _>("global_discount_type").ok().flatten(),
            r.try_get::<Decimal, _>("global_discount_value").unwrap_or(Decimal::ZERO),
        )
    })
    .unwrap_or((None, Decimal::ZERO))
}

async fn recompute_totals(db: &vortex_plugin_sdk::sqlx::PgPool, order_id: Uuid) {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT quantity, unit_price, discount_percent, tax_id FROM sales_order_line \
         WHERE order_id = $1 AND display_type IS NULL",
    )
    .bind(order_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    // Fold the per-line discount into an effective unit price so the tax
    // engine (and the stored totals) see the net the customer actually pays.
    let hundred = Decimal::from(100);
    let mut eff_lines: Vec<(Decimal, Decimal, Option<Uuid>)> = rows
        .iter()
        .map(|r| {
            let qty: Decimal = r.get("quantity");
            let price: Decimal = r.get("unit_price");
            let disc: Decimal = r.try_get("discount_percent").unwrap_or(Decimal::ZERO);
            let eff = (price * (hundred - disc) / hundred).round_dp(6);
            (qty, eff, r.try_get("tax_id").ok().flatten())
        })
        .collect();
    // Apply the whole-quote discount as a single uniform factor across lines.
    let (gd_type, gd_value) = order_global_discount(db, order_id).await;
    let subtotal: Decimal = eff_lines.iter().map(|(q, p, _)| q * p).sum();
    let factor = global_factor(gd_type.as_deref(), gd_value, subtotal);
    if factor != Decimal::ONE {
        for l in eff_lines.iter_mut() {
            l.1 = (l.1 * factor).round_dp(6);
        }
    }
    let lines = eff_lines;
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

// ─────────────────────────────────────────────────────────────────────────
// Inline quote editor (Xero-style single-screen grid)
// ─────────────────────────────────────────────────────────────────────────

/// JSON array of active products for the editor's line grid: the client
/// builds the product dropdown from this and autofills description / price /
/// tax / classification when a product is picked.
async fn products_json(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT p.id, p.code, p.name, \
                COALESCE(NULLIF(p.sales_description, ''), p.name) AS side_desc, \
                CASE WHEN p.list_price > 0 THEN p.list_price ELSE p.cost END AS side_price, \
                p.sales_tax_id, p.classification_code, u.code AS uom, p.uom_id \
         FROM stock_product p LEFT JOIN uoms u ON u.id = p.uom_id \
         WHERE p.active ORDER BY p.code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let price: Decimal = r.try_get("side_price").unwrap_or(Decimal::ZERO);
            json!({
                "id": id.to_string(),
                "code": r.get::<String, _>("code"),
                "name": r.get::<String, _>("name"),
                "description": r.get::<String, _>("side_desc"),
                "unit_price": price.round_dp(2).to_string(),
                "tax_id": r.try_get::<Option<Uuid>, _>("sales_tax_id").ok().flatten().map(|t| t.to_string()),
                "classification_code": r.try_get::<Option<String>, _>("classification_code").ok().flatten(),
                "uom": r.try_get::<Option<String>, _>("uom").ok().flatten(),
                "uom_id": r.try_get::<Option<Uuid>, _>("uom_id").ok().flatten().map(|u| u.to_string()),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

/// JSON array of every active unit of measure for the per-line unit selector.
async fn uoms_json(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM uoms WHERE active ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            json!({
                "id": id.to_string(),
                "code": r.get::<String, _>("code"),
                "name": r.get::<String, _>("name"),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

/// JSON array of sale-side taxes with the parameters the client needs to
/// estimate tax live (authoritative totals are recomputed server-side).
async fn taxes_json(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, amount_type, amount, price_include \
         FROM taxes WHERE active AND type_tax_use IN ('sale', 'none') ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let amount: Decimal = r.try_get("amount").unwrap_or(Decimal::ZERO);
            json!({
                "id": id.to_string(),
                "name": r.get::<String, _>("name"),
                "amount_type": r.get::<String, _>("amount_type"),
                "amount": amount.to_string(),
                "price_include": r.try_get::<bool, _>("price_include").unwrap_or(false),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

/// One line as submitted by the editor (all strings — parsed server-side so a
/// blank field degrades to a product default rather than a 422).
#[derive(serde::Deserialize)]
struct QuoteLinePayload {
    /// `"section"` or `"note"` for display-only rows; absent/empty = product line.
    display_type: Option<String>,
    product_id: Option<String>,
    description: Option<String>,
    quantity: Option<String>,
    unit_price: Option<String>,
    discount_percent: Option<String>,
    tax_id: Option<String>,
    uom_id: Option<String>,
    classification_code: Option<String>,
}

/// The whole quote as submitted by the editor's Save button (JSON body).
#[derive(serde::Deserialize)]
struct QuotePayload {
    customer_id: Option<String>,
    order_date: Option<String>,
    expected_date: Option<String>,
    validity_date: Option<String>,
    currency_id: Option<String>,
    source_location_id: Option<String>,
    payment_term_id: Option<String>,
    title: Option<String>,
    summary: Option<String>,
    note: Option<String>,
    /// Whole-quote discount: `"percent"` or `"fixed"` (absent/other = none).
    global_discount_type: Option<String>,
    global_discount_value: Option<String>,
    #[serde(default)]
    lines: Vec<QuoteLinePayload>,
}

/// Parse the submitted whole-quote discount into a validated (type, value)
/// pair. An unknown type or a zero value collapses to "no discount".
fn parse_global_discount(payload: &QuotePayload) -> (Option<String>, Decimal) {
    let value = d_opt(&payload.global_discount_value)
        .unwrap_or(Decimal::ZERO)
        .max(Decimal::ZERO);
    let ty = s_opt(&payload.global_discount_type)
        .filter(|t| t == "percent" || t == "fixed")
        .filter(|_| value > Decimal::ZERO);
    match ty {
        Some(t) => (Some(t), value),
        None => (None, Decimal::ZERO),
    }
}

fn s_opt(v: &Option<String>) -> Option<String> {
    v.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty()).map(|s| s.to_string())
}
fn u_opt(v: &Option<String>) -> Option<Uuid> {
    v.as_deref().and_then(|s| Uuid::parse_str(s.trim()).ok())
}
fn d_opt(v: &Option<String>) -> Option<Decimal> {
    v.as_deref().and_then(|s| s.trim().parse::<Decimal>().ok())
}
/// Sanitize an optional rich-text field to the safe allow-list, collapsing an
/// empty result to `None`.
fn rich_opt(v: &Option<String>) -> Option<String> {
    let cleaned = crate::richtext::sanitize_rich(v.as_deref().unwrap_or_default());
    if cleaned.trim().is_empty() {
        None
    } else {
        Some(cleaned)
    }
}

/// Insert the submitted lines for a quote, filling blanks from the product
/// master (same defaults the client autofills) and sequencing them 10, 20, …
async fn insert_quote_lines(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    order_id: Uuid,
    company_id: Option<Uuid>,
    lines: &[QuoteLinePayload],
) {
    let hundred = Decimal::from(100);
    let mut seq = 10i32;
    for l in lines {
        // Section / note rows: text-only, no product / qty / tax.
        if let Some(dt) = s_opt(&l.display_type).filter(|d| d == "section" || d == "note") {
            let text = s_opt(&l.description).unwrap_or_default();
            if text.is_empty() {
                continue; // drop empty display rows
            }
            let _ = vortex_plugin_sdk::sqlx::query(
                "INSERT INTO sales_order_line \
                 (id, order_id, sequence, product_id, description, quantity, unit_price, \
                  discount_percent, tax_id, classification_code, company_id, display_type) \
                 VALUES ($1,$2,$3,NULL,$4,0,0,0,NULL,NULL,$5,$6)",
            )
            .bind(Uuid::now_v7())
            .bind(order_id)
            .bind(seq)
            .bind(&text)
            .bind(company_id)
            .bind(&dt)
            .execute(db)
            .await;
            seq += 10;
            continue;
        }
        let Some(product_id) = u_opt(&l.product_id) else { continue };
        let quantity = d_opt(&l.quantity).unwrap_or(Decimal::ONE);
        if quantity <= Decimal::ZERO {
            continue;
        }
        let product = vortex_plugin_sdk::sqlx::query(
            "SELECT COALESCE(NULLIF(sales_description, ''), name) AS side_desc, \
                    CASE WHEN list_price > 0 THEN list_price ELSE cost END AS side_price, \
                    sales_tax_id, classification_code, uom_id \
             FROM stock_product WHERE id = $1",
        )
        .bind(product_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten();
        let Some(product) = product else { continue };
        // Descriptions may carry inline rich formatting — sanitize to the
        // allow-list before storing (it is later rendered raw).
        let description = crate::richtext::sanitize_rich(
            &s_opt(&l.description).unwrap_or_else(|| product.get("side_desc")),
        );
        let unit_price = d_opt(&l.unit_price).unwrap_or_else(|| product.try_get("side_price").unwrap_or(Decimal::ZERO));
        let discount = d_opt(&l.discount_percent)
            .unwrap_or(Decimal::ZERO)
            .clamp(Decimal::ZERO, hundred);
        let tax_id = u_opt(&l.tax_id)
            .or_else(|| product.try_get::<Option<Uuid>, _>("sales_tax_id").ok().flatten());
        // Chosen unit, or the product's own unit as the fallback.
        let uom_id = u_opt(&l.uom_id)
            .or_else(|| product.try_get::<Option<Uuid>, _>("uom_id").ok().flatten());
        let classification = s_opt(&l.classification_code)
            .or_else(|| product.try_get::<Option<String>, _>("classification_code").ok().flatten());
        let _ = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO sales_order_line \
             (id, order_id, sequence, product_id, description, quantity, unit_price, \
              discount_percent, tax_id, uom_id, classification_code, company_id) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
        )
        .bind(Uuid::now_v7())
        .bind(order_id)
        .bind(seq)
        .bind(product_id)
        .bind(&description)
        .bind(quantity)
        .bind(unit_price)
        .bind(discount)
        .bind(tax_id)
        .bind(uom_id)
        .bind(classification)
        .bind(company_id)
        .execute(db)
        .await;
        seq += 10;
    }
}

/// Render the single-screen quote editor (header fields + reactive line grid
/// + live totals). Used for both create and draft-edit; `action_url` is the
/// JSON save endpoint, `lines_json` seeds existing rows (`"[]"` for new).
#[allow(clippy::too_many_arguments)]
fn render_quote_editor(
    heading: &str,
    action_url: &str,
    cancel_url: &str,
    customers_sel: &str,
    locations_sel: &str,
    currencies_sel: &str,
    payment_terms_sel: &str,
    order_date: &str,
    expected_date: &str,
    validity_date: &str,
    title: &str,
    summary: &str,
    note: &str,
    products_json: &str,
    taxes_json: &str,
    lines_json: &str,
    customers_json: &str,
    uoms_json: &str,
    templates_json: &str,
    gd_type: &str,
    gd_value: &str,
) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let gd_sel = |v: &str| if gd_type == v { " selected" } else { "" };
    let script = QUOTE_EDITOR_JS.replace("__ACTION__", &action_url.replace('"', ""));
    format!(
        r##"<div class="max-w-6xl">
{rt_head}
<a href="{cancel_url}" class="btn btn-ghost btn-sm mb-3">← Cancel</a>
<h1 class="text-2xl font-bold mb-3">{heading}</h1>

{rt_toolbar}

<div class="card bg-base-100 shadow mb-4"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-3 gap-3">
<div class="form-control md:col-span-1"><label class="label py-1"><span class="label-text text-xs">Customer *</span></label>
<select id="f-customer" class="select select-bordered select-sm" required>{customers}</select>
<div id="cust-ctx" class="hidden text-xs text-base-content/60 mt-1 leading-snug"></div></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Quote Date</span></label>
<input id="f-order-date" type="date" value="{order_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Valid Until</span></label>
<input id="f-validity" type="date" value="{validity_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Expected Date</span></label>
<input id="f-expected" type="date" value="{expected_date}" class="input input-bordered input-sm"/></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Currency</span></label>
<select id="f-currency" class="select select-bordered select-sm">{currencies}</select></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Ship-From</span></label>
<select id="f-location" class="select select-bordered select-sm">{locations}</select></div>
<div class="form-control"><label class="label py-1"><span class="label-text text-xs">Payment Terms</span></label>
<select id="f-payment-term" class="select select-bordered select-sm">{payment_terms}</select></div>
</div>
<div class="form-control mt-3"><label class="label py-1"><span class="label-text text-xs">Title</span></label>
<div id="f-title" contenteditable="true" data-ph="e.g. Supply &amp; installation of…" class="rt-field input input-bordered input-sm h-auto py-1">{title}</div></div>
<div class="form-control mt-2"><label class="label py-1"><span class="label-text text-xs">Summary / intro</span></label>
<div id="f-summary" contenteditable="true" data-ph="A short intro shown under the title" class="rt-field textarea textarea-bordered textarea-sm leading-snug">{summary}</div></div>
</div></div>

<div class="card bg-base-100 shadow mb-4"><div class="card-body">
<h2 class="card-title text-lg mb-2">Lines</h2>
<div class="hidden sm:flex items-center gap-2 pb-1 mb-1 border-b border-base-300 text-xs font-semibold uppercase tracking-wide text-base-content/50">
<span class="w-5"></span>
<span class="w-44">Product</span>
<span class="flex-1">Description</span>
<span class="w-16 text-right">Qty</span>
<span class="w-20">Unit</span>
<span class="w-24 text-right">Unit Price</span>
<span class="w-16 text-right">Disc %</span>
<span class="w-28">Tax</span>
<span class="w-24 text-right">Amount</span>
<span class="w-6"></span>
</div>
<div id="lines-body"></div>
<div class="flex gap-2 mt-3 flex-wrap">
<button type="button" id="add-line" class="btn btn-outline btn-sm">+ Add a line</button>
<button type="button" id="add-section" class="btn btn-ghost btn-sm">+ Add a section</button>
<button type="button" id="add-note" class="btn btn-ghost btn-sm">+ Add a note</button>
</div>
<div class="flex justify-end mt-4">
<table class="text-sm">
<tr><td class="text-base-content/60 pr-6">Subtotal</td><td class="text-right font-mono"><span id="sum-sub">0.00</span> <span class="sum-cur"></span></td></tr>
<tr id="disc-row"><td class="text-base-content/60 pr-6 py-1">
<div class="flex items-center gap-1">
<span>Discount</span>
<select id="f-gdtype" class="select select-bordered select-xs">
<option value=""{gd_none}>None</option>
<option value="percent"{gd_pct}>% off</option>
<option value="fixed"{gd_fix}>Amount</option>
</select>
<input id="f-gdval" type="number" step="0.01" min="0" value="{gd_value}" class="input input-bordered input-xs w-20 text-right {gd_hide}" placeholder="0"/>
</div></td><td class="text-right font-mono text-error">- <span id="sum-disc">0.00</span> <span class="sum-cur"></span></td></tr>
<tr><td class="text-base-content/60 pr-6">Tax</td><td class="text-right font-mono"><span id="sum-tax">0.00</span> <span class="sum-cur"></span></td></tr>
<tr><td class="font-semibold pr-6">Total</td><td class="text-right font-mono font-semibold"><span id="sum-tot">0.00</span> <span class="sum-cur"></span></td></tr>
</table>
</div>
</div></div>

<div class="card bg-base-100 shadow mb-4"><div class="card-body">
<div class="flex items-center justify-between mb-1 flex-wrap gap-2">
<label class="label-text text-xs">Note / terms (printed under the lines)</label>
<div class="flex items-center gap-1">
<span class="text-xs text-base-content/50">Apply template:</span>
<select id="f-note-template" class="select select-bordered select-xs"></select>
</div>
</div>
<div class="form-control">
<div id="f-note" contenteditable="true" data-ph="Payment terms, delivery notes, disclaimers…" class="rt-field textarea textarea-bordered textarea-sm leading-snug">{note}</div></div>
</div></div>

<div class="flex gap-2 items-center">
<button type="button" id="save-quote" class="btn btn-primary">Save Quotation</button>
<button type="button" id="save-preview" class="btn btn-outline">Save &amp; Preview</button>
<a href="{cancel_url}" class="btn btn-ghost">Cancel</a>
<span id="save-err" class="text-error text-sm"></span>
</div>

<script type="application/json" id="prod-data">{products}</script>
<script type="application/json" id="tax-data">{taxes}</script>
<script type="application/json" id="line-data">{lines}</script>
<script type="application/json" id="cust-data">{cust}</script>
<script type="application/json" id="uom-data">{uoms}</script>
<script type="application/json" id="tpl-data">{templates}</script>
<script>{rt_js}</script>
<script>{script}</script>
</div>"##,
        cancel_url = esc(cancel_url),
        heading = esc(heading),
        customers = customers_sel,
        currencies = currencies_sel,
        locations = locations_sel,
        payment_terms = payment_terms_sel,
        order_date = esc(order_date),
        expected_date = esc(expected_date),
        validity_date = esc(validity_date),
        title = crate::richtext::sanitize_rich(title),
        summary = crate::richtext::sanitize_rich(summary),
        note = crate::richtext::sanitize_rich(note),
        products = products_json,
        taxes = taxes_json,
        lines = lines_json,
        cust = customers_json,
        uoms = uoms_json,
        templates = templates_json,
        gd_none = gd_sel(""),
        gd_pct = gd_sel("percent"),
        gd_fix = gd_sel("fixed"),
        gd_value = esc(gd_value),
        gd_hide = if gd_type.is_empty() { "hidden" } else { "" },
        rt_head = RICH_TEXT_HEAD,
        rt_toolbar = RICH_TOOLBAR_HTML,
        rt_js = RICH_TEXT_JS,
        script = script,
    )
}

/// Shared `<style>` for the WYSIWYG rich-text fields — used by both the quote
/// editor and the note-template editor so contenteditable fields + inserted
/// tables render identically everywhere.
const RICH_TEXT_HEAD: &str = r#"<style>
.rt-field{ min-height:1.9rem; }
.rt-field:empty:before{ content:attr(data-ph); color:#9ca3af; pointer-events:none; }
.rt-field:focus{ outline:2px solid hsl(var(--p)/.4); outline-offset:1px; }
.rt-field table{ border-collapse:collapse; width:100%; }
.rt-field td, .rt-field th{ border:1px solid #ccc; padding:4px 6px; min-width:2rem; }
</style>"#;

/// The shared rich-text toolbar markup (formatting + table builder). Reused by
/// every page that hosts `.rt-field` contenteditable fields.
const RICH_TOOLBAR_HTML: &str = r##"<div id="rt-toolbar" class="sticky top-0 z-20 flex flex-wrap items-center gap-1 bg-base-100 border border-base-300 rounded px-2 py-1 mb-3 shadow-sm">
<button type="button" data-cmd="bold" class="btn btn-ghost btn-xs font-bold w-8" title="Bold">B</button>
<button type="button" data-cmd="italic" class="btn btn-ghost btn-xs italic w-8" title="Italic">I</button>
<button type="button" data-cmd="underline" class="btn btn-ghost btn-xs underline w-8" title="Underline">U</button>
<span class="mx-1 text-base-content/20">|</span>
<select id="rt-size" class="select select-bordered select-xs" title="Font size">
<option value="">Size</option><option value="2">Small</option><option value="3">Normal</option><option value="5">Large</option><option value="6">Huge</option>
</select>
<label class="flex items-center gap-1 text-xs cursor-pointer" title="Text colour">
<span>Colour</span>
<input type="color" id="rt-color" value="#111827" class="w-7 h-6 p-0 border border-base-300 rounded bg-base-100"/>
</label>
<button type="button" id="rt-clear" class="btn btn-ghost btn-xs" title="Clear formatting">Clear</button>
<span class="mx-1 text-base-content/20">|</span>
<button type="button" data-tbl="insert" class="btn btn-ghost btn-xs" title="Insert a table">⊞ Table</button>
<button type="button" data-tbl="row+" class="btn btn-ghost btn-xs" title="Add row">+Row</button>
<button type="button" data-tbl="col+" class="btn btn-ghost btn-xs" title="Add column">+Col</button>
<button type="button" data-tbl="row-" class="btn btn-ghost btn-xs" title="Delete row">−Row</button>
<button type="button" data-tbl="col-" class="btn btn-ghost btn-xs" title="Delete column">−Col</button>
<span class="text-xs text-base-content/40 ml-auto hidden sm:inline">Select text, then format</span>
</div>"##;

/// Self-contained toolbar client: wires `#rt-toolbar` to `document.execCommand`
/// (bold/italic/underline/size/colour/clear) and DOM table operations, acting
/// on whichever `.rt-field` holds the caret. Include once per page that renders
/// [`RICH_TOOLBAR_HTML`]. Formatting is sanitized server-side on save.
const RICH_TEXT_JS: &str = r#"
(function(){
  var tb=document.getElementById('rt-toolbar'); if(!tb) return;
  var savedRange=null;
  document.addEventListener('selectionchange', function(){
    var s=window.getSelection(); if(!s.rangeCount) return;
    var r=s.getRangeAt(0), n=r.commonAncestorContainer, el=n.nodeType===1?n:n.parentNode;
    if(el && el.closest && el.closest('.rt-field')) savedRange=r.cloneRange();
  });
  function restore(){ if(savedRange){ var s=window.getSelection(); s.removeAllRanges(); s.addRange(savedRange); } }
  function cmd(c, v){
    try{ document.execCommand('styleWithCSS', false, true); }catch(_){}
    document.execCommand(c, false, v===undefined?null:v);
  }
  tb.querySelectorAll('button[data-cmd]').forEach(function(b){
    b.addEventListener('mousedown', function(e){ e.preventDefault(); cmd(b.dataset.cmd); });
  });
  var sz=document.getElementById('rt-size');
  if(sz) sz.addEventListener('change', function(){ if(sz.value){ restore(); cmd('fontSize', sz.value); sz.selectedIndex=0; } });
  var col=document.getElementById('rt-color');
  if(col) col.addEventListener('input', function(){ restore(); cmd('foreColor', col.value); });
  var clr=document.getElementById('rt-clear');
  if(clr) clr.addEventListener('mousedown', function(e){ e.preventDefault(); cmd('removeFormat'); });

  // ---- table builder ----
  var CELL='border:1px solid #ccc;padding:4px 6px';
  function newCell(){ var td=document.createElement('td'); td.setAttribute('style', CELL); td.innerHTML='<br>'; return td; }
  function curCell(){ if(!savedRange) return null; var n=savedRange.commonAncestorContainer; var e=n.nodeType===1?n:n.parentNode; return e&&e.closest?e.closest('td,th'):null; }
  function insertTable(){
    restore();
    var c='<td style="'+CELL+'"><br></td>';
    var html='<table style="border-collapse:collapse;width:100%"><tbody><tr>'+c+c+'</tr><tr>'+c+c+'</tr></tbody></table><p><br></p>';
    document.execCommand('insertHTML', false, html);
  }
  function rowAdd(){ var c=curCell(); if(!c) return; var tr=c.closest('tr'); var nr=document.createElement('tr'); for(var i=0;i<tr.children.length;i++) nr.appendChild(newCell()); tr.parentNode.insertBefore(nr, tr.nextSibling); }
  function colAdd(){ var c=curCell(); if(!c) return; var idx=Array.prototype.indexOf.call(c.parentNode.children,c); c.closest('table').querySelectorAll('tr').forEach(function(tr){ var ref=tr.children[idx]; var cell=newCell(); if(ref) tr.insertBefore(cell, ref.nextSibling); else tr.appendChild(cell); }); }
  function rowDel(){ var c=curCell(); if(!c) return; var tbl=c.closest('table'); if(tbl.querySelectorAll('tr').length>1) c.closest('tr').remove(); }
  function colDel(){ var c=curCell(); if(!c) return; var idx=Array.prototype.indexOf.call(c.parentNode.children,c); var rows=c.closest('table').querySelectorAll('tr'); if(rows[0].children.length<=1) return; rows.forEach(function(tr){ if(tr.children[idx]) tr.children[idx].remove(); }); }
  var TBL={ 'insert':insertTable, 'row+':rowAdd, 'col+':colAdd, 'row-':rowDel, 'col-':colDel };
  tb.querySelectorAll('button[data-tbl]').forEach(function(b){
    b.addEventListener('mousedown', function(e){ e.preventDefault(); var f=TBL[b.dataset.tbl]; if(f) f(); });
  });
})();
"#;

/// Reactive line-grid client for the quote editor. Builds product/tax
/// dropdowns from the embedded JSON, autofills on product select, keeps line
/// amounts and the subtotal/tax/total live, and POSTs the whole quote as JSON.
/// `__ACTION__` is replaced with the save endpoint.
const QUOTE_EDITOR_JS: &str = r#"
(function(){
  var PRODUCTS = JSON.parse(document.getElementById('prod-data').textContent || '[]');
  var TAXES    = JSON.parse(document.getElementById('tax-data').textContent || '[]');
  var LINES    = JSON.parse(document.getElementById('line-data').textContent || '[]');
  var CUSTS    = JSON.parse((document.getElementById('cust-data')||{}).textContent || '[]');
  var UOMS     = JSON.parse((document.getElementById('uom-data')||{}).textContent || '[]');
  var TEMPLATES= JSON.parse((document.getElementById('tpl-data')||{}).textContent || '[]');
  var ACTION   = '__ACTION__';
  var body = document.getElementById('lines-body');
  var prodById = {}; PRODUCTS.forEach(function(p){ prodById[p.id]=p; });
  var taxById  = {}; TAXES.forEach(function(t){ taxById[t.id]=t; });
  var custById = {}; CUSTS.forEach(function(c){ custById[c.id]=c; });

  function esc(x){ return String(x==null?'':x).replace(/[&<>"]/g,function(c){
    return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]; }); }
  function num(v){ var n=parseFloat(v); return isFinite(n)?n:0; }
  function prodLabel(p){ return p?(p.code+' · '+p.name):''; }
  // Rich-text field accessors (contenteditable divs vs plain inputs).
  function rtGet(el){ if(!el) return ''; return el.isContentEditable ? el.innerHTML : el.value; }
  function rtSet(el, html){ if(!el) return; if(el.isContentEditable) el.innerHTML = html||''; else el.value = html||''; }
  function rtSetText(el, txt){ if(!el) return; if(el.isContentEditable) el.textContent = txt||''; else el.value = txt||''; }

  function taxOptions(sel){
    var s='<option value="">— no tax —</option>';
    TAXES.forEach(function(t){
      s+='<option value="'+t.id+'"'+(t.id===sel?' selected':'')+'>'+esc(t.name)+'</option>';
    });
    return s;
  }
  function uomOptions(sel){
    var s='<option value="">—</option>';
    UOMS.forEach(function(u){
      s+='<option value="'+u.id+'"'+(u.id===sel?' selected':'')+'>'+esc(u.code)+'</option>';
    });
    return s;
  }
  function currencyCode(){
    var sel=document.getElementById('f-currency');
    if(!sel || sel.selectedIndex<0) return '';
    var t=sel.options[sel.selectedIndex].text||'';
    return (t.split('—')[0].trim().split(/\s+/)[0])||'';
  }

  // ---- drag-to-reorder (pointer events → works with touch AND mouse) ----
  var dragRow=null, dragPid=null;
  function attachDrag(row){
    var h=row.querySelector('.l-drag');
    if(!h) return;
    h.addEventListener('pointerdown', function(e){
      e.preventDefault();
      dragRow=row; dragPid=e.pointerId;
      row.classList.add('opacity-40','ring','ring-primary/40');
      try{ h.setPointerCapture(e.pointerId); }catch(_){}
    });
    h.addEventListener('pointermove', function(e){
      if(!dragRow) return;
      e.preventDefault();
      var el=document.elementFromPoint(e.clientX, e.clientY);
      var tgt=el && el.closest ? el.closest('.qline') : null;
      if(!tgt || tgt===dragRow || tgt.parentNode!==body) return;
      var rect=tgt.getBoundingClientRect();
      var before=(e.clientY - rect.top) < rect.height/2;
      body.insertBefore(dragRow, before?tgt:tgt.nextSibling);
    });
    function end(){
      if(dragRow){ dragRow.classList.remove('opacity-40','ring','ring-primary/40'); }
      try{ if(dragPid!=null) h.releasePointerCapture(dragPid); }catch(_){}
      dragRow=null; dragPid=null; recalc();
    }
    h.addEventListener('pointerup', end);
    h.addEventListener('pointercancel', end);
  }

  // ---- product typeahead (client-side; the full product list is embedded) ----
  // Replaces the old giant <select> so a user with thousands of products can
  // just type "cable" and pick, keyboard-only.
  function filterProducts(q){
    q=(q||'').trim().toLowerCase();
    var out=[];
    for(var i=0;i<PRODUCTS.length && out.length<60;i++){
      var p=PRODUCTS[i];
      if(!q || (p.code+' '+p.name).toLowerCase().indexOf(q)>=0) out.push(p);
    }
    return out;
  }
  function selectProduct(row, id){
    var p=prodById[id]; if(!p) return;
    row.querySelector('.l-prod').value=id;
    row.querySelector('.l-prod-search').value=prodLabel(p);
    // Only overwrite fields the user hasn't already typed into.
    var desc=row.querySelector('.l-desc'); if(!rtGet(desc).trim()) rtSetText(desc, p.description||'');
    var price=row.querySelector('.l-price'); if(!price.value) price.value=p.unit_price||'';
    if(p.tax_id) row.querySelector('.l-tax').value=p.tax_id;
    row.dataset.cls=p.classification_code||'';
    // Default the unit to the product's, unless the user already picked one.
    var uom=row.querySelector('.l-uom'); if(uom && !uom.value && p.uom_id) uom.value=p.uom_id;
    closeProdMenu(row);
    recalc();
    // Xero-style: filling the last row spawns a fresh one so entry keeps flowing.
    if(row===body.lastElementChild){ var nr=addRow({}); var ns=nr.querySelector('.l-prod-search'); if(ns) ns.focus(); }
    else { var q=row.querySelector('.l-qty'); if(q) q.focus(); }
  }
  function closeProdMenu(row){
    var m=row.querySelector('.l-prod-menu'); if(m){ m.classList.add('hidden'); m.innerHTML=''; }
  }
  function renderProdMenu(row){
    var m=row.querySelector('.l-prod-menu');
    var q=row.querySelector('.l-prod-search').value;
    var list=filterProducts(q);
    if(!list.length){ m.innerHTML='<div class="px-2 py-1 text-base-content/50">No match</div>'; m.classList.remove('hidden'); return; }
    m.innerHTML=list.map(function(p,i){
      return '<div class="l-opt px-2 py-1 cursor-pointer hover:bg-base-200'+(i===0?' bg-base-200':'')+'" data-id="'+esc(p.id)+'">'+esc(prodLabel(p))+'</div>';
    }).join('');
    m.classList.remove('hidden');
  }
  function moveHighlight(m, dir){
    var opts=m.querySelectorAll('.l-opt'); if(!opts.length) return;
    var cur=-1; for(var i=0;i<opts.length;i++){ if(opts[i].classList.contains('bg-base-200')){ cur=i; break; } }
    if(cur>=0) opts[cur].classList.remove('bg-base-200');
    var nx=(cur+dir+opts.length)%opts.length;
    opts[nx].classList.add('bg-base-200');
    opts[nx].scrollIntoView({block:'nearest'});
  }
  function attachProdCombo(row){
    var inp=row.querySelector('.l-prod-search');
    var menu=row.querySelector('.l-prod-menu');
    inp.addEventListener('focus', function(){ renderProdMenu(row); });
    inp.addEventListener('input', function(){ row.querySelector('.l-prod').value=''; renderProdMenu(row); });
    inp.addEventListener('blur', function(){ setTimeout(function(){ closeProdMenu(row); }, 150); });
    inp.addEventListener('keydown', function(e){
      if(e.key==='ArrowDown'){ e.preventDefault(); if(menu.classList.contains('hidden')) renderProdMenu(row); else moveHighlight(menu,1); }
      else if(e.key==='ArrowUp'){ e.preventDefault(); moveHighlight(menu,-1); }
      else if(e.key==='Enter'){ var h=menu.querySelector('.l-opt.bg-base-200'); if(h){ e.preventDefault(); selectProduct(row, h.dataset.id); } }
      else if(e.key==='Escape'){ closeProdMenu(row); }
    });
    menu.addEventListener('mousedown', function(e){
      var opt=e.target.closest?e.target.closest('.l-opt'):null;
      if(opt){ e.preventDefault(); selectProduct(row, opt.dataset.id); }
    });
  }

  // On phones each line is a bordered card (clear separation); on >=sm it
  // collapses back to a single flat table-style row.
  var ROW='qline flex flex-wrap items-center gap-2 border border-base-300 rounded-lg p-3 mb-3 sm:border-0 sm:border-b sm:border-base-200 sm:rounded-none sm:p-0 sm:py-2 sm:mb-0';
  function addRow(d){
    d=d||{};
    var kind=(d.display_type==='section'||d.display_type==='note')?d.display_type:'line';
    var row=document.createElement('div');
    row.className=ROW+(kind==='section'?' bg-base-200/50':'');
    row.dataset.kind=kind;
    var drag='<span class="l-drag select-none text-lg leading-none text-base-content/40 w-5 text-center shrink-0" title="Drag to reorder" style="cursor:grab;touch-action:none">⠿</span>';
    var del='<button type="button" class="btn btn-ghost btn-xs text-error l-del ml-auto sm:ml-0 sm:w-6" title="Remove">✕</button>';
    if(kind==='line'){
      row.innerHTML= drag+
        '<div class="l-prod-wrap relative w-full sm:w-44">'+
          '<input type="text" autocomplete="off" class="input input-bordered input-xs w-full l-prod-search" placeholder="Search product…"/>'+
          '<input type="hidden" class="l-prod"/>'+
          '<div class="l-prod-menu hidden absolute z-30 mt-1 w-64 max-h-60 overflow-auto bg-base-100 border border-base-300 rounded shadow text-xs"></div>'+
        '</div>'+
        '<div contenteditable="true" data-ph="Description" class="l-desc rt-field textarea textarea-bordered textarea-xs w-full sm:flex-1 sm:w-auto leading-snug"></div>'+
        '<input type="number" step="0.0001" min="0" class="input input-bordered input-xs w-16 text-right l-qty" placeholder="Qty"/>'+
        '<select class="select select-bordered select-xs w-20 l-uom" title="Unit of measure">'+uomOptions(d.uom_id)+'</select>'+
        '<input type="number" step="0.0001" min="0" class="input input-bordered input-xs w-24 text-right l-price" placeholder="Price"/>'+
        '<input type="number" step="0.01" min="0" max="100" class="input input-bordered input-xs w-16 text-right l-disc" placeholder="Disc%"/>'+
        '<select class="select select-bordered select-xs w-28 l-tax">'+taxOptions(d.tax_id)+'</select>'+
        '<span class="font-mono text-right w-24 l-amt">0.00</span>'+del;
      body.appendChild(row);
      rtSet(row.querySelector('.l-desc'), d.description!=null?d.description:'');
      row.querySelector('.l-qty').value  = d.quantity!=null?d.quantity:'1';
      row.querySelector('.l-price').value= d.unit_price!=null?d.unit_price:'';
      row.querySelector('.l-disc').value = d.discount_percent!=null?d.discount_percent:'0';
      row.dataset.cls = d.classification_code||'';
      // Seed a pre-selected product (edit mode) into the typeahead.
      if(d.product_id && prodById[d.product_id]){
        var sp=prodById[d.product_id];
        row.querySelector('.l-prod').value=d.product_id;
        row.querySelector('.l-prod-search').value=prodLabel(sp);
        // Fall back to the product's own unit when the line stored none.
        var uu=row.querySelector('.l-uom'); if(!uu.value && sp.uom_id) uu.value=sp.uom_id;
      }
      attachProdCombo(row);
    } else {
      var field = kind==='section'
        ? '<input type="text" class="input input-bordered input-xs flex-1 font-semibold l-text" placeholder="Section name (e.g. Phase 1 — Materials)"/>'
        : '<textarea rows="1" class="textarea textarea-bordered textarea-xs flex-1 italic leading-snug l-text" placeholder="Note shown to the customer"></textarea>';
      row.innerHTML= drag+field+del;
      body.appendChild(row);
      row.querySelector('.l-text').value = d.description!=null?d.description:'';
    }
    row.querySelectorAll('input,textarea,select').forEach(function(el){
      el.addEventListener('input', recalc); el.addEventListener('change', recalc);
    });
    row.querySelector('.l-del').addEventListener('click', function(){ row.remove(); recalc(); });
    attachDrag(row);
    recalc();
    return row;
  }

  // Whole-quote discount factor (mirrors the server): a single uniform scale
  // applied to every line's net. `netSum` is only needed for a fixed amount.
  function globalFactor(netSum){
    var gt=document.getElementById('f-gdtype'); if(!gt) return 1;
    var t=gt.value, v=num((document.getElementById('f-gdval')||{}).value);
    if(t==='percent') return Math.max(0,(100-Math.min(v,100))/100);
    if(t==='fixed' && netSum>0) return Math.max(0,(netSum-Math.min(v,netSum))/netSum);
    return 1;
  }
  function recalc(){
    var rows=[], netSum=0;
    body.querySelectorAll('.qline').forEach(function(tr){
      if(tr.dataset.kind!=='line') return; // sections / notes carry no money
      var qty=num(tr.querySelector('.l-qty').value);
      var price=num(tr.querySelector('.l-price').value);
      var disc=num(tr.querySelector('.l-disc').value);
      var net=qty*price*(1-disc/100);
      tr.querySelector('.l-amt').textContent=net.toFixed(2);
      rows.push({net:net, t:taxById[tr.querySelector('.l-tax').value]});
      netSum+=net;
    });
    var factor=globalFactor(netSum);
    var subPre=0, base=0, taxT=0;
    rows.forEach(function(r){
      var t=r.t, a=t?num(t.amount):0, dnet=r.net*factor;
      if(t && t.amount_type==='fixed'){ subPre+=r.net; base+=dnet; taxT+=a; }
      else if(t && t.price_include){ subPre+=r.net/(1+a/100); base+=dnet/(1+a/100); taxT+=dnet-dnet/(1+a/100); }
      else { subPre+=r.net; base+=dnet; taxT+=(t?dnet*a/100:0); }
    });
    var disc=subPre-base; if(disc<0) disc=0;
    var cur=currencyCode();
    document.getElementById('sum-sub').textContent=subPre.toFixed(2);
    document.getElementById('sum-disc').textContent=disc.toFixed(2);
    document.getElementById('disc-row').style.display = disc>0 ? '' : 'none';
    document.getElementById('sum-tax').textContent=taxT.toFixed(2);
    document.getElementById('sum-tot').textContent=(base+taxT).toFixed(2);
    document.querySelectorAll('.sum-cur').forEach(function(e){ e.textContent=cur; });
  }
  // Discount controls: toggle the amount field + recompute.
  (function(){
    var gt=document.getElementById('f-gdtype'), gv=document.getElementById('f-gdval');
    if(!gt||!gv) return;
    function sync(){ if(gt.value){ gv.classList.remove('hidden'); } else { gv.classList.add('hidden'); } recalc(); }
    gt.addEventListener('change', sync); gv.addEventListener('input', recalc);
  })();

  document.getElementById('add-line').addEventListener('click', function(){ var r=addRow({}); r.querySelector('.l-prod-search').focus(); });
  document.getElementById('add-section').addEventListener('click', function(){ addRow({display_type:'section'}); });
  document.getElementById('add-note').addEventListener('click', function(){ addRow({display_type:'note'}); });
  var curSel=document.getElementById('f-currency'); if(curSel) curSel.addEventListener('change', recalc);
  if(LINES.length){ LINES.forEach(addRow); } else { addRow({}); }

  // ---- customer context (address + credit limit shown on pick) ----
  var custSel=document.getElementById('f-customer');
  var custCtx=document.getElementById('cust-ctx');
  var ptSel=document.getElementById('f-payment-term');
  function showCust(){
    if(!custSel||!custCtx) return;
    var c=custById[custSel.value];
    if(!c || (!c.address && !c.credit_limit)){ custCtx.classList.add('hidden'); custCtx.innerHTML=''; return; }
    var bits=[];
    if(c.address) bits.push('📍 '+esc(c.address));
    if(c.credit_limit) bits.push('💳 Credit limit '+esc(c.credit_limit));
    custCtx.innerHTML=bits.join('<br>');
    custCtx.classList.remove('hidden');
  }
  // On picking a customer, default the payment terms to their master default.
  // Only on an explicit change — so editing an existing quote keeps its own
  // saved term (which is pre-selected server-side) until the customer changes.
  function applyCustDefaults(){
    var c=custById[custSel.value];
    if(c && ptSel && c.payment_term_id){ ptSel.value=c.payment_term_id; }
  }
  if(custSel){
    custSel.addEventListener('change', function(){ showCust(); applyCustDefaults(); });
    showCust();
  }

  // ---- Notes/Terms template picker (copy-on-insert; never mutates template) ----
  (function(){
    var sel=document.getElementById('f-note-template'), note=document.getElementById('f-note');
    if(!sel||!note) return;
    var tplById={};
    var opts='<option value="">— choose —</option>';
    TEMPLATES.forEach(function(t){ tplById[t.id]=t; opts+='<option value="'+esc(t.id)+'">'+esc(t.name)+'</option>'; });
    sel.innerHTML=opts;
    if(!TEMPLATES.length){ sel.disabled=true; sel.title='No templates yet — create them under Sales ▸ Configuration ▸ Terms Templates'; }
    sel.addEventListener('change', function(){
      var t=tplById[sel.value]; sel.selectedIndex=0;
      if(!t) return;
      var cur=note.innerHTML.replace(/<br\s*\/?>|\s|&nbsp;/gi,'');
      if(cur && !window.confirm('Replace the current Notes / Terms with the "'+t.name+'" template?')) return;
      note.innerHTML=t.body||'';
    });
  })();

  function val(id){ var e=document.getElementById(id); return e?e.value:''; }
  function rval(id){ var e=document.getElementById(id); return e ? (e.isContentEditable ? e.innerHTML : e.value) : ''; }

  // The rich-text toolbar itself is wired by the shared RICH_TEXT_JS component.
  // Title is single-line: swallow Enter so it can't become multi-paragraph.
  (function(){ var t=document.getElementById('f-title'); if(t) t.addEventListener('keydown', function(e){ if(e.key==='Enter') e.preventDefault(); }); })();

  var btn=document.getElementById('save-quote');
  var pbtn=document.getElementById('save-preview');
  function reset(){ btn.disabled=false; btn.textContent='Save Quotation'; if(pbtn){ pbtn.disabled=false; pbtn.textContent='Save & Preview'; } }
  function doSave(preview){
    var err=document.getElementById('save-err'); err.textContent='';
    var lines=[], productLines=0, zeroPrice=0;
    body.querySelectorAll('.qline').forEach(function(tr){
      if(tr.dataset.kind==='section' || tr.dataset.kind==='note'){
        var text=tr.querySelector('.l-text').value;
        if(!text) return;
        lines.push({ display_type: tr.dataset.kind, description: text });
        return;
      }
      var pid=tr.querySelector('.l-prod').value;
      if(!pid) return;
      productLines++;
      if(num(tr.querySelector('.l-price').value)<=0) zeroPrice++;
      lines.push({
        product_id: pid,
        description: rtGet(tr.querySelector('.l-desc')),
        quantity: tr.querySelector('.l-qty').value,
        unit_price: tr.querySelector('.l-price').value,
        discount_percent: tr.querySelector('.l-disc').value,
        tax_id: tr.querySelector('.l-tax').value||null,
        uom_id: tr.querySelector('.l-uom').value||null,
        classification_code: tr.dataset.cls||null
      });
    });
    // Client-side guards — catch the common "sent an empty/zero quote" mistakes.
    if(!val('f-customer')){ err.textContent='Choose a customer first.'; return; }
    if(productLines===0){ err.textContent='Add at least one product line before saving.'; return; }
    if(zeroPrice>0 && !window.confirm(zeroPrice+' line'+(zeroPrice>1?'s have':' has')+' no price. Save anyway?')) return;
    var payload={
      customer_id: val('f-customer')||null,
      order_date: val('f-order-date')||null,
      expected_date: val('f-expected')||null,
      validity_date: val('f-validity')||null,
      currency_id: val('f-currency')||null,
      source_location_id: val('f-location')||null,
      payment_term_id: val('f-payment-term')||null,
      title: rval('f-title')||null,
      summary: rval('f-summary')||null,
      note: rval('f-note')||null,
      global_discount_type: val('f-gdtype')||null,
      global_discount_value: val('f-gdval')||null,
      lines: lines
    };
    btn.disabled=true; btn.textContent='Saving…'; if(pbtn){ pbtn.disabled=true; }
    DIRTY=false; // saving — don't warn on the resulting navigation
    fetch(ACTION,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(payload)})
      .then(function(r){ return r.json().then(function(j){ return {ok:r.ok,j:j}; }); })
      .then(function(res){
        if(res.ok && res.j && res.j.redirect){
          // Preview: land on the branded printable quote; else the record.
          window.location = preview ? (res.j.redirect + '/print-quote') : res.j.redirect;
          return;
        }
        DIRTY=true;
        err.textContent=(res.j && res.j.error)||'Save failed.'; reset();
      })
      .catch(function(){ DIRTY=true; err.textContent='Network error.'; reset(); });
  }
  btn.addEventListener('click', function(){ doSave(false); });
  if(pbtn){ pbtn.addEventListener('click', function(){ doSave(true); }); }
  // Ctrl/Cmd+Enter saves from anywhere in the editor.
  document.addEventListener('keydown', function(e){
    if((e.ctrlKey||e.metaKey) && e.key==='Enter'){ e.preventDefault(); doSave(false); }
  });

  // ---- unsaved-changes guard ----
  var DIRTY=false;
  document.addEventListener('input', function(){ DIRTY=true; }, true);
  document.addEventListener('change', function(){ DIRTY=true; }, true);
  window.addEventListener('beforeunload', function(e){
    if(DIRTY){ e.preventDefault(); e.returnValue=''; return ''; }
  });
})();
"#;

async fn new_order_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let customers = customer_options(&db, None).await;
    let locations = location_options(&db, None).await;
    // Preselect the company's base currency so it isn't left blank.
    let base_currency = company_currency_id(&db).await;
    let currencies = currency_options(&db, base_currency).await;
    let payment_terms =
        vortex_accounting::handlers_payment_terms::payment_term_options(&db, None).await;
    let products = products_json(&db).await;
    let taxes = taxes_json(&db).await;
    let cust_ctx = customers_json(&db).await;
    let uoms = uoms_json(&db).await;
    let templates = note_templates_json(&db).await;

    // Sensible date defaults: quote dated today, valid for 30 days — so the
    // expiry sweep has something to act on and the user rarely has to touch them.
    let today = vortex_plugin_sdk::chrono::Local::now().date_naive();
    let order_date = today.format("%Y-%m-%d").to_string();
    let validity_date = (today + vortex_plugin_sdk::chrono::Duration::days(30))
        .format("%Y-%m-%d")
        .to_string();

    let content = render_quote_editor(
        "New Quotation",
        "/sales/orders/create",
        "/sales/quotes",
        &customers,
        &locations,
        &currencies,
        &payment_terms,
        &order_date,
        "",
        &validity_date,
        "",
        "",
        "",
        &products,
        &taxes,
        "[]",
        &cust_ctx,
        &uoms,
        &templates,
        "",
        "",
    );

    Html(page_shell(&sidebar, "New Quotation", &content)).into_response()
}

/// JSON `{redirect}` on success, `(status, {error})` otherwise.
fn json_redirect(url: String) -> Response {
    vortex_plugin_sdk::axum::Json(json!({ "redirect": url })).into_response()
}
fn json_err(code: vortex_plugin_sdk::axum::http::StatusCode, msg: &str) -> Response {
    (code, vortex_plugin_sdk::axum::Json(json!({ "error": msg }))).into_response()
}

async fn create_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::Json(payload): vortex_plugin_sdk::axum::Json<QuotePayload>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let Some(customer_id) = u_opt(&payload.customer_id) else {
        return json_err(StatusCode::BAD_REQUEST, "Customer is required");
    };

    // Every sale starts life as a quotation: QT number now, SO number
    // only at confirmation.
    let quote_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &QT_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "QT sequence generation failed");
            return json_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate quotation number");
        }
    };
    let company_id = default_company(&db).await;

    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        s_opt(&payload.order_date).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        s_opt(&payload.expected_date).and_then(|s| s.parse().ok());
    // Default validity: 30 days from today.
    let validity_date: vortex_plugin_sdk::chrono::NaiveDate = s_opt(&payload.validity_date)
        .and_then(|v| v.parse().ok())
        .unwrap_or_else(|| {
            vortex_plugin_sdk::chrono::Utc::now().date_naive()
                + vortex_plugin_sdk::chrono::Duration::days(30)
        });

    let (gd_type, gd_value) = parse_global_discount(&payload);

    let order_id = Uuid::now_v7();
    // order_date column defaults to CURRENT_DATE; pass COALESCE via Option.
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_order \
         (id, quote_number, revision, root_quote_id, validity_date, customer_id, order_date, \
          expected_date, currency_id, source_location_id, note, title, summary, \
          global_discount_type, global_discount_value, company_id, created_by, payment_term_id) \
         VALUES ($1,$2,1,$1,$3,$4,COALESCE($5, CURRENT_DATE),$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
    )
    .bind(order_id)
    .bind(&quote_number)
    .bind(validity_date)
    .bind(customer_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(u_opt(&payload.currency_id))
    .bind(u_opt(&payload.source_location_id))
    .bind(rich_opt(&payload.note))
    .bind(rich_opt(&payload.title))
    .bind(rich_opt(&payload.summary))
    .bind(&gd_type)
    .bind(gd_value)
    .bind(company_id)
    .bind(user.id)
    .bind(u_opt(&payload.payment_term_id))
    .execute(&db)
    .await;

    if let Err(e) = res {
        error!(error = %e, "quotation insert failed");
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to create quotation");
    }

    insert_quote_lines(&db, order_id, company_id, &payload.lines).await;
    recompute_totals(&db, order_id).await;

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
    json_redirect(format!("/sales/orders/{order_id}"))
}

/// GET the inline editor pre-populated for an existing **draft** quotation.
/// Non-draft quotations are read-only, so this redirects to the record view.
async fn edit_quote_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT state, customer_id, order_date::text AS order_date, \
                expected_date::text AS expected_date, validity_date::text AS validity_date, \
                currency_id, source_location_id, payment_term_id, title, summary, note, \
                global_discount_type, \
                CASE WHEN global_discount_value > 0 THEN global_discount_value::text ELSE '' END AS global_discount_value \
         FROM sales_order WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Quotation not found").into_response();
    };
    let po_state: String = row.get("state");
    if po_state != "quotation" {
        return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/sales/orders/{id}")).into_response();
    }
    let customer_id: Option<Uuid> = row.try_get("customer_id").ok();
    let currency_id: Option<Uuid> = row.try_get("currency_id").ok().flatten();
    let source_location_id: Option<Uuid> = row.try_get("source_location_id").ok().flatten();
    let payment_term_id: Option<Uuid> = row.try_get("payment_term_id").ok().flatten();

    let customers = customer_options(&db, customer_id).await;
    let locations = location_options(&db, source_location_id).await;
    let currencies = currency_options(&db, currency_id).await;
    let payment_terms =
        vortex_accounting::handlers_payment_terms::payment_term_options(&db, payment_term_id).await;
    let products = products_json(&db).await;
    let taxes = taxes_json(&db).await;
    let cust_ctx = customers_json(&db).await;
    let uoms = uoms_json(&db).await;
    let templates = note_templates_json(&db).await;

    // Existing lines → JSON rows for the grid to seed.
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT product_id, description, quantity, unit_price, discount_percent, \
                tax_id, classification_code, display_type, uom_id \
         FROM sales_order_line WHERE order_id = $1 ORDER BY sequence, created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let lines_arr: Vec<serde_json::Value> = line_rows
        .iter()
        .map(|r| {
            let display_type: Option<String> = r.try_get("display_type").ok().flatten();
            if let Some(dt) = display_type {
                // Section / note row — only the kind + its text matter.
                return json!({
                    "display_type": dt,
                    "description": r.try_get::<Option<String>, _>("description").ok().flatten(),
                });
            }
            let pid: Option<Uuid> = r.try_get("product_id").ok().flatten();
            let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ONE);
            let price: Decimal = r.try_get("unit_price").unwrap_or(Decimal::ZERO);
            let disc: Decimal = r.try_get("discount_percent").unwrap_or(Decimal::ZERO);
            json!({
                "product_id": pid.map(|p| p.to_string()),
                "description": r.try_get::<Option<String>, _>("description").ok().flatten(),
                "quantity": qty.normalize().to_string(),
                "unit_price": price.round_dp(4).normalize().to_string(),
                "discount_percent": disc.normalize().to_string(),
                "tax_id": r.try_get::<Option<Uuid>, _>("tax_id").ok().flatten().map(|t| t.to_string()),
                "classification_code": r.try_get::<Option<String>, _>("classification_code").ok().flatten(),
                "uom_id": r.try_get::<Option<Uuid>, _>("uom_id").ok().flatten().map(|u| u.to_string()),
            })
        })
        .collect();
    let lines_json = serde_json::to_string(&lines_arr).unwrap_or_else(|_| "[]".into());

    let get = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let content = render_quote_editor(
        "Edit Quotation",
        &format!("/sales/orders/{id}/save"),
        &format!("/sales/orders/{id}"),
        &customers,
        &locations,
        &currencies,
        &payment_terms,
        &get("order_date"),
        &get("expected_date"),
        &get("validity_date"),
        &get("title"),
        &get("summary"),
        &get("note"),
        &products,
        &taxes,
        &lines_json,
        &cust_ctx,
        &uoms,
        &templates,
        &get("global_discount_type"),
        &get("global_discount_value"),
    );
    Html(page_shell(&sidebar, "Edit Quotation", &content)).into_response()
}

/// POST the edited draft quotation (JSON): replace header + lines wholesale.
async fn save_quote(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::Json(payload): vortex_plugin_sdk::axum::Json<QuotePayload>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    if !is_state(&db, id, "quotation").await {
        return json_err(StatusCode::CONFLICT, "Only open quotations can be edited");
    }
    let Some(customer_id) = u_opt(&payload.customer_id) else {
        return json_err(StatusCode::BAD_REQUEST, "Customer is required");
    };

    // Snapshot BEFORE mutating so we can diff header + line items for history.
    let hdr_before = quote_header_snapshot(&db, id).await;
    let lines_before = quote_line_snapshot(&db, id).await;

    let order_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        s_opt(&payload.order_date).and_then(|s| s.parse().ok());
    let expected_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        s_opt(&payload.expected_date).and_then(|s| s.parse().ok());
    let validity_date: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        s_opt(&payload.validity_date).and_then(|s| s.parse().ok());

    let (gd_type, gd_value) = parse_global_discount(&payload);

    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_order SET customer_id = $2, \
            order_date = COALESCE($3, order_date), expected_date = $4, \
            validity_date = COALESCE($5, validity_date), currency_id = $6, \
            source_location_id = $7, note = $8, title = $9, summary = $10, \
            global_discount_type = $11, global_discount_value = $12, \
            payment_term_id = $13, updated_at = NOW() \
         WHERE id = $1",
    )
    .bind(id)
    .bind(customer_id)
    .bind(order_date)
    .bind(expected_date)
    .bind(validity_date)
    .bind(u_opt(&payload.currency_id))
    .bind(u_opt(&payload.source_location_id))
    .bind(rich_opt(&payload.note))
    .bind(rich_opt(&payload.title))
    .bind(rich_opt(&payload.summary))
    .bind(&gd_type)
    .bind(gd_value)
    .bind(u_opt(&payload.payment_term_id))
    .execute(&db)
    .await;
    if let Err(e) = res {
        error!(error = %e, "quotation header update failed");
        return json_err(StatusCode::INTERNAL_SERVER_ERROR, "Failed to save quotation");
    }

    // Draft lines carry no delivery/invoice history, so a wholesale replace is
    // safe and keeps the grid the single source of truth.
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM sales_order_line WHERE order_id = $1")
        .bind(id)
        .execute(&db)
        .await;
    let company_id = default_company(&db).await;
    insert_quote_lines(&db, id, company_id, &payload.lines).await;
    recompute_totals(&db, id).await;

    // Diff header + line items and record the change set on the history trail.
    let hdr_after = quote_header_snapshot(&db, id).await;
    let lines_after = quote_line_snapshot(&db, id).await;
    let mut changes = diff_header(&hdr_before, &hdr_after);
    changes.extend(diff_lines(&lines_before, &lines_after));
    audit_so_changes(&state, &db_ctx, &db, user.id, &user.username, id, "edited", changes).await;
    json_redirect(format!("/sales/orders/{id}"))
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
                po.title, po.summary, \
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
    let customer_name: String = row.get("customer_name");
    let order_date: Option<String> = row.try_get("order_date").ok();
    let expected_date: Option<String> = row.try_get("expected_date").ok();
    let po_state: String = row.get("state");
    let dest_name: Option<String> = row.try_get("dest_name").ok();
    let currency_code: Option<String> = row.try_get("currency_code").ok();
    let note: Option<String> = row.try_get("note").ok();
    let quote_title: Option<String> = row.try_get("title").ok().flatten();
    let quote_summary: Option<String> = row.try_get("summary").ok().flatten();
    let untaxed: Decimal = row.try_get("untaxed_amount").unwrap_or(Decimal::ZERO);
    let tax: Decimal = row.try_get("tax_amount").unwrap_or(Decimal::ZERO);
    let total: Decimal = row.try_get("total_amount").unwrap_or(Decimal::ZERO);
    let is_draft = po_state == "quotation";
    let is_quote_stage = matches!(po_state.as_str(), "quotation" | "sent" | "superseded" | "lost" | "expired");
    let identity = doc_identity(number.as_deref(), quote_number.as_deref(), revision);
    let cur = currency_code.clone().unwrap_or_default();

    // Whole-quote discount → show Subtotal (pre) + Discount rows above Untaxed.
    let discount_rows = {
        let (gd_type, gd_value) = order_global_discount(&db, id).await;
        if gd_type.is_some() && gd_value > Decimal::ZERO {
            let pre: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT COALESCE(SUM(quantity * unit_price * (100 - discount_percent) / 100), 0) \
                 FROM sales_order_line WHERE order_id = $1 AND display_type IS NULL",
            )
            .bind(id)
            .fetch_one(&db)
            .await
            .unwrap_or(Decimal::ZERO);
            let factor = global_factor(gd_type.as_deref(), gd_value, pre);
            let amt = (pre * (Decimal::ONE - factor)).round_dp(2);
            let label = match gd_type.as_deref() {
                Some("percent") => format!("Discount ({}%)", gd_value.normalize()),
                _ => "Discount".to_string(),
            };
            format!(
                "<tr><td class=\"text-base-content/60 pr-6\">Subtotal</td><td class=\"text-right font-mono\">{pre} {cur}</td></tr>\
                 <tr><td class=\"text-base-content/60 pr-6\">{label}</td><td class=\"text-right font-mono text-error\">- {amt} {cur}</td></tr>",
                pre = money(pre.round_dp(2)),
                label = esc(&label),
                amt = money(amt),
                cur = esc(&cur),
            )
        } else {
            String::new()
        }
    };

    // ── Lines table ──
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, p.code AS product_code, p.name AS product_name, l.description, \
                l.quantity, l.unit_price, l.discount_percent, t.name AS tax_name, \
                l.classification_code, l.qty_delivered, l.qty_invoiced, l.display_type, \
                u.code AS uom \
         FROM sales_order_line l LEFT JOIN stock_product p ON p.id = l.product_id \
         LEFT JOIN uoms u ON u.id = COALESCE(l.uom_id, p.uom_id) \
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
        // Section / note rows span the whole table.
        if let Some(dt) = r.try_get::<Option<String>, _>("display_type").ok().flatten() {
            let text = r.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default();
            let del = if is_draft {
                format!(
                    r#"<td class="text-right"><form method="POST" action="/sales/orders/{id}/lines/{lid}/delete" onsubmit="return confirm('Remove this row?')"><button class="btn btn-ghost btn-xs text-error">✕</button></form></td>"#,
                    id = id, lid = lid
                )
            } else {
                r#"<td></td>"#.to_string()
            };
            if dt == "section" {
                lines_html.push_str(&format!(
                    r#"<tr class="bg-base-200"><td colspan="9" class="font-semibold">{}</td>{del}</tr>"#,
                    esc(&text), del = del
                ));
            } else {
                lines_html.push_str(&format!(
                    r#"<tr><td colspan="9" class="italic text-base-content/60" style="white-space:pre-line">{}</td>{del}</tr>"#,
                    esc(&text), del = del
                ));
            }
            continue;
        }
        let pcode: String = r.try_get("product_code").ok().flatten().unwrap_or_default();
        let pname: String = r.try_get("product_name").ok().flatten().unwrap_or_default();
        let desc: Option<String> = r.try_get("description").ok();
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        let uom: Option<String> = r.try_get("uom").ok().flatten();
        let qty_disp = match uom.as_deref().filter(|u| !u.is_empty()) {
            Some(u) => format!("{} {}", qty.normalize(), esc(u)),
            None => qty.normalize().to_string(),
        };
        let price: Decimal = r.try_get("unit_price").unwrap_or(Decimal::ZERO);
        let tax_name: Option<String> = r.try_get("tax_name").ok().flatten();
        let classification: Option<String> = r.try_get("classification_code").ok().flatten();
        let recv: Decimal = r.try_get("qty_delivered").unwrap_or(Decimal::ZERO);
        let invoiced: Decimal = r.try_get("qty_invoiced").unwrap_or(Decimal::ZERO);
        let backorder = qty - recv;
        let disc: Decimal = r.try_get("discount_percent").unwrap_or(Decimal::ZERO);
        let subtotal = (qty * price * (Decimal::from(100) - disc) / Decimal::from(100)).round_dp(2);
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
            desc = desc.filter(|d| !d.is_empty()).map(|d| format!(r#"<br><span class="text-xs text-base-content/50">{}</span>"#, crate::richtext::sanitize_rich(&d))).unwrap_or_default(),
            qty = qty_disp,
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
    // Draft quotations are edited on the single-screen grid editor.
    let add_line_form = if is_draft {
        format!(
            r#"<div class="mt-4"><a href="/sales/orders/{id}/edit" class="btn btn-primary btn-sm">✎ Edit lines &amp; details</a></div>"#,
            id = id
        )
    } else {
        String::new()
    };

    // ── Header (editable in draft, read-only otherwise) ──
    // Read-only header for every state; drafts edit on the grid editor
    // (the "✎ Edit lines & details" button), so there's one edit surface.
    let title_block = quote_title
        .as_deref()
        .filter(|t| !t.is_empty())
        .map(|t| format!(r#"<div class="text-lg font-semibold mb-1">{}</div>"#, crate::richtext::sanitize_rich(t)))
        .unwrap_or_default();
    let summary_block = quote_summary
        .as_deref()
        .filter(|s| !s.is_empty())
        .map(|s| format!(r#"<div class="text-sm text-base-content/70 mb-3">{}</div>"#, crate::richtext::sanitize_rich(s)))
        .unwrap_or_default();
    let header = format!(
        r#"{title_block}{summary_block}<div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
<div><div class="text-base-content/50">Customer</div><div class="font-medium">{customer}</div></div>
<div><div class="text-base-content/50">Order Date</div><div class="font-medium">{order_date}</div></div>
<div><div class="text-base-content/50">Expected</div><div class="font-medium">{expected}</div></div>
<div><div class="text-base-content/50">Ship-From</div><div class="font-medium">{dest}</div></div>
<div><div class="text-base-content/50">Quotation</div><div class="font-medium">{quote_no}</div></div>
<div><div class="text-base-content/50">Valid Until</div><div class="font-medium">{validity}</div></div>
</div>{note}"#,
        title_block = title_block,
        summary_block = summary_block,
        customer = esc(&customer_name),
        order_date = esc(order_date.as_deref().unwrap_or("—")),
        expected = esc(expected_date.as_deref().unwrap_or("—")),
        dest = esc(dest_name.as_deref().unwrap_or("—")),
        quote_no = {
            let q = quote_number.as_deref().unwrap_or("—");
            if revision > 1 { format!("{} (Rev {})", esc(q), revision) } else { esc(q).to_string() }
        },
        validity = esc(validity_date.as_deref().unwrap_or("—")),
        note = note.filter(|n| !n.is_empty()).map(|n| format!(r#"<div class="mt-3 text-sm text-base-content/70">{}</div>"#, crate::richtext::sanitize_rich(&n))).unwrap_or_default(),
    );

    // ── Action buttons by state ──
    let has_lines = !line_rows.is_empty();
    let mut actions = String::new();
    // Print + (when the headless-Chromium PDF engine is enabled) a server-side
    // Download PDF. Shared across every quote-visible state.
    let pdf_btn = if vortex_plugin_sdk::framework::pdf::available() {
        format!(
            r#"<a href="/sales/orders/{id}/print-quote?format=pdf" class="btn btn-outline btn-sm ml-2" title="Download a PDF rendered on the server">Download PDF</a>"#,
            id = id
        )
    } else {
        String::new()
    };
    let print_btns = format!(
        r#"<a href="/sales/orders/{id}/print-quote" target="_blank" class="btn btn-outline btn-sm">Print Quotation</a>{pdf}"#,
        id = id,
        pdf = pdf_btn
    );
    match po_state.as_str() {
        "quotation" => {
            actions.push_str(&print_btns);
            if has_lines {
                actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/send" class="inline ml-2"><button class="btn btn-primary btn-sm" title="Freezes this revision — the customer now holds a copy">Mark as Sent</button></form>"#, id = id));
                actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/confirm" class="inline ml-2"><button class="btn btn-success btn-sm">Confirm Order</button></form>"#, id = id));
            }
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/lost" class="inline ml-2" onsubmit="return confirm('Mark this quotation as lost?')"><button class="btn btn-ghost btn-sm">Mark Lost</button></form>"#, id = id));
        }
        "sent" => {
            actions.push_str(&print_btns);
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/confirm" class="inline ml-2"><button class="btn btn-primary btn-sm">Confirm Order</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/revise" class="inline ml-2"><button class="btn btn-outline btn-sm" title="Creates the next revision; this one stays exactly as the customer received it">Revise</button></form>"#, id = id));
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/lost" class="inline ml-2" onsubmit="return confirm('Mark this quotation as lost?')"><button class="btn btn-ghost btn-sm">Mark Lost</button></form>"#, id = id));
        }
        "expired" | "lost" => {
            actions.push_str(&print_btns);
            actions.push_str(&format!(r#"<form method="POST" action="/sales/orders/{id}/revise" class="inline ml-2"><button class="btn btn-primary btn-sm">Revise</button></form>"#, id = id));
        }
        "superseded" => {
            actions.push_str(&print_btns);
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
    // Duplicate is available from every state: unlike Revise (next
    // revision of THIS family), it starts a brand-new quotation family.
    actions.push_str(&format!(
        r#"<span class="inline ml-2">{}</span>"#,
        duplicate_button(&format!("/sales/orders/{id}/duplicate"))
    ));

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

    // Record history (audit trail: created, sent, confirmed, edited, …).
    let history_panel = vortex_plugin_sdk::framework::render_audit_trail(&db, "sales_order", id).await;
    // Activity stream: schedule/assign/complete tasks, messages, attachments.
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("sales_order", id);

    let content = format!(
        r#"<div class="flex items-center justify-between mb-4">
<div>
<a href="{back_url}" class="btn btn-ghost btn-sm mb-2">← Back to {back_label}</a>
<h1 class="text-2xl font-bold">{number}{quote_ref} {badge}</h1>
</div>
<div class="vortex-actions">{actions}</div>
</div>
<div class="mb-4">{statusbar}</div>
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
{discount_rows}<tr><td class="text-base-content/60 pr-6">Untaxed</td><td class="text-right font-mono">{untaxed} {cur}</td></tr>
<tr><td class="text-base-content/60 pr-6">Tax</td><td class="text-right font-mono">{tax} {cur}</td></tr>
<tr><td class="font-semibold pr-6">Total</td><td class="text-right font-mono font-semibold">{total} {cur}</td></tr>
</table>
</div>
</div></div>

{deliveries_card}
{invoices_card}
{revisions_card}
<div class="grid lg:grid-cols-2 gap-6 mt-6 items-start">
<div>{history_panel}</div>
<div>{activity_panel}</div>
</div>"#,
        back_url = if is_quote_stage { "/sales/quotes" } else { "/sales" },
        back_label = if is_quote_stage { "Quotations" } else { "Sales Orders" },
        number = esc(&identity),
        quote_ref = quote_ref,
        statusbar = order_statusbar(&po_state),
        lost_banner = lost_banner,
        badge = state_badge(&po_state),
        actions = actions,
        header = header,
        lines = lines_html,
        add_line = add_line_form,
        discount_rows = discount_rows,
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
    let line_count: i64 = vortex_plugin_sdk::sqlx::query_scalar("SELECT COUNT(*) FROM sales_order_line WHERE order_id = $1 AND display_type IS NULL")
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
          expected_date, currency_id, source_location_id, note, company_id, created_by, payment_term_id) \
         SELECT $1, quote_number, $3, root_quote_id, $4, customer_id, CURRENT_DATE, \
                expected_date, currency_id, source_location_id, note, company_id, $5, payment_term_id \
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

/// POST /sales/orders/{id}/duplicate — Odoo-style Duplicate, distinct from
/// Revise: works from ANY state and starts a brand-new document family
/// (fresh QT number, revision 1, its own root_quote_id). Lifecycle state,
/// SO number, fulfilment/invoice links and counters all reset; stored
/// totals are recomputed from the cloned lines.
async fn duplicate_order(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let quote_number = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &QT_SEQ).await {
        Ok(n) => n,
        Err(e) => {
            error!(error = %e, "duplicate QT sequence draw failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response();
        }
    };
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    let validity = today + vortex_plugin_sdk::chrono::Duration::days(30);

    let new_id = Uuid::now_v7();
    let spec = DuplicateSpec::new("sales_order")
        .with_id(new_id)
        // Fresh identity: new quotation family rooted at itself.
        .set("quote_number", json!(quote_number))
        .set("revision", json!(1))
        .set("root_quote_id", json!(new_id))
        // Back to the initial 'quotation' state via the DB default.
        .skip("state")
        // SO number is only minted at confirmation; lost verdicts,
        // review stamps and the invoice bridge belong to the source.
        .skip("number")
        .skip("lost_reason")
        .skip("updated_by")
        .skip("customer_invoice_move_id")
        // Stored totals restart at 0 and are recomputed below.
        .skip("untaxed_amount")
        .skip("tax_amount")
        .skip("total_amount")
        // Commercial dates restart from today.
        .set("order_date", json!(today.to_string()))
        .set("validity_date", json!(validity.to_string()))
        .child(
            ChildCopy::new("sales_order_line", "order_id")
                // Fulfilment counters restart at zero, like revise_quote.
                .set("qty_delivered", json!(0))
                .set("qty_invoiced", json!(0)),
        );
    if let Err(e) = spec.execute(&db, id, Some(user.id)).await {
        error!(error = %e, "sales order duplicate failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response();
    }
    recompute_totals(&db, new_id).await;

    audit_so(&state, &db_ctx, &db, user.id, &user.username, new_id, "duplicated").await;
    info!(quote = %quote_number, source = %id, "sales order duplicated");
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
    audit_so_changes(state, db_ctx, db, user_id, username, id, action, Vec::new()).await;
}

/// Like [`audit_so`] but with a field-level change set (`{field, from, to}`),
/// so the History timeline shows exactly what was edited — header fields and
/// individual line items.
#[allow(clippy::too_many_arguments)]
async fn audit_so_changes(
    state: &AppState,
    db_ctx: &DatabaseContext,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user_id: Uuid,
    username: &str,
    id: Uuid,
    action: &str,
    changes: Vec<serde_json::Value>,
) {
    let number: String = vortex_plugin_sdk::sqlx::query_scalar("SELECT number FROM sales_order WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let details = if changes.is_empty() {
        json!({ "action": action })
    } else {
        json!({ "action": action, "changes": changes })
    };
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user_id))
    .with_username(username)
    .with_database(&db_ctx.db_name)
    .with_resource("sales_order", id.to_string())
    .with_resource_name(&number)
    .with_details(details);
    let _ = state.audit.log(entry).await;
}

/// Ordered display values of the tracked header fields, for before/after diff.
async fn quote_header_snapshot(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    id: Uuid,
) -> Vec<(&'static str, String)> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT c.name AS customer, o.order_date::text AS order_date, \
                o.expected_date::text AS expected_date, o.validity_date::text AS validity_date, \
                cur.code AS currency, loc.name AS location, o.title, o.summary, o.note, \
                CASE WHEN o.global_discount_value > 0 THEN \
                    o.global_discount_type || ' ' || o.global_discount_value::text \
                    ELSE '' END AS global_discount \
         FROM sales_order o JOIN contacts c ON c.id = o.customer_id \
         LEFT JOIN currencies cur ON cur.id = o.currency_id \
         LEFT JOIN stock_location loc ON loc.id = o.source_location_id \
         WHERE o.id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let mut out = Vec::new();
    if let Some(r) = row {
        let g = |k: &str| -> String { r.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
        out.push(("Customer", g("customer")));
        out.push(("Quote Date", g("order_date")));
        out.push(("Expected Date", g("expected_date")));
        out.push(("Valid Until", g("validity_date")));
        out.push(("Currency", g("currency")));
        out.push(("Ship-From", g("location")));
        out.push(("Title", g("title")));
        out.push(("Summary", g("summary")));
        out.push(("Note", g("note")));
        out.push(("Discount", g("global_discount")));
    }
    out
}

/// One line reduced to a matching `key` (stable across edits) and a `label`
/// (its full human display), for the line-item diff.
struct LineSnap {
    key: String,
    label: String,
}

/// Snapshot every line of a quote as `(key, label)` for before/after diff.
async fn quote_line_snapshot(db: &vortex_plugin_sdk::sqlx::PgPool, id: Uuid) -> Vec<LineSnap> {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.product_id, l.display_type, l.description, l.quantity, l.unit_price, \
                l.discount_percent, p.code AS product_code, p.name AS product_name, t.name AS tax_name \
         FROM sales_order_line l \
         LEFT JOIN stock_product p ON p.id = l.product_id \
         LEFT JOIN taxes t ON t.id = l.tax_id \
         WHERE l.order_id = $1 ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = Vec::new();
    for r in &rows {
        let desc: String = r.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default();
        if let Some(dt) = r.try_get::<Option<String>, _>("display_type").ok().flatten() {
            if dt == "section" {
                out.push(LineSnap { key: format!("s:{}", desc.to_lowercase()), label: format!("Section: {desc}") });
            } else {
                out.push(LineSnap { key: format!("n:{}", desc.to_lowercase()), label: format!("Note: {desc}") });
            }
            continue;
        }
        let pid: Option<Uuid> = r.try_get("product_id").ok().flatten();
        let code: String = r.try_get::<Option<String>, _>("product_code").ok().flatten().unwrap_or_default();
        let pname: String = r.try_get::<Option<String>, _>("product_name").ok().flatten().unwrap_or_default();
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        let price: Decimal = r.try_get("unit_price").unwrap_or(Decimal::ZERO);
        let disc: Decimal = r.try_get("discount_percent").unwrap_or(Decimal::ZERO);
        let tax: String = r.try_get::<Option<String>, _>("tax_name").ok().flatten().unwrap_or_default();
        let name = if !desc.is_empty() { desc.clone() } else if !pname.is_empty() { pname.clone() } else { code.clone() };
        let disc_s = if disc > Decimal::ZERO { format!(", {}% disc", disc.normalize()) } else { String::new() };
        let tax_s = if !tax.is_empty() { format!(", {tax}") } else { String::new() };
        let label = format!("{} — {} × {}{}{}", name, qty.normalize(), money(price), disc_s, tax_s);
        let key = format!("p:{}", pid.map(|u| u.to_string()).unwrap_or_else(|| code.clone()));
        out.push(LineSnap { key, label });
    }
    out
}

/// Diff two ordered `(label, value)` header snapshots into `{field, from, to}`.
fn diff_header(before: &[(&'static str, String)], after: &[(&'static str, String)]) -> Vec<serde_json::Value> {
    let bmap: HashMap<&'static str, String> = before.iter().map(|(k, v)| (*k, v.clone())).collect();
    let mut changes = Vec::new();
    for (label, aval) in after {
        let bval = bmap.get(label).cloned().unwrap_or_default();
        if &bval != aval {
            changes.push(json!({ "field": label, "from": bval, "to": aval }));
        }
    }
    changes
}

/// Diff two line snapshots, matching by `key` (multiset, paired in order) so a
/// changed line reads as one change, not a remove+add, and reorders are quiet.
fn diff_lines(old: &[LineSnap], new: &[LineSnap]) -> Vec<serde_json::Value> {
    let mut old_by: HashMap<&str, Vec<&str>> = HashMap::new();
    for l in old {
        old_by.entry(l.key.as_str()).or_default().push(l.label.as_str());
    }
    let mut new_by: HashMap<&str, Vec<&str>> = HashMap::new();
    for l in new {
        new_by.entry(l.key.as_str()).or_default().push(l.label.as_str());
    }
    // Stable key order: new order first, then old-only keys.
    let mut keys: Vec<&str> = Vec::new();
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for l in new {
        if seen.insert(l.key.as_str()) {
            keys.push(l.key.as_str());
        }
    }
    for l in old {
        if seen.insert(l.key.as_str()) {
            keys.push(l.key.as_str());
        }
    }
    let mut changes = Vec::new();
    for k in keys {
        let ol = old_by.get(k).cloned().unwrap_or_default();
        let nl = new_by.get(k).cloned().unwrap_or_default();
        let n = ol.len().min(nl.len());
        for i in 0..n {
            if ol[i] != nl[i] {
                changes.push(json!({ "field": "Line changed", "from": ol[i], "to": nl[i] }));
            }
        }
        for l in ol.iter().skip(n) {
            changes.push(json!({ "field": "Line removed", "from": *l, "to": "" }));
        }
        for l in nl.iter().skip(n) {
            changes.push(json!({ "field": "Line added", "from": "", "to": *l }));
        }
    }
    changes
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

/// Built-in quotation layout, expressed as a template for the sandboxed
/// engine (`vortex_framework::user_reports`). This is what prints when no
/// custom template has been saved, and what "Load default" offers in the
/// layout editor — so users start from the real layout and tweak it. The
/// surrounding page chrome + CSS (branding, paper size, print button) come
/// from `print_layout::render_doc_page`; classes used here are documented in
/// `print_layout::base_css`.
pub const DEFAULT_QUOTATION_TEMPLATE: &str = r#"{% if doc.watermark %}<div class="watermark">{{ doc.watermark }}</div>{% endif %}
<div class="head">
  <div class="seller">
    {% if company.logo %}<img class="logo" src="{{ company.logo }}"/>{% endif %}
    <p class="name">{{ company.name }}</p>
    {% if company.addr1 %}<p>{{ company.addr1 }}</p>{% endif %}
    {% if company.addr2 %}<p>{{ company.addr2 }}</p>{% endif %}
    {% if company.city_line %}<p>{{ company.city_line }}</p>{% endif %}
    <p>{{ company.phone }} {{ company.email }}</p>
    {% if company.reg %}<p class="label">Reg No: {{ company.reg }}</p>{% endif %}
  </div>
  <div style="text-align:right">
    <h1 class="doc-title">Quotation</h1>
    <table class="meta" style="margin-left:auto">
      <tr><td class="label">Number</td><td><b>{{ doc.number }}</b></td></tr>
      <tr><td class="label">Date</td><td>{{ doc.date }}</td></tr>
      <tr><td class="label">Valid Until</td><td>{{ doc.validity }}</td></tr>
    </table>
  </div>
</div>
<div class="buyer" style="margin-bottom:1em">
  <p class="label">To</p>
  <p><b>{{ customer.name }}</b></p>
  {% if customer.street %}<p>{{ customer.street }}</p>{% endif %}
  {% if customer.street2 %}<p>{{ customer.street2 }}</p>{% endif %}
  {% if customer.city_line %}<p>{{ customer.city_line }}</p>{% endif %}
  <p>{{ customer.phone }} {{ customer.email }}</p>
</div>
{% if doc.headline %}<h2 class="doc-headline">{{ doc.headline }}</h2>{% endif %}
{% if doc.summary %}<p class="doc-summary">{{ doc.summary }}</p>{% endif %}
<table class="items">
  <thead><tr><th>Code</th><th>Description</th><th class="num">Qty</th><th class="num">Unit Price</th><th>Tax</th><th class="num">Amount</th></tr></thead>
  <tbody>
  {% for line in lines %}{% if line.is_section %}<tr class="sec-row"><td colspan="6">{{ line.text }}</td></tr>{% endif %}{% if line.is_note %}<tr class="note-row"><td colspan="6">{{ line.text }}</td></tr>{% endif %}{% if line.is_line %}<tr>
    <td class="mono">{{ line.code }}</td>
    <td>{{ line.description }}</td>
    <td class="num">{{ line.qty }}</td>
    <td class="num">{{ line.unit_price }}</td>
    <td>{{ line.tax }}</td>
    <td class="num">{{ line.amount }}</td>
  </tr>{% endif %}{% endfor %}
  </tbody>
</table>
<table class="totals">
  {% if totals.discount %}<tr><td class="label">Subtotal</td><td class="num">{{ totals.subtotal_pre }} {{ currency }}</td></tr>
  <tr><td class="label">{{ totals.discount_label }}</td><td class="num">- {{ totals.discount }} {{ currency }}</td></tr>
  <tr><td class="label">After discount</td><td class="num">{{ totals.untaxed }} {{ currency }}</td></tr>{% else %}<tr><td class="label">Subtotal</td><td class="num">{{ totals.untaxed }} {{ currency }}</td></tr>{% endif %}
  <tr><td class="label">Tax</td><td class="num">{{ totals.tax }} {{ currency }}</td></tr>
  <tr class="grand"><td>Total</td><td class="num">{{ totals.total }} {{ currency }}</td></tr>
</table>
{% if doc.payment_term %}<div class="note"><span class="label">Payment Terms</span><br/>{{ doc.payment_term }}{% if doc.due_date %} — due {{ doc.due_date }}{% endif %}</div>{% endif %}
{% if doc.note %}<div class="note"><span class="label">Notes</span><br/>{{ doc.note }}</div>{% endif %}
<div class="accept">
  <div>Issued by<br><br>Name:<br>Date:</div>
  <div>Accepted by (customer)<br><br>Name, company stamp:<br>Date:</div>
</div>"#;

/// The quotation's entry in the print-layout registry: label, default
/// template, and the variables an author may use in a custom template.
pub fn quotation_print_doc() -> vortex_plugin_sdk::framework::PrintDocType {
    let vars = [
        ("doc.number", "Quotation number (with revision)"),
        ("doc.date", "Order date"),
        ("doc.validity", "Valid-until date"),
        ("doc.headline", "Quotation Title (headline text)"),
        ("doc.summary", "Quotation Summary / intro paragraph"),
        ("doc.note", "Free-text note on the quotation"),
        ("doc.payment_term", "Payment terms name, e.g. Net 30"),
        ("doc.due_date", "Payment due date (order date + term days)"),
        ("doc.watermark", "SUPERSEDED / LOST / EXPIRED, else empty"),
        ("currency", "Currency code, e.g. MYR"),
        ("company.name / company.logo / company.addr1 / company.addr2 / company.city_line / company.phone / company.email / company.reg", "Your company (logo is a data URI)"),
        ("customer.name / customer.street / customer.street2 / customer.city_line / customer.phone / customer.email", "Bill-to customer"),
        ("totals.untaxed / totals.tax / totals.total", "Money totals"),
        ("lines (loop)", "{% for line in lines %} product rows: {% if line.is_line %} line.code, line.description, line.qty, line.unit_price, line.discount, line.tax, line.amount {% endif %} — section/note rows: {% if line.is_section %}line.text{% endif %}{% if line.is_note %}line.text{% endif %} {% endfor %}"),
    ];
    // Sample data for the editor's live preview (no real record needed).
    let g = |pairs: &[(&str, &str)]| -> std::collections::BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    };
    let sample_globals = g(&[
        ("doc.number", "SQ/2026/00042"),
        ("doc.date", "2026-07-08"),
        ("doc.validity", "2026-07-22"),
        ("doc.headline", "Supply & installation of stainless fittings"),
        ("doc.summary", "Thank you for the opportunity to quote. This proposal covers materials and on-site installation as discussed."),
        ("doc.note", "Lead time 2–3 weeks. Prices exclude delivery."),
        ("doc.payment_term", "Net 30"),
        ("doc.due_date", "2026-08-07"),
        ("doc.watermark", ""),
        ("currency", "MYR"),
        ("company.name", "Acme Trading Sdn Bhd"),
        ("company.addr1", "12 Jalan Contoh"),
        ("company.city_line", "50450 Kuala Lumpur"),
        ("company.phone", "+60 3-1234 5678"),
        ("company.email", "sales@acme.example"),
        ("company.reg", "202001012345"),
        ("customer.name", "Beta Industries Sdn Bhd"),
        ("customer.street", "88 Persiaran Sample"),
        ("customer.city_line", "40000 Shah Alam"),
        ("customer.phone", "+60 3-8765 4321"),
        ("customer.email", "ap@beta.example"),
        ("totals.subtotal_pre", "1,388.00"),
        ("totals.discount", "138.00"),
        ("totals.discount_label", "Discount (10%)"),
        ("totals.untaxed", "1,250.00"),
        ("totals.tax", "75.00"),
        ("totals.total", "1,325.00"),
    ]);
    let sample_lines = vec![
        g(&[("is_section", "1"), ("text", "Phase 1 — Materials")]),
        g(&[("is_line", "1"), ("code", "PRD-001"), ("description", "Widget, stainless"), ("qty", "10"), ("unit_price", "100.00"), ("discount", ""), ("tax", "SST 6%"), ("amount", "1,000.00")]),
        g(&[("is_line", "1"), ("code", "PRD-014"), ("description", "Mounting bracket"), ("qty", "5"), ("unit_price", "50.00"), ("discount", "10%"), ("tax", "SST 6%"), ("amount", "225.00")]),
        g(&[("is_note", "1"), ("text", "Installation scheduled within 2 weeks of acceptance.")]),
    ];
    vortex_plugin_sdk::framework::PrintDocType {
        doc_type: "sales.quotation".to_string(),
        label: "Quotation".to_string(),
        default_template: DEFAULT_QUOTATION_TEMPLATE.to_string(),
        variables: vars.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
        sample_globals,
        sample_lines,
        // Enables the no-code Visual editor. Its compiled output matches
        // DEFAULT_QUOTATION_TEMPLATE, so "Visual" and "HTML" open on the same
        // starting layout.
        default_config: Some(vortex_plugin_sdk::framework::LayoutConfig::transactional("Quotation")),
    }
}

/// Printable quotation — branded A4 page with prices, taxes, validity and an
/// acceptance block, rendered through the customisable print-layout engine
/// (custom template if the user saved one, [`DEFAULT_QUOTATION_TEMPLATE`]
/// otherwise). Reprintable for any revision, exactly as issued.
async fn print_quote(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let want_pdf = q.get("format").map(|f| f == "pdf").unwrap_or(false);
    let head = vortex_plugin_sdk::sqlx::query(
        "SELECT o.quote_number, o.revision, o.number, o.state, o.order_date, o.validity_date, \
                o.note, o.title, o.summary, o.untaxed_amount, o.tax_amount, o.total_amount, \
                o.global_discount_type, o.global_discount_value, \
                cu.code AS currency_code, \
                pt.name AS payment_term_name, pt.due_days AS payment_term_days, \
                c.name AS customer_name, c.street, c.street2, c.city, c.zip, \
                c.phone AS customer_phone, c.email AS customer_email \
         FROM sales_order o \
         JOIN contacts c ON c.id = o.customer_id \
         LEFT JOIN currencies cu ON cu.id = o.currency_id \
         LEFT JOIN payment_term pt ON pt.id = o.payment_term_id \
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
                l.quantity, l.unit_price, l.discount_percent, t.name AS tax_name, l.display_type, \
                u.code AS uom \
         FROM sales_order_line l \
         LEFT JOIN stock_product p ON p.id = l.product_id \
         LEFT JOIN uoms u ON u.id = COALESCE(l.uom_id, p.uom_id) \
         LEFT JOIN taxes t ON t.id = l.tax_id \
         WHERE l.order_id = $1 ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Raw (unescaped) header/company getters — the template engine escapes on
    // output, so pre-escaping here would double-escape.
    let hval = |k: &str| -> String {
        head.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default()
    };
    let cval = |k: &str| -> String {
        company
            .as_ref()
            .and_then(|c| c.try_get::<Option<String>, _>(k).ok().flatten())
            .unwrap_or_default()
    };
    let company_name = company
        .as_ref()
        .map(|c| c.get::<String, _>("name"))
        .unwrap_or_else(|| "Company".into());

    // Logo as a data URI (empty when none uploaded).
    let logo_data = match state.files.get(&db_ctx.db_name, "company/logo").await {
        Ok(Some(data)) => {
            use base64::Engine;
            let ct = if data.starts_with(&[0xFF, 0xD8, 0xFF]) { "image/jpeg" } else { "image/png" };
            format!("data:{ct};base64,{}", base64::engine::general_purpose::STANDARD.encode(&data))
        }
        _ => String::new(),
    };

    let revision: i32 = head.try_get("revision").unwrap_or(1);
    let quote_state: String = head.get("state");
    let display_number = {
        let q = hval("quote_number");
        if revision > 1 { format!("{q} (Rev {revision})") } else { q }
    };
    let cur = {
        let c = hval("currency_code");
        if c.is_empty() { "MYR".to_string() } else { c }
    };
    // A superseded/lost/expired print carries its status as a watermark.
    let watermark = match quote_state.as_str() {
        "superseded" => "SUPERSEDED",
        "lost" => "LOST",
        "expired" => "EXPIRED",
        _ => "",
    };
    let date = head
        .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("order_date")
        .ok().flatten().map(|d| d.to_string()).unwrap_or_default();
    let validity = head
        .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("validity_date")
        .ok().flatten().map(|d| d.to_string()).unwrap_or_else(|| "—".into());
    // "postcode city" as one address line, trimmed.
    let join2 = |a: String, b: String| format!("{} {}", a.trim(), b.trim()).trim().to_string();

    // Rich-text fields (title/summary/note/line descriptions) carry inline
    // formatting. The template engine ESCAPES every `{{ }}`, so we substitute a
    // collision-proof token here and splice the sanitized HTML back in after the
    // template renders — the engine stays a pure escaper (no raw-output hole).
    let nonce = Uuid::now_v7().simple().to_string();
    let mut rich_tokens: Vec<(String, String)> = Vec::new();
    let mut rich = |raw: &str| -> String {
        let safe = crate::richtext::sanitize_rich(raw);
        if safe.trim().is_empty() {
            return String::new();
        }
        let tok = format!("\u{2063}RT{}_{}\u{2063}", nonce, rich_tokens.len());
        rich_tokens.push((tok.clone(), safe));
        tok
    };

    use std::collections::BTreeMap;
    let mut g: BTreeMap<String, String> = BTreeMap::new();
    g.insert("doc.number".into(), display_number.clone());
    g.insert("doc.date".into(), date);
    g.insert("doc.validity".into(), validity);
    g.insert("doc.watermark".into(), watermark.to_string());
    g.insert("doc.note".into(), rich(&hval("note")));
    g.insert("doc.headline".into(), rich(&hval("title")));
    g.insert("doc.summary".into(), rich(&hval("summary")));
    // Payment terms + a due date computed from the order date + term days.
    g.insert("doc.payment_term".into(), hval("payment_term_name"));
    let term_days: Option<i32> = head.try_get("payment_term_days").ok().flatten();
    let order_nd = head
        .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("order_date")
        .ok()
        .flatten();
    let due_date = match (order_nd, term_days) {
        (Some(d), Some(days)) => {
            (d + vortex_plugin_sdk::chrono::Duration::days(days as i64)).to_string()
        }
        _ => String::new(),
    };
    g.insert("doc.due_date".into(), due_date);
    g.insert("currency".into(), cur);
    g.insert("company.logo".into(), logo_data);
    g.insert("company.name".into(), company_name);
    g.insert("company.addr1".into(), cval("company_address1"));
    g.insert("company.addr2".into(), cval("company_address2"));
    g.insert("company.city_line".into(), join2(cval("company_postcode"), cval("company_city")));
    g.insert("company.phone".into(), cval("company_phone"));
    g.insert("company.email".into(), cval("company_email"));
    g.insert("company.reg".into(), cval("company_id_value"));
    g.insert("customer.name".into(), hval("customer_name"));
    g.insert("customer.street".into(), hval("street"));
    g.insert("customer.street2".into(), hval("street2"));
    g.insert("customer.city_line".into(), join2(hval("zip"), hval("city")));
    g.insert("customer.phone".into(), hval("customer_phone"));
    g.insert("customer.email".into(), hval("customer_email"));
    g.insert("totals.untaxed".into(), money(head.try_get("untaxed_amount").unwrap_or(Decimal::ZERO)));
    g.insert("totals.tax".into(), money(head.try_get("tax_amount").unwrap_or(Decimal::ZERO)));
    g.insert("totals.total".into(), money(head.try_get("total_amount").unwrap_or(Decimal::ZERO)));

    // Whole-quote discount: show a pre-discount subtotal + the amount off, so
    // the document reconciles (the stored `untaxed` is already post-discount).
    let gd_type: Option<String> = head.try_get("global_discount_type").ok().flatten();
    let gd_value: Decimal = head.try_get("global_discount_value").unwrap_or(Decimal::ZERO);
    let hundred = Decimal::from(100);
    let pre_subtotal: Decimal = lines
        .iter()
        .filter(|l| l.try_get::<Option<String>, _>("display_type").ok().flatten().is_none())
        .map(|l| {
            let qty: Decimal = l.try_get("quantity").unwrap_or(Decimal::ZERO);
            let price: Decimal = l.try_get("unit_price").unwrap_or(Decimal::ZERO);
            let disc: Decimal = l.try_get("discount_percent").unwrap_or(Decimal::ZERO);
            qty * price * (hundred - disc) / hundred
        })
        .sum();
    let factor = global_factor(gd_type.as_deref(), gd_value, pre_subtotal);
    let discount_amount = (pre_subtotal * (Decimal::ONE - factor)).round_dp(2);
    if gd_type.is_some() && discount_amount > Decimal::ZERO {
        let label = match gd_type.as_deref() {
            Some("percent") => format!("Discount ({}%)", gd_value.normalize()),
            _ => "Discount".to_string(),
        };
        g.insert("totals.subtotal_pre".into(), money(pre_subtotal.round_dp(2)));
        g.insert("totals.discount".into(), money(discount_amount));
        g.insert("totals.discount_label".into(), label);
    } else {
        // Empty string reads as falsy in the template `{% if %}` truthy test.
        g.insert("totals.subtotal_pre".into(), String::new());
        g.insert("totals.discount".into(), String::new());
        g.insert("totals.discount_label".into(), String::new());
    }

    let mut line_maps: Vec<BTreeMap<String, String>> = Vec::new();
    for l in &lines {
        let mut m = BTreeMap::new();
        let display_type: Option<String> = l.try_get("display_type").ok().flatten();
        // Per-row kind flags — the template branches on these (truthy test).
        if let Some(dt) = display_type {
            let text = l.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default();
            if dt == "section" {
                m.insert("is_section".into(), "1".into());
            } else {
                m.insert("is_note".into(), "1".into());
            }
            m.insert("text".into(), text);
            line_maps.push(m);
            continue;
        }
        let qty: Decimal = l.try_get("quantity").unwrap_or(Decimal::ZERO);
        let price: Decimal = l.try_get("unit_price").unwrap_or(Decimal::ZERO);
        let disc: Decimal = l.try_get("discount_percent").unwrap_or(Decimal::ZERO);
        let net = (qty * price * (Decimal::from(100) - disc) / Decimal::from(100)).round_dp(2);
        m.insert("is_line".into(), "1".into());
        m.insert("code".into(), l.try_get::<Option<String>, _>("code").ok().flatten().unwrap_or_default());
        let desc_raw = l.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default();
        m.insert("description".into(), rich(&desc_raw));
        // Fold the unit into the qty so every layout shows "5 kg" with no
        // template change needed.
        let uom = l.try_get::<Option<String>, _>("uom").ok().flatten().unwrap_or_default();
        let qty_disp = if uom.is_empty() {
            qty.normalize().to_string()
        } else {
            format!("{} {}", qty.normalize(), uom)
        };
        m.insert("qty".into(), qty_disp);
        m.insert("unit_price".into(), money(price));
        m.insert(
            "discount".into(),
            if disc > Decimal::ZERO { format!("{}%", disc.normalize()) } else { String::new() },
        );
        m.insert(
            "tax".into(),
            l.try_get::<Option<String>, _>("tax_name").ok().flatten().unwrap_or_else(|| "—".into()),
        );
        // Amount is net of the line discount, matching the stored totals.
        m.insert("amount".into(), money(net));
        line_maps.push(m);
    }

    let title = format!("{display_number} — Quotation");
    let mut html = vortex_plugin_sdk::framework::print_layout::render_document(
        &db,
        "sales.quotation",
        DEFAULT_QUOTATION_TEMPLATE,
        &title,
        &g,
        &line_maps,
    )
    .await;
    // Splice the sanitized rich-text HTML back in over its placeholder tokens.
    for (tok, safe_html) in &rich_tokens {
        html = html.replace(tok, safe_html);
    }

    // `?format=pdf` renders the same branded page through the headless-Chromium
    // PDF engine and returns it as a download; otherwise serve the print page
    // (the browser's own Print → Save as PDF still works when the engine is off).
    if want_pdf {
        if !vortex_plugin_sdk::framework::pdf::available() {
            return (
                vortex_plugin_sdk::axum::http::StatusCode::SERVICE_UNAVAILABLE,
                "PDF engine not enabled on this server — use Print and the browser's Save as PDF.",
            )
                .into_response();
        }
        let opts = vortex_plugin_sdk::framework::pdf::PdfOptions::default();
        return match vortex_plugin_sdk::framework::pdf::html_to_pdf(&html, &opts).await {
            Ok(bytes) => {
                // Filename from the quote number, path-safe.
                let fname = format!(
                    "{}.pdf",
                    display_number.replace(['/', '\\', ' '], "-")
                );
                (
                    [
                        (
                            vortex_plugin_sdk::axum::http::header::CONTENT_TYPE,
                            "application/pdf".to_string(),
                        ),
                        (
                            vortex_plugin_sdk::axum::http::header::CONTENT_DISPOSITION,
                            format!("attachment; filename=\"{fname}\""),
                        ),
                    ],
                    bytes,
                )
                    .into_response()
            }
            Err(e) => {
                error!(error = %e, "quotation pdf render failed");
                (
                    vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                    "PDF rendering failed — check the server's Chromium (VORTEX_CHROMIUM).",
                )
                    .into_response()
            }
        };
    }
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
            desc = desc.filter(|d| !d.is_empty()).map(|d| format!(r#"<br><span class="text-xs text-base-content/50" style="white-space:pre-line">{}</span>"#, esc(&d))).unwrap_or_default(),
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
        "SELECT number, state, customer_id, order_date, company_id, customer_invoice_move_id, \
                payment_term_id \
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
    // Due date from the order's payment term (invoice date + term days).
    let payment_term_id: Option<Uuid> = po.try_get("payment_term_id").ok().flatten();
    let due_date =
        vortex_accounting::handlers_payment_terms::due_date_for(&db, payment_term_id, invoice_date)
            .await;

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
                l.unit_price, l.discount_percent, l.tax_id, l.product_id, \
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

    // Whole-quote discount: bill the discounted price so partial invoices sum
    // back to the quoted total. The factor is order-level (derived from the FULL
    // order subtotal), so every partial invoice carries its proportional share.
    let (gd_type, gd_value) = order_global_discount(&db, id).await;
    let full_subtotal: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COALESCE(SUM(quantity * unit_price * (100 - discount_percent) / 100), 0) \
         FROM sales_order_line WHERE order_id = $1 AND display_type IS NULL",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(Decimal::ZERO);
    let g_factor = global_factor(gd_type.as_deref(), gd_value, full_subtotal);

    let mut lines = Vec::new();
    let mut billed: Vec<(Uuid, Decimal)> = Vec::new();
    for r in &line_rows {
        let line_id: Uuid = r.get("id");
        // Order-line descriptions are rich TEXT (formatted, multi-line); the
        // accounting invoice-line description is a bounded plain VARCHAR(255),
        // so strip formatting to plain text and cap the length.
        let name: String = crate::richtext::strip_tags(&r.get::<String, _>("name"))
            .chars()
            .take(255)
            .collect();
        let quantity: Decimal = r.get("billable");
        // Bill the net-of-discount unit price (per-line discount then the
        // whole-quote factor, both applied before tax).
        let list_price: Decimal = r.get("unit_price");
        let discount: Decimal = r.try_get("discount_percent").unwrap_or(Decimal::ZERO);
        let unit_price = (list_price * (Decimal::from(100) - discount) / Decimal::from(100) * g_factor).round_dp(4);
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
            due_date,
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

// ─────────────────────────────────────────────────────────────────────────
// Notes / Terms template library (Sales ▸ Configuration)
// ─────────────────────────────────────────────────────────────────────────

/// Sync the contenteditable body into the form's hidden field on submit.
const TPL_SUBMIT_JS: &str = r#"var f=document.getElementById('tpl-form'); if(f){ f.addEventListener('submit', function(){ document.querySelector('[name=body]').value = document.getElementById('tpl-body').innerHTML; }); }"#;

async fn list_note_templates(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let config = ListConfig::new("Terms Templates", "sales_note_template")
        .custom_select("id, name, active")
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("name"))
        .column(ListColumn::new("active", "Status").bool_badge("Active", "badge-success", "Archived", "badge-warning").sql_expr("active"))
        .detail_url("/sales/note-templates/{id}")
        .create("New Template", "/sales/note-templates/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error = %e, "note template list failed"); return Html("<h1>Failed to load templates</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/sales/note-templates");
    Html(page_shell(&sidebar, "Terms Templates", &list_html)).into_response()
}

fn note_template_form_body(action: &str, title: &str, name: &str, body: &str, active: bool, is_new: bool) -> String {
    let active_box = if is_new { String::new() } else {
        format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="active" class="checkbox checkbox-sm" {}/><span class="label-text">Active (offered in the quote editor)</span></label></div>"#, if active { "checked" } else { "" })
    };
    // Standard record entry form → canonical Odoo-style sheet. The rich-text
    // <style> head and the sticky editing toolbar stay above the form (they act
    // on the contenteditable body inside the sheet), so they ride in the sheet's
    // control row; the editor + submit-sync scripts follow the sheet verbatim.
    let fields = format!(
        r##"<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name}" required placeholder="e.g. Standard payment terms"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Body</span></label>
<div id="tpl-body" contenteditable="true" data-ph="Type the terms… use the toolbar above for bold / colour / tables" class="rt-field textarea textarea-bordered leading-snug" style="min-height:12rem">{body}</div>
<input type="hidden" name="body"/></div>
{active_box}"##,
        name = name, body = body, active_box = active_box,
    );
    let sheet = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/sales/note-templates",
        control_row: &format!("{rt_head}{rt_toolbar}", rt_head = RICH_TEXT_HEAD, rt_toolbar = RICH_TOOLBAR_HTML),
        form_attrs: &format!(r#"method="POST" action="{action}" id="tpl-form""#, action = action),
        title,
        inner: &vortex_plugin_sdk::framework::form_section_raw("", &fields),
        footer: r#"<a href="/sales/note-templates" class="btn btn-ghost btn-sm">Cancel</a><button class="btn btn-primary btn-sm">Save</button>"#,
        below: "",
    });
    format!(
        r#"{sheet}
<script>{rt_js}</script>
<script>{sync_js}</script>"#,
        sheet = sheet,
        rt_js = RICH_TEXT_JS,
        sync_js = TPL_SUBMIT_JS,
    )
}

async fn new_note_template_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let body = note_template_form_body("/sales/note-templates/create", "New Terms Template", "", "", true, true);
    Html(page_shell(&sidebar, "New Terms Template", &body)).into_response()
}

async fn create_note_template(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let name = form.get("name").map(|s| s.trim().to_string()).unwrap_or_default();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    // Body is user rich text → sanitize to the allow-list before storing.
    let body = crate::richtext::sanitize_rich(form.get("body").map(|s| s.as_str()).unwrap_or(""));
    let company_id = default_company(&db).await;
    let tpl_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO sales_note_template (id, name, body, company_id) VALUES ($1,$2,$3,$4)",
    )
    .bind(tpl_id).bind(&name).bind(&body).bind(company_id)
    .execute(&db).await
    {
        error!(error = %e, "note template insert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create template: {e}")).into_response();
    }
    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("sales_note_template", tpl_id.to_string())
    .with_resource_name(&name);
    let _ = state.audit.log(audit_entry).await;
    vortex_plugin_sdk::axum::response::Redirect::to("/sales/note-templates").into_response()
}

async fn edit_note_template(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, body, active FROM sales_note_template WHERE id = $1")
        .bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        _ => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let name: String = row.get("name");
    let body: String = row.try_get("body").unwrap_or_default();
    let active: bool = row.try_get("active").unwrap_or(true);
    // Re-sanitize on the way out (defense in depth) before raw-embedding.
    let body_safe = crate::richtext::sanitize_rich(&body);
    // Title is HTML-escaped by render_form_sheet, so pass the raw name here
    // (the name field value below is still escaped for its raw-embedded input).
    let content = note_template_form_body(
        &format!("/sales/note-templates/{id}"), &format!("Edit {}", name),
        &esc(&name), &body_safe, active, false,
    );
    Html(page_shell(&sidebar, "Edit Terms Template", &content)).into_response()
}

async fn update_note_template(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let name = form.get("name").map(|s| s.trim().to_string()).unwrap_or_default();
    if name.is_empty() {
        return (StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let body = crate::richtext::sanitize_rich(form.get("body").map(|s| s.as_str()).unwrap_or(""));
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE sales_note_template SET name=$1, body=$2, active=$3, updated_at=NOW() WHERE id=$4",
    )
    .bind(&name).bind(&body).bind(form.contains_key("active")).bind(id)
    .execute(&db).await
    {
        error!(error = %e, "note template update failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update template: {e}")).into_response();
    }
    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("sales_note_template", id.to_string())
    .with_resource_name(&name);
    let _ = state.audit.log(audit_entry).await;
    vortex_plugin_sdk::axum::response::Redirect::to("/sales/note-templates").into_response()
}

/// JSON array of active Notes/Terms templates for the quote editor's
/// "Apply template" picker (id + name + sanitized body).
async fn note_templates_json(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, body FROM sales_note_template WHERE active ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let arr: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            json!({
                "id": id.to_string(),
                "name": r.get::<String, _>("name"),
                "body": crate::richtext::sanitize_rich(&r.try_get::<String, _>("body").unwrap_or_default()),
            })
        })
        .collect();
    serde_json::to_string(&arr).unwrap_or_else(|_| "[]".into())
}

#[cfg(test)]
mod tests {
    use super::global_factor;
    use vortex_plugin_sdk::rust_decimal::Decimal;

    fn d(n: i64) -> Decimal {
        Decimal::from(n)
    }

    #[test]
    fn no_discount_is_identity() {
        assert_eq!(global_factor(None, d(0), d(300)), Decimal::ONE);
        assert_eq!(global_factor(Some("bogus"), d(10), d(300)), Decimal::ONE);
    }

    #[test]
    fn percent_discount() {
        // 10% off → factor 0.9 (independent of subtotal).
        assert_eq!(global_factor(Some("percent"), d(10), d(300)), d(90) / d(100));
        // Over-100% is clamped → factor 0 (never negative).
        assert_eq!(global_factor(Some("percent"), d(150), d(300)), Decimal::ZERO);
    }

    #[test]
    fn fixed_discount() {
        // 50 off a 300 subtotal → factor 250/300.
        assert_eq!(global_factor(Some("fixed"), d(50), d(300)), d(250) / d(300));
        // Fixed amount ≥ subtotal is clamped → factor 0, not negative.
        assert_eq!(global_factor(Some("fixed"), d(400), d(300)), Decimal::ZERO);
        // Zero subtotal can't divide → identity.
        assert_eq!(global_factor(Some("fixed"), d(50), d(0)), Decimal::ONE);
    }
}
