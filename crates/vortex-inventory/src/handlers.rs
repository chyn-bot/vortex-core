//! Inventory CRUD handlers — products, locations, stock moves, and the
//! on-hand view. Built on the same core primitives the contacts plugin
//! demonstrates (list framework, sequences, audit ledger, field
//! tracker), rendered inside the platform's sidebar shell.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

/// Product code sequence — `PRD/000001`.
const PRODUCT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("inventory.product", "PRD").with_padding(6);

/// Stock-move reference sequence — `MOV/000001`.
const MOVE_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("inventory.move", "MOV").with_padding(6);

/// Build the inventory route set.
pub fn inventory_routes() -> Router<Arc<AppState>> {
    Router::new()
        // Products (primary landing at /inventory)
        .route("/inventory", get(list_products))
        .route("/inventory/products/new", get(new_product_form))
        .route("/inventory/products/create", post(create_product))
        .route("/inventory/products/{id}", get(edit_product))
        .route("/inventory/products/{id}", post(update_product))
        .route("/inventory/products/{id}/delete", post(delete_product))
        .route("/inventory/products/{id}/duplicate", post(duplicate_product))
        // Product categories (configuration)
        .route("/inventory/categories", get(list_categories))
        .route("/inventory/categories/new", get(new_category_form))
        .route("/inventory/categories/create", post(create_category))
        .route("/inventory/categories/{id}", get(edit_category))
        .route("/inventory/categories/{id}", post(update_category))
        // Locations
        .route("/inventory/locations", get(list_locations))
        .route("/inventory/locations/new", get(new_location_form))
        .route("/inventory/locations/create", post(create_location))
        .route("/inventory/locations/{id}", get(edit_location))
        .route("/inventory/locations/{id}", post(update_location))
        .route("/inventory/locations/{id}/delete", post(delete_location))
        // Units of measure (configuration)
        .route("/inventory/uoms", get(list_uoms))
        .route("/inventory/uoms/new", get(new_uom_form))
        .route("/inventory/uoms/create", post(create_uom))
        .route("/inventory/uoms/{id}", get(edit_uom))
        .route("/inventory/uoms/{id}", post(update_uom))
        // Stock moves
        .route("/inventory/moves", get(list_moves))
        .route("/inventory/moves/new", get(new_move_form))
        .route("/inventory/moves/create", post(create_move))
        .route("/inventory/moves/{id}/validate", post(validate_move))
        .route("/inventory/moves/{id}/cancel", post(cancel_move))
        // Lots / serials
        .route("/inventory/lots", get(list_lots))
        .route("/inventory/lots/new", get(new_lot_form))
        .route("/inventory/lots/create", post(create_lot))
        .route("/inventory/lots/{id}", get(edit_lot))
        .route("/inventory/lots/{id}", post(update_lot))
        // Stock adjustment wizard
        .route("/inventory/adjust", get(adjust_form))
        .route("/inventory/adjust", post(apply_adjustment))
        // On-hand
        .route("/inventory/onhand", get(list_onhand))
}

// ─────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────

/// Wrap page content in the platform's full HTML shell (sidebar, navbar,
/// theme, responsive layout). Mirrors the contacts plugin shell.
fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
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

/// Build the platform sidebar with "inventory" as the active module.
fn render_sidebar(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext) -> String {
    render_sidebar_active(state, user, db_ctx, "inventory")
}

/// Build the sidebar marking a specific menu-entry id active — used for
/// sub-menu pages (e.g. `inventory.categories`) so the Configuration
/// branch auto-expands and the exact item highlights.
fn render_sidebar_active(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext, active: &str) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    vortex_plugin_sdk::framework::build_sidebar(
        active,
        display_name,
        &initials,
        &db_ctx.installed_modules,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
        "",
    )
}

/// Default company id (single-tenant convenience, same as contacts).
async fn default_company(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// `<option>` list of active UoMs, marking `selected` the given id.
async fn uom_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query("SELECT id, name, code FROM uoms WHERE active ORDER BY name")
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Unit --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        let code: String = r.get("code");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{name} ({code})</option>"#,
            id = id,
            sel = sel,
            name = esc(&name),
            code = esc(&code),
        ));
    }
    out
}

/// `<option>` list of active product categories.
async fn category_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name FROM stock_product_category WHERE active ORDER BY name",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Category --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{name}</option>"#,
            id = id,
            sel = sel,
            name = esc(&name),
        ));
    }
    out
}

/// `<option>` list of active locations, optionally filtered by type.
async fn location_options(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    selected: Option<Uuid>,
) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, location_type FROM stock_location WHERE active ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Location --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        let ltype: String = r.get("location_type");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{code} · {name} ({ltype})</option>"#,
            id = id,
            sel = sel,
            code = esc(&code),
            name = esc(&name),
            ltype = esc(&ltype),
        ));
    }
    out
}

/// `<option>` list of active **internal** locations only (where real
/// on-hand lives). Used by the stock-adjustment wizard.
async fn internal_location_options(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM stock_location \
         WHERE active AND location_type = 'internal' ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Location --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        out.push_str(&format!(
            r#"<option value="{id}">{code} · {name}</option>"#,
            id = id, code = esc(&code), name = esc(&name),
        ));
    }
    out
}

/// Parse a form string into a Decimal, defaulting to zero.
fn dec(form: &HashMap<String, String>, key: &str) -> Decimal {
    form.get(key)
        .and_then(|s| s.trim().parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO)
}

/// Parse an optional UUID form field (empty → None).
fn opt_uuid(form: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    form.get(key).filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
}

/// Apply a signed quantity delta to the on-hand balance for a
/// (product, location, lot) triple, creating the quant row if absent.
/// `lot_id` is `None` for untracked products. `IS NOT DISTINCT FROM`
/// matches the NULL-lot row correctly; the unique index on
/// (product, location, COALESCE(lot, sentinel)) keeps it singular.
pub(crate) async fn adjust_quant(
    conn: &mut vortex_plugin_sdk::sqlx::PgConnection,
    product_id: Uuid,
    location_id: Uuid,
    lot_id: Option<Uuid>,
    delta: Decimal,
    company_id: Option<Uuid>,
) -> Result<(), vortex_plugin_sdk::sqlx::Error> {
    let updated = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_quant SET quantity = quantity + $1, updated_at = NOW() \
         WHERE product_id = $2 AND location_id = $3 AND lot_id IS NOT DISTINCT FROM $4",
    )
    .bind(delta)
    .bind(product_id)
    .bind(location_id)
    .bind(lot_id)
    .execute(&mut *conn)
    .await?;

    if updated.rows_affected() == 0 {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO stock_quant (product_id, location_id, lot_id, quantity, company_id) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(product_id)
        .bind(location_id)
        .bind(lot_id)
        .bind(delta)
        .bind(company_id)
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────
// Products
// ─────────────────────────────────────────────────────────────────────────


/// "Document Defaults" card shared by the product forms — soft links
/// into the accounting plugin's chart/catalogues (queries fail
/// gracefully to empty pickers when accounting is absent) plus core
/// taxes. `sel_*` = current values on the edit form.
#[allow(clippy::too_many_arguments)]
async fn doc_defaults_card(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    sel_class: Option<&str>,
    sel_income: Option<Uuid>,
    sel_expense: Option<Uuid>,
    sel_sales_tax: Option<Uuid>,
    sel_purchase_tax: Option<Uuid>,
) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let account_opts = |rows: &[(Uuid, String)], sel: Option<Uuid>| {
        let mut out = String::from("<option value=\"\">— company default —</option>");
        for (id, label) in rows {
            let s = if sel == Some(*id) { " selected" } else { "" };
            out.push_str(&format!("<option value=\"{id}\"{s}>{}</option>", esc(label)));
        }
        out
    };
    let fetch_accounts = |types: &'static str| {
        let db = db.clone();
        async move {
            vortex_plugin_sdk::sqlx::query(&format!(
                "SELECT id, code, name FROM acc_account WHERE active AND account_type IN {types} ORDER BY code"
            ))
            .fetch_all(&db)
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| {
                (
                    r.get::<Uuid, _>("id"),
                    format!("{} {}", r.get::<String, _>("code"), r.get::<String, _>("name")),
                )
            })
            .collect::<Vec<_>>()
        }
    };
    let income = fetch_accounts("('income', 'income_other')").await;
    let expense = fetch_accounts(
        "('expense', 'expense_direct_cost', 'expense_depreciation', 'asset_fixed', 'asset_current', 'asset_non_current')",
    )
    .await;
    let tax_opts = |use_kind: &str, sel: Option<Uuid>| {
        let db = db.clone();
        let use_kind = use_kind.to_string();
        async move {
            let rows = vortex_plugin_sdk::sqlx::query(
                "SELECT id, name FROM taxes WHERE active AND type_tax_use IN ($1, 'none') ORDER BY name",
            )
            .bind(&use_kind)
            .fetch_all(&db)
            .await
            .unwrap_or_default();
            let mut out = String::from("<option value=\"\">— none —</option>");
            for r in &rows {
                let id: Uuid = r.get("id");
                let s = if sel == Some(id) { " selected" } else { "" };
                out.push_str(&format!(
                    "<option value=\"{id}\"{s}>{}</option>",
                    vortex_plugin_sdk::framework::html_escape(&r.get::<String, _>("name"))
                ));
            }
            out
        }
    };
    let sales_tax = tax_opts("sale", sel_sales_tax).await;
    let purchase_tax = tax_opts("purchase", sel_purchase_tax).await;
    // LHDN classification catalogue (accounting plugin) — datalist.
    let class_opts: String = vortex_plugin_sdk::sqlx::query(
        "SELECT code, description FROM acc_lhdn_code WHERE code_type = 'classification' AND active ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| {
        format!(
            "<option value=\"{}\">{}</option>",
            esc(&r.get::<String, _>("code")),
            esc(&r.get::<String, _>("description")),
        )
    })
    .collect();
    let gl_block = if income.is_empty() && expense.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Income GL Account (sales)</span></label>
<select name="income_account_id" class="select select-bordered select-sm">{}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Expense GL Account (purchases)</span></label>
<select name="expense_account_id" class="select select-bordered select-sm">{}</select>
</div>
</div>"#,
            account_opts(&income, sel_income),
            account_opts(&expense, sel_expense),
        )
    };
    format!(
        r#"<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-4">Document Defaults</h2>
<p class="text-xs opacity-60 mb-2">Applied automatically when this product is picked on an invoice, bill or order line.</p>
{gl_block}
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Sales Tax</span></label>
<select name="sales_tax_id" class="select select-bordered select-sm">{sales_tax}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Purchase Tax</span></label>
<select name="purchase_tax_id" class="select select-bordered select-sm">{purchase_tax}</select>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">LHDN e-Invoice Classification</span></label>
<input name="classification_code" value="{class_val}" list="dl-prod-class" placeholder="e.g. 022" class="input input-bordered input-sm font-mono"/>
<datalist id="dl-prod-class">{class_opts}</datalist>
</div>
</div></div>"#,
        class_val = esc(sel_class.unwrap_or("")),
    )
}

async fn list_products(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("Products", "stock_product")
        .custom_from(
            "stock_product p \
             LEFT JOIN stock_product_category c ON c.id = p.category_id \
             LEFT JOIN uoms u ON u.id = p.uom_id \
             LEFT JOIN ( \
                 SELECT q.product_id, COALESCE(SUM(q.quantity),0) AS on_hand \
                 FROM stock_quant q JOIN stock_location l ON l.id = q.location_id \
                 WHERE l.location_type = 'internal' GROUP BY q.product_id \
             ) oh ON oh.product_id = p.id",
        )
        .custom_select(
            "p.id, p.code, p.name, c.name AS category_name, \
             p.product_type, p.tracking, u.code AS uom_code, \
             p.cost::text AS cost, COALESCE(oh.on_hand,0)::text AS on_hand, p.active",
        )
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("p.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("p.name"))
        .column(ListColumn::new("category_name", "Category").sortable().searchable().sql_expr("c.name"))
        .column(
            ListColumn::new("product_type", "Type")
                .filterable(&[
                    ("stockable", "Stockable"),
                    ("consumable", "Consumable"),
                    ("service", "Service"),
                ])
                .badge(&[
                    ("stockable", "Stockable", "badge-info"),
                    ("consumable", "Consumable", "badge-secondary"),
                    ("service", "Service", "badge-ghost"),
                ])
                .sql_expr("p.product_type"),
        )
        .column(ListColumn::new("uom_code", "Unit").sql_expr("u.code"))
        .column(ListColumn::new("on_hand", "On Hand").sortable().sql_expr("COALESCE(oh.on_hand,0)"))
        .column(ListColumn::new("cost", "Cost").sortable().sql_expr("p.cost"))
        .column(
            ListColumn::new("active", "Status").bool_badge(
                "Active", "badge-success", "Archived", "badge-warning",
            ).sql_expr("p.active"),
        )
        .detail_url("/inventory/products/{id}")
        .create("New Product", "/inventory/products/new")
        .pivot_url("/pivot/stock_product?rows=product_type")
        .default_sort("code")
        .group_by_options(&[
            ("category_name", "Category"),
            ("product_type", "Type"),
            ("active", "Status"),
        ]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "products list query failed");
            return Html("<h1>Failed to load products</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/inventory");
    let toolbar = r#"<div class="flex justify-end mb-3"><a href="/inventory/categories" class="btn btn-ghost btn-sm">Manage Categories</a></div>"#;
    Html(page_shell(&sidebar, "Products", &format!("{}{}", toolbar, list_html))).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Product categories (configuration)
// ─────────────────────────────────────────────────────────────────────────

async fn list_categories(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "inventory.categories");
    let config = ListConfig::new("Product Categories", "stock_product_category")
        .custom_from("stock_product_category c LEFT JOIN stock_product_category p ON p.id = c.parent_id")
        .custom_select("c.id, c.name, p.name AS parent_name, c.active")
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("c.name"))
        .column(ListColumn::new("parent_name", "Parent").sql_expr("p.name"))
        .column(ListColumn::new("active", "Status").bool_badge("Active", "badge-success", "Archived", "badge-warning").sql_expr("c.active"))
        .detail_url("/inventory/categories/{id}")
        .create("New Category", "/inventory/categories/new")
        .default_sort("name");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error = %e, "product category list failed"); return Html("<h1>Failed to load categories</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/inventory/categories");
    Html(page_shell(&sidebar, "Product Categories", &list_html)).into_response()
}

fn category_form_body(action: &str, title: &str, name: &str, parents: &str, active: bool, is_new: bool) -> String {
    let active_box = if is_new { String::new() } else {
        format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="active" class="checkbox checkbox-sm" {}/><span class="label-text">Active</span></label></div>"#, if active { "checked" } else { "" })
    };
    format!(
        r#"<div class="max-w-xl">
<a href="/inventory/categories" class="btn btn-ghost btn-sm mb-4">← Back to Categories</a>
<h1 class="text-2xl font-bold mb-6">{title}</h1>
<form method="POST" action="{action}">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parent Category</span></label>
<select name="parent_id" class="select select-bordered select-sm">{parents}</select></div>
{active_box}
<div class="flex gap-2"><button class="btn btn-primary btn-sm">Save</button>
<a href="/inventory/categories" class="btn btn-ghost btn-sm">Cancel</a></div>
</div></div></form></div>"#,
        title = title, action = action, name = name, parents = parents, active_box = active_box,
    )
}

async fn new_category_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let parents = category_options(&db, None).await;
    let body = category_form_body("/inventory/categories/create", "New Category", "", &parents, true, true);
    Html(page_shell(&sidebar, "New Category", &body)).into_response()
}

async fn create_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let company_id = default_company(&db).await;
    let category_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query("INSERT INTO stock_product_category (id, name, parent_id, company_id) VALUES ($1,$2,$3,$4)")
        .bind(category_id).bind(&name).bind(opt_uuid(&form, "parent_id")).bind(company_id)
        .execute(&db).await
    {
        error!(error = %e, "product category insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create category: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_product_category", category_id.to_string())
    .with_resource_name(&name);
    if let Err(e) = state.audit.log(audit_entry).await {
        error!(error = %e, "audit log for category creation failed");
    }

    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/categories").into_response()
}

async fn edit_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, parent_id, active FROM stock_product_category WHERE id = $1")
        .bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        _ => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let name: String = row.get("name");
    let parent_id: Option<Uuid> = row.try_get("parent_id").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let parents = category_options(&db, parent_id).await;
    let body = category_form_body(&format!("/inventory/categories/{id}"), &format!("Edit {}", name), &esc(&name), &parents, active, false);
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("stock_category", id);
    let content = format!(r#"{body}<div class="mt-6">{activity_panel}</div>"#);
    Html(page_shell(&sidebar, "Edit Category", &content)).into_response()
}

async fn update_category(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let parent_id = opt_uuid(&form, "parent_id").filter(|p| *p != id);
    if let Err(e) = vortex_plugin_sdk::sqlx::query("UPDATE stock_product_category SET name=$1, parent_id=$2, active=$3, updated_at=NOW() WHERE id=$4")
        .bind(&name).bind(parent_id).bind(form.contains_key("active")).bind(id)
        .execute(&db).await
    {
        error!(error = %e, "product category update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update category: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_product_category", id.to_string())
    .with_resource_name(&name);
    if let Err(e) = state.audit.log(audit_entry).await {
        error!(error = %e, "audit log for category update failed");
    }

    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/categories").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Units of measure (configuration) — the master list every commerce module
// (sales/purchase/inventory) draws its per-line units from.
// ─────────────────────────────────────────────────────────────────────────

/// `<option>` list of UoM categories (Unit, Weight, Length, …).
async fn uom_category_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query("SELECT id, name FROM uom_categories WHERE active ORDER BY name")
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Category --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let name: String = r.get("name");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(r#"<option value="{id}"{sel}>{name}</option>"#, id = id, sel = sel, name = esc(&name)));
    }
    out
}

/// `<option>` list of the three UoM roles.
fn uom_type_options(selected: &str) -> String {
    let sel = |v: &str| if selected == v { " selected" } else { "" };
    format!(
        concat!(
            r#"<option value="reference"{r}>Reference (base unit of its category)</option>"#,
            r#"<option value="bigger"{b}>Bigger than the reference</option>"#,
            r#"<option value="smaller"{s}>Smaller than the reference</option>"#,
        ),
        r = sel("reference"), b = sel("bigger"), s = sel("smaller"),
    )
}

async fn list_uoms(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "inventory.uoms");
    let config = ListConfig::new("Units of Measure", "uoms")
        .custom_from("uoms u JOIN uom_categories c ON c.id = u.category_id")
        .custom_select("u.id, u.code, u.name, c.name AS category, u.uom_type, u.factor::text AS factor, u.active")
        .column(ListColumn::new("code", "Code").sortable().searchable().code().sql_expr("u.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("u.name"))
        .column(ListColumn::new("category", "Category").sortable().sql_expr("c.name"))
        .column(ListColumn::new("uom_type", "Type").sql_expr("u.uom_type"))
        .column(ListColumn::new("factor", "Factor").sql_expr("u.factor"))
        .column(ListColumn::new("active", "Status").bool_badge("Active", "badge-success", "Archived", "badge-warning").sql_expr("u.active"))
        .detail_url("/inventory/uoms/{id}")
        .create("New Unit", "/inventory/uoms/new")
        .default_sort("category");
    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => { error!(error = %e, "uom list failed"); return Html("<h1>Failed to load units</h1>").into_response(); }
    };
    let list_html = render_list(&config, &result, &params, "/inventory/uoms");
    Html(page_shell(&sidebar, "Units of Measure", &list_html)).into_response()
}

#[allow(clippy::too_many_arguments)]
fn uom_form_body(
    action: &str, title: &str, name: &str, code: &str, categories: &str,
    type_opts: &str, factor: &str, active: bool, is_new: bool,
) -> String {
    let active_box = if is_new { String::new() } else {
        format!(r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="active" class="checkbox checkbox-sm" {}/><span class="label-text">Active (shown in unit pickers)</span></label></div>"#, if active { "checked" } else { "" })
    };
    format!(
        r#"<div class="max-w-xl">
<a href="/inventory/uoms" class="btn btn-ghost btn-sm mb-4">← Back to Units</a>
<h1 class="text-2xl font-bold mb-6">{title}</h1>
<form method="POST" action="{action}">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Code *</span></label>
<input name="code" class="input input-bordered input-sm" value="{code}" required placeholder="e.g. box"/></div>
</div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Category *</span></label>
<select name="category_id" class="select select-bordered select-sm" required>{categories}</select></div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3"><label class="label"><span class="label-text">Type</span></label>
<select name="uom_type" class="select select-bordered select-sm">{type_opts}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Factor</span></label>
<input name="factor" type="number" step="0.0000000001" min="0" class="input input-bordered input-sm" value="{factor}"/></div>
</div>
<p class="text-xs text-base-content/60 mb-3">The <b>factor</b> is how many reference units one of this unit equals (1 dozen = 12 units → factor 12). Keep exactly one <b>Reference</b> unit per category. For a simple count unit that isn't converted, a factor of 1 is fine.</p>
{active_box}
<div class="flex gap-2"><button class="btn btn-primary btn-sm">Save</button>
<a href="/inventory/uoms" class="btn btn-ghost btn-sm">Cancel</a></div>
</div></div></form></div>"#,
        title = title, action = action, name = name, code = code, categories = categories,
        type_opts = type_opts, factor = factor, active_box = active_box,
    )
}

async fn new_uom_form(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let categories = uom_category_options(&db, None).await;
    let body = uom_form_body(
        "/inventory/uoms/create", "New Unit", "", "", &categories,
        &uom_type_options("bigger"), "1", true, true,
    );
    Html(page_shell(&sidebar, "New Unit", &body)).into_response()
}

async fn create_uom(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let name = form.get("name").map(|s| s.trim().to_string()).unwrap_or_default();
    let code = form.get("code").map(|s| s.trim().to_string()).unwrap_or_default();
    let Some(category_id) = opt_uuid(&form, "category_id") else {
        return (StatusCode::BAD_REQUEST, "Category is required").into_response();
    };
    if name.is_empty() || code.is_empty() {
        return (StatusCode::BAD_REQUEST, "Name and code are required").into_response();
    }
    let uom_type = uom_type_value(&form);
    let factor = form.get("factor").and_then(|f| f.trim().parse::<Decimal>().ok()).unwrap_or(Decimal::ONE);
    // Friendlier than a raw unique-violation 500.
    let taken: bool = vortex_plugin_sdk::sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM uoms WHERE code = $1)")
        .bind(&code).fetch_one(&db).await.unwrap_or(false);
    if taken {
        return (StatusCode::CONFLICT, format!("The code '{code}' is already in use — pick another.")).into_response();
    }
    let uom_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO uoms (id, category_id, name, code, factor, uom_type) VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(uom_id).bind(category_id).bind(&name).bind(&code).bind(factor).bind(&uom_type)
    .execute(&db).await
    {
        error!(error = %e, "uom insert failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create unit: {e}")).into_response();
    }
    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("uom", uom_id.to_string())
    .with_resource_name(&name);
    if let Err(e) = state.audit.log(audit_entry).await {
        error!(error = %e, "audit log for uom creation failed");
    }
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/uoms").into_response()
}

async fn edit_uom(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let row = match vortex_plugin_sdk::sqlx::query("SELECT name, code, category_id, uom_type, factor::text AS factor, active FROM uoms WHERE id = $1")
        .bind(id).fetch_optional(&db).await {
        Ok(Some(r)) => r,
        _ => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let name: String = row.get("name");
    let code: String = row.get("code");
    let category_id: Option<Uuid> = row.try_get("category_id").ok();
    let uom_type: String = row.try_get("uom_type").unwrap_or_else(|_| "bigger".into());
    let factor: String = row.try_get("factor").unwrap_or_else(|_| "1".into());
    let active: bool = row.try_get("active").unwrap_or(true);
    let categories = uom_category_options(&db, category_id).await;
    let body = uom_form_body(
        &format!("/inventory/uoms/{id}"), &format!("Edit {}", name),
        &esc(&name), &esc(&code), &categories, &uom_type_options(&uom_type), &esc(&factor), active, false,
    );
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("uom", id);
    let content = format!(r#"{body}<div class="mt-6">{activity_panel}</div>"#);
    Html(page_shell(&sidebar, "Edit Unit", &content)).into_response()
}

async fn update_uom(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::axum::http::StatusCode;
    let name = form.get("name").map(|s| s.trim().to_string()).unwrap_or_default();
    let code = form.get("code").map(|s| s.trim().to_string()).unwrap_or_default();
    let Some(category_id) = opt_uuid(&form, "category_id") else {
        return (StatusCode::BAD_REQUEST, "Category is required").into_response();
    };
    if name.is_empty() || code.is_empty() {
        return (StatusCode::BAD_REQUEST, "Name and code are required").into_response();
    }
    let uom_type = uom_type_value(&form);
    let factor = form.get("factor").and_then(|f| f.trim().parse::<Decimal>().ok()).unwrap_or(Decimal::ONE);
    // Guard the unique code against a *different* row.
    let taken: bool = vortex_plugin_sdk::sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM uoms WHERE code = $1 AND id <> $2)")
        .bind(&code).bind(id).fetch_one(&db).await.unwrap_or(false);
    if taken {
        return (StatusCode::CONFLICT, format!("The code '{code}' is already in use — pick another.")).into_response();
    }
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE uoms SET name=$1, code=$2, category_id=$3, uom_type=$4, factor=$5, active=$6 WHERE id=$7",
    )
    .bind(&name).bind(&code).bind(category_id).bind(&uom_type).bind(factor).bind(form.contains_key("active")).bind(id)
    .execute(&db).await
    {
        error!(error = %e, "uom update failed");
        return (StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update unit: {e}")).into_response();
    }
    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("uom", id.to_string())
    .with_resource_name(&name);
    if let Err(e) = state.audit.log(audit_entry).await {
        error!(error = %e, "audit log for uom update failed");
    }
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/uoms").into_response()
}

/// Read a valid `uom_type` from the form, defaulting to `bigger`.
fn uom_type_value(form: &HashMap<String, String>) -> String {
    match form.get("uom_type").map(|s| s.as_str()) {
        Some("reference") => "reference",
        Some("smaller") => "smaller",
        _ => "bigger",
    }
    .to_string()
}

async fn new_product_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let categories = category_options(&db, None).await;
    let uoms = uom_options(&db, None).await;
    let doc_defaults = doc_defaults_card(&db, None, None, None, None, None).await;

    let content = format!(
        r#"<div class="max-w-2xl">
<a href="/inventory" class="btn btn-ghost btn-sm mb-4">← Back to Products</a>
<h1 class="text-2xl font-bold mb-6">New Product</h1>
<form method="POST" action="/inventory/products/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" required/>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="product_type" class="select select-bordered select-sm">
<option value="stockable">Stockable</option>
<option value="consumable">Consumable</option>
<option value="service">Service</option>
</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Tracking</span></label>
<select name="tracking" class="select select-bordered select-sm">
<option value="none">None</option>
<option value="lot">By Lot</option>
<option value="serial">By Serial</option>
</select>
</div>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Category</span></label>
<select name="category_id" class="select select-bordered select-sm">{categories}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Unit of Measure</span></label>
<select name="uom_id" class="select select-bordered select-sm">{uoms}</select>
</div>
</div>
<div class="grid grid-cols-3 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Cost</span></label>
<input name="cost" type="number" step="0.0001" class="input input-bordered input-sm" value="0"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Sale Price</span></label>
<input name="list_price" type="number" step="0.01" class="input input-bordered input-sm" value="0" placeholder="0 = use cost"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Reorder Min</span></label>
<input name="reorder_min" type="number" step="0.0001" class="input input-bordered input-sm" value="0"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Reorder Max</span></label>
<input name="reorder_max" type="number" step="0.0001" class="input input-bordered input-sm" value="0"/>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Barcode</span></label>
<input name="barcode" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered" rows="2"></textarea>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Sales Description</span></label>
<textarea name="sales_description" class="textarea textarea-bordered" rows="2" placeholder="Line text on customer invoices — empty uses the product name"></textarea>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Purchase Description</span></label>
<textarea name="purchase_description" class="textarea textarea-bordered" rows="2" placeholder="Line text on POs and vendor bills — empty uses the product name"></textarea>
</div>
</div>
</div></div>
{doc_defaults}
<div class="flex gap-2 mt-4">
<button type="submit" class="btn btn-primary btn-sm">Create</button>
<a href="/inventory" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</form>
</div>"#,
        categories = categories,
        uoms = uoms,
    );

    Html(page_shell(&sidebar, "New Product", &content)).into_response()
}

async fn create_product(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }
    let product_type = form.get("product_type").cloned().unwrap_or_else(|| "stockable".into());
    let tracking = form.get("tracking").cloned().unwrap_or_else(|| "none".into());

    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &PRODUCT_SEQ).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "product sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate product code").into_response();
        }
    };

    let Some(company_id) = default_company(&db).await else {
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "No company found").into_response();
    };

    let product_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_product \
         (id, code, name, barcode, description, category_id, product_type, uom_id, \
          tracking, cost, reorder_min, reorder_max, sales_description, \
          purchase_description, classification_code, income_account_id, \
          expense_account_id, sales_tax_id, purchase_tax_id, list_price, \
          company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)",
    )
    .bind(product_id)
    .bind(&code)
    .bind(&name)
    .bind(form.get("barcode").filter(|s| !s.is_empty()))
    .bind(form.get("description").filter(|s| !s.is_empty()))
    .bind(opt_uuid(&form, "category_id"))
    .bind(&product_type)
    .bind(opt_uuid(&form, "uom_id"))
    .bind(&tracking)
    .bind(dec(&form, "cost"))
    .bind(dec(&form, "reorder_min"))
    .bind(dec(&form, "reorder_max"))
    .bind(form.get("sales_description").filter(|s| !s.is_empty()))
    .bind(form.get("purchase_description").filter(|s| !s.is_empty()))
    .bind(form.get("classification_code").map(|s| s.trim()).filter(|s| !s.is_empty()))
    .bind(opt_uuid(&form, "income_account_id"))
    .bind(opt_uuid(&form, "expense_account_id"))
    .bind(opt_uuid(&form, "sales_tax_id"))
    .bind(opt_uuid(&form, "purchase_tax_id"))
    .bind(dec(&form, "list_price"))
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "product insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create product: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_product", product_id.to_string())
    .with_resource_name(&name)
    .with_details(json!({ "code": code, "product_type": product_type }));
    if let Err(e) = state.audit.log(audit_entry).await {
        error!(error = %e, "audit log for product creation failed");
    }

    info!(code = %code, name = %name, "product created");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory").into_response()
}

/// Tracked fields for the product audit trail (Odoo-style `tracking=True`).
fn product_tracker() -> vortex_plugin_sdk::framework::Tracker {
    use vortex_plugin_sdk::framework::Tracker;
    Tracker::new("stock_product")
        .text("name", "Name")
        .text("barcode", "Barcode")
        .text("description", "Description")
        .selection("product_type", "Type")
        .selection("tracking", "Tracking")
        .money("cost", "Cost")
        .boolean("active", "Status", "Active", "Archived")
        .reference("category_id", "Category", "stock_product_category")
        .reference("uom_id", "Unit", "uoms")
}

async fn edit_product(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, barcode, description, sales_description, purchase_description, classification_code, income_account_id, expense_account_id, sales_tax_id, purchase_tax_id, list_price, category_id, product_type, \
         uom_id, tracking, cost, reorder_min, reorder_max, active \
         FROM stock_product WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Product not found").into_response(),
        Err(e) => {
            error!(error = %e, "product fetch failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let code: String = row.get("code");
    let name: String = row.get("name");
    let barcode: Option<String> = row.try_get("barcode").ok();
    let description: Option<String> = row.try_get("description").ok();
    let category_id: Option<Uuid> = row.try_get("category_id").ok();
    let doc_defaults = doc_defaults_card(
        &db,
        row.try_get::<Option<String>, _>("classification_code").ok().flatten().as_deref(),
        row.try_get::<Option<Uuid>, _>("income_account_id").ok().flatten(),
        row.try_get::<Option<Uuid>, _>("expense_account_id").ok().flatten(),
        row.try_get::<Option<Uuid>, _>("sales_tax_id").ok().flatten(),
        row.try_get::<Option<Uuid>, _>("purchase_tax_id").ok().flatten(),
    )
    .await;
    let product_type: String = row.get("product_type");
    let uom_id: Option<Uuid> = row.try_get("uom_id").ok();
    let tracking: String = row.get("tracking");
    let cost: Decimal = row.try_get("cost").unwrap_or(Decimal::ZERO);
    let reorder_min: Decimal = row.try_get("reorder_min").unwrap_or(Decimal::ZERO);
    let reorder_max: Decimal = row.try_get("reorder_max").unwrap_or(Decimal::ZERO);
    let active: bool = row.try_get("active").unwrap_or(true);

    let esc = vortex_plugin_sdk::framework::html_escape;
    let sel = |val: &str, opt: &str| if val == opt { "selected" } else { "" };
    let categories = category_options(&db, category_id).await;
    let uoms = uom_options(&db, uom_id).await;

    // On-hand per internal location for this product.
    let quant_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.code, l.name, q.quantity \
         FROM stock_quant q JOIN stock_location l ON l.id = q.location_id \
         WHERE q.product_id = $1 AND l.location_type = 'internal' AND q.quantity <> 0 \
         ORDER BY l.code",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut onhand_rows = String::new();
    let mut total = Decimal::ZERO;
    for r in &quant_rows {
        let lcode: String = r.get("code");
        let lname: String = r.get("name");
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        total += qty;
        onhand_rows.push_str(&format!(
            "<tr><td class=\"font-mono\">{}</td><td>{}</td><td class=\"text-right\">{}</td></tr>",
            esc(&lcode), esc(&lname), qty
        ));
    }
    if onhand_rows.is_empty() {
        onhand_rows.push_str(r#"<tr><td colspan="3" class="text-base-content/50">No stock on hand</td></tr>"#);
    }

    // Lots / serials panel — only for tracked products.
    let lots_panel = if tracking == "none" {
        String::new()
    } else {
        let lot_rows = vortex_plugin_sdk::sqlx::query(
            "SELECT lo.id, lo.name, COALESCE(oh.on_hand, 0) AS on_hand \
             FROM stock_lot lo \
             LEFT JOIN ( \
                 SELECT q.lot_id, COALESCE(SUM(q.quantity),0) AS on_hand \
                 FROM stock_quant q JOIN stock_location l ON l.id = q.location_id \
                 WHERE l.location_type = 'internal' GROUP BY q.lot_id \
             ) oh ON oh.lot_id = lo.id \
             WHERE lo.product_id = $1 AND lo.active ORDER BY lo.name LIMIT 200",
        )
        .bind(id)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        let mut rows_html = String::new();
        for r in &lot_rows {
            let lid: Uuid = r.get("id");
            let lname: String = r.get("name");
            let qty: Decimal = r.try_get("on_hand").unwrap_or(Decimal::ZERO);
            rows_html.push_str(&format!(
                r#"<tr class="hover cursor-pointer" onclick="window.location='/inventory/lots/{lid}'"><td class="font-mono">{name}</td><td class="text-right">{qty}</td></tr>"#,
                lid = lid, name = esc(&lname), qty = qty,
            ));
        }
        if rows_html.is_empty() {
            rows_html.push_str(r#"<tr><td colspan="2" class="text-base-content/50">No lots/serials yet</td></tr>"#);
        }
        let label = if tracking == "serial" { "Serial Numbers" } else { "Lots" };
        format!(
            r#"<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex items-center justify-between mb-2">
<h2 class="card-title text-lg">{label}</h2>
<a href="/inventory/lots/new" class="btn btn-ghost btn-xs">+ New</a>
</div>
<table class="table table-sm"><thead><tr><th>Number</th><th class="text-right">On Hand</th></tr></thead>
<tbody>{rows_html}</tbody></table>
</div></div>"#,
            label = label,
            rows_html = rows_html,
        )
    };

    let history_panel = vortex_plugin_sdk::framework::render_audit_trail(&db, "stock_product", id).await;
    // Activity stream: schedule/assign/complete tasks, messages, attachments.
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("stock_product", id);

    let content = format!(
        r#"<div class="flex items-center justify-between mb-6">
<div>
<a href="/inventory" class="btn btn-ghost btn-sm mb-2">← Back to Products</a>
<h1 class="text-2xl font-bold">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span></h1>
</div>
<div class="flex items-center gap-2">
{dup_btn}
<form method="POST" action="/inventory/products/{id}/delete" onsubmit="return confirm('Archive this product?')">
<button class="btn btn-error btn-sm btn-outline">Archive</button>
</form>
</div>
</div>

<form method="POST" action="/inventory/products/{id}">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-4">General</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name_val}" required/>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="product_type" class="select select-bordered select-sm">
<option value="stockable" {sel_stk}>Stockable</option>
<option value="consumable" {sel_con}>Consumable</option>
<option value="service" {sel_svc}>Service</option>
</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Tracking</span></label>
<select name="tracking" class="select select-bordered select-sm">
<option value="none" {sel_tnone}>None</option>
<option value="lot" {sel_tlot}>By Lot</option>
<option value="serial" {sel_tser}>By Serial</option>
</select>
</div>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Category</span></label>
<select name="category_id" class="select select-bordered select-sm">{categories}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Unit of Measure</span></label>
<select name="uom_id" class="select select-bordered select-sm">{uoms}</select>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Barcode</span></label>
<input name="barcode" class="input input-bordered input-sm" value="{barcode_val}"/>
</div>
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" {active_checked}/>
<span class="label-text">Active</span>
</label>
</div>
</div></div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-4">Costing & Reordering</h2>
<div class="grid grid-cols-3 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Cost</span></label>
<input name="cost" type="number" step="0.0001" class="input input-bordered input-sm" value="{cost_val}"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Sale Price</span></label>
<input name="list_price" type="number" step="0.01" class="input input-bordered input-sm" value="{list_price_val}" placeholder="0 = use cost"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Reorder Min</span></label>
<input name="reorder_min" type="number" step="0.0001" class="input input-bordered input-sm" value="{rmin_val}"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Reorder Max</span></label>
<input name="reorder_max" type="number" step="0.0001" class="input input-bordered input-sm" value="{rmax_val}"/>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered" rows="2">{desc_val}</textarea>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Sales Description</span></label>
<textarea name="sales_description" class="textarea textarea-bordered" rows="2" placeholder="Line text on customer invoices — empty uses the product name">{sales_desc_val}</textarea>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Purchase Description</span></label>
<textarea name="purchase_description" class="textarea textarea-bordered" rows="2" placeholder="Line text on POs and vendor bills — empty uses the product name">{purchase_desc_val}</textarea>
</div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-4">On Hand <span class="badge badge-ghost">{total}</span></h2>
<table class="table table-sm"><thead><tr><th>Location</th><th>Name</th><th class="text-right">Qty</th></tr></thead>
<tbody>{onhand_rows}</tbody></table>
</div></div>
{lots_panel}
{activity_panel}
{history_panel}
</div>
</div>

<div class="mt-6">{doc_defaults}</div>
<div class="mt-6 flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Save</button>
<a href="/inventory" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</form>"#,
        id = id,
        name = esc(&name),
        code = esc(&code),
        dup_btn = duplicate_button(&format!("/inventory/products/{id}/duplicate")),
        name_val = esc(&name),
        barcode_val = esc(barcode.as_deref().unwrap_or("")),
        desc_val = esc(description.as_deref().unwrap_or("")),
        list_price_val = row.try_get::<vortex_plugin_sdk::rust_decimal::Decimal, _>("list_price").unwrap_or_default().round_dp(2),
        sales_desc_val = esc(row.try_get::<Option<String>, _>("sales_description").ok().flatten().as_deref().unwrap_or("")),
        purchase_desc_val = esc(row.try_get::<Option<String>, _>("purchase_description").ok().flatten().as_deref().unwrap_or("")),
        categories = categories,
        uoms = uoms,
        cost_val = cost,
        rmin_val = reorder_min,
        rmax_val = reorder_max,
        sel_stk = sel(&product_type, "stockable"),
        sel_con = sel(&product_type, "consumable"),
        sel_svc = sel(&product_type, "service"),
        sel_tnone = sel(&tracking, "none"),
        sel_tlot = sel(&tracking, "lot"),
        sel_tser = sel(&tracking, "serial"),
        active_checked = if active { "checked" } else { "" },
        total = total,
        onhand_rows = onhand_rows,
        lots_panel = lots_panel,
        history_panel = history_panel,
        activity_panel = activity_panel,
    );

    Html(page_shell(&sidebar, &format!("Edit {}", name), &content)).into_response()
}

async fn update_product(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Name is required").into_response();
    }

    let before = product_tracker().snapshot(&db, id).await;

    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_product SET \
         name = $1, barcode = $2, description = $3, category_id = $4, \
         product_type = $5, uom_id = $6, tracking = $7, \
         cost = $8, reorder_min = $9, reorder_max = $10, active = $11, \
         sales_description = $12, purchase_description = $13, \
         classification_code = $14, income_account_id = $15, \
         expense_account_id = $16, sales_tax_id = $17, purchase_tax_id = $18, \
         list_price = $19, updated_by = $20, updated_at = NOW() \
         WHERE id = $21",
    )
    .bind(&name)
    .bind(form.get("barcode").filter(|s| !s.is_empty()))
    .bind(form.get("description").filter(|s| !s.is_empty()))
    .bind(opt_uuid(&form, "category_id"))
    .bind(form.get("product_type").map(|s| s.as_str()).unwrap_or("stockable"))
    .bind(opt_uuid(&form, "uom_id"))
    .bind(form.get("tracking").map(|s| s.as_str()).unwrap_or("none"))
    .bind(dec(&form, "cost"))
    .bind(dec(&form, "reorder_min"))
    .bind(dec(&form, "reorder_max"))
    .bind(form.contains_key("active"))
    .bind(form.get("sales_description").filter(|s| !s.is_empty()))
    .bind(form.get("purchase_description").filter(|s| !s.is_empty()))
    .bind(form.get("classification_code").map(|s| s.trim()).filter(|s| !s.is_empty()))
    .bind(opt_uuid(&form, "income_account_id"))
    .bind(opt_uuid(&form, "expense_account_id"))
    .bind(opt_uuid(&form, "sales_tax_id"))
    .bind(opt_uuid(&form, "purchase_tax_id"))
    .bind(dec(&form, "list_price"))
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "product update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update: {e}")).into_response();
    }

    product_tracker()
        .log_update(
            &state.audit, &db, &db_ctx.db_name,
            user.id, &user.username, "stock_product", id, &name, &before, &form,
        )
        .await;

    info!(id = %id, name = %name, "product updated");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory").into_response()
}

async fn delete_product(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_product SET active = false, updated_by = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "product archive failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to archive: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordDeleted,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_product", id.to_string())
    .with_details(json!({ "changes": [{ "field": "active", "from": "Active", "to": "Archived" }] }));
    let _ = state.audit.log(audit_entry).await;

    info!(id = %id, "product archived");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory").into_response()
}

/// POST /inventory/products/{id}/duplicate — copy a product into a fresh,
/// editable record. Master data only: the copy gets a freshly drawn PRD
/// code (the (company_id, code) unique key forbids reuse) and a blank
/// barcode (a barcode identifies one physical product). Stock moves,
/// quants, lots, and adjustments are ledger entries and are deliberately
/// never copied — the duplicate starts with zero on-hand.
async fn duplicate_product(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // Same sequence source as create_product, so codes never collide.
    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &PRODUCT_SEQ).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "product duplicate sequence draw failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response();
        }
    };

    let spec = DuplicateSpec::new("stock_product")
        .set("code", json!(code)) // fresh sequence — UNIQUE (company_id, code)
        .skip("barcode") // NULL — a barcode belongs to exactly one product
        .skip("updated_by") // NULL — the copy has never been edited
        .copy_suffix("name"); // "Widget" -> "Widget (copy)"

    match spec.execute(&db, id, Some(user.id)).await {
        Ok(new_id) => {
            let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
                vortex_plugin_sdk::security::AuditAction::RecordCreated,
                vortex_plugin_sdk::security::AuditSeverity::Info,
            )
            .with_user(vortex_plugin_sdk::common::UserId(user.id))
            .with_username(&user.username)
            .with_database(&db_ctx.db_name)
            .with_resource("stock_product", new_id.to_string())
            .with_details(json!({ "duplicated_from": id, "code": code }));
            if let Err(e) = state.audit.log(audit_entry).await {
                error!(error = %e, "audit log for product duplicate failed");
            }

            info!(id = %new_id, code = %code, "product duplicated");
            vortex_plugin_sdk::axum::response::Redirect::to(&format!("/inventory/products/{new_id}")).into_response()
        }
        Err(e) => {
            error!(error = %e, "product duplicate failed");
            (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Locations
// ─────────────────────────────────────────────────────────────────────────

async fn list_locations(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "inventory.locations");

    let config = ListConfig::new("Locations", "stock_location")
        .custom_from("stock_location l LEFT JOIN stock_location p ON p.id = l.parent_id")
        .custom_select("l.id, l.code, l.name, l.location_type, p.name AS parent_name, l.active")
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("l.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("l.name"))
        .column(
            ListColumn::new("location_type", "Type")
                .filterable(&[
                    ("internal", "Internal"),
                    ("supplier", "Supplier"),
                    ("customer", "Customer"),
                    ("inventory", "Inventory"),
                    ("transit", "Transit"),
                ])
                .badge(&[
                    ("internal", "Internal", "badge-success"),
                    ("supplier", "Supplier", "badge-info"),
                    ("customer", "Customer", "badge-secondary"),
                    ("inventory", "Inventory", "badge-warning"),
                    ("transit", "Transit", "badge-ghost"),
                ])
                .sql_expr("l.location_type"),
        )
        .column(ListColumn::new("parent_name", "Parent").sql_expr("p.name"))
        .column(
            ListColumn::new("active", "Status").bool_badge(
                "Active", "badge-success", "Archived", "badge-warning",
            ).sql_expr("l.active"),
        )
        .detail_url("/inventory/locations/{id}")
        .create("New Location", "/inventory/locations/new")
        .default_sort("code")
        .group_by_options(&[("location_type", "Type"), ("active", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "locations list query failed");
            return Html("<h1>Failed to load locations</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/inventory/locations");
    Html(page_shell(&sidebar, "Locations", &list_html)).into_response()
}

/// Render the location create/edit form body.
fn location_form_body(
    action: &str,
    back: &str,
    title: &str,
    code: &str,
    name: &str,
    ltype: &str,
    parent_options: &str,
    notes: &str,
    active: bool,
    is_new: bool,
) -> String {
    let sel = |val: &str, opt: &str| if val == opt { "selected" } else { "" };
    let active_box = if is_new {
        String::new()
    } else {
        format!(
            r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" {}/>
<span class="label-text">Active</span></label></div>"#,
            if active { "checked" } else { "" }
        )
    };
    format!(
        r#"<div class="max-w-2xl">
<a href="{back}" class="btn btn-ghost btn-sm mb-4">← Back to Locations</a>
<h1 class="text-2xl font-bold mb-6">{title}</h1>
<form method="POST" action="{action}">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Code *</span></label>
<input name="code" class="input input-bordered input-sm" value="{code}" required/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="location_type" class="select select-bordered select-sm">
<option value="internal" {sel_int}>Internal</option>
<option value="supplier" {sel_sup}>Supplier</option>
<option value="customer" {sel_cus}>Customer</option>
<option value="inventory" {sel_inv}>Inventory</option>
<option value="transit" {sel_tra}>Transit</option>
</select>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name}" required/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Parent Location</span></label>
<select name="parent_id" class="select select-bordered select-sm">{parent_options}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Notes</span></label>
<textarea name="notes" class="textarea textarea-bordered" rows="2">{notes}</textarea>
</div>
{active_box}
<div class="flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Save</button>
<a href="{back}" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        back = back,
        title = title,
        action = action,
        code = code,
        name = name,
        parent_options = parent_options,
        notes = notes,
        active_box = active_box,
        sel_int = sel(ltype, "internal"),
        sel_sup = sel(ltype, "supplier"),
        sel_cus = sel(ltype, "customer"),
        sel_inv = sel(ltype, "inventory"),
        sel_tra = sel(ltype, "transit"),
    )
}

async fn new_location_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let parents = location_options(&db, None).await;
    let content = location_form_body(
        "/inventory/locations/create", "/inventory/locations", "New Location",
        "", "", "internal", &parents, "", true, true,
    );
    Html(page_shell(&sidebar, "New Location", &content)).into_response()
}

async fn create_location(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let code = form.get("code").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    if code.trim().is_empty() || name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Code and name are required").into_response();
    }
    let ltype = form.get("location_type").cloned().unwrap_or_else(|| "internal".into());
    let company_id = default_company(&db).await;

    let loc_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_location (id, code, name, parent_id, location_type, notes, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8)",
    )
    .bind(loc_id)
    .bind(&code)
    .bind(&name)
    .bind(opt_uuid(&form, "parent_id"))
    .bind(&ltype)
    .bind(form.get("notes").filter(|s| !s.is_empty()))
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "location insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create location: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_location", loc_id.to_string())
    .with_resource_name(&name)
    .with_details(json!({ "code": code, "location_type": ltype }));
    let _ = state.audit.log(audit_entry).await;

    info!(code = %code, "location created");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/locations").into_response()
}

async fn edit_location(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, parent_id, location_type, notes, active FROM stock_location WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Location not found").into_response(),
        Err(e) => {
            error!(error = %e, "location fetch failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let code: String = row.get("code");
    let name: String = row.get("name");
    let parent_id: Option<Uuid> = row.try_get("parent_id").ok();
    let ltype: String = row.get("location_type");
    let notes: Option<String> = row.try_get("notes").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let parents = location_options(&db, parent_id).await;

    let body = location_form_body(
        &format!("/inventory/locations/{id}"),
        "/inventory/locations",
        &format!("Edit {}", name),
        &esc(&code), &esc(&name), &ltype, &parents,
        &esc(notes.as_deref().unwrap_or("")), active, false,
    );
    let delete = format!(
        r#"<div class="max-w-2xl mt-4"><form method="POST" action="/inventory/locations/{id}/delete" onsubmit="return confirm('Archive this location?')">
<button class="btn btn-error btn-sm btn-outline">Archive Location</button></form></div>"#
    );
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("stock_location", id);
    let content = format!(r#"{}{}<div class="mt-6">{activity_panel}</div>"#, body, delete);
    Html(page_shell(&sidebar, &format!("Edit {}", name), &content)).into_response()
}

async fn update_location(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let code = form.get("code").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    if code.trim().is_empty() || name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Code and name are required").into_response();
    }

    // Guard against a location being its own parent.
    let parent_id = opt_uuid(&form, "parent_id").filter(|p| *p != id);

    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_location SET \
         code = $1, name = $2, parent_id = $3, location_type = $4, notes = $5, active = $6, \
         updated_by = $7, updated_at = NOW() WHERE id = $8",
    )
    .bind(&code)
    .bind(&name)
    .bind(parent_id)
    .bind(form.get("location_type").map(|s| s.as_str()).unwrap_or("internal"))
    .bind(form.get("notes").filter(|s| !s.is_empty()))
    .bind(form.contains_key("active"))
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "location update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update: {e}")).into_response();
    }

    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/locations").into_response()
}

async fn delete_location(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_location SET active = false, updated_by = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "location archive failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to archive: {e}")).into_response();
    }
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/locations").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Stock moves
// ─────────────────────────────────────────────────────────────────────────

async fn list_moves(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("Stock Moves", "stock_move")
        .custom_from(
            "stock_move m \
             JOIN stock_product p ON p.id = m.product_id \
             LEFT JOIN stock_lot lo ON lo.id = m.lot_id \
             JOIN stock_location sl ON sl.id = m.source_location_id \
             JOIN stock_location dl ON dl.id = m.dest_location_id",
        )
        .custom_select(
            "m.id, m.reference, p.name AS product_name, m.quantity::text AS quantity, \
             lo.name AS lot_name, \
             sl.code AS source_code, dl.code AS dest_code, m.state, \
             m.scheduled_date::text AS scheduled_date",
        )
        .column(ListColumn::new("reference", "Reference").sortable().code().sql_expr("m.reference"))
        .column(ListColumn::new("product_name", "Product").searchable().sql_expr("p.name"))
        .column(ListColumn::new("quantity", "Qty").sql_expr("m.quantity"))
        .column(ListColumn::new("lot_name", "Lot/Serial").code().searchable().sql_expr("lo.name"))
        .column(ListColumn::new("source_code", "From").sql_expr("sl.code"))
        .column(ListColumn::new("dest_code", "To").sql_expr("dl.code"))
        .column(ListColumn::new("scheduled_date", "Scheduled").sortable().sql_expr("m.scheduled_date"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("draft", "Draft"),
                    ("done", "Done"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("draft", "Draft", "badge-ghost"),
                    ("done", "Done", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("m.state"),
        )
        .create("New Move", "/inventory/moves/new")
        .default_sort("reference")
        .group_by_options(&[("state", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "moves list query failed");
            return Html("<h1>Failed to load stock moves</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/inventory/moves");

    // Pending draft moves get inline validate/cancel action rows below the list.
    let drafts = vortex_plugin_sdk::sqlx::query(
        "SELECT m.id, m.reference, p.name AS product_name, m.quantity \
         FROM stock_move m JOIN stock_product p ON p.id = m.product_id \
         WHERE m.state = 'draft' ORDER BY m.created_at DESC LIMIT 50",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut actions = String::new();
    if !drafts.is_empty() {
        let esc = vortex_plugin_sdk::framework::html_escape;
        actions.push_str(r#"<div class="card bg-base-100 shadow mt-6"><div class="card-body">
<h2 class="card-title text-lg mb-2">Draft moves — validate to post</h2>
<table class="table table-sm"><tbody>"#);
        for r in &drafts {
            let mid: Uuid = r.get("id");
            let reference: String = r.get("reference");
            let pname: String = r.get("product_name");
            let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
            actions.push_str(&format!(
                r#"<tr><td class="font-mono">{reference}</td><td>{pname}</td><td class="text-right">{qty}</td>
<td class="text-right"><form method="POST" action="/inventory/moves/{mid}/validate" class="inline">
<button class="btn btn-success btn-xs">Validate</button></form>
<form method="POST" action="/inventory/moves/{mid}/cancel" class="inline ml-1" onsubmit="return confirm('Cancel this move?')">
<button class="btn btn-ghost btn-xs">Cancel</button></form></td></tr>"#,
                reference = esc(&reference),
                pname = esc(&pname),
                qty = qty,
                mid = mid,
            ));
        }
        actions.push_str("</tbody></table></div></div>");
    }

    let content = format!("{}{}", list_html, actions);
    Html(page_shell(&sidebar, "Stock Moves", &content)).into_response()
}

async fn new_move_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let products = {
        let esc = vortex_plugin_sdk::framework::html_escape;
        let rows = vortex_plugin_sdk::sqlx::query(
            "SELECT id, code, name FROM stock_product WHERE active AND product_type <> 'service' ORDER BY code",
        )
        .fetch_all(&db)
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
    };
    let sources = location_options(&db, Some(Uuid::nil())).await; // none preselected (nil never matches)
    let dests = location_options(&db, None).await;
    let uoms = uom_options(&db, None).await;
    // Datalist of existing lot/serial numbers, labelled by product, to
    // autocomplete the free-text lot field (typing a new one creates it).
    let lots = {
        let esc = vortex_plugin_sdk::framework::html_escape;
        let rows = vortex_plugin_sdk::sqlx::query(
            "SELECT lo.name, p.code FROM stock_lot lo \
             JOIN stock_product p ON p.id = lo.product_id \
             WHERE lo.active ORDER BY lo.name LIMIT 500",
        )
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        let mut out = String::new();
        for r in &rows {
            let lname: String = r.get("name");
            let pcode: String = r.get("code");
            out.push_str(&format!(
                r#"<option value="{name}">{name} ({code})</option>"#,
                name = esc(&lname),
                code = esc(&pcode),
            ));
        }
        out
    };

    let content = format!(
        r#"<div class="max-w-2xl">
<a href="/inventory/moves" class="btn btn-ghost btn-sm mb-4">← Back to Stock Moves</a>
<h1 class="text-2xl font-bold mb-6">New Stock Move</h1>
<form method="POST" action="/inventory/moves/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Product *</span></label>
<select name="product_id" class="select select-bordered select-sm" required>{products}</select>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Quantity *</span></label>
<input name="quantity" type="number" step="0.0001" min="0.0001" class="input input-bordered input-sm" required/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Unit of Measure</span></label>
<select name="uom_id" class="select select-bordered select-sm">{uoms}</select>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Lot / Serial number</span></label>
<input name="lot_name" class="input input-bordered input-sm" list="known-lots" placeholder="Required for lot/serial-tracked products"/>
<datalist id="known-lots">{lots}</datalist>
<label class="label"><span class="label-text-alt text-base-content/50">Required when the product is lot- or serial-tracked. A new number is created automatically; an existing one is reused.</span></label>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">From *</span></label>
<select name="source_location_id" class="select select-bordered select-sm" required>{sources}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">To *</span></label>
<select name="dest_location_id" class="select select-bordered select-sm" required>{dests}</select>
</div>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Scheduled Date</span></label>
<input name="scheduled_date" type="date" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Source Document</span></label>
<input name="reference_doc" class="input input-bordered input-sm" placeholder="e.g. PO/2026/0001"/>
</div>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Note</span></label>
<textarea name="note" class="textarea textarea-bordered" rows="2"></textarea>
</div>
<div class="flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Create (Draft)</button>
<a href="/inventory/moves" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        products = products,
        uoms = uoms,
        lots = lots,
        sources = sources,
        dests = dests,
    );

    Html(page_shell(&sidebar, "New Stock Move", &content)).into_response()
}

async fn create_move(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let product_id = opt_uuid(&form, "product_id");
    let source_id = opt_uuid(&form, "source_location_id");
    let dest_id = opt_uuid(&form, "dest_location_id");
    let quantity = dec(&form, "quantity");

    let (Some(product_id), Some(source_id), Some(dest_id)) = (product_id, source_id, dest_id) else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product, source and destination are required").into_response();
    };
    if quantity <= Decimal::ZERO {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Quantity must be greater than zero").into_response();
    }
    if source_id == dest_id {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Source and destination must differ").into_response();
    }

    // Look up the product's tracking mode + default UoM in one go.
    let prod = match vortex_plugin_sdk::sqlx::query(
        "SELECT tracking, uom_id FROM stock_product WHERE id = $1",
    )
    .bind(product_id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product not found").into_response(),
        Err(e) => {
            error!(error = %e, "product lookup failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };
    let tracking: String = prod.get("tracking");
    let product_uom: Option<Uuid> = prod.try_get("uom_id").ok();

    // Default the move UoM to the product's UoM when not given.
    let uom_id = opt_uuid(&form, "uom_id").or(product_uom);

    // Resolve the lot/serial for tracked products. The lot name field
    // doubles as create-or-match: an unknown name creates a new lot, a
    // known name reuses it (e.g. issuing an existing serial).
    let company_id = default_company(&db).await;
    let lot_id: Option<Uuid> = if tracking == "none" {
        None
    } else {
        let lot_name = form.get("lot_name").map(|s| s.trim()).unwrap_or("");
        if lot_name.is_empty() {
            return (
                vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
                "A lot or serial number is required for this product.",
            )
                .into_response();
        }
        if tracking == "serial" && quantity != Decimal::ONE {
            return (
                vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
                "Serial-tracked products must move exactly one unit per move.",
            )
                .into_response();
        }
        match resolve_lot(&db, product_id, lot_name, &tracking, company_id, user.id).await {
            Ok(id) => Some(id),
            Err(e) => {
                error!(error = %e, "lot resolve failed");
                return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve lot").into_response();
            }
        }
    };

    let scheduled_date: Option<vortex_plugin_sdk::chrono::NaiveDate> = form
        .get("scheduled_date")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    let reference = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &MOVE_SEQ).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "move sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate move reference").into_response();
        }
    };

    let move_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_move \
         (id, reference, product_id, quantity, uom_id, lot_id, source_location_id, dest_location_id, \
          scheduled_date, reference_doc, note, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
    )
    .bind(move_id)
    .bind(&reference)
    .bind(product_id)
    .bind(quantity)
    .bind(uom_id)
    .bind(lot_id)
    .bind(source_id)
    .bind(dest_id)
    .bind(scheduled_date)
    .bind(form.get("reference_doc").filter(|s| !s.is_empty()))
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "move insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create move: {e}")).into_response();
    }

    info!(reference = %reference, "stock move created (draft)");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/moves").into_response()
}

/// Validate (post) a draft move: flip state to done and update on-hand
/// quants for the source and destination locations, atomically.
async fn validate_move(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "could not start transaction");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    // Lock the move row and confirm it is still a draft.
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT reference, product_id, quantity, lot_id, source_location_id, dest_location_id, company_id \
         FROM stock_move WHERE id = $1 AND state = 'draft' FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => {
            let _ = tx.rollback().await;
            return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Move is not in draft state").into_response();
        }
        Err(e) => {
            let _ = tx.rollback().await;
            error!(error = %e, "move lock failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let reference: String = row.get("reference");
    let product_id: Uuid = row.get("product_id");
    let quantity: Decimal = row.get("quantity");
    let lot_id: Option<Uuid> = row.try_get("lot_id").ok();
    let source_id: Uuid = row.get("source_location_id");
    let dest_id: Uuid = row.get("dest_location_id");
    let company_id: Option<Uuid> = row.try_get("company_id").ok();

    // Mark done.
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_move SET state = 'done', done_at = NOW(), updated_by = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(user.id)
    .bind(id)
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        error!(error = %e, "move state update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to validate move").into_response();
    }

    // Debit source, credit destination — lot-aware, one quant row per
    // (product, location, lot).
    for (loc, delta) in [(source_id, -quantity), (dest_id, quantity)] {
        if let Err(e) = adjust_quant(&mut tx, product_id, loc, lot_id, delta, company_id).await {
            let _ = tx.rollback().await;
            error!(error = %e, "quant update failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to update on-hand").into_response();
        }
    }

    if let Err(e) = tx.commit().await {
        error!(error = %e, "move validate commit failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit").into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_move", id.to_string())
    .with_resource_name(&reference)
    .with_details(json!({ "action": "validated", "quantity": quantity.to_string() }));
    let _ = state.audit.log(audit_entry).await;

    info!(reference = %reference, "stock move validated");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/moves").into_response()
}

async fn cancel_move(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // Only draft moves may be cancelled — done moves have already touched
    // on-hand and must be reversed with a counter-move instead.
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_move SET state = 'cancelled', updated_by = $1, updated_at = NOW() \
         WHERE id = $2 AND state = 'draft'",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await;

    match res {
        Ok(r) if r.rows_affected() == 0 => {
            return (vortex_plugin_sdk::axum::http::StatusCode::CONFLICT, "Only draft moves can be cancelled").into_response();
        }
        Ok(_) => {}
        Err(e) => {
            error!(error = %e, "move cancel failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to cancel").into_response();
        }
    }

    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/moves").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Lots / serials
// ─────────────────────────────────────────────────────────────────────────

/// Find the lot named `name` for `product_id`, creating it if absent.
/// Returns the lot id. Used by move creation so receiving an unknown
/// lot/serial auto-registers it.
pub(crate) async fn resolve_lot(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    product_id: Uuid,
    name: &str,
    lot_type: &str,
    company_id: Option<Uuid>,
    user_id: Uuid,
) -> Result<Uuid, vortex_plugin_sdk::sqlx::Error> {
    if let Some(existing) = vortex_plugin_sdk::sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM stock_lot WHERE product_id = $1 AND name = $2",
    )
    .bind(product_id)
    .bind(name)
    .fetch_optional(db)
    .await?
    {
        return Ok(existing);
    }

    let lot_id = Uuid::now_v7();
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_lot (id, name, product_id, lot_type, company_id, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(lot_id)
    .bind(name)
    .bind(product_id)
    .bind(lot_type)
    .bind(company_id)
    .bind(user_id)
    .execute(db)
    .await?;
    Ok(lot_id)
}

async fn list_lots(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("Lots / Serials", "stock_lot")
        .custom_from(
            "stock_lot lo \
             JOIN stock_product p ON p.id = lo.product_id \
             LEFT JOIN ( \
                 SELECT q.lot_id, COALESCE(SUM(q.quantity),0) AS on_hand \
                 FROM stock_quant q JOIN stock_location l ON l.id = q.location_id \
                 WHERE l.location_type = 'internal' GROUP BY q.lot_id \
             ) oh ON oh.lot_id = lo.id",
        )
        .custom_select(
            "lo.id, lo.name, p.code AS product_code, p.name AS product_name, \
             lo.lot_type, COALESCE(oh.on_hand,0)::text AS on_hand, lo.active",
        )
        .column(ListColumn::new("name", "Number").sortable().code().searchable().sql_expr("lo.name"))
        .column(ListColumn::new("product_code", "Product Code").sortable().sql_expr("p.code"))
        .column(ListColumn::new("product_name", "Product").searchable().sql_expr("p.name"))
        .column(
            ListColumn::new("lot_type", "Type")
                .filterable(&[("lot", "Lot"), ("serial", "Serial")])
                .badge(&[
                    ("lot", "Lot", "badge-info"),
                    ("serial", "Serial", "badge-secondary"),
                ])
                .sql_expr("lo.lot_type"),
        )
        .column(ListColumn::new("on_hand", "On Hand").sortable().sql_expr("COALESCE(oh.on_hand,0)"))
        .column(
            ListColumn::new("active", "Status").bool_badge(
                "Active", "badge-success", "Archived", "badge-warning",
            ).sql_expr("lo.active"),
        )
        .detail_url("/inventory/lots/{id}")
        .create("New Lot / Serial", "/inventory/lots/new")
        .default_sort("name")
        .group_by_options(&[("product_code", "Product"), ("lot_type", "Type")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "lots list query failed");
            return Html("<h1>Failed to load lots</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/inventory/lots");
    Html(page_shell(&sidebar, "Lots / Serials", &list_html)).into_response()
}

/// `<option>` list of tracked products (tracking <> none), for the lot form.
async fn tracked_product_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name, tracking FROM stock_product \
         WHERE active AND tracking <> 'none' ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">-- Product --</option>"#);
    for r in &rows {
        let id: Uuid = r.get("id");
        let code: String = r.get("code");
        let name: String = r.get("name");
        let tracking: String = r.get("tracking");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{code} · {name} ({tracking})</option>"#,
            id = id, sel = sel, code = esc(&code), name = esc(&name), tracking = esc(&tracking),
        ));
    }
    out
}

async fn new_lot_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let products = tracked_product_options(&db, None).await;

    let content = format!(
        r#"<div class="max-w-2xl">
<a href="/inventory/lots" class="btn btn-ghost btn-sm mb-4">← Back to Lots / Serials</a>
<h1 class="text-2xl font-bold mb-6">New Lot / Serial</h1>
<form method="POST" action="/inventory/lots/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Product *</span></label>
<select name="product_id" class="select select-bordered select-sm" required>{products}</select>
<label class="label"><span class="label-text-alt text-base-content/50">Only lot/serial-tracked products are listed. The type is taken from the product.</span></label>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Lot / Serial Number *</span></label>
<input name="name" class="input input-bordered input-sm" required/>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Note</span></label>
<textarea name="note" class="textarea textarea-bordered" rows="2"></textarea>
</div>
<div class="flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Create</button>
<a href="/inventory/lots" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        products = products,
    );

    Html(page_shell(&sidebar, "New Lot / Serial", &content)).into_response()
}

async fn create_lot(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    let Some(product_id) = opt_uuid(&form, "product_id") else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product is required").into_response();
    };
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Lot/serial number is required").into_response();
    }

    // Derive the lot type from the product's tracking mode; reject
    // untracked products (a lot makes no sense for them).
    let tracking: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT tracking FROM stock_product WHERE id = $1",
    )
    .bind(product_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let lot_type = match tracking.as_deref() {
        Some("lot") => "lot",
        Some("serial") => "serial",
        _ => return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product is not lot/serial-tracked").into_response(),
    };
    let company_id = default_company(&db).await;

    let lot_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_lot (id, name, product_id, lot_type, note, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(lot_id)
    .bind(&name)
    .bind(product_id)
    .bind(lot_type)
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(company_id)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "lot insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to create lot: {e}")).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_lot", lot_id.to_string())
    .with_resource_name(&name)
    .with_details(json!({ "lot_type": lot_type }));
    let _ = state.audit.log(audit_entry).await;

    info!(name = %name, "lot created");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/lots").into_response()
}

async fn edit_lot(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT lo.name, lo.lot_type, lo.note, lo.active, \
                p.code AS product_code, p.name AS product_name \
         FROM stock_lot lo JOIN stock_product p ON p.id = lo.product_id \
         WHERE lo.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Lot not found").into_response(),
        Err(e) => {
            error!(error = %e, "lot fetch failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let name: String = row.get("name");
    let lot_type: String = row.get("lot_type");
    let note: Option<String> = row.try_get("note").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let product_code: String = row.get("product_code");
    let product_name: String = row.get("product_name");

    // On-hand per location for this lot.
    let quant_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.code, l.name, l.location_type, q.quantity \
         FROM stock_quant q JOIN stock_location l ON l.id = q.location_id \
         WHERE q.lot_id = $1 AND q.quantity <> 0 ORDER BY l.code",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut onhand_rows = String::new();
    let mut total = Decimal::ZERO;
    for r in &quant_rows {
        let lcode: String = r.get("code");
        let lname: String = r.get("name");
        let ltype: String = r.get("location_type");
        let qty: Decimal = r.try_get("quantity").unwrap_or(Decimal::ZERO);
        if ltype == "internal" {
            total += qty;
        }
        onhand_rows.push_str(&format!(
            "<tr><td class=\"font-mono\">{}</td><td>{}</td><td>{}</td><td class=\"text-right\">{}</td></tr>",
            esc(&lcode), esc(&lname), esc(&ltype), qty
        ));
    }
    if onhand_rows.is_empty() {
        onhand_rows.push_str(r#"<tr><td colspan="4" class="text-base-content/50">No stock on hand</td></tr>"#);
    }

    let history_panel = vortex_plugin_sdk::framework::render_audit_trail(&db, "stock_lot", id).await;
    // Activity stream: schedule/assign/complete tasks, messages, attachments.
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("stock_lot", id);

    let content = format!(
        r#"<div class="mb-6">
<a href="/inventory/lots" class="btn btn-ghost btn-sm mb-2">← Back to Lots / Serials</a>
<h1 class="text-2xl font-bold">{name} <span class="badge {type_css} badge-sm align-middle">{lot_type}</span></h1>
<p class="text-base-content/50 text-sm">{product_code} · {product_name}</p>
</div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<form method="POST" action="/inventory/lots/{id}">
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-4">Details</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Number *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name_val}" required/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Note</span></label>
<textarea name="note" class="textarea textarea-bordered" rows="2">{note_val}</textarea>
</div>
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" {active_checked}/>
<span class="label-text">Active</span></label>
</div>
<div class="flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Save</button>
<a href="/inventory/lots" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title text-lg mb-4">On Hand <span class="badge badge-ghost">{total}</span></h2>
<table class="table table-sm"><thead><tr><th>Location</th><th>Name</th><th>Type</th><th class="text-right">Qty</th></tr></thead>
<tbody>{onhand_rows}</tbody></table>
</div></div>
{activity_panel}
{history_panel}
</div>
</div>"#,
        id = id,
        name = esc(&name),
        name_val = esc(&name),
        activity_panel = activity_panel,
        lot_type = esc(&lot_type),
        type_css = if lot_type == "serial" { "badge-secondary" } else { "badge-info" },
        product_code = esc(&product_code),
        product_name = esc(&product_name),
        note_val = esc(note.as_deref().unwrap_or("")),
        active_checked = if active { "checked" } else { "" },
        total = total,
        onhand_rows = onhand_rows,
        history_panel = history_panel,
    );

    Html(page_shell(&sidebar, &format!("Lot {}", name), &content)).into_response()
}

async fn update_lot(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(_db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let name = form.get("name").cloned().unwrap_or_default();
    if name.trim().is_empty() {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Number is required").into_response();
    }

    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE stock_lot SET name = $1, note = $2, active = $3, \
         updated_by = $4, updated_at = NOW() WHERE id = $5",
    )
    .bind(&name)
    .bind(form.get("note").filter(|s| !s.is_empty()))
    .bind(form.contains_key("active"))
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "lot update failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to update: {e}")).into_response();
    }

    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/lots").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Stock adjustment wizard
// ─────────────────────────────────────────────────────────────────────────

/// GET /inventory/adjust — set the counted on-hand for a
/// (product, internal location, lot) directly. Applying the form posts a
/// balancing stock move against the Inventory Adjustment location so the
/// audit trail and ledger stay consistent — quants are never edited blind.
async fn adjust_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let esc = vortex_plugin_sdk::framework::html_escape;

    let products = {
        let rows = vortex_plugin_sdk::sqlx::query(
            "SELECT id, code, name FROM stock_product \
             WHERE active AND product_type <> 'service' ORDER BY code",
        )
        .fetch_all(&db)
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
    };
    let locations = internal_location_options(&db).await;
    let lots = {
        let rows = vortex_plugin_sdk::sqlx::query(
            "SELECT lo.name, p.code FROM stock_lot lo \
             JOIN stock_product p ON p.id = lo.product_id \
             WHERE lo.active ORDER BY lo.name LIMIT 500",
        )
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        let mut out = String::new();
        for r in &rows {
            let lname: String = r.get("name");
            let pcode: String = r.get("code");
            out.push_str(&format!(
                r#"<option value="{name}">{name} ({code})</option>"#,
                name = esc(&lname), code = esc(&pcode),
            ));
        }
        out
    };

    let content = format!(
        r#"<div class="max-w-2xl">
<a href="/inventory/onhand" class="btn btn-ghost btn-sm mb-4">← Back to On Hand</a>
<h1 class="text-2xl font-bold mb-2">Stock Adjustment</h1>
<p class="text-base-content/60 mb-6">Set the counted on-hand quantity. Vortex posts a balancing move against the Inventory Adjustment location to reconcile the difference.</p>
<form method="POST" action="/inventory/adjust">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Product *</span></label>
<select name="product_id" class="select select-bordered select-sm" required>{products}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Location *</span></label>
<select name="location_id" class="select select-bordered select-sm" required>{locations}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Lot / Serial number</span></label>
<input name="lot_name" class="input input-bordered input-sm" list="adj-lots" placeholder="Required for lot/serial-tracked products"/>
<datalist id="adj-lots">{lots}</datalist>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Counted Quantity *</span></label>
<input name="counted" type="number" step="0.0001" min="0" class="input input-bordered input-sm" required/>
<label class="label"><span class="label-text-alt text-base-content/50">The new on-hand value. The difference vs. current on-hand becomes the adjustment move.</span></label>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Reason / Note</span></label>
<input name="note" class="input input-bordered input-sm" placeholder="e.g. cycle count, breakage, found stock"/>
</div>
<div class="flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Apply Adjustment</button>
<a href="/inventory/onhand" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</div></div>
</form>
</div>"#,
        products = products,
        locations = locations,
        lots = lots,
    );

    Html(page_shell(&sidebar, "Stock Adjustment", &content)).into_response()
}

/// POST /inventory/adjust — compute the delta vs current on-hand and post
/// a validated balancing move to/from the Inventory Adjustment location.
async fn apply_adjustment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<HashMap<String, String>>,
) -> Response {
    let (Some(product_id), Some(location_id)) =
        (opt_uuid(&form, "product_id"), opt_uuid(&form, "location_id"))
    else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product and location are required").into_response();
    };
    let Some(counted) = form.get("counted").and_then(|s| s.trim().parse::<Decimal>().ok()) else {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "A counted quantity is required").into_response();
    };
    if counted < Decimal::ZERO {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Counted quantity cannot be negative").into_response();
    }

    // Product tracking + default UoM.
    let prod = match vortex_plugin_sdk::sqlx::query("SELECT tracking, uom_id FROM stock_product WHERE id = $1")
        .bind(product_id)
        .fetch_optional(&db)
        .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Product not found").into_response(),
        Err(e) => {
            error!(error = %e, "product lookup failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };
    let tracking: String = prod.get("tracking");
    let uom_id: Option<Uuid> = prod.try_get("uom_id").ok();
    let company_id = default_company(&db).await;

    // Resolve lot for tracked products (serial counts are limited to 0/1).
    let lot_id: Option<Uuid> = if tracking == "none" {
        None
    } else {
        let lot_name = form.get("lot_name").map(|s| s.trim()).unwrap_or("");
        if lot_name.is_empty() {
            return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "A lot or serial number is required for this product.").into_response();
        }
        if tracking == "serial" && counted != Decimal::ZERO && counted != Decimal::ONE {
            return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Serial-tracked on-hand can only be 0 or 1.").into_response();
        }
        match resolve_lot(&db, product_id, lot_name, &tracking, company_id, user.id).await {
            Ok(id) => Some(id),
            Err(e) => {
                error!(error = %e, "lot resolve failed");
                return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to resolve lot").into_response();
            }
        }
    };

    // The Inventory Adjustment counterpart location.
    let adj_location: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM stock_location WHERE location_type = 'inventory' AND active ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(adj_location) = adj_location else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::PRECONDITION_FAILED,
            "No Inventory Adjustment location exists. Create a location of type 'inventory' first.",
        )
            .into_response();
    };
    if adj_location == location_id {
        return (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, "Cannot adjust the Inventory Adjustment location itself").into_response();
    }

    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!(error = %e, "could not start transaction");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    // Current on-hand for this (product, location, lot), locked.
    let current: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT quantity FROM stock_quant \
         WHERE product_id = $1 AND location_id = $2 AND lot_id IS NOT DISTINCT FROM $3 FOR UPDATE",
    )
    .bind(product_id)
    .bind(location_id)
    .bind(lot_id)
    .fetch_optional(&mut *tx)
    .await
    .ok()
    .flatten()
    .unwrap_or(Decimal::ZERO);

    let delta = counted - current;
    if delta == Decimal::ZERO {
        let _ = tx.rollback().await;
        return vortex_plugin_sdk::axum::response::Redirect::to("/inventory/onhand").into_response();
    }

    // Orient the move so on-hand at `location_id` ends at `counted`.
    // delta > 0 → receive from adjustment; delta < 0 → send to adjustment.
    let (source_id, dest_id, qty) = if delta > Decimal::ZERO {
        (adj_location, location_id, delta)
    } else {
        (location_id, adj_location, -delta)
    };

    let reference = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &MOVE_SEQ).await {
        Ok(r) => r,
        Err(e) => {
            let _ = tx.rollback().await;
            error!(error = %e, "move sequence generation failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to generate move reference").into_response();
        }
    };

    let note = form.get("note").filter(|s| !s.is_empty()).cloned();
    let move_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO stock_move \
         (id, reference, product_id, quantity, uom_id, lot_id, source_location_id, dest_location_id, \
          state, done_at, reference_doc, note, company_id, created_by) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,'done',NOW(),$9,$10,$11,$12)",
    )
    .bind(move_id)
    .bind(&reference)
    .bind(product_id)
    .bind(qty)
    .bind(uom_id)
    .bind(lot_id)
    .bind(source_id)
    .bind(dest_id)
    .bind("Stock Adjustment")
    .bind(note.as_deref())
    .bind(company_id)
    .bind(user.id)
    .execute(&mut *tx)
    .await
    {
        let _ = tx.rollback().await;
        error!(error = %e, "adjustment move insert failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, format!("Failed to post adjustment: {e}")).into_response();
    }

    for (loc, d) in [(source_id, -qty), (dest_id, qty)] {
        if let Err(e) = adjust_quant(&mut tx, product_id, loc, lot_id, d, company_id).await {
            let _ = tx.rollback().await;
            error!(error = %e, "quant update failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to update on-hand").into_response();
        }
    }

    if let Err(e) = tx.commit().await {
        error!(error = %e, "adjustment commit failed");
        return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "Failed to commit").into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("stock_move", move_id.to_string())
    .with_resource_name(&reference)
    .with_details(json!({
        "action": "stock_adjustment",
        "from": current.to_string(),
        "to": counted.to_string(),
        "delta": delta.to_string(),
    }));
    let _ = state.audit.log(audit_entry).await;

    info!(reference = %reference, delta = %delta, "stock adjustment posted");
    vortex_plugin_sdk::axum::response::Redirect::to("/inventory/onhand").into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// On-hand
// ─────────────────────────────────────────────────────────────────────────

async fn list_onhand(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{execute_list, render_list, ListColumn, ListConfig, ListParams};

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("On Hand", "stock_quant")
        .custom_from(
            "stock_quant q \
             JOIN stock_product p ON p.id = q.product_id \
             LEFT JOIN stock_lot lo ON lo.id = q.lot_id \
             JOIN stock_location l ON l.id = q.location_id",
        )
        .custom_select(
            "q.id, p.code AS product_code, p.name AS product_name, lo.name AS lot_name, \
             l.code AS location_code, l.location_type, q.quantity::text AS quantity",
        )
        .base_filter("q.quantity <> 0")
        .column(ListColumn::new("product_code", "Code").sortable().code().sql_expr("p.code"))
        .column(ListColumn::new("product_name", "Product").searchable().sql_expr("p.name"))
        .column(ListColumn::new("lot_name", "Lot/Serial").code().searchable().sql_expr("lo.name"))
        .column(ListColumn::new("location_code", "Location").sortable().sql_expr("l.code"))
        .column(
            ListColumn::new("location_type", "Loc Type")
                .filterable(&[
                    ("internal", "Internal"),
                    ("supplier", "Supplier"),
                    ("customer", "Customer"),
                    ("inventory", "Inventory"),
                    ("transit", "Transit"),
                ])
                .badge(&[
                    ("internal", "Internal", "badge-success"),
                    ("supplier", "Supplier", "badge-info"),
                    ("customer", "Customer", "badge-secondary"),
                    ("inventory", "Inventory", "badge-warning"),
                    ("transit", "Transit", "badge-ghost"),
                ])
                .sql_expr("l.location_type"),
        )
        .column(ListColumn::new("quantity", "Qty").sortable().sql_expr("q.quantity"))
        .default_sort("product_code")
        .group_by_options(&[("location_code", "Location"), ("location_type", "Loc Type")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "on-hand list query failed");
            return Html("<h1>Failed to load on-hand stock</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/inventory/onhand");
    let toolbar = r#"<div class="flex justify-end mb-3"><a href="/inventory/adjust" class="btn btn-primary btn-sm">Adjust Stock</a></div>"#;
    let hint = r#"<div class="text-sm text-base-content/50 mt-3">On-hand balances are derived from validated stock moves. Run the <a class="link" href="/reports">On-Hand Valuation</a> report for costed totals.</div>"#;
    let content = format!("{}{}{}", toolbar, list_html, hint);
    Html(page_shell(&sidebar, "On Hand", &content)).into_response()
}
