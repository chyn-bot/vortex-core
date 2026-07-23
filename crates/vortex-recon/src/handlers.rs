//! Reconciliation HTTP handlers — list (list framework), create/edit
//! (form engine), and a record page wearing the platform widgets:
//! status bar, chatter, audit-logged transitions.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

/// Auto-generated record codes: RCB/000001
const ITEM_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("recon.batch", "RCB")
        .with_padding(6);

/// How far Σ(extracted lines) may drift from the invoice's printed total
/// before the self-check flags an exception. Absorbs cent-level rounding on
/// per-line prices; anything larger means the extraction is wrong.
const VALIDATION_TOLERANCE: f64 = 0.05;

/// Server-generated FileStore key for an uploaded scan: `recon/<uuid>.<ext>`.
/// The extension is sanitized; anything unusual falls back to `bin`.
fn new_store_key(file_name: &str) -> String {
    let ext = std::path::Path::new(file_name)
        .extension()
        .and_then(|e| e.to_str())
        .filter(|e| e.len() <= 10 && e.chars().all(|c| c.is_ascii_alphanumeric()))
        .unwrap_or("bin");
    format!("recon/{}.{}", Uuid::new_v4(), ext.to_ascii_lowercase())
}

/// Public portal routes — served WITHOUT authentication. Only expose
/// data that is truly public for the tenant. No AuthUser here.
pub fn public_routes() -> Router<Arc<AppState>> {
    Router::new().route("/p/recon", get(public_board))
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/recon", get(list_items))
        .route("/recon/dashboard", get(dashboard))
        .route("/recon/verify", get(verify_worklist))
        .route("/recon/new", get(new_item_form))
        .route("/recon/create", post(create_item))
        // Invoice upload inbox — a separate step from reconciliation: drop the
        // scanned PDF(s) now, extraction/matching happens later.
        .route("/recon/upload", get(upload_form))
        .route("/recon/upload", post(upload_invoices))
        // Batch extraction queue (async, ~50% cheaper) + manual submit.
        .route("/recon/batch", get(batch_page))
        .route("/recon/batch/submit", post(batch_submit))
        .route("/recon/attachments/{att_id}/download", get(serve_attachment))
        // M3 (ERP) data pool — bulk CSV/Excel import, linked at match time.
        .route("/recon/m3", get(m3_pool))
        .route("/recon/m3/import", get(m3_import_form))
        .route("/recon/m3/import", post(m3_import))
        .route("/recon/{id}", get(item_page))
        .route("/recon/{id}", post(update_item))
        .route("/recon/{id}/edit", get(edit_item_form))
        .route("/recon/{id}/duplicate", post(duplicate_item))
        .route("/recon/{id}/status/{state}", post(change_status))
        // Extraction self-check (Part 1): save the extracted/keyed lines, then
        // validate Σ(lines) against the invoice's own printed total.
        .route("/recon/{id}/lines", post(save_lines))
        .route("/recon/{id}/validate", post(validate_totals))
        // Matcher (Part 2): link this invoice to the M3 pool and reconcile
        // line-by-line (alias → UOM → tolerance).
        .route("/recon/{id}/match", post(run_match))
        // Map an invoice item code → M3 SKU once; remembered for next time.
        .route("/recon/{id}/map", post(save_item_alias))
        // GL double-entry: map item → GL account (self-learning) + CSV export.
        .route("/recon/{id}/glmap", post(save_gl_map))
        .route("/recon/{id}/glmap-bulk", post(save_gl_map_bulk))
        .route("/recon/{id}/gl.csv", get(gl_csv))
        // GL configuration: accounts, defaults, mapping rules.
        .route("/recon/gl", get(gl_config_page))
        .route("/recon/gl/defaults", post(gl_save_defaults))
        .route("/recon/gl/account", post(gl_add_account))
        .route("/recon/gl/rule", post(gl_add_rule))
        .route("/recon/gl/rule/{rid}/delete", post(gl_delete_rule))
        .route("/recon/gl/sku", post(gl_add_sku))
        // AI OCR: provider config + per-invoice extraction into the review grid.
        .route("/recon/ai", get(ai_config_form))
        .route("/recon/ai", post(ai_config_save))
        // Multiple stored providers — activate/delete a saved profile.
        .route("/recon/ai/{cid}/activate", post(ai_config_activate))
        .route("/recon/ai/{cid}/delete", post(ai_config_delete))
        // Connectivity/credentials check when configuring a provider.
        .route("/recon/ai/test", post(ai_config_test))
        // AI token usage + extraction cost (superadmin only).
        .route("/recon/ai/usage", get(ai_usage_page))
        .route("/recon/ai/pricing", post(ai_pricing_save))
        .route("/recon/{id}/extract", post(ai_extract))
        // Self-learning: save a correction as a knowledge-base rule, then re-run
        // extraction with it applied. Plus deactivate a learned rule.
        .route("/recon/{id}/reextract", post(reextract_with_feedback))
        .route("/recon/hint/{hid}/toggle", post(toggle_extract_hint))
        .route("/recon/{id}/extract-status", get(extract_status))
        // Remote auto-pickup (SFTP/FTP): config CRUD + on-demand fetch.
        .route("/recon/ingest", get(ingest_list))
        .route("/recon/ingest", post(ingest_save))
        .route("/recon/ingest/new", get(ingest_new_form))
        .route("/recon/ingest/{id}", get(ingest_edit_form))
        .route("/recon/ingest/{id}/fetch", post(ingest_fetch_now))
        .route("/recon/ingest/{id}/delete", post(ingest_delete))
}

/// The create/edit form — *generated* from the `#[derive(Model)]`
/// metadata (Initiative #6), narrowed to the fields a user actually
/// types. Add a field in `model.rs`, then list its name here to surface
/// it (order is honoured). Widgets, labels and required-ness come from
/// the model; no need to restate them. For a fully hand-built form,
/// swap this for `FormConfig::new(...).field(...)`.
fn item_form() -> FormConfig {
    FormConfig::from_model_fields(
        <crate::model::ReconBatch as vortex_plugin_sdk::orm::model::Model>::meta(),
        "/recon",
        &[
            "supplier_no",
            "supplier_name",
            "invoice_no",
            "invoice_date",
            "currency",
            "currency_rate",
            "doc_total",
            "phase",
            "source_provider",
            "proposal_no",
        ],
    )
}

/// Platform HTML shell: sidebar, vendored assets, mobile layout.
fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/tailwind.css?v=21" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
<script src="/static/vendor/htmx.min.js"></script>
</head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">{content}</main>
</div>
<dialog id="preview-modal" class="modal"><div class="modal-box w-11/12 max-w-5xl h-[85vh] flex flex-col">
  <div class="flex justify-between items-center mb-4">
    <h3 class="font-bold text-lg" id="preview-title">Preview</h3>
    <div class="flex gap-2">
      <a id="preview-download" href="#" class="btn btn-sm btn-ghost" download>Download</a>
      <button class="btn btn-sm btn-circle btn-ghost" onclick="document.getElementById('preview-modal').close();">✕</button>
    </div>
  </div>
  <div id="preview-content" class="flex-1 overflow-hidden bg-base-200 rounded-lg"></div>
</div><form method="dialog" class="modal-backdrop"><button>close</button></form></dialog>
</body></html>"##,
        title = title, sidebar = sidebar, content = content,
    )
}

fn sidebar_for(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    vortex_plugin_sdk::framework::build_sidebar(
        "recon",
        display_name,
        &initials,
        &db_ctx.installed_modules,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
        "",
    )
}

/// GET /recon/dashboard — analytics overview for the reconciliation pipeline:
/// verification KPIs, a stage funnel, verification-status breakdown, recent
/// invoices and top suppliers. All figures are read-only aggregates over
/// `recon_batch` (active rows); nothing here changes state, so no audit.
async fn dashboard(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let scalar = |sql: &'static str| {
        let db = db.clone();
        async move {
            vortex_plugin_sdk::sqlx::query_scalar::<_, i64>(sql)
                .fetch_one(&db)
                .await
                .unwrap_or(0)
        }
    };

    // ── Headline KPIs ────────────────────────────────────────────────────
    let total = scalar("SELECT COUNT(*) FROM recon_batch WHERE active").await;
    let passed =
        scalar("SELECT COUNT(*) FROM recon_batch WHERE active AND validation_status='passed'")
            .await;
    let pending = scalar(
        "SELECT COUNT(*) FROM recon_batch WHERE active AND COALESCE(validation_status,'pending')<>'passed'",
    )
    .await;
    // Variance exceptions: self-check ran and Σ(lines) ≠ printed total.
    let variance = scalar(
        "SELECT COUNT(*) FROM recon_batch WHERE active AND total_variance IS NOT NULL AND ABS(total_variance) > 0.005",
    )
    .await;
    let validated =
        scalar("SELECT COUNT(*) FROM recon_batch WHERE active AND validated_at IS NOT NULL").await;

    let sum_value: f64 = vortex_plugin_sdk::sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(doc_total)::float8 FROM recon_batch WHERE active",
    )
    .fetch_one(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0.0);

    let pass_rate = if total > 0 {
        format!("{:.0}%", (passed as f64 / total as f64) * 100.0)
    } else {
        "—".into()
    };

    let stat = |title: &str, value: &str, desc: &str, cls: &str| {
        format!(
            r#"<div class="stat bg-base-100 rounded-box shadow"><div class="stat-title">{t}</div><div class="stat-value text-2xl {c}">{v}</div><div class="stat-desc">{d}</div></div>"#,
            t = esc(title),
            v = esc(value),
            d = esc(desc),
            c = cls,
        )
    };
    let kpis = format!(
        r#"<div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 mb-6">{}{}{}{}{}{}</div>"#,
        stat("Invoices", &total.to_string(), "captured, active", ""),
        stat("Verified", &passed.to_string(), "matched to M3", "text-success"),
        stat("Pending", &pending.to_string(), "awaiting verification", "text-warning"),
        stat(
            "Variance",
            &variance.to_string(),
            "self-check mismatch",
            if variance > 0 { "text-error" } else { "" }
        ),
        stat("Pass rate", &pass_rate, "verified ÷ total", ""),
        stat(
            "Invoice value",
            &format!("{:.0}", sum_value),
            "Σ document total",
            ""
        ),
    );

    // ── Stage funnel ─────────────────────────────────────────────────────
    // Canonical order + daisyUI colour per stage, sourced from record_stages.
    let stages: Vec<(&str, &str, &str)> = vec![
        ("draft", "Draft", "neutral"),
        ("extracted", "Extracted", "info"),
        ("matched", "Matched", "primary"),
        ("validated", "Validated", "warning"),
        ("approved", "Approved", "success"),
        ("rejected", "Rejected", "error"),
    ];
    let stage_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT record_state, COUNT(*) AS n FROM recon_batch WHERE active GROUP BY record_state",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut stage_counts: std::collections::HashMap<String, i64> =
        std::collections::HashMap::new();
    for r in &stage_rows {
        let s: Option<String> = r.get("record_state");
        let n: i64 = r.get("n");
        stage_counts.insert(s.unwrap_or_default(), n);
    }
    let max_stage = stage_counts.values().copied().max().unwrap_or(1).max(1);
    let mut funnel = String::new();
    for (key, label, color) in &stages {
        let n = stage_counts.get(*key).copied().unwrap_or(0);
        let pct = (n as f64 / max_stage as f64 * 100.0).round() as i64;
        funnel.push_str(&format!(
            r#"<div class="flex items-center gap-3 mb-2">
<div class="w-24 text-sm text-right shrink-0"><span class="badge badge-{color} badge-sm">{label}</span></div>
<div class="flex-1 bg-base-200 rounded h-6 overflow-hidden"><div class="bg-{color} h-6 flex items-center" style="width:{pct}%;min-width:{minw}"></div></div>
<div class="w-10 text-sm font-mono text-right shrink-0">{n}</div>
</div>"#,
            color = color,
            label = esc(label),
            pct = pct,
            minw = if n > 0 { "2rem" } else { "0" },
            n = n,
        ));
    }

    // ── Recent invoices ──────────────────────────────────────────────────
    let recent = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, supplier_name, invoice_no, doc_total::float8 AS doc_total, currency, record_state, validation_status, created_at \
         FROM recon_batch WHERE active ORDER BY created_at DESC LIMIT 10",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let stage_color = |s: &str| {
        stages
            .iter()
            .find(|(k, _, _)| *k == s)
            .map(|(_, _, c)| *c)
            .unwrap_or("neutral")
    };
    let mut recent_rows = String::new();
    for r in &recent {
        let id: Uuid = r.get("id");
        let code: Option<String> = r.get("code");
        let supplier: Option<String> = r.get("supplier_name");
        let inv: Option<String> = r.get("invoice_no");
        let total: Option<f64> = r.get("doc_total");
        let cur: Option<String> = r.get("currency");
        let st: Option<String> = r.get("record_state");
        let vs: Option<String> = r.get("validation_status");
        let st = st.unwrap_or_default();
        let vs = vs.unwrap_or_else(|| "pending".into());
        let (vbadge_cls, vlabel) = if vs == "passed" {
            ("badge-success", "Verified")
        } else {
            ("badge-warning badge-outline", "Pending")
        };
        recent_rows.push_str(&format!(
            r#"<tr class="hover">
<td><a href="/recon/{id}" class="link link-hover font-mono text-xs">{code}</a></td>
<td class="text-sm">{supplier}</td>
<td class="font-mono text-xs">{inv}</td>
<td class="text-right font-mono text-sm">{total} {cur}</td>
<td><span class="badge badge-{scolor} badge-sm">{stage}</span></td>
<td><span class="badge {vcls} badge-sm">{vlabel}</span></td>
</tr>"#,
            id = id,
            code = esc(code.as_deref().unwrap_or("—")),
            supplier = esc(supplier.as_deref().unwrap_or("—")),
            inv = esc(inv.as_deref().unwrap_or("—")),
            total = total.map(|t| format!("{:.2}", t)).unwrap_or_else(|| "—".into()),
            cur = esc(cur.as_deref().unwrap_or("")),
            scolor = stage_color(&st),
            stage = esc(if st.is_empty() { "—" } else { &st }),
            vcls = vbadge_cls,
            vlabel = vlabel,
        ));
    }
    if recent_rows.is_empty() {
        recent_rows.push_str(r#"<tr><td colspan="6" class="text-center opacity-60 py-6">No invoices yet — <a href="/recon/upload" class="link">upload one</a>.</td></tr>"#);
    }

    // ── Top suppliers ────────────────────────────────────────────────────
    let suppliers = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(NULLIF(supplier_name,''), supplier_no, '(unknown)') AS name, \
                COUNT(*) AS n, SUM(doc_total)::float8 AS total \
         FROM recon_batch WHERE active GROUP BY 1 ORDER BY total DESC NULLS LAST LIMIT 5",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut supplier_rows = String::new();
    for r in &suppliers {
        let name: String = r.get("name");
        let n: i64 = r.get("n");
        let total: Option<f64> = r.get("total");
        supplier_rows.push_str(&format!(
            r#"<tr class="hover"><td class="text-sm">{name}</td><td class="text-right font-mono text-sm">{n}</td><td class="text-right font-mono text-sm">{total}</td></tr>"#,
            name = esc(&name),
            n = n,
            total = total.map(|t| format!("{:.2}", t)).unwrap_or_else(|| "—".into()),
        ));
    }
    if supplier_rows.is_empty() {
        supplier_rows.push_str(r#"<tr><td colspan="3" class="text-center opacity-60 py-6">—</td></tr>"#);
    }

    let content = format!(
        r##"<div class="flex items-center justify-between flex-wrap gap-2 mb-6">
<h1 class="text-2xl font-bold">Reconciliation Dashboard</h1>
<div class="flex gap-2">
  <a href="/recon/verify" class="btn btn-sm btn-outline">Verification worklist</a>
  <a href="/recon/upload" class="btn btn-sm btn-primary">Upload invoices</a>
</div>
</div>
{kpis}
<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
  <div class="lg:col-span-2 card bg-base-100 shadow"><div class="card-body">
    <h2 class="card-title text-lg mb-3">Pipeline</h2>
    {funnel}
    <p class="text-xs opacity-60 mt-2">Invoices by processing stage. {validated} validated to date.</p>
  </div></div>
  <div class="card bg-base-100 shadow"><div class="card-body">
    <h2 class="card-title text-lg mb-3">Top suppliers</h2>
    <div class="overflow-x-auto"><table class="table table-sm">
    <thead><tr><th>Supplier</th><th class="text-right">Invoices</th><th class="text-right">Value</th></tr></thead>
    <tbody>{supplier_rows}</tbody></table></div>
  </div></div>
</div>
<div class="card bg-base-100 shadow mt-6"><div class="card-body">
  <div class="flex items-center justify-between mb-3">
    <h2 class="card-title text-lg">Recent invoices</h2>
    <a href="/recon" class="link link-hover text-sm">View all →</a>
  </div>
  <div class="overflow-x-auto"><table class="table table-sm">
  <thead><tr><th>Code</th><th>Supplier</th><th>Invoice #</th><th class="text-right">Total</th><th>Stage</th><th>Verification</th></tr></thead>
  <tbody>{recent_rows}</tbody></table></div>
</div></div>"##,
        kpis = kpis,
        funnel = funnel,
        validated = validated,
        supplier_rows = supplier_rows,
        recent_rows = recent_rows,
    );

    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Reconciliation Dashboard", &content)).into_response()
}

/// GET /recon — list view: search, sort, filters, pagination all
/// come from the list framework; you only declare columns.
async fn list_items(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListConfig, ListParams, SortDir,
    };

    // Columns are *generated* from the `#[derive(Model)]` metadata
    // (Initiative #6): scalar fields become sortable/searchable columns,
    // booleans render as badges. To hand-pick columns, filters and
    // coloured status badges, swap this for
    // `ListConfig::new("Reconciliation", "recon_batch").column(...)`.
    let config = ListConfig::from_model(
        <crate::model::ReconBatch as vortex_plugin_sdk::orm::model::Model>::meta(),
    )
    .detail_url("/recon/{id}")
    .create("+ New", "/recon/new")
    // Newest invoices first by default (created_at is a system column, so this
    // resolves via the author-controlled literal fallback — safe).
    .default_sort("created_at");

    let mut params = ListParams::from_query(&query);
    // Default to latest-first. Only when the user hasn't chosen a column
    // (`?sort=` absent) — an explicit column sort is always honoured, and its
    // direction round-trips through the header links unchanged.
    if !query.contains_key("sort") {
        params.sort_dir = SortDir::Desc;
    }
    let table = match execute_list(&db, &config, &params).await {
        Ok(result) => render_list(&config, &result, &params, "/recon"),
        Err(e) => {
            error!("recon list failed: {e}");
            format!("<div class=\"alert alert-error\">List error: {e}</div>")
        }
    };

    let content = format!(
        r##"<div class="flex justify-between items-center mb-6 flex-wrap gap-3">
  <h1 class="text-2xl font-bold">Reconciliation</h1>
  <a href="/recon/upload" class="btn btn-primary btn-sm">
    <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-8l-4-4m0 0L8 8m4-4v12"/></svg>
    Upload Invoices
  </a>
</div>{table}"##,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Reconciliation", &content)).into_response()
}

/// GET /recon/new — create form, rendered by the form engine.
async fn new_item_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let form = render_form(
        &db, &item_form(), FormMode::Create, None, &Default::default(), &[],
    )
    .await;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "New - Reconciliation", &form)).into_response()
}

/// POST /recon/create — validate + insert via the form engine,
/// then stamp the sequence code, audit, redirect.
async fn create_item(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match execute_form_save(&db, &item_form(), &pairs, None).await {
        Ok(SaveOutcome::Saved(id)) => {
            // Post-create enrichments the form doesn't own: sequence
            // code and creator.
            let code = vortex_plugin_sdk::orm::sequence::next(&db_ctx.pool, &ITEM_SEQ)
                .await
                .unwrap_or_else(|_| id.to_string());
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_batch SET code = $2, created_by = $3 WHERE id = $1",
            )
            .bind(id)
            .bind(&code)
            .bind(user.id)
            .execute(&db)
            .await;

            audit_item(&state, &user, &db_ctx, id, AuditAction::RecordCreated, json!({"code": code})).await;
            Redirect::to(&format!("/recon/{id}")).into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let form = render_form(&db, &item_form(), FormMode::Create, None, &values, &errors).await;
            let sidebar = sidebar_for(&state, &user, &db_ctx);
            Html(page_shell(&sidebar, "New - Reconciliation", &form)).into_response()
        }
        Err(e) => {
            error!("create failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Create failed").into_response()
        }
    }
}

/// GET /recon/{id}/edit — edit form, pre-filled by the engine.
async fn edit_item_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let values = match load_record(&db, &item_form(), id).await {
        Ok(Some(v)) => v,
        Ok(None) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
        Err(e) => {
            error!("load failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Load failed").into_response();
        }
    };
    let form = render_form(
        &db, &item_form(), FormMode::Edit, Some(&id.to_string()), &values, &[],
    )
    .await;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Edit - Reconciliation", &form)).into_response()
}

/// POST /recon/{id} — validate + update via the form engine.
async fn update_item(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match execute_form_save(&db, &item_form(), &pairs, Some(id)).await {
        Ok(SaveOutcome::Saved(_)) => {
            audit_item(&state, &user, &db_ctx, id, AuditAction::RecordUpdated, json!({"via": "form"})).await;
            Redirect::to(&format!("/recon/{id}")).into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let form = render_form(
                &db, &item_form(), FormMode::Edit, Some(&id.to_string()), &values, &errors,
            )
            .await;
            let sidebar = sidebar_for(&state, &user, &db_ctx);
            Html(page_shell(&sidebar, "Edit - Reconciliation", &form)).into_response()
        }
        Err(e) => {
            error!("update failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Update failed").into_response()
        }
    }
}

/// GET /recon/{id} — record page: status bar + fields + chatter.
async fn item_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT code, supplier_no, supplier_name, invoice_no, invoice_no_canonical,
                currency, doc_total::float8 AS doc_total, record_state,
                validation_status, computed_total::float8 AS computed_total,
                total_variance::float8 AS total_variance,
                doc_tax::float8 AS doc_tax, doc_subtotal::float8 AS doc_subtotal,
                tax_per_line
         FROM recon_batch WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let code: Option<String> = row.try_get("code").ok().flatten();
    let supplier_no: String = row.try_get("supplier_no").unwrap_or_default();
    let supplier_name: Option<String> = row.try_get("supplier_name").ok().flatten();
    let invoice_no: Option<String> = row.try_get("invoice_no").ok().flatten();
    let invoice_canon: Option<String> = row.try_get("invoice_no_canonical").ok().flatten();
    let currency: Option<String> = row.try_get("currency").ok().flatten();
    let doc_total: Option<f64> = row.try_get("doc_total").ok().flatten();
    let record_state: String = row.get("record_state");
    let validation_status: String =
        row.try_get("validation_status").unwrap_or_else(|_| "pending".into());
    let computed_total: Option<f64> = row.try_get("computed_total").ok().flatten();
    let total_variance: Option<f64> = row.try_get("total_variance").ok().flatten();
    let doc_tax: Option<f64> = row.try_get("doc_tax").ok().flatten();
    let tax_per_line: bool = row.try_get("tax_per_line").unwrap_or(false);

    // Page title: supplier + invoice number, falling back to the code.
    let title = supplier_name
        .clone()
        .or_else(|| Some(supplier_no.clone()))
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| code.clone().unwrap_or_else(|| "Reconciliation".into()));

    // Status bar: stages come from the DB (admins edit them in
    // Settings ▸ Stages); clicking a stage POSTs to /status/{state}.
    // Status bar is display-only; movement is via role-gated action buttons.
    let bar = vortex_plugin_sdk::framework::status::StatusBar::from_db(
        &db, "recon_batch", "recon_batch", "record_state",
    )
    .await
    .render(&record_state, &format!("/recon/{id}/status"));
    let stage_actions = vortex_plugin_sdk::framework::status::StageActions::from_db(&db, "recon_batch")
        .await
        .render(&record_state, &user.roles, &format!("/recon/{id}/status"));

    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let total_str = doc_total
        .map(|d| format!("{} {:.2}", currency.as_deref().unwrap_or(""), d))
        .unwrap_or_else(|| "—".into());
    let canon_note = invoice_canon
        .as_deref()
        .filter(|c| Some(*c) != invoice_no.as_deref())
        .map(|c| format!(" <span class=\"opacity-50\">(canonical: <code>{}</code>)</span>", esc(c)))
        .unwrap_or_default();

    // Scanned invoice card: the uploaded PDF, previewed inline via pdf.js.
    let scan = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, mimetype FROM ir_attachment
         WHERE res_model = 'recon.batch' AND res_id = $1
         ORDER BY created_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let has_scan = scan.is_some();
    let scan_card = match scan {
        Some(r) => {
            let att_id: Uuid = r.get("id");
            let fname: String = r.try_get("name").unwrap_or_default();
            let mime: String = r.try_get("mimetype").ok().flatten().unwrap_or_default();
            let url = format!("/recon/attachments/{att_id}/download");
            let kind = if mime.starts_with("image/") { "image" } else { "pdf" };
            // Both PDFs and images are rendered into the same zoom/pan viewport
            // by JS below (reconRenderScan / reconRenderImage) — so the viewer
            // container starts empty for both.
            let viewer = String::new();
            format!(
                r##"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <div class="flex justify-between items-center flex-wrap gap-2">
    <h2 class="card-title text-base">Scanned Invoice <span class="font-normal opacity-60 text-sm">{fname}</span></h2>
    <div class="flex gap-1 items-center">
      <button type="button" class="btn btn-xs btn-outline" onclick="reconZoomStep(-1)" title="Zoom out">−</button>
      <button type="button" class="btn btn-xs btn-outline" onclick="reconFit()" title="Fit whole page">Fit</button>
      <button type="button" class="btn btn-xs btn-outline" onclick="reconZoomStep(1)" title="Zoom in">+</button>
      <a href="{url}" target="_blank" rel="noopener" class="btn btn-xs btn-ghost ml-1">Open</a>
    </div>
  </div>
  <p class="text-xs opacity-50 mt-1" id="recon-locate-hint">Click a line on the left to zoom to it on the document.</p>
  <!-- Fixed viewport: the preview STAYS PUT; clicking a line pans + zooms the
       document to that line (transform on the pages layer), so a long invoice
       stays usable without scrolling the panel away. -->
  <div id="recon-scan" class="mt-2 border border-base-300 rounded" style="position:relative;height:calc(100vh - 11rem);min-height:22rem;overflow:auto;background:#525659">{viewer}</div>
  <script>
  window.__reconDoc = {{ el:null, sizer:null, pages:null, items:[], baseW:0, baseH:0, focusZoom:2.0, lastCy:null, ready:false }};
  // Scale the pages layer AND size a spacer to its scaled dimensions, so the
  // fixed viewport gets real scrollbars — the user can pan up/down/left/right.
  function reconSetZoom(Z){{
    var D=window.__reconDoc; if(!D.pages) return;
    D.zoom=Z;
    D.pages.style.transform='scale('+Z+')';
    D.sizer.style.width=(D.baseW*Z)+'px'; D.sizer.style.height=(D.baseH*Z)+'px';
  }}
  window.reconFit=function(){{ var D=window.__reconDoc; if(!D.el) return; D.lastCy=null; reconSetZoom(1); D.el.scrollTo({{top:0,left:0}}); }};
  window.reconFocus=function(cy){{
    var D=window.__reconDoc; if(!D.el) return; D.lastCy=cy; var Z=D.focusZoom; reconSetZoom(Z);
    var left=(D.baseW/2)*Z - D.el.clientWidth/2, top=cy*Z - D.el.clientHeight/2;
    D.el.scrollTo({{left:Math.max(0,left), top:Math.max(0,top), behavior:'smooth'}});
  }};
  window.reconZoomStep=function(dir){{
    var D=window.__reconDoc; if(!D.el) return;
    D.focusZoom=Math.max(1, Math.min(6, D.focusZoom*(dir>0?1.25:0.8)));
    if(D.lastCy!=null) reconFocus(D.lastCy); else reconSetZoom(D.focusZoom);
  }};
  // Click-and-drag panning (mouse only; touch keeps native scrolling).
  function reconEnableDrag(el){{
    var down=false, sx=0, sy=0, sl=0, st=0;
    el.style.cursor='grab';
    el.addEventListener('pointerdown', function(e){{
      if(e.button!==0 || (e.pointerType && e.pointerType!=='mouse')) return;
      down=true; sx=e.clientX; sy=e.clientY; sl=el.scrollLeft; st=el.scrollTop;
      el.style.cursor='grabbing';
      try{{ el.setPointerCapture(e.pointerId); }}catch(_e){{}}
      e.preventDefault();
    }});
    el.addEventListener('pointermove', function(e){{
      if(!down) return;
      el.scrollLeft=sl-(e.clientX-sx); el.scrollTop=st-(e.clientY-sy);
    }});
    function end(e){{ if(!down) return; down=false; el.style.cursor='grab';
      try{{ el.releasePointerCapture(e.pointerId); }}catch(_e){{}} }}
    el.addEventListener('pointerup', end);
    el.addEventListener('pointercancel', end);
    el.addEventListener('pointerleave', end);
  }}
  window.reconRenderScan = function(url, el){{
    el.innerHTML='<div class="rpdf-sizer" style="position:relative">'+
      '<div class="rpdf-pages" style="position:relative;transform-origin:0 0;will-change:transform;'+
      'display:inline-flex;flex-direction:column;align-items:center;gap:10px;padding:10px;background:#525659"></div></div>';
    var sizer=el.firstChild, pages=sizer.firstChild;
    window.__reconDoc.el=el; window.__reconDoc.sizer=sizer; window.__reconDoc.pages=pages; window.__reconDoc.items=[];
    reconEnableDrag(el);
    var status=document.createElement('div');
    status.style.cssText='padding:2rem;text-align:center;color:#ddd'; status.textContent='Loading document…';
    pages.appendChild(status);
    import('/static/vendor/pdfjs/pdf.min.mjs').then(function(pdfjs){{
      pdfjs.GlobalWorkerOptions.workerSrc='/static/vendor/pdfjs/pdf.worker.min.mjs';
      return pdfjs.getDocument({{url:url, withCredentials:true}}).promise.then(function(pdf){{
        if(status.parentNode) status.remove();
        var maxW=Math.min(el.clientWidth-20,1100), dpr=window.devicePixelRatio||1, chain=Promise.resolve();
        for(var i=1;i<=pdf.numPages;i++){{(function(n){{
          chain=chain.then(function(){{ return pdf.getPage(n).then(function(page){{
            var base=page.getViewport({{scale:1}}), scale=maxW/base.width, vp=page.getViewport({{scale:scale}});
            var wrap=document.createElement('div'); wrap.className='rpdf-page'; wrap.__pi=n; wrap.style.cssText='position:relative;flex:0 0 auto';
            var canvas=document.createElement('canvas');
            canvas.width=Math.floor(vp.width*dpr); canvas.height=Math.floor(vp.height*dpr);
            canvas.style.width=vp.width+'px'; canvas.style.height=vp.height+'px'; canvas.style.display='block'; canvas.style.background='#fff';
            wrap.appendChild(canvas);
            var hl=document.createElement('div'); hl.className='rpdf-hl'; hl.style.cssText='position:absolute;inset:0;pointer-events:none'; wrap.appendChild(hl);
            pages.appendChild(wrap);
            var ctx=canvas.getContext('2d'); ctx.scale(dpr,dpr);
            return page.render({{canvasContext:ctx,viewport:vp}}).promise.then(function(){{ return page.getTextContent(); }}).then(function(tc){{
              tc.items.forEach(function(it){{
                if(!it.str||!it.str.trim()) return;
                var m=pdfjs.Util.transform(vp.transform, it.transform);
                var fh=Math.hypot(m[2],m[3])||10;
                window.__reconDoc.items.push({{wrap:wrap, hl:hl, top:m[5]-fh, h:fh, str:it.str}});
              }});
            }});
          }}); }});
        }})(i);}}
        return chain.then(function(){{
          var D=window.__reconDoc; D.baseW=D.pages.offsetWidth; D.baseH=D.pages.offsetHeight; D.ready=true; reconFit();
        }});
      }});
    }}).catch(function(e){{
      pages.innerHTML='<div style="padding:2rem;text-align:center;color:#f88">Could not render PDF — '+(e&&e.message||e)+'</div>';
    }});
  }};
  // Images have no text layer, so we render the raster into the SAME zoom/pan
  // viewport (single "page"). This makes +/−, Fit and drag-pan work identically
  // to PDFs. Per-line highlighting is driven by stored bands (reconLocateBand),
  // not text search — see the row click handler.
  window.reconRenderImage = function(url, el){{
    el.innerHTML='<div class="rpdf-sizer" style="position:relative">'+
      '<div class="rpdf-pages" style="position:relative;transform-origin:0 0;will-change:transform;'+
      'display:inline-flex;flex-direction:column;align-items:center;gap:10px;padding:10px;background:#525659"></div></div>';
    var sizer=el.firstChild, pages=sizer.firstChild;
    var D=window.__reconDoc; D.el=el; D.sizer=sizer; D.pages=pages; D.items=[];
    reconEnableDrag(el);
    var wrap=document.createElement('div'); wrap.className='rpdf-page'; wrap.__pi=1;
    wrap.style.cssText='position:relative;flex:0 0 auto';
    var img=document.createElement('img'); img.alt='scan';
    var maxW=Math.min(el.clientWidth-20,1100);
    img.style.cssText='display:block;width:'+maxW+'px;height:auto;background:#fff';
    wrap.appendChild(img);
    var hl=document.createElement('div'); hl.className='rpdf-hl';
    hl.style.cssText='position:absolute;inset:0;pointer-events:none'; wrap.appendChild(hl);
    pages.appendChild(wrap);
    D.imgWrap=wrap; D.imgHl=hl;
    img.onload=function(){{
      var D=window.__reconDoc; D.baseW=D.pages.offsetWidth; D.baseH=D.pages.offsetHeight; D.ready=true; reconFit();
    }};
    img.onerror=function(){{ pages.innerHTML='<div style="padding:2rem;text-align:center;color:#f88">Could not load image.</div>'; }};
    img.src=url;
  }};
  // Highlight + smart-zoom to a stored line band on an IMAGE scan. y/h are
  // fractions of page height (0..1) supplied by the vision model at extraction.
  window.reconLocateBand = function(y, h){{
    var D=window.__reconDoc; if(!D||!D.imgHl||!D.imgWrap||!D.baseH) return 0;
    D.imgHl.querySelectorAll('.rpdf-band').forEach(function(n){{n.remove();}});
    if(y==null||isNaN(y)) return 0;
    var imgH=D.imgWrap.offsetHeight||D.baseH;
    var top=Math.max(0, y*imgH), ht=Math.max((h||0.03)*imgH, 10);
    var band=document.createElement('div'); band.className='rpdf-band';
    band.style.cssText='position:absolute;left:0;right:0;top:'+top+'px;height:'+ht+'px;'+
      'background:rgba(255,214,0,0.32);border-top:2px solid rgba(235,170,0,.95);border-bottom:2px solid rgba(235,170,0,.95);pointer-events:none';
    D.imgHl.appendChild(band);
    var cy=D.imgWrap.offsetTop + top + ht/2; reconFocus(cy);
    return 1;
  }};
  // Find the invoice row matching the line (SKU first, description words fallback),
  // highlight it, and smart-zoom the fixed preview to it.
  window.reconLocate = function(sku, desc){{
    var D=window.__reconDoc; if(!D||!D.pages) return 0;
    D.pages.querySelectorAll('.rpdf-band').forEach(function(n){{n.remove();}});
    function norm(s){{ return (s||'').toUpperCase().replace(/[^A-Z0-9]/g,''); }}
    var targets=[]; var skn=norm(sku);
    if(skn.length>=4) targets.push(skn);
    if(!targets.length && desc){{ desc.split(/\s+/).forEach(function(w){{ var n=norm(w); if(n.length>=5) targets.push(n); }}); }}
    if(!targets.length || !D.items.length) return 0;
    var seen=new Set(), matches=[];
    D.items.forEach(function(it){{
      var n=norm(it.str); if(n.length<3) return;
      for(var k=0;k<targets.length;k++){{ var t=targets[k];
        if(n.indexOf(t)>=0 || (t.indexOf(n)>=0 && n.length>=5)){{
          var key=it.wrap.__pi+':'+Math.round(it.top); if(!seen.has(key)){{ seen.add(key); matches.push(it); }} break; }}
      }}
    }});
    var first=null;
    matches.forEach(function(it){{
      var band=document.createElement('div'); band.className='rpdf-band';
      band.style.cssText='position:absolute;left:0;right:0;top:'+(it.top-3)+'px;height:'+(it.h+6)+'px;'+
        'background:rgba(255,214,0,0.32);border-top:2px solid rgba(235,170,0,.95);border-bottom:2px solid rgba(235,170,0,.95);pointer-events:none';
      it.hl.appendChild(band); if(!first) first=it;
    }});
    if(first){{ var cy=first.wrap.offsetTop + first.top + first.h/2; reconFocus(cy); }}
    return matches.length;
  }};
  window.__reconKind = "{kind}";
  document.addEventListener("DOMContentLoaded",function(){{
    var el=document.getElementById("recon-scan");
    if(!el) return;
    if("{kind}"==="pdf") window.reconRenderScan("{url}", el);
    else if("{kind}"==="image") window.reconRenderImage("{url}", el);
  }});
  </script>
</div></div>"##,
                fname = esc(&fname), url = esc(&url), kind = kind, viewer = viewer,
            )
        }
        None => format!(
            r##"<div class="alert mb-6"><span>No scanned invoice attached.
<a href="/recon/upload" class="link">Upload one</a>.</span></div>"##
        ),
    };

    // ── Extraction self-check card (Part 1) ──────────────────────────────────
    // Existing lines seed the editable grid; the verdict banner shows the last
    // self-check result.
    let cur = currency.clone().unwrap_or_default();
    let inv_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT line_no, supplier_sku, description, uom,
                qty::float8 AS qty, unit_price_excl::float8 AS unit_price,
                discount_pct::float8 AS discount_pct, discount_amt::float8 AS discount_amt,
                sales_tax::float8 AS tax, doc_y::float8 AS doc_y, doc_h::float8 AS doc_h
         FROM recon_inv_line WHERE batch_id = $1 ORDER BY line_no NULLS LAST, created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let lines_json: Vec<vortex_plugin_sdk::serde_json::Value> = inv_lines
        .iter()
        .map(|r| {
            json!({
                "line_no": r.try_get::<Option<i32>, _>("line_no").ok().flatten(),
                "supplier_sku": r.try_get::<Option<String>, _>("supplier_sku").ok().flatten(),
                "description": r.try_get::<Option<String>, _>("description").ok().flatten(),
                "uom": r.try_get::<Option<String>, _>("uom").ok().flatten(),
                "qty": r.try_get::<Option<f64>, _>("qty").ok().flatten(),
                "unit_price": r.try_get::<Option<f64>, _>("unit_price").ok().flatten(),
                "discount_pct": r.try_get::<Option<f64>, _>("discount_pct").ok().flatten(),
                "discount_amt": r.try_get::<Option<f64>, _>("discount_amt").ok().flatten(),
                // Invoice-level SST is stored as allocated per-line tax; only
                // surface it in the Line Tax field when the invoice is genuinely
                // per-line — otherwise it's driven by the footer SST field.
                "tax": if tax_per_line {
                    r.try_get::<Option<f64>, _>("tax").ok().flatten()
                } else {
                    Some(0.0)
                },
                // Line-locate band (image scans); carried so the grid can zoom
                // to the line and a manual save preserves the coordinates.
                "doc_y": r.try_get::<Option<f64>, _>("doc_y").ok().flatten(),
                "doc_h": r.try_get::<Option<f64>, _>("doc_h").ok().flatten(),
            })
        })
        .collect();
    // Guard the seed against a stray `</script>` in DB text.
    let lines_seed = vortex_plugin_sdk::serde_json::to_string(&lines_json)
        .unwrap_or_else(|_| "[]".into())
        .replace("</", "<\\/");

    let verdict = match validation_status.as_str() {
        "passed" => format!(
            r##"<div class="alert alert-success mb-4"><span>✓ <b>Self-check passed.</b> Computed grand total {cur} {computed:.2} = printed invoice total (variance {var:.2}).</span></div>"##,
            cur = esc(&cur),
            computed = computed_total.unwrap_or(0.0),
            var = total_variance.unwrap_or(0.0),
        ),
        "exception" => format!(
            r##"<div class="alert alert-error mb-4"><div>
  <div class="font-bold">⚠ Exception — computed total does not match the invoice.</div>
  <div class="text-sm">Computed grand total = <b>{cur} {computed:.2}</b>, printed total = <b>{cur} {stated:.2}</b>, variance = <b>{var:+.2}</b>. Check the lines / discount / SST against the scan, correct, and re-validate.</div>
</div></div>"##,
            cur = esc(&cur),
            computed = computed_total.unwrap_or(0.0),
            stated = doc_total.unwrap_or(0.0),
            var = total_variance.unwrap_or(0.0),
        ),
        _ => String::new(),
    };

    // Queue/batch state for this invoice → a badge + the urgent "Extract now".
    let ai_row = vortex_plugin_sdk::sqlx::query(
        "SELECT ai_extract_state, ai_batch_id IS NOT NULL AS in_batch FROM recon_batch WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let ai_state: String = ai_row.as_ref().and_then(|r| r.try_get::<String, _>("ai_extract_state").ok()).unwrap_or_else(|| "none".into());
    let in_batch: bool = ai_row.as_ref().map(|r| r.try_get::<bool, _>("in_batch").unwrap_or(false)).unwrap_or(false);
    let state_badge = match ai_state.as_str() {
        "queued" => r#"<span class="badge badge-warning badge-sm" title="Waiting for a batch">⏳ Queued for batch</span>"#,
        // 'processing' means either an on-demand Extract-now is running, or the
        // invoice was submitted in a batch — the batch link tells them apart.
        "processing" if in_batch => r#"<span class="badge badge-info badge-sm" title="Submitted to the batch API">⚙ In batch…</span>"#,
        "processing" => r#"<span class="badge badge-info badge-sm" title="Extraction in progress">⚙ Extracting…</span>"#,
        "error" => r#"<span class="badge badge-error badge-sm">Extraction failed</span>"#,
        _ => "",
    };
    let extract_btn = if has_scan {
        // "Extract now" jumps the batch queue for an urgent invoice (synchronous).
        format!(
            r##"{badge}<button type="button" class="btn btn-sm btn-secondary" onclick="reconExtract('{id}')" title="OCR this scan immediately (skips the batch queue)">⚡ Extract now</button>"##,
            badge = state_badge, id = id
        )
    } else {
        String::new()
    };

    let lines_card = format!(
        r##"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <div class="flex justify-between items-center flex-wrap gap-2">
    <h2 class="card-title text-base">Extraction — Invoice Lines</h2>
    <div class="flex items-center gap-2">
      {extract_btn}
      <button type="button" class="btn btn-sm btn-outline" onclick="reconAddLine()">+ Add line</button>
      <button type="button" class="btn btn-sm btn-primary" onclick="reconSaveLines('{id}')">Save lines</button>
      <button type="button" class="btn btn-sm btn-success" onclick="reconValidate('{id}')">Validate total</button>
    </div>
  </div>
  {verdict}
  <div id="recon-lines" class="mt-2 flex flex-col gap-2"></div>
  <div class="flex justify-end mt-3">
    <table class="text-sm w-full max-w-sm">
      <tr><td class="py-1">Subtotal (excl SST)</td>
          <td class="text-right font-mono" id="recon-subtotal">0.00</td></tr>
      <tr><td class="py-1">SST / Tax
            <span class="opacity-50 text-xs" id="recon-tax-mode"></span></td>
          <td class="text-right"><input id="recon-doctax" type="number" step="0.01" inputmode="decimal"
                class="input input-bordered input-xs w-28 text-right" value="{doctax}" placeholder="0.00"></td></tr>
      <tr class="border-t border-base-300"><td class="py-1 font-semibold">Grand total (incl)</td>
          <td class="text-right font-mono font-bold" id="recon-grand">0.00</td></tr>
      <tr><td class="py-1">Printed invoice total</td>
          <td class="text-right"><input id="recon-stated" type="number" step="0.01" inputmode="decimal"
                class="input input-bordered input-xs w-28 text-right" value="{stated}" placeholder="0.00"></td></tr>
      <tr><td class="py-1">Variance (grand − printed)</td>
          <td class="text-right font-mono font-bold" id="recon-variance">—</td></tr>
    </table>
  </div>
  <p class="text-xs opacity-50 mt-1">Currency: <code>{cur}</code>. Net = Qty × Unit Price × (1 − Disc%) − Disc Amt (use whichever the invoice prints). Enter <b>Line Tax</b> when SST is printed per line; otherwise leave it 0 and put the footer SST in <b>SST / Tax</b> — it is allocated across lines. Passes when the computed grand total matches the printed total within {tol:.2}.</p>
</div></div>
<script>
(function(){{
  var SEED = {seed};
  function r2(x){{ return Math.round(x*100)/100; }}
  function esc(s){{ return (s==null?'':String(s)); }}
  function inp(cls,val,type,step,ph){{
    return '<input type="'+(type||'text')+'"'+(step?' step="'+step+'"':'')+(type==='number'?' inputmode="decimal"':'')+
      ' placeholder="'+(ph||'')+'" class="input input-bordered input-sm w-full '+(cls||'')+
      '" value="'+esc(val).replace(/"/g,'&quot;')+'" oninput="reconRecalc()">';
  }}
  function fld(label,html){{
    return '<label class="flex flex-col gap-1"><span class="text-xs opacity-60">'+label+'</span>'+html+'</label>';
  }}
  window.reconAddLine=function(seedRow){{
    var box=document.getElementById('recon-lines');
    var r=seedRow||{{}};
    var div=document.createElement('div');
    div.className='reco-row border border-base-300 rounded-lg p-3 bg-base-200/40 cursor-pointer';
    div.title='Click to highlight this line on the document';
    // Stash the image-locate band (if the extractor found one) so an image scan
    // can zoom to this line, and a manual save round-trips the coordinates.
    if(r.doc_y!=null){{ div.dataset.docY=r.doc_y; div.dataset.docH=(r.doc_h!=null?r.doc_h:0.03); }}
    // Row 1 — identity. Row 2 — labelled numbers, so nothing gets clipped.
    div.innerHTML=
      '<div class="flex items-center gap-2 mb-2">'+
        '<span class="reco-idx badge badge-neutral badge-sm shrink-0"></span>'+
        '<div class="w-40 shrink-0">'+inp('reco-sku',r.supplier_sku,'text','','Supplier SKU')+'</div>'+
        '<div class="flex-1 min-w-0">'+inp('reco-desc',r.description,'text','','Description')+'</div>'+
        '<div class="w-24 shrink-0">'+inp('reco-uom',r.uom,'text','','UOM')+'</div>'+
        '<button type="button" class="btn btn-ghost btn-sm shrink-0" title="Remove line" onclick="this.closest(\'.reco-row\').remove();reconRecalc()">✕</button>'+
      '</div>'+
      '<div class="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-6 gap-2">'+
        fld('Qty', inp('reco-qty text-right',r.qty,'number','0.0001','0'))+
        fld('Unit Price', inp('reco-price text-right',r.unit_price,'number','0.0001','0.00'))+
        fld('Disc %', inp('reco-disc text-right',r.discount_pct,'number','0.01','0'))+
        fld('Disc Amt', inp('reco-discamt text-right',r.discount_amt,'number','0.01','0.00'))+
        fld('Line Tax', inp('reco-tax text-right',r.tax,'number','0.01','0.00'))+
        fld('Net (excl)', '<div class="reco-net input input-bordered input-sm bg-base-200 text-right font-mono flex items-center justify-end">0.00</div>')+
      '</div>';
    // Click the line → highlight its row on the scanned document.
    div.addEventListener('click', function(ev){{
      if(ev.target.closest('button')) return; // remove button
      document.querySelectorAll('#recon-lines .reco-row').forEach(function(r){{ r.classList.remove('ring','ring-2','ring-warning'); }});
      div.classList.add('ring','ring-2','ring-warning');
      var hint=document.getElementById('recon-locate-hint');
      if(window.__reconKind==="image"){{
        // Images have no text layer: zoom to the stored band for this line.
        if(div.dataset.docY!=null && window.reconLocateBand){{
          var m=window.reconLocateBand(parseFloat(div.dataset.docY), parseFloat(div.dataset.docH));
          if(hint) hint.textContent = m>0 ? 'Zoomed to this line on the scan.' : 'Could not place this line on the image.';
        }} else if(hint){{
          hint.textContent = 'No saved position for this line. Enable "Locate lines on images" in AI Extraction, then re-extract.';
        }}
      }} else if(window.reconLocate){{
        var n=window.reconLocate(div.querySelector('.reco-sku').value, div.querySelector('.reco-desc').value);
        if(hint) hint.textContent = n>0 ? ('Highlighted on document — '+n+' match'+(n>1?'es':'')+'.') : 'No text match found (scanned image, or wording differs from the invoice).';
      }}
    }});
    box.appendChild(div);
    reconRecalc();
  }};
  window.reconRecalc=function(){{
    var rows=document.querySelectorAll('#recon-lines .reco-row'), subtotal=0, lineTax=0;
    rows.forEach(function(tr,i){{
      tr.querySelector('.reco-idx').textContent=(i+1);
      var q=parseFloat(tr.querySelector('.reco-qty').value)||0;
      var p=parseFloat(tr.querySelector('.reco-price').value)||0;
      var d=parseFloat(tr.querySelector('.reco-disc').value)||0;
      var da=parseFloat(tr.querySelector('.reco-discamt').value)||0;
      var t=parseFloat(tr.querySelector('.reco-tax').value)||0;
      var net=r2(q*p*(1-d/100)-da); subtotal+=net; lineTax+=t;
      tr.querySelector('.reco-net').textContent=net.toFixed(2);
    }});
    subtotal=r2(subtotal); lineTax=r2(lineTax);
    var docTaxEl=document.getElementById('recon-doctax');
    var docTax=parseFloat(docTaxEl.value)||0;
    var perLine=lineTax>0.005;
    var effTax=perLine?lineTax:docTax;
    document.getElementById('recon-tax-mode').textContent=perLine?'(per line)':'(invoice-level, allocated)';
    docTaxEl.disabled=perLine;
    if(perLine) docTaxEl.value=lineTax.toFixed(2);
    var grand=r2(subtotal+effTax);
    document.getElementById('recon-subtotal').textContent=subtotal.toFixed(2);
    document.getElementById('recon-grand').textContent=grand.toFixed(2);
    var stated=parseFloat(document.getElementById('recon-stated').value);
    var vEl=document.getElementById('recon-variance');
    if(isNaN(stated)){{ vEl.textContent='—'; vEl.className='text-right font-mono font-bold'; }}
    else{{ var v=r2(grand-stated); vEl.textContent=(v>0?'+':'')+v.toFixed(2);
      vEl.className='text-right font-mono font-bold '+(Math.abs(v)<={tol}?'text-success':'text-error'); }}
  }};
  function collect(){{
    var lines=[];
    document.querySelectorAll('#recon-lines .reco-row').forEach(function(tr,i){{
      lines.push({{line_no:i+1,
        supplier_sku:tr.querySelector('.reco-sku').value,
        description:tr.querySelector('.reco-desc').value,
        uom:tr.querySelector('.reco-uom').value,
        qty:parseFloat(tr.querySelector('.reco-qty').value)||0,
        unit_price:parseFloat(tr.querySelector('.reco-price').value)||0,
        discount_pct:parseFloat(tr.querySelector('.reco-disc').value)||0,
        discount_amt:parseFloat(tr.querySelector('.reco-discamt').value)||0,
        tax:parseFloat(tr.querySelector('.reco-tax').value)||0,
        doc_y:(tr.dataset.docY!=null?parseFloat(tr.dataset.docY):null),
        doc_h:(tr.dataset.docH!=null?parseFloat(tr.dataset.docH):null)}});
    }});
    var st=parseFloat(document.getElementById('recon-stated').value);
    var dt=parseFloat(document.getElementById('recon-doctax').value);
    return {{stated_total:isNaN(st)?null:st, doc_tax:isNaN(dt)?null:dt, currency:{cur_js}, lines:lines}};
  }}
  function post(url,body,cb){{
    fetch(url,{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body||{{}})}})
      .then(function(r){{return r.json().then(function(j){{return {{ok:r.ok,j:j}};}});}})
      .then(function(res){{ if(!res.ok){{ alert(res.j.error||'Request failed'); return; }} cb&&cb(res.j); }})
      .catch(function(){{ alert('Network error'); }});
  }}
  window.reconSaveLines=function(id){{ post('/recon/'+id+'/lines',collect(),function(){{location.reload();}}); }};
  window.reconValidate=function(id){{ post('/recon/'+id+'/validate',{{}},function(){{location.reload();}}); }};
  if(SEED.length){{ SEED.forEach(reconAddLine); }} else {{ reconAddLine(); }}
  reconRecalc();
}})();
</script>"##,
        id = id,
        verdict = verdict,
        seed = lines_seed,
        stated = doc_total.map(|d| format!("{d:.2}")).unwrap_or_default(),
        doctax = doc_tax.map(|d| format!("{d:.2}")).unwrap_or_default(),
        cur = esc(&cur),
        cur_js = vortex_plugin_sdk::serde_json::to_string(&cur).unwrap_or_else(|_| "\"\"".into()),
        tol = VALIDATION_TOLERANCE,
        extract_btn = extract_btn,
    );

    // ── Verification vs M3 ───────────────────────────────────────────────────
    // The invoice was already keyed into M3; we VERIFY that by checking the M3
    // total (sum of ALL its lines, incl any price-difference/adjustment line)
    // equals the invoice's printed total EXACTLY. Any difference is flagged so
    // the keyed M3 entry can be corrected. No tolerance.
    let canon = invoice_no
        .as_deref()
        .map(canon_invoice)
        .filter(|s| !s.is_empty());
    let m3_lines = match &canon {
        Some(c) => vortex_plugin_sdk::sqlx::query(
            "SELECT lseo_sku, vendor_item_code, description, m3_voucher_no,
                    qty::float8 AS qty, line_total::float8 AS amt
               FROM recon_m3_line
              WHERE regexp_replace(upper(COALESCE(invoice_no,'')), '[-/].*$', '') = $1
              ORDER BY line_total DESC NULLS LAST",
        )
        .bind(c)
        .fetch_all(&db)
        .await
        .unwrap_or_default(),
        None => Vec::new(),
    };
    let m3_total = round2(
        m3_lines
            .iter()
            .map(|r| r.try_get::<Option<f64>, _>("amt").ok().flatten().unwrap_or(0.0))
            .sum(),
    );
    let m3_count = m3_lines.len();

    let verify_banner = if canon.is_none() {
        r##"<div class="alert mb-3"><span>This invoice has no invoice number yet — extract it first, then it can be verified against M3.</span></div>"##.to_string()
    } else if m3_count == 0 {
        format!(
            r##"<div class="alert alert-error mb-3"><span>⚠ <b>No M3 entry found</b> for invoice <code>{inv}</code>. It may not have been keyed into M3 yet, or the number differs.</span></div>"##,
            inv = esc(invoice_no.as_deref().unwrap_or("")),
        )
    } else if doc_total.is_none() {
        format!(
            r##"<div class="alert alert-warning mb-3"><span>M3 has {n} line(s) totalling <b>{cur} {m3:.2}</b>. Enter/extract the invoice's printed total above to verify it was captured correctly.</span></div>"##,
            n = m3_count, cur = esc(&cur), m3 = m3_total,
        )
    } else {
        let pdf = doc_total.unwrap_or(0.0);
        let diff = round2(pdf - m3_total);
        if diff.abs() <= 0.005 {
            // Passed → informational; the "Validate" button (role-gated, top of
            // the page) performs the sign-off. Show a badge once validated.
            let done = if record_state == "validated" || record_state == "approved" {
                r##" <span class="badge badge-success">✓ Validated</span>"##
            } else {
                " Ready to <b>Validate</b>."
            };
            format!(
                r##"<div class="alert alert-success mb-3"><span>✓ <b>Captured correctly.</b> Invoice total <b>{cur} {pdf:.2}</b> matches the M3 entry ({n} line(s), {cur} {m3:.2}).{done}</span></div>"##,
                cur = esc(&cur), pdf = pdf, m3 = m3_total, n = m3_count, done = done,
            )
        } else {
            format!(
                r##"<div class="alert alert-error mb-3"><div>
  <div class="font-bold">⚠ Does not match M3 — check the keyed entry.</div>
  <div class="text-sm">Invoice total = <b>{cur} {pdf:.2}</b>, M3 total = <b>{cur} {m3:.2}</b>, difference = <b>{diff:+.2}</b>. Correct the M3 entry (or add the price-difference line) so it matches the invoice.</div>
</div></div>"##,
                cur = esc(&cur), pdf = pdf, m3 = m3_total, diff = diff,
            )
        }
    };

    // Collapsible: expanded when there's an M3 entry to check; collapsed (with a
    // status badge) when there's nothing to compare against.
    let vopen = m3_count > 0;
    let vbadge = if canon.is_none() {
        String::new()
    } else if m3_count == 0 {
        r##"<span class="badge badge-error badge-outline badge-sm">No M3 entry</span>"##.to_string()
    } else if doc_total.is_none() {
        r##"<span class="badge badge-warning badge-sm">needs total</span>"##.to_string()
    } else if round2(doc_total.unwrap_or(0.0) - m3_total).abs() <= 0.005 {
        r##"<span class="badge badge-success badge-sm">✓ Captured</span>"##.to_string()
    } else {
        format!(r##"<span class="badge badge-error badge-sm">⚠ {:+.2}</span>"##, round2(doc_total.unwrap_or(0.0) - m3_total))
    };

    let m3_rows_html: String = m3_lines
        .iter()
        .map(|r| {
            let sku: Option<String> = r.try_get("lseo_sku").ok().flatten();
            let ifsite: Option<String> = r.try_get("vendor_item_code").ok().flatten();
            let desc: Option<String> = r.try_get("description").ok().flatten();
            let qty: Option<f64> = r.try_get("qty").ok().flatten();
            let amt: Option<f64> = r.try_get("amt").ok().flatten();
            // A line with an amount but no product SKU is a price-difference / adjustment.
            let is_adj = sku.as_deref().map_or(true, |s| s.is_empty());
            format!(
                r##"<tr>
  <td><code>{sku}</code>{adj}</td>
  <td class="opacity-70">{ifsite}</td>
  <td class="text-xs opacity-70">{desc}</td>
  <td class="text-right font-mono">{qty}</td>
  <td class="text-right font-mono">{amt}</td>
</tr>"##,
                sku = esc(sku.as_deref().filter(|s| !s.is_empty()).unwrap_or("—")),
                adj = if is_adj { " <span class=\"badge badge-ghost badge-xs\">adjustment</span>" } else { "" },
                ifsite = esc(ifsite.as_deref().unwrap_or("")),
                desc = esc(desc.as_deref().unwrap_or("")),
                qty = qty.map(|v| format!("{v:.0}")).unwrap_or_else(|| "—".into()),
                amt = amt.map(|v| format!("{v:.2}")).unwrap_or_else(|| "—".into()),
            )
        })
        .collect();

    // ── Per-product verification ─────────────────────────────────────────────
    // Consolidate the invoice's lines by item code (so a supplier's 30+690 split
    // becomes 720), then match each to an M3 line by IFSITE / SKU / a saved
    // alias. Unmatched invoice items get a "map once" control that trains
    // vendor_item_alias so the next upload auto-matches.
    struct M3L { sku: String, ifsite: String, desc: String, qty: f64, amt: f64, used: bool }
    let mut m3v: Vec<M3L> = m3_lines
        .iter()
        .map(|r| M3L {
            sku: r.try_get::<Option<String>, _>("lseo_sku").ok().flatten().unwrap_or_default(),
            ifsite: r.try_get::<Option<String>, _>("vendor_item_code").ok().flatten().unwrap_or_default(),
            desc: r.try_get::<Option<String>, _>("description").ok().flatten().unwrap_or_default(),
            qty: r.try_get::<Option<f64>, _>("qty").ok().flatten().unwrap_or(0.0),
            amt: r.try_get::<Option<f64>, _>("amt").ok().flatten().unwrap_or(0.0),
            used: false,
        })
        .collect();

    let inv_prod = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(supplier_sku,'') AS code, SUM(qty)::float8 AS qty,
                SUM(line_total)::float8 AS amt, COUNT(*) AS nlines
           FROM recon_inv_line WHERE batch_id = $1 GROUP BY supplier_sku
          ORDER BY SUM(line_total) DESC NULLS LAST",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut alias_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    if !supplier_no.trim().is_empty() {
        let rows = vortex_plugin_sdk::sqlx::query(
            "SELECT supplier_sku, lseo_sku FROM vendor_item_alias WHERE supplier_no = $1 AND active",
        )
        .bind(&supplier_no)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        for r in &rows {
            if let (Ok(k), Ok(v)) = (r.try_get::<String, _>("supplier_sku"), r.try_get::<String, _>("lseo_sku")) {
                alias_map.insert(k, v);
            }
        }
    }

    let fmt_qty = |v: f64| if v.fract().abs() < 0.001 { format!("{v:.0}") } else { format!("{v:.2}") };
    // Map dropdown options: every M3 item on this invoice.
    let m3_options: String = m3v
        .iter()
        .filter(|m| !m.sku.is_empty())
        .map(|m| format!(r##"<option value="{s}">{s} — {d}</option>"##, s = esc(&m.sku), d = esc(&m.desc)))
        .collect();

    let mut prod_rows = String::new();
    let mut n_unmapped = 0;
    let mut n_diff = 0;
    for p in &inv_prod {
        let code: String = p.try_get("code").unwrap_or_default();
        let iqty: f64 = p.try_get::<Option<f64>, _>("qty").ok().flatten().unwrap_or(0.0);
        let iamt: f64 = round2(p.try_get::<Option<f64>, _>("amt").ok().flatten().unwrap_or(0.0));
        let resolved = alias_map.get(&code).cloned();
        let idx = m3v.iter().position(|m| {
            !m.used
                && ((!code.is_empty() && (m.ifsite == code || m.sku == code))
                    || resolved.as_ref().map_or(false, |r| &m.sku == r))
        });
        if let Some(i) = idx {
            m3v[i].used = true;
            let (msku, mif, mqty, mamt) = (m3v[i].sku.clone(), m3v[i].ifsite.clone(), m3v[i].qty, round2(m3v[i].amt));
            let qty_ok = (iqty - mqty).abs() <= 0.005;
            let amt_ok = (iamt - mamt).abs() <= 0.005;
            if !(qty_ok && amt_ok) { n_diff += 1; }
            let (bc, bl) = if qty_ok && amt_ok {
                ("badge-success", "✓ matches".to_string())
            } else if !qty_ok {
                ("badge-error", format!("qty {:+}", fmt_qty(iqty - mqty)))
            } else {
                ("badge-error", format!("amount {:+.2}", iamt - mamt))
            };
            let via = if resolved.as_deref() == Some(msku.as_str()) && code != msku { " <span class=\"opacity-50\">(mapped)</span>" } else { "" };
            prod_rows += &format!(
                r##"<tr><td><code>{code}</code>{via}</td><td class="text-right font-mono">{iq}</td><td class="text-right font-mono">{ia:.2}</td>
  <td><code>{msku}</code> <span class="opacity-50 text-xs">{mif}</span></td><td class="text-right font-mono">{mq}</td><td class="text-right font-mono">{ma:.2}</td>
  <td><span class="badge {bc} badge-sm">{bl}</span></td></tr>"##,
                code = esc(&code), via = via, iq = fmt_qty(iqty), ia = iamt,
                msku = esc(&msku), mif = esc(&mif), mq = fmt_qty(mqty), ma = mamt, bc = bc, bl = esc(&bl),
            );
        } else {
            n_unmapped += 1;
            prod_rows += &format!(
                r##"<tr class="bg-warning/10"><td><code>{code}</code></td><td class="text-right font-mono">{iq}</td><td class="text-right font-mono">{ia:.2}</td>
  <td colspan="3"><form method="post" action="/recon/{id}/map" class="flex gap-2 items-center">
    <input type="hidden" name="supplier_sku" value="{code}"/>
    <select name="lseo_sku" class="select select-xs select-bordered w-full max-w-xs"><option value="">— map to M3 item —</option>{opts}</select>
    <button type="submit" class="btn btn-xs btn-primary">Map</button></form></td>
  <td><span class="badge badge-warning badge-sm">unmapped</span></td></tr>"##,
                code = esc(&code), iq = fmt_qty(iqty), ia = iamt, id = id, opts = m3_options,
            );
        }
    }
    // M3 lines not matched to any invoice item (extra keyed lines / adjustments).
    for m in m3v.iter().filter(|m| !m.used) {
        let label = if m.sku.is_empty() { "adjustment".to_string() } else { m.sku.clone() };
        let desc = if m.desc.is_empty() { String::new() } else { format!(" <span class=\"opacity-60 text-xs\">{}</span>", esc(&m.desc)) };
        prod_rows += &format!(
            r##"<tr class="opacity-70"><td colspan="3" class="text-right italic opacity-60">— not on invoice —</td>
  <td><code>{sku}</code>{desc}</td><td class="text-right font-mono">{q}</td><td class="text-right font-mono">{a:.2}</td>
  <td><span class="badge badge-ghost badge-sm">M3 only</span></td></tr>"##,
            sku = esc(&label), desc = desc, q = fmt_qty(m.qty), a = round2(m.amt),
        );
    }

    let has_products = !inv_prod.is_empty();
    let product_summary = if has_products {
        let issues = n_unmapped + n_diff;
        if issues == 0 {
            r##"<div class="text-sm text-success mb-2">✓ Every invoice item matches an M3 item (qty &amp; amount).</div>"##.to_string()
        } else {
            format!(r##"<div class="text-sm text-warning mb-2">⚠ {n} item(s) need attention: {u} unmapped, {d} with qty/amount differences.</div>"##, n = issues, u = n_unmapped, d = n_diff)
        }
    } else {
        String::new()
    };

    let detail = if has_products {
        format!(
            r##"{summary}<div class="overflow-x-auto"><table class="table table-sm">
    <thead><tr><th>Invoice item</th><th class="text-right">Inv Qty</th><th class="text-right">Inv Amount</th>
      <th>M3 item</th><th class="text-right">M3 Qty</th><th class="text-right">M3 Amount</th><th>Status</th></tr></thead>
    <tbody>{rows}</tbody>
    <tfoot><tr><th colspan="2"></th><th class="text-right font-mono">{cur} {pdf}</th><th colspan="2"></th><th class="text-right font-mono">{cur} {m3:.2}</th><th></th></tr></tfoot>
  </table></div>"##,
            summary = product_summary, rows = prod_rows, cur = esc(&cur),
            pdf = doc_total.map(|v| format!("{v:.2}")).unwrap_or_else(|| "—".into()), m3 = m3_total,
        )
    } else if m3_count > 0 {
        format!(
            r##"<div class="overflow-x-auto"><table class="table table-sm">
    <thead><tr><th>M3 SKU</th><th>IFSITE</th><th>Description</th><th class="text-right">Qty</th><th class="text-right">Amount (incl)</th></tr></thead>
    <tbody>{rows}</tbody>
    <tfoot><tr><th colspan="4" class="text-right">M3 total</th><th class="text-right font-mono">{cur} {m3:.2}</th></tr></tfoot>
  </table></div>
  <p class="text-xs opacity-50 mt-1">Extract the invoice's lines above to verify per-product (qty &amp; item) against M3.</p>"##,
            rows = m3_rows_html, cur = esc(&cur), m3 = m3_total,
        )
    } else {
        String::new()
    };

    let match_card = format!(
        r##"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <details {vopen}>
    <summary class="cursor-pointer flex items-center gap-2 flex-wrap">
      <span class="card-title text-base">Verification vs M3</span>
      <span class="font-normal opacity-50 text-sm">what was keyed into the ERP</span>
      {vbadge}
    </summary>
    <div class="mt-3">
      {verify_banner}
      {detail}
      <p class="text-xs opacity-50 mt-1">Invoice items are consolidated by code, then matched to M3 by item code (IFSITE) / SKU / a saved mapping. Map an unrecognised item once — it's remembered for next time. Any total, qty or amount difference is flagged.</p>
    </div>
  </details>
</div></div>"##,
        vopen = if vopen { "open" } else { "" },
        vbadge = vbadge,
        verify_banner = verify_banner,
        detail = detail,
    );

    // ── Proposed GL double-entry ─────────────────────────────────────────────
    let gl_lines = build_gl_entry(&db, id, &supplier_no, doc_total).await;
    let gl_accounts = vortex_plugin_sdk::sqlx::query(
        "SELECT code, name FROM recon_gl_account WHERE active ORDER BY code",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let gl_acct_list: Vec<(String, String)> = gl_accounts
        .iter()
        .map(|a| (a.try_get::<String, _>("code").unwrap_or_default(), a.try_get::<String, _>("name").unwrap_or_default()))
        .collect();
    let gl_options: String = gl_acct_list
        .iter()
        .map(|(c, n)| format!(r##"<option value="{c}">{c} — {n}</option>"##, c = esc(c), n = esc(n)))
        .collect();
    // Build a <select>'s options with `current` pre-selected.
    let gl_sel_options = |current: &str| -> String {
        gl_acct_list
            .iter()
            .map(|(c, n)| {
                format!(
                    r##"<option value="{c}"{s}>{c} — {n}</option>"##,
                    c = esc(c), n = esc(n), s = if c == current { " selected" } else { "" },
                )
            })
            .collect::<String>()
    };
    // SKU master (LSEO item codes) for matching the vendor's printed code.
    let sku_master = vortex_plugin_sdk::sqlx::query(
        "SELECT sku, COALESCE(description,'') AS d FROM recon_sku_master WHERE active ORDER BY sku",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let sku_list: Vec<(String, String)> = sku_master
        .iter()
        .map(|r| (r.try_get::<String, _>("sku").unwrap_or_default(), r.try_get::<String, _>("d").unwrap_or_default()))
        .collect();
    let sku_sel_options = |current: &str| -> String {
        sku_list
            .iter()
            .map(|(c, d)| {
                let label = if d.is_empty() { c.clone() } else { format!("{c} — {d}") };
                format!(r##"<option value="{c}"{s}>{l}</option>"##, c = esc(c), l = esc(&label), s = if c == current { " selected" } else { "" })
            })
            .collect::<String>()
    };

    let gl_card = if gl_lines.is_empty() {
        r##"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <h2 class="card-title text-base">Proposed GL Entry</h2>
  <p class="opacity-60 text-sm mt-1">Extract the invoice's lines and total to generate the double-entry M3 posting.</p>
</div></div>"##.to_string()
    } else {
        let mut dr = 0.0;
        let mut cr = 0.0;
        let mut has_mappable = false;
        let rows: String = gl_lines.iter().map(|l| {
            dr += l.debit; cr += l.credit;
            // Goods lines map INLINE: a SKU dropdown (vendor code → LSEO SKU) and
            // an account dropdown, both pre-set. Variance / AP lines are static.
            let (sku_cell, acct) = if let Some(vendor) = &l.item_key {
                has_mappable = true;
                let sku_unmapped = l.lseo_sku.is_none();
                let cur_sku = l.lseo_sku.as_deref().unwrap_or("");
                let sku_badge = if sku_unmapped { r##" <span class="badge badge-warning badge-xs align-middle">?</span>"## } else { "" };
                // Vendors that print an item code show it; description-keyed
                // lines say so, since the description is already in the detail cell.
                let key_label = if l.key_is_sku {
                    format!(r##"<div class="text-xs opacity-60"><code>{v}</code></div>"##, v = esc(vendor))
                } else {
                    r##"<div class="text-xs opacity-50 italic">no item code — matched by description</div>"##.to_string()
                };
                let sku_cell = format!(
                    r##"<input type="hidden" name="vendor" value="{v}"/>
  <input type="hidden" name="keykind" value="{k}"/>
  {key_label}
  <select name="lseo_sku" class="sku-sel select select-xs select-bordered w-full">{sopts}</select>{sbadge}"##,
                    v = esc(vendor), k = if l.key_is_sku { "sku" } else { "desc" }, key_label = key_label,
                    sopts = format!("<option value=\"\">— LSEO SKU —</option>{}", sku_sel_options(cur_sku)), sbadge = sku_badge,
                );
                let gl_badge = if l.unmapped { r##" <span class="badge badge-warning badge-xs align-middle">default</span>"## } else { "" };
                let acct = format!(
                    r##"<select name="gl_code" class="gl-sel select select-xs select-bordered w-full">{opts}</select>{gl_badge}
  <div class="text-xs opacity-60 mt-0.5">{detail}</div>"##,
                    opts = gl_sel_options(&l.account), gl_badge = gl_badge, detail = esc(&l.detail),
                );
                (sku_cell, acct)
            } else if l.account.is_empty() {
                (String::new(), format!(r##"<span class="text-error">unset</span><div class="text-xs opacity-60">{}</div>"##, esc(&l.detail)))
            } else {
                (String::new(), format!(r##"<code>{c}</code> <span class="opacity-60 text-xs">{n}</span><div class="text-xs opacity-60">{d}</div>"##,
                    c = esc(&l.account), n = esc(&l.account_name), d = esc(&l.detail)))
            };
            format!(
                r##"<tr><td>{sku_cell}</td><td>{acct}</td>
  <td class="text-right font-mono">{dr}</td><td class="text-right font-mono">{cr}</td></tr>"##,
                sku_cell = sku_cell, acct = acct,
                dr = if l.debit != 0.0 { format!("{:.2}", l.debit) } else { String::new() },
                cr = if l.credit != 0.0 { format!("{:.2}", l.credit) } else { String::new() },
            )
        }).collect();
        let dr = round2(dr); let cr = round2(cr);
        let balanced = (dr - cr).abs() <= 0.005;
        let banner = if balanced {
            r##"<div class="alert alert-success mb-3 py-2"><span>✓ <b>Balanced.</b> Σ Debit = Σ Credit = the invoice total.</span></div>"##.to_string()
        } else {
            format!(r##"<div class="alert alert-error mb-3 py-2"><span>⚠ <b>Out of balance</b> by {d:.2} — check the GL mapping / accounts.</span></div>"##, d = (dr - cr).abs())
        };

        // Toolbar (set-all + one Save) only when there are goods lines to map.
        let toolbar = if has_mappable {
            format!(
                r##"<div class="flex items-center gap-2 flex-wrap justify-end mb-2">
    <select id="gl-setall-{id}" class="select select-xs select-bordered"><option value="">set all to…</option>{opts}</select>
    <button type="button" class="btn btn-xs" onclick="var v=document.getElementById('gl-setall-{id}').value;if(v)document.getElementById('gl-form-{id}').querySelectorAll('.gl-sel').forEach(function(s){{s.value=v;}});">Apply to all</button>
    <button type="submit" class="btn btn-xs btn-primary">Save mappings</button>
  </div>"##,
                id = id, opts = gl_options,
            )
        } else { String::new() };

        format!(
            r##"<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <div class="flex justify-between items-center flex-wrap gap-2">
    <h2 class="card-title text-base">Proposed GL Entry <span class="font-normal opacity-50 text-sm">M3 posting from this invoice</span></h2>
    <a href="/recon/{id}/gl.csv" onclick="this.href='/recon/{id}/gl.csv?t='+Date.now()" class="btn btn-xs btn-outline">Export CSV</a>
  </div>
  {banner}
  <form id="gl-form-{id}" method="post" action="/recon/{id}/glmap-bulk">
  {toolbar}
  <div class="overflow-x-auto"><table class="table table-sm">
    <thead><tr><th>Item (SKU)</th><th>Account</th><th class="text-right">Debit</th><th class="text-right">Credit</th></tr></thead>
    <tbody>{rows}</tbody>
    <tfoot><tr><th colspan="2" class="text-right">Totals</th><th class="text-right font-mono">{dr:.2}</th><th class="text-right font-mono">{cr:.2}</th></tr></tfoot>
  </table></div>
  </form>
  <p class="text-xs opacity-50 mt-1">Set each goods line's account inline (or "set all"), then Save once. Dr goods (SST-inclusive), variance absorbs rounding, Cr the supplier's AP. Mappings are remembered next time. Defaults: Configuration ▸ GL Mapping.</p>
</div></div>"##,
            id = id, banner = banner, rows = rows, dr = dr, cr = cr, toolbar = toolbar,
        )
    };

    let content = format!(
        r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<div id="recon-header" class="card bg-base-100 shadow mb-6" style="position:sticky;top:0;z-index:30"><div class="card-body">
  <div class="flex justify-between items-start flex-wrap gap-4">
    <div><h1 class="text-2xl font-bold">{title}</h1>
    <p class="opacity-60"><code>{code}</code></p></div>
    <div class="flex flex-col items-end gap-2">
      {bar}
      <div class="flex items-center gap-2 flex-wrap justify-end">{stage_actions}
        <a href="/recon/{id}/edit" class="btn btn-sm btn-outline">Edit</a>{duplicate}</div>
    </div>
  </div>
  <dl class="mt-4 grid grid-cols-2 gap-x-6 gap-y-2 max-w-xl text-sm">
    <dt class="opacity-60">Supplier No</dt><dd>{supplier_no}</dd>
    <dt class="opacity-60">Invoice No</dt><dd>{invoice_no}{canon_note}</dd>
    <dt class="opacity-60">Invoice Total</dt><dd>{total}</dd>
  </dl>
</div></div>
{ai_cost}
<!-- Review workspace: input details on the LEFT, the scanned document on the
     RIGHT (sticky, so it stays in view while you edit the lines). Stacks on
     narrow screens. -->
<div class="grid grid-cols-1 lg:grid-cols-5 gap-6 items-start">
  <div class="lg:col-span-3 min-w-0">{lines_card}{feedback_card}{match_card}{gl_card}</div>
  <div class="lg:col-span-2 min-w-0" style="position:sticky;top:calc(var(--recon-hdr, 1rem) + 1rem);align-self:start">{scan_card}</div>
</div>
<script>
// Frozen header: publish its live height so the sticky scan preview parks just
// below it (and stays correct when the header wraps on a narrow screen).
(function(){{
  var h=document.getElementById('recon-header');
  if(!h) return;
  function upd(){{ document.documentElement.style.setProperty('--recon-hdr', h.offsetHeight+'px'); }}
  upd(); window.addEventListener('resize', upd); setTimeout(upd, 250);
}})();
window.reconMatch=function(id){{
  fetch('/recon/'+id+'/match',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:'{{}}'}})
    .then(function(r){{return r.json().then(function(j){{return {{ok:r.ok,j:j}};}});}})
    .then(function(res){{ if(!res.ok){{ alert(res.j.error||'Match failed'); return; }} location.reload(); }})
    .catch(function(){{ alert('Network error'); }});
}};
window.reconExtract=function(id){{
  var btns=document.querySelectorAll('button[onclick^="reconExtract"]');
  var reset=function(){{ btns.forEach(function(b){{b.disabled=false;b.textContent='⚡ Extract now';}}); }};
  btns.forEach(function(b){{b.disabled=true;b.textContent='Extracting…';}});
  var before=document.querySelectorAll('#recon-lines .reco-row').length;
  fetch('/recon/'+id+'/extract',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:'{{}}'}})
    .then(function(r){{return r.json().then(function(j){{return {{ok:r.ok,j:j}};}});}})
    .then(function(res){{
      if(!res.ok){{ alert(res.j.error||'Extraction failed'); reset(); return; }}
      // Extraction runs in the background (OCR can take ~30s). Poll until the
      // lines land, then refresh — the request itself never blocks.
      btns.forEach(function(b){{b.textContent='Extracting… (~30s)';}});
      var tries=0;
      var iv=setInterval(function(){{
        tries++;
        fetch('/recon/'+id+'/extract-status').then(function(r){{return r.json();}}).then(function(s){{
          if(s.lines && s.lines!==before){{ clearInterval(iv); location.reload(); }}
          else if(tries>=30){{ clearInterval(iv); reset(); alert('Still working — refresh in a moment to see the result.'); }}
        }}).catch(function(){{}});
      }}, 4000);
    }})
    .catch(function(){{ alert('Could not start extraction. Please try again.'); reset(); }});
}};
// Re-extract with a reviewer correction. The correction is saved to the
// per-supplier knowledge base, then extraction re-runs with it applied.
window.reconReextract=function(id){{
  var ta=document.getElementById('recon-feedback');
  var fb=(ta&&ta.value||'').trim();
  if(!fb){{ alert('Type what the extractor got wrong first.'); if(ta) ta.focus(); return; }}
  var glob=document.getElementById('recon-feedback-global');
  var btn=document.getElementById('recon-reextract-btn');
  if(btn){{ btn.disabled=true; btn.textContent='Re-extracting… (~30s)'; }}
  var before=document.querySelectorAll('#recon-lines .reco-row').length;
  fetch('/recon/'+id+'/reextract',{{method:'POST',headers:{{'Content-Type':'application/json'}},
    body:JSON.stringify({{feedback:fb, global:!!(glob&&glob.checked)}})}})
    .then(function(r){{return r.json().then(function(j){{return {{ok:r.ok,j:j}};}});}})
    .then(function(res){{
      if(!res.ok){{ alert(res.j.error||'Re-extract failed'); if(btn){{btn.disabled=false;btn.textContent='Save correction & re-extract';}} return; }}
      var tries=0;
      var iv=setInterval(function(){{
        tries++;
        fetch('/recon/'+id+'/extract-status').then(function(r){{return r.json();}}).then(function(s){{
          if(tries>=3 || (s.lines && s.lines!==before)){{ clearInterval(iv); location.reload(); }}
          else if(tries>=30){{ clearInterval(iv); location.reload(); }}
        }}).catch(function(){{}});
      }}, 4000);
    }})
    .catch(function(){{ alert('Could not start re-extract.'); if(btn){{btn.disabled=false;btn.textContent='Save correction & re-extract';}} }});
}};
// Deactivate / reactivate a learned rule.
window.reconToggleHint=function(hid){{
  fetch('/recon/hint/'+hid+'/toggle',{{method:'POST'}})
    .then(function(r){{return r.json().then(function(j){{return {{ok:r.ok,j:j}};}});}})
    .then(function(res){{ if(!res.ok){{ alert(res.j.error||'Failed'); return; }} location.reload(); }})
    .catch(function(){{ alert('Network error'); }});
}};
</script>
<!-- Activity stream (messages, tasks, attachments) first, then the record
     history (WORM audit trail: created, extracted, matched, validated,
     edited, …) — both reusable core primitives. -->
{activity}
{history}"##,
        title = esc(&title),
        code = esc(code.as_deref().unwrap_or("—")),
        bar = bar,
        stage_actions = stage_actions,
        duplicate = duplicate_button(&format!("/recon/{id}/duplicate")),
        supplier_no = esc(&supplier_no),
        invoice_no = esc(invoice_no.as_deref().unwrap_or("—")),
        canon_note = canon_note,
        total = esc(&total_str),
        scan_card = scan_card,
        lines_card = lines_card,
        feedback_card = render_feedback_card(&db, id, &supplier_no, has_scan).await,
        match_card = match_card,
        gl_card = gl_card,
        history = vortex_plugin_sdk::framework::render_audit_trail(&db, "recon_batch", id).await,
        activity = vortex_plugin_sdk::framework::render_chatter_panel("recon_batch", id),
        ai_cost = ai_cost_chip(&db, id, &user).await,
        id = id,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, &title, &content)).into_response()
}

/// POST /recon/{id}/duplicate — copy the record into a fresh draft:
/// new sequence code, state back to the DB default, name marked "(copy)".
async fn duplicate_item(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let code = match vortex_plugin_sdk::orm::sequence::next(&db_ctx.pool, &ITEM_SEQ).await {
        Ok(code) => code,
        Err(e) => {
            error!("duplicate sequence draw failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response();
        }
    };
    let spec = DuplicateSpec::new("recon_batch")
        .set("code", json!(code))
        .skip("record_state")
        .copy_suffix("invoice_no");
    match spec.execute(&db, id, Some(user.id)).await {
        Ok(new_id) => {
            audit_item(&state, &user, &db_ctx, new_id, AuditAction::RecordCreated, json!({"duplicated_from": id, "code": code})).await;
            Redirect::to(&format!("/recon/{new_id}")).into_response()
        }
        Err(e) => {
            error!("duplicate failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Duplicate failed").into_response()
        }
    }
}

/// POST /recon/{id}/status/{state} — audited stage transition.
async fn change_status(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((id, new_state)): Path<(Uuid, String)>,
) -> Response {
    // Only states that exist as stages for this model are legal.
    let legal: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT code FROM record_stages WHERE model = 'recon_batch' AND code = $1",
    )
    .bind(&new_state)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    if legal.is_none() {
        return (StatusCode::BAD_REQUEST, "Unknown state").into_response();
    }

    // Access-rights gate: the user must hold the role for a button that performs
    // this transition (mirrors exactly what the UI shows — a hand-crafted POST
    // can't bypass it).
    let current: String = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT record_state FROM recon_batch WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or_default();
    let actions =
        vortex_plugin_sdk::framework::status::StageActions::from_db(&db, "recon_batch").await;
    if !actions.can_transition(&current, &new_state, &user.roles) {
        return (
            StatusCode::FORBIDDEN,
            "You don't have permission to move this record to that stage.",
        )
            .into_response();
    }

    // Guard: an invoice may only be "validated" when its total actually matches
    // M3 — so a discrepancy can't be signed off by mistake (or a direct POST).
    if new_state == "validated" {
        let hdr = vortex_plugin_sdk::sqlx::query(
            "SELECT invoice_no, doc_total::float8 AS pdf FROM recon_batch WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
        let inv: Option<String> = hdr.as_ref().and_then(|r| r.try_get("invoice_no").ok().flatten());
        let pdf: Option<f64> = hdr.as_ref().and_then(|r| r.try_get("pdf").ok().flatten());
        let canon = inv.as_deref().map(canon_invoice).filter(|s| !s.is_empty());
        let m3: Option<f64> = match &canon {
            Some(c) => vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT SUM(line_total)::float8 FROM recon_m3_line
                  WHERE regexp_replace(upper(COALESCE(invoice_no,'')), '[-/].*$', '') = $1",
            )
            .bind(c)
            .fetch_one(&db)
            .await
            .ok()
            .flatten(),
            None => None,
        };
        let matches = matches!((pdf, m3), (Some(p), Some(m)) if round2(p - m).abs() <= 0.005);
        if !matches {
            return (
                StatusCode::BAD_REQUEST,
                "Cannot validate: the invoice total does not match M3.",
            )
                .into_response();
        }
    }

    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch SET record_state = $2, updated_at = NOW() WHERE id = $1",
    )
    .bind(id)
    .bind(&new_state)
    .execute(&db)
    .await
    {
        error!("status update failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Update failed").into_response();
    }

    audit_item(&state, &user, &db_ctx, id, AuditAction::RecordUpdated, json!({"record_state": new_state})).await;
    Redirect::to(&format!("/recon/{id}")).into_response()
}

// ── Invoice upload (inbox) ───────────────────────────────────────────
// Uploading a scanned invoice is a *separate step* from reconciliation:
// finance drops PDFs into the inbox now; each file becomes a `draft`
// `recon_batch` with the scan attached, waiting to be extracted/matched later.

/// Store one scanned invoice (blob → draft `recon_batch` → `ir_attachment`) and
/// audit it. Shared by the manual upload inbox and the SFTP/FTP auto-ingest.
/// `actor` is `Some((user_id, username))` for a person, `None` for a system
/// pickup. Returns the new batch id, or `None` on failure (blob rolled back).
pub async fn create_scan_batch(
    state: &AppState,
    pool: &vortex_plugin_sdk::orm::ConnectionPool,
    db_name: &str,
    actor: Option<(Uuid, &str)>,
    file_name: &str,
    content_type: Option<&str>,
    data: &[u8],
    via: &str,
) -> Option<Uuid> {
    let db = pool.pool();
    let store_key = new_store_key(file_name);
    if let Err(e) = state.files.put(db_name, &store_key, data, content_type).await {
        error!("scan store failed for {file_name}: {e}");
        return None;
    }
    let code = vortex_plugin_sdk::orm::sequence::next(pool, &ITEM_SEQ).await.ok();
    let batch_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO recon_batch
            (id, code, scan_filename, uploaded_at, record_state, active, created_by)
         VALUES (gen_random_uuid(), $1, $2, NOW(), 'draft', true, $3)
         RETURNING id",
    )
    .bind(&code)
    .bind(file_name)
    .bind(actor.map(|(id, _)| id))
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    let Some(batch_id) = batch_id else {
        let _ = state.files.delete(db_name, &store_key).await;
        error!("batch insert failed for {file_name}");
        return None;
    };

    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO ir_attachment
            (name, res_model, res_id, store_fname, file_size, mimetype, created_by)
         VALUES ($1, 'recon.batch', $2, $3, $4, $5, $6)",
    )
    .bind(file_name)
    .bind(batch_id)
    .bind(&store_key)
    .bind(data.len() as i64)
    .bind(content_type)
    .bind(actor.map(|(id, _)| id))
    .execute(db)
    .await;

    let mut entry = AuditEntry::new(AuditAction::RecordCreated, AuditSeverity::Info)
        .with_database(db_name)
        .with_resource("recon_batch", batch_id.to_string())
        .with_details(json!({"code": code, "file": file_name, "via": via}));
    match actor {
        Some((id, name)) => entry = entry.with_user(UserId(id)).with_username(name),
        None => entry = entry.with_username("recon-ingest"),
    }
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
    Some(batch_id)
}

/// GET /recon/upload — the drop-zone form (accepts multiple PDFs/images).
async fn upload_form(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let content = r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<h1 class="text-2xl font-bold mb-6">Upload Invoices</h1>
<div class="card bg-base-100 shadow max-w-2xl"><div class="card-body">
  <p class="opacity-70 mb-4 text-sm">Drop one or more scanned supplier invoices (PDF or image).
  Choose how to extract them below.</p>
  <form method="post" action="/recon/upload" enctype="multipart/form-data" class="flex flex-col gap-4">
    <input type="file" name="files" accept="application/pdf,image/png,image/jpeg" multiple required
      class="file-input file-input-bordered w-full"/>
    <div>
      <label class="label"><span class="label-text font-semibold">After upload</span></label>
      <div class="flex flex-col gap-2">
        <label class="flex items-start gap-3 cursor-pointer p-2 rounded border border-base-300">
          <input type="radio" name="mode" value="queue" class="radio radio-sm mt-0.5" checked/>
          <span class="text-sm"><b>Queue for batch extraction</b>
            <span class="block text-xs opacity-60">Async, ~50% cheaper. Processes from the <a href="/recon/batch" class="link">Batch Extraction</a> queue. Recommended for bulk.</span></span>
        </label>
        <label class="flex items-start gap-3 cursor-pointer p-2 rounded border border-base-300">
          <input type="radio" name="mode" value="now" class="radio radio-sm mt-0.5"/>
          <span class="text-sm"><b>Extract now</b>
            <span class="block text-xs opacity-60">Immediate, full price. Extracts in the background right after upload.</span></span>
        </label>
      </div>
    </div>
    <div class="flex gap-2">
      <button type="submit" class="btn btn-primary">Upload</button>
      <a href="/recon" class="btn btn-ghost">Cancel</a>
    </div>
  </form>
</div></div>"##;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Upload Invoices", content)).into_response()
}

/// POST /recon/upload — store each uploaded file via FileStore and create a
/// draft batch + `ir_attachment` row per file. Multi-file in one submit.
async fn upload_invoices(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    mut multipart: vortex_plugin_sdk::axum::extract::Multipart,
) -> Response {
    // "queue" (default, batch) or "now" (on-demand). Captured whichever order
    // the field arrives; extraction is decided after all files are stored.
    let mut mode = String::from("queue");
    let mut ids: Vec<Uuid> = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        let name = field.name().map(|s| s.to_string());
        match name.as_deref() {
            Some("mode") => {
                mode = field.text().await.unwrap_or_else(|_| "queue".into());
            }
            Some("files") => {
                let file_name = field.file_name().unwrap_or("invoice.pdf").to_string();
                let content_type = field.content_type().map(|s| s.to_string());
                let Ok(bytes) = field.bytes().await else { continue };
                if bytes.is_empty() {
                    continue;
                }
                let data = bytes.to_vec();
                if let Some(bid) = create_scan_batch(
                    &state, &db_ctx.pool, &db_ctx.db_name, Some((user.id, &user.username)),
                    &file_name, content_type.as_deref(), &data, "upload",
                )
                .await
                {
                    ids.push(bid);
                }
            }
            _ => continue,
        }
    }

    if ids.is_empty() {
        return (StatusCode::BAD_REQUEST, "No files were uploaded").into_response();
    }

    if mode == "now" {
        // On-demand: claim each out of the queue and extract in the background
        // (full price). Claiming (state='processing') keeps a batch submit from
        // also picking it up — no double extraction.
        for bid in ids {
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_batch SET ai_extract_state='processing', ai_batch_id=NULL WHERE id=$1",
            )
            .bind(bid)
            .execute(&db)
            .await;
            let st = state.clone();
            let dbn = db_ctx.db_name.clone();
            let (uid, uname) = (user.id, user.username.clone());
            tokio::spawn(async move {
                let Ok(cp) = st.pool_manager.get_pool(&dbn).await else { return };
                let db = cp.pool().clone();
                if let Err(e) = extract_batch(&st, &db, &dbn, bid, Some((uid, &uname))).await {
                    vortex_plugin_sdk::tracing::warn!(batch = %bid, "upload extract-now failed: {e}");
                    let _ = vortex_plugin_sdk::sqlx::query(
                        "UPDATE recon_batch SET ai_extract_state='error' WHERE id=$1 AND ai_extract_state='processing'",
                    )
                    .bind(bid)
                    .execute(&db)
                    .await;
                }
            });
        }
        return Redirect::to("/recon").into_response();
    }

    // Default: queue for batch extraction.
    for bid in &ids {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_batch SET ai_extract_state = 'queued' WHERE id = $1",
        )
        .bind(bid)
        .execute(&db)
        .await;
    }
    Redirect::to("/recon/batch").into_response()
}

/// GET /recon/batch — the batch-extraction queue: counts, a manual submit
/// button, and recent submitted batches with their status.
async fn batch_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let count = |sql: &'static str| {
        let db = db.clone();
        async move { vortex_plugin_sdk::sqlx::query_scalar::<_, i64>(sql).fetch_one(&db).await.unwrap_or(0) }
    };
    let queued = count("SELECT COUNT(*) FROM recon_batch WHERE ai_extract_state='queued' AND active").await;
    let processing = count("SELECT COUNT(*) FROM recon_batch WHERE ai_extract_state='processing' AND active").await;
    let done = count("SELECT COUNT(*) FROM recon_batch WHERE ai_extract_state='done' AND active").await;
    let errored = count("SELECT COUNT(*) FROM recon_batch WHERE ai_extract_state='error' AND active").await;

    // Active provider + auto-submit state (drives the button + hints).
    let cfg_row = vortex_plugin_sdk::sqlx::query(
        "SELECT name, provider, batch_auto FROM recon_ai_config WHERE active ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let active_provider = cfg_row.as_ref().and_then(|r| r.try_get::<String, _>("provider").ok()).unwrap_or_default();
    let auto_on = cfg_row.as_ref().map(|r| r.try_get::<bool, _>("batch_auto").unwrap_or(false)).unwrap_or(false);
    let is_anthropic = active_provider == "anthropic";

    let flash = match q.get("msg").map(|s| s.as_str()) {
        Some("submitted") => r#"<div class="alert alert-success mb-4"><span>✓ Batch submitted. Invoices will fill in as the provider finishes (usually minutes, up to 24h).</span></div>"#.to_string(),
        Some(other) => format!(r#"<div class="alert alert-error mb-4"><span>{}</span></div>"#, esc(other)),
        None => String::new(),
    };

    let submit_btn = if !is_anthropic {
        r#"<div class="alert alert-warning text-sm"><span>Batch extraction isn't available with the current AI setup. An administrator can enable it in <a href="/recon/ai" class="link">AI Extraction</a> — or use <b>Extract now</b> on an individual invoice.</span></div>"#.to_string()
    } else if queued == 0 {
        r#"<button class="btn btn-primary" disabled>Nothing queued</button>"#.to_string()
    } else {
        format!(r#"<form method="post" action="/recon/batch/submit"><button type="submit" class="btn btn-primary">Submit {n} queued for batch extraction</button></form>"#, n = queued.min(100))
    };
    let cap_note = if queued > 100 {
        format!(r#"<p class="text-xs opacity-60 mt-1">Submits the oldest 100 now; the remaining {} stay queued for the next batch.</p>"#, queued - 100)
    } else {
        String::new()
    };
    let auto_note = if auto_on {
        r#"<span class="badge badge-info badge-sm">Auto-submit ON</span>"#
    } else {
        r#"<span class="badge badge-ghost badge-sm">Auto-submit off</span>"#
    };

    // Recent batches.
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT submitted_at, provider, model, status, total, succeeded, errored, ended_at
           FROM recon_ai_batch ORDER BY submitted_at DESC LIMIT 15",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    // Human duration: 45s / 3m 12s / 1h 04m.
    fn fmt_dur(secs: i64) -> String {
        let s = secs.max(0);
        if s < 60 {
            format!("{s}s")
        } else if s < 3600 {
            format!("{}m {:02}s", s / 60, s % 60)
        } else {
            format!("{}h {:02}m", s / 3600, (s % 3600) / 60)
        }
    }
    let mut batch_rows = String::new();
    for r in &rows {
        let submitted: Option<vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>> = r.try_get("submitted_at").ok();
        let ended: Option<vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>> = r.try_get("ended_at").ok().flatten();
        let provider: String = r.try_get("provider").unwrap_or_default();
        let model: String = r.try_get("model").unwrap_or_default();
        let status: String = r.try_get("status").unwrap_or_default();
        let total: i32 = r.try_get("total").unwrap_or(0);
        let succ: i32 = r.try_get("succeeded").unwrap_or(0);
        let err: i32 = r.try_get("errored").unwrap_or(0);
        let (badge, label) = match status.as_str() {
            "ended" => ("badge-success", "Done"),
            "failed" => ("badge-error", "Failed"),
            _ => ("badge-warning", "In progress"),
        };
        let ended_cell = ended.map(|w| w.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_else(|| "—".into());
        let dur_cell = match (submitted, ended) {
            (Some(s), Some(e)) => fmt_dur((e - s).num_seconds()),
            _ => "—".into(),
        };
        let _ = (&provider, &model);
        batch_rows.push_str(&format!(
            r#"<tr class="hover"><td class="text-xs opacity-70">{when}</td><td class="text-xs opacity-70">{ended}</td><td class="text-xs font-mono">{dur}</td><td><span class="badge {badge} badge-sm">{label}</span></td><td class="text-right">{total}</td><td class="text-right text-success">{succ}</td><td class="text-right {errcls}">{err}</td></tr>"#,
            when = submitted.map(|w| w.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            ended = esc(&ended_cell), dur = esc(&dur_cell),
            badge = badge, label = label,
            total = total, succ = succ, err = err, errcls = if err > 0 { "text-error" } else { "opacity-40" },
        ));
    }
    if batch_rows.is_empty() {
        batch_rows.push_str(r#"<tr><td colspan="7" class="text-center opacity-60 py-6">No batches submitted yet.</td></tr>"#);
    }

    let stat = |t: &str, v: i64, cls: &str| format!(
        r#"<div class="stat bg-base-100 rounded-box shadow"><div class="stat-title">{t}</div><div class="stat-value text-2xl {cls}">{v}</div></div>"#,
        t = esc(t), v = v, cls = cls);

    let content = format!(
        r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<div class="flex items-center justify-between flex-wrap gap-2 mb-1">
  <h1 class="text-2xl font-bold">Batch Extraction</h1>
  <a href="/recon/upload" class="btn btn-sm btn-primary">Upload invoices</a>
</div>
<p class="opacity-60 text-sm mb-4">Uploaded invoices queue here and extract in bulk via the provider's batch API (~50% cheaper, async). For an urgent one, open it and hit <b>Extract now</b>. {auto_note}</p>
{flash}
<div class="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
  {s_queued}{s_proc}{s_done}{s_err}
</div>
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <h2 class="card-title text-lg mb-2">Submit a batch</h2>
  {submit_btn}
  {cap_note}
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
  <h2 class="card-title text-lg mb-3">Recent batches</h2>
  <div class="overflow-x-auto"><table class="table table-sm">
  <thead><tr><th>Submitted</th><th>Completed</th><th>Duration</th><th>Status</th><th class="text-right">Total</th><th class="text-right">OK</th><th class="text-right">Err</th></tr></thead>
  <tbody>{batch_rows}</tbody></table></div>
</div></div>"##,
        auto_note = auto_note, flash = flash,
        s_queued = stat("Queued", queued, "text-warning"),
        s_proc = stat("Processing", processing, ""),
        s_done = stat("Extracted", done, "text-success"),
        s_err = stat("Errors", errored, if errored > 0 { "text-error" } else { "" }),
        submit_btn = submit_btn, cap_note = cap_note, batch_rows = batch_rows,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Batch Extraction", &content)).into_response()
}

/// POST /recon/batch/submit — submit all queued invoices as one batch.
async fn batch_submit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    match submit_queued_batch(&state, &db, &db_ctx.db_name, Some(user.id), None).await {
        Ok(_) => Redirect::to("/recon/batch?msg=submitted").into_response(),
        Err(e) => {
            let short: String = e.chars().take(200).collect();
            Redirect::to(&format!("/recon/batch?msg={}", pct_encode(&short))).into_response()
        }
    }
}

/// Minimal percent-encoder for a flash message placed in a redirect query.
fn pct_encode(s: &str) -> String {
    let mut out = String::new();
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => out.push(b as char),
            b' ' => out.push_str("%20"),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// GET /recon/attachments/{att_id}/download — serve a stored scan inline
/// (so pdf.js can render it in-page). Scoped to `res_model = 'recon.batch'`.
async fn serve_attachment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(att_id): Path<Uuid>,
) -> Response {
    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT name, store_fname, mimetype FROM ir_attachment
         WHERE id = $1 AND res_model = 'recon.batch'",
    )
    .bind(att_id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        _ => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };
    let name: String = row.try_get("name").unwrap_or_default();
    let store_fname: Option<String> = row.try_get("store_fname").ok().flatten();
    let mimetype: String = row
        .try_get("mimetype")
        .ok()
        .flatten()
        .unwrap_or_else(|| "application/pdf".into());
    let Some(store_fname) = store_fname else {
        return (StatusCode::NOT_FOUND, "No stored file").into_response();
    };
    let data = match state.files.get(&db_ctx.db_name, &store_fname).await {
        Ok(Some(d)) => d,
        Ok(None) => return (StatusCode::NOT_FOUND, "File missing from storage").into_response(),
        Err(e) => {
            error!("scan fetch failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Storage error").into_response();
        }
    };
    (
        [
            (vortex_plugin_sdk::axum::http::header::CONTENT_TYPE, mimetype),
            (
                vortex_plugin_sdk::axum::http::header::CONTENT_DISPOSITION,
                format!("inline; filename=\"{}\"", name.replace('"', "")),
            ),
        ],
        data,
    )
        .into_response()
}

// ── M3 (ERP) data pool ───────────────────────────────────────────────
// M3 EDI-voucher / payment-info extracts are uploaded in bulk (CSV or Excel),
// independently of any scanned PDF. Every line lands in `recon_m3_line` with
// batch_id = NULL; matching later links each line to an invoice batch.

/// Map a spreadsheet header cell to a `recon_m3_line` column. Normalizes to
/// lowercase alphanumerics so "Supp_No", "supplier no", "P3SUNO" all resolve.
fn map_m3_header(h: &str) -> Option<&'static str> {
    let n: String = h.chars().filter(|c| c.is_ascii_alphanumeric()).collect::<String>().to_lowercase();
    Some(match n.as_str() {
        "invno" | "invoiceno" | "invoicenumber" | "p3sino" => "invoice_no",
        "suppno" | "supplierno" | "suppliernumber" | "p3suno" => "supplier_no",
        "voucherno" | "vouchernumber" | "vouchno" => "m3_voucher_no",
        "division" | "div" | "p3odiv" => "division",
        "sku" | "lseosku" | "itemcode" | "lseoitemcode" => "lseo_sku",
        // IFSITE = the vendor / PO item code printed on the supplier invoice
        // (join key to the uploaded invoice's item code).
        "ifsite" | "vendoritemcode" | "vendoritem" | "poitem" => "vendor_item_code",
        "itemdesp" | "itemdescription" | "description" | "desc" | "itemdesc" => "description",
        // GL posting account. Acct_Desp doubles as the description for non-product
        // lines (variance / adjustment) that have no Item_Desp.
        "acctid" | "accountid" | "glaccount" | "glacct" => "acct_id",
        "acctdesp" | "acctdesc" | "accountdesp" | "accountdesc" => "acct_desp",
        "pouom" | "uom" | "baseuom" | "unit" => "base_uom",
        "invqty" | "qty" | "quantity" => "qty",
        "unitprice" | "price" | "unitpriceincl" => "unit_price_incl",
        // Amount. The GL voucher export carries the authoritative posted amount
        // in GL_Amt_For / gl_amt (and it's the ONLY place a price-variance line's
        // value appears — its total_price is blank). Both map to line_total; the
        // per-row setter keeps whichever is non-null (they agree on goods lines).
        "totalprice" | "total" | "lineamount" | "amount" | "linetotal" => "line_total",
        "glamtfor" | "glamt" | "glamount" => "line_total",
        "pono" | "purchaseorderno" | "purchaseorder" => "po_no",
        "dono" | "deliveryorderno" | "sono" => "do_no",
        "eventid" => "event_id",
        "curcode" | "currency" | "currencycode" | "p3cucd" => "currency",
        "currate" | "currencyrate" | "rate" => "currency_rate",
        _ => return None,
    })
}

/// Parse a numeric cell tolerantly: strips commas, spaces and currency letters.
fn parse_num(s: &str) -> Option<f64> {
    let cleaned: String = s
        .chars()
        .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
        .collect();
    if cleaned.is_empty() { None } else { cleaned.parse::<f64>().ok() }
}

/// One extracted M3 line, all-optional (columns absent from the file stay None).
#[derive(Default)]
struct M3Row {
    invoice_no: Option<String>,
    supplier_no: Option<String>,
    m3_voucher_no: Option<String>,
    division: Option<String>,
    lseo_sku: Option<String>,
    vendor_item_code: Option<String>,
    description: Option<String>,
    acct_id: Option<String>,
    acct_desp: Option<String>,
    base_uom: Option<String>,
    qty: Option<f64>,
    unit_price_incl: Option<f64>,
    line_total: Option<f64>,
    po_no: Option<String>,
    do_no: Option<String>,
    event_id: Option<String>,
    currency: Option<String>,
    currency_rate: Option<f64>,
}

impl M3Row {
    /// True for rows we don't import. We keep the DEBIT lines — products AND
    /// price-difference / adjustment lines (positive amounts) — whose sum is the
    /// invoice's value. We drop value-less header rows AND the offsetting AP
    /// CREDIT line (negative GL amount = the payable), so Σ(line_total) equals
    /// the invoice total rather than netting to zero.
    fn is_empty(&self) -> bool {
        !self.line_total.map_or(false, |t| t > 0.005)
    }
    /// Assign a mapped column's raw cell value.
    fn set(&mut self, field: &str, raw: &str) {
        let v = raw.trim();
        // M3 exports empties as the literal string "NULL"; treat as absent.
        if v.is_empty() || v.eq_ignore_ascii_case("NULL") { return; }
        let s = || Some(v.to_string());
        match field {
            "invoice_no" => self.invoice_no = s(),
            "supplier_no" => self.supplier_no = s(),
            "m3_voucher_no" => self.m3_voucher_no = s(),
            "division" => self.division = s(),
            // "FAL" is M3's placeholder SKU on non-product GL lines (variance /
            // header) — treat as no SKU so they read as adjustments, not items.
            "lseo_sku" => self.lseo_sku = if v.eq_ignore_ascii_case("FAL") { None } else { s() },
            "vendor_item_code" => self.vendor_item_code = s(),
            "description" => self.description = s(),
            "acct_id" => self.acct_id = s(),
            "acct_desp" => self.acct_desp = s(),
            "base_uom" => self.base_uom = s(),
            "qty" => self.qty = parse_num(v),
            "unit_price_incl" => self.unit_price_incl = parse_num(v),
            "line_total" => self.line_total = parse_num(v),
            "po_no" => self.po_no = s(),
            "do_no" => self.do_no = s(),
            "event_id" => self.event_id = s(),
            "currency" => self.currency = s(),
            "currency_rate" => self.currency_rate = parse_num(v),
            _ => {}
        }
    }
}

/// Turn raw `rows` (row 0 = header) into mapped M3 rows. Returns
/// (rows, recognized_header_count).
fn parse_m3_rows(rows: &[Vec<String>]) -> (Vec<M3Row>, usize) {
    let Some(header) = rows.first() else { return (Vec::new(), 0) };
    let colmap: Vec<Option<&'static str>> = header.iter().map(|h| map_m3_header(h)).collect();
    let recognized = colmap.iter().filter(|c| c.is_some()).count();
    let mut out = Vec::new();
    for row in rows.iter().skip(1) {
        let mut m = M3Row::default();
        for (i, cell) in row.iter().enumerate() {
            if let Some(Some(field)) = colmap.get(i) {
                m.set(field, cell);
            }
        }
        if !m.is_empty() { out.push(m); }
    }
    (out, recognized)
}

/// Read an uploaded CSV or XLSX into `Vec<Vec<String>>` (row 0 = header).
fn read_tabular(filename: &str, data: &[u8]) -> Result<(Vec<Vec<String>>, &'static str), String> {
    let lower = filename.to_ascii_lowercase();
    if lower.ends_with(".xlsx") || lower.ends_with(".xls") {
        use calamine::Reader;
        let cursor = std::io::Cursor::new(data.to_vec());
        let mut wb = calamine::open_workbook_auto_from_rs(cursor)
            .map_err(|e| format!("could not open workbook: {e}"))?;
        let range = wb
            .worksheet_range_at(0)
            .ok_or_else(|| "workbook has no sheets".to_string())?
            .map_err(|e| format!("could not read sheet: {e}"))?;
        let rows = range
            .rows()
            .map(|r| r.iter().map(|c| c.to_string()).collect())
            .collect();
        Ok((rows, "xlsx"))
    } else {
        // Treat everything else as delimited text.
        let mut rdr = csv::ReaderBuilder::new()
            .has_headers(false)
            .flexible(true)
            .from_reader(std::io::Cursor::new(data));
        let mut rows = Vec::new();
        for rec in rdr.records() {
            match rec {
                Ok(r) => rows.push(r.iter().map(|s| s.to_string()).collect()),
                Err(e) => return Err(format!("CSV parse error: {e}")),
            }
        }
        Ok((rows, "csv"))
    }
}

/// GET /recon/m3 — browse the pool: import runs + recent lines, with counts.
async fn m3_pool(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let (total, pooled): (i64, i64) = vortex_plugin_sdk::sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE batch_id IS NULL) FROM recon_m3_line",
    )
    .fetch_one(&db)
    .await
    .unwrap_or((0, 0));

    // Recent lines (pool first).
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT invoice_no, supplier_no, m3_voucher_no, lseo_sku, description,
                base_uom, qty::float8 AS qty, line_total::float8 AS line_total,
                po_no, currency, batch_id
         FROM recon_m3_line ORDER BY created_at DESC LIMIT 200",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut body = String::new();
    for r in &rows {
        let inv: Option<String> = r.try_get("invoice_no").ok().flatten();
        let sup: Option<String> = r.try_get("supplier_no").ok().flatten();
        let vou: Option<String> = r.try_get("m3_voucher_no").ok().flatten();
        let sku: Option<String> = r.try_get("lseo_sku").ok().flatten();
        let desc: Option<String> = r.try_get("description").ok().flatten();
        let uom: Option<String> = r.try_get("base_uom").ok().flatten();
        let qty: Option<f64> = r.try_get("qty").ok().flatten();
        let tot: Option<f64> = r.try_get("line_total").ok().flatten();
        let po: Option<String> = r.try_get("po_no").ok().flatten();
        let cur: Option<String> = r.try_get("currency").ok().flatten();
        let linked: Option<Uuid> = r.try_get("batch_id").ok().flatten();
        let badge = if linked.is_some() {
            r#"<span class="badge badge-success badge-sm">linked</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-sm">pool</span>"#
        };
        body.push_str(&format!(
            r##"<tr>
<td>{inv}</td><td>{sup}</td><td>{vou}</td><td>{sku}</td>
<td class="max-w-xs truncate">{desc}</td><td>{uom}</td>
<td class="text-right">{qty}</td><td class="text-right">{tot}</td>
<td>{po}</td><td>{cur}</td><td>{badge}</td></tr>"##,
            inv = esc(inv.as_deref().unwrap_or("—")),
            sup = esc(sup.as_deref().unwrap_or("—")),
            vou = esc(vou.as_deref().unwrap_or("—")),
            sku = esc(sku.as_deref().unwrap_or("—")),
            desc = esc(desc.as_deref().unwrap_or("")),
            uom = esc(uom.as_deref().unwrap_or("—")),
            qty = qty.map(|q| format!("{q:.2}")).unwrap_or_else(|| "—".into()),
            tot = tot.map(|t| format!("{t:.2}")).unwrap_or_else(|| "—".into()),
            po = esc(po.as_deref().unwrap_or("—")),
            cur = esc(cur.as_deref().unwrap_or("—")),
            badge = badge,
        ));
    }
    if body.is_empty() {
        body = r#"<tr><td colspan="11" class="text-center opacity-60 py-8">No M3 data imported yet.</td></tr>"#.to_string();
    }

    let content = format!(
        r##"<div class="flex justify-between items-center mb-6 flex-wrap gap-3">
  <h1 class="text-2xl font-bold">M3 Data (ERP)</h1>
  <a href="/recon/m3/import" class="btn btn-primary btn-sm">Import M3 Data</a>
</div>
<div class="stats shadow mb-6">
  <div class="stat"><div class="stat-title">Total lines</div><div class="stat-value text-2xl">{total}</div></div>
  <div class="stat"><div class="stat-title">In pool (unlinked)</div><div class="stat-value text-2xl">{pooled}</div></div>
</div>
<div class="overflow-x-auto"><table class="table table-sm table-zebra">
<thead><tr><th>Invoice No</th><th>Supplier</th><th>Voucher</th><th>LSEO SKU</th>
<th>Description</th><th>UOM</th><th class="text-right">Qty</th><th class="text-right">Total</th>
<th>PO</th><th>Cur</th><th>Status</th></tr></thead>
<tbody>{body}</tbody></table></div>
<p class="text-xs opacity-50 mt-2">Showing up to 200 most recent lines.</p>"##,
        total = total, pooled = pooled, body = body,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "M3 Data (ERP)", &content)).into_response()
}

/// GET /recon/m3/import — the M3 extract upload form (CSV or Excel).
async fn m3_import_form(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let content = r##"<div class="mb-4"><a href="/recon/m3" class="link link-hover text-sm">← M3 Data</a></div>
<h1 class="text-2xl font-bold mb-6">Import M3 Data</h1>
<div class="card bg-base-100 shadow max-w-2xl"><div class="card-body">
  <p class="opacity-70 mb-4 text-sm">Upload an M3 EDI-voucher / payment-info extract (CSV or Excel).
  Rows load into the pool; matching links them to uploaded invoices later. Columns are matched by
  header name — recognized headers include Inv_No, Supp_No, Voucher_No, SKU, Item_Desp, PO_UOM,
  inv_qty, unit_price, total_price, PO_No, DO_No, Cur_Code, Cur_Rate, Division.</p>
  <form method="post" action="/recon/m3/import" enctype="multipart/form-data" class="flex flex-col gap-4">
    <input type="file" name="file" accept=".csv,.xlsx,.xls,text/csv" required
      class="file-input file-input-bordered w-full"/>
    <div class="flex gap-2">
      <button type="submit" class="btn btn-primary">Import</button>
      <a href="/recon/m3" class="btn btn-ghost">Cancel</a>
    </div>
  </form>
</div></div>"##;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Import M3 Data", content)).into_response()
}

/// POST /recon/m3/import — parse the uploaded file and insert pool lines.
async fn m3_import(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    mut multipart: vortex_plugin_sdk::axum::extract::Multipart,
) -> Response {
    let mut file_name = String::new();
    let mut data: Vec<u8> = Vec::new();
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("file") {
            file_name = field.file_name().unwrap_or("m3.csv").to_string();
            if let Ok(b) = field.bytes().await { data = b.to_vec(); }
        }
    }
    if data.is_empty() {
        return (StatusCode::BAD_REQUEST, "No file received").into_response();
    }

    let (raw_rows, fmt) = match read_tabular(&file_name, &data) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, format!("Import failed: {e}")).into_response(),
    };
    let (m3_rows, recognized) = parse_m3_rows(&raw_rows);
    if recognized == 0 {
        return (
            StatusCode::BAD_REQUEST,
            "No recognized columns in the header row — check the M3 export column names.",
        )
            .into_response();
    }
    if m3_rows.is_empty() {
        return (StatusCode::BAD_REQUEST, "No data rows found.").into_response();
    }

    // Record the import run first, then attribute every line to it.
    let import_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO recon_m3_import (filename, format, row_count, created_by)
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(&file_name)
    .bind(fmt)
    .bind(m3_rows.len() as i32)
    .bind(user.id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let mut inserted = 0i64;
    for m in &m3_rows {
        let res = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_m3_line
                (import_id, invoice_no, supplier_no, m3_voucher_no, division, lseo_sku,
                 description, base_uom, qty, unit_price_incl, line_total, po_no, do_no,
                 event_id, currency, currency_rate, vendor_item_code, acct_id, acct_desp)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)",
        )
        .bind(import_id)
        .bind(&m.invoice_no)
        .bind(&m.supplier_no)
        .bind(&m.m3_voucher_no)
        .bind(&m.division)
        .bind(&m.lseo_sku)
        // Description falls back to the GL account description (Acct_Desp) for
        // non-product lines with no Item_Desp (e.g. the price-variance line).
        .bind(m.description.as_deref().or(m.acct_desp.as_deref()))
        .bind(&m.base_uom)
        .bind(m.qty)
        .bind(m.unit_price_incl)
        .bind(m.line_total)
        .bind(&m.po_no)
        .bind(&m.do_no)
        .bind(&m.event_id)
        .bind(&m.currency)
        .bind(m.currency_rate)
        .bind(&m.vendor_item_code)
        .bind(&m.acct_id)
        .bind(&m.acct_desp)
        .execute(&db)
        .await;
        if res.is_ok() { inserted += 1; }
    }

    if let Some(iid) = import_id {
        audit_item(
            &state,
            &user,
            &db_ctx,
            iid,
            AuditAction::RecordCreated,
            json!({"m3_import": file_name, "format": fmt, "lines": inserted}),
        )
        .await;
    }
    Redirect::to("/recon/m3").into_response()
}

/// Evidence on the WORM ledger — every state change is recorded.
// ── Part 1: extraction self-check ───────────────────────────────────────────
//
// Flow: extraction (OCR / e-invoice / keyed) yields per-line qty + unit price
// and the invoice's own printed grand total. We store the lines, then compute
// Σ(qty × unit price) (+ per-line tax) and compare it to the printed total.
// Equal within tolerance → `passed`; otherwise → `exception` for a human. This
// runs BEFORE any M3 matching — it proves we read the physical invoice right.

#[derive(serde::Deserialize)]
struct InvLinePayload {
    #[serde(default)]
    line_no: Option<i32>,
    #[serde(default)]
    supplier_sku: Option<String>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    uom: Option<String>,
    #[serde(default)]
    qty: Option<f64>,
    #[serde(default)]
    unit_price: Option<f64>,
    /// Line discount percentage (e.g. 5 = 5% off). 0 when absent.
    #[serde(default)]
    discount_pct: Option<f64>,
    /// Line discount as a money amount (some invoices print it this way). 0 when absent.
    #[serde(default)]
    discount_amt: Option<f64>,
    /// Per-line tax amount (some invoices print SST per line). Leave 0 when the
    /// invoice shows SST only as a footer total — put that in `doc_tax` instead.
    #[serde(default)]
    tax: Option<f64>,
    /// Line-locate band (image scans only) carried back from the grid so a
    /// manual save doesn't discard the coordinates the extractor found.
    #[serde(default)]
    doc_y: Option<f64>,
    #[serde(default)]
    doc_h: Option<f64>,
}

#[derive(serde::Deserialize)]
struct LinesPayload {
    /// The grand total printed on the physical invoice (TOTAL INCL SST).
    #[serde(default)]
    stated_total: Option<f64>,
    /// Invoice-level SST (footer "SST" figure) when tax is not shown per line.
    #[serde(default)]
    doc_tax: Option<f64>,
    #[serde(default)]
    currency: Option<String>,
    #[serde(default)]
    lines: Vec<InvLinePayload>,
}

fn json_ok(body: vortex_plugin_sdk::serde_json::Value) -> Response {
    vortex_plugin_sdk::axum::Json(body).into_response()
}
fn json_error(code: StatusCode, msg: &str) -> Response {
    (code, vortex_plugin_sdk::axum::Json(json!({ "error": msg }))).into_response()
}

/// One line's inputs before totalling.
struct RawLine {
    qty: f64,
    unit_price: f64,
    discount_pct: f64,
    discount_amt: f64,
    line_tax: f64,
}
/// One line's computed figures: net (after discount, excl tax), tax, incl total.
struct CalcLine {
    net: f64,
    tax: f64,
    total: f64,
}

/// Compute per-line net / tax / incl total for a whole invoice, handling BOTH
/// tax layouts, plus the document subtotal and total tax.
///
/// - net = qty × unit_price × (1 − discount%/100) − discount_amt   (printed "AMOUNT")
/// - Tax mode is auto-detected:
///   * per-line — if any line carries an explicit tax, each line's tax is used
///     verbatim (invoices that print SST per line).
///   * invoice-level — otherwise `doc_tax` (the footer SST) is allocated across
///     lines pro-rata by net, last line absorbing the rounding residual.
/// Either way Σ(total) = subtotal + total_tax = the printed grand total, and
/// every `total` is SST-inclusive so the M3 matcher stays correct.
fn compute_totals(lines: &[RawLine], doc_tax: Option<f64>) -> (Vec<CalcLine>, f64, f64) {
    let nets: Vec<f64> = lines
        .iter()
        .map(|l| round2(l.qty * l.unit_price * (1.0 - l.discount_pct / 100.0) - l.discount_amt))
        .collect();
    let subtotal = round2(nets.iter().sum());
    let per_line_tax_sum: f64 = lines.iter().map(|l| l.line_tax).sum();
    let doc_tax = doc_tax.filter(|t| t.abs() > 0.005);

    let calc: Vec<CalcLine> = if per_line_tax_sum.abs() > 0.005 {
        lines
            .iter()
            .zip(&nets)
            .map(|(l, &net)| {
                let tax = round2(l.line_tax);
                CalcLine { net, tax, total: round2(net + tax) }
            })
            .collect()
    } else if let (Some(dt), true) = (doc_tax, subtotal.abs() > 0.005) {
        let mut out = Vec::with_capacity(nets.len());
        let mut allocated = 0.0;
        let n = nets.len();
        for (i, &net) in nets.iter().enumerate() {
            let tax = if i + 1 == n {
                round2(dt - allocated)
            } else {
                let t = round2(dt * net / subtotal);
                allocated += t;
                t
            };
            out.push(CalcLine { net, tax, total: round2(net + tax) });
        }
        out
    } else {
        nets.iter().map(|&net| CalcLine { net, tax: 0.0, total: net }).collect()
    };
    let total_tax = round2(calc.iter().map(|c| c.tax).sum());
    (calc, subtotal, total_tax)
}

/// POST /recon/{id}/lines — replace this batch's extracted invoice lines and
/// the printed grand total. Moves a `draft` batch to `extracted`. Saving lines
/// invalidates any prior verdict (validation_status back to `pending`).
async fn save_lines(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::Json(payload): vortex_plugin_sdk::axum::Json<LinesPayload>,
) -> Response {
    // Batch must exist.
    let exists: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT record_state FROM recon_batch WHERE id = $1")
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();
    let Some(record_state) = exists else {
        return json_error(StatusCode::NOT_FOUND, "Batch not found");
    };

    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(e) => {
            error!("save_lines begin failed: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Save failed");
        }
    };

    // Replace-all: the grid always POSTs the full line set.
    if let Err(e) = vortex_plugin_sdk::sqlx::query("DELETE FROM recon_inv_line WHERE batch_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        error!("save_lines clear failed: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Save failed");
    }

    // Compute nets, allocate tax, and derive the document subtotal + total tax.
    let raw: Vec<RawLine> = payload
        .lines
        .iter()
        .map(|l| RawLine {
            qty: l.qty.unwrap_or(0.0),
            unit_price: l.unit_price.unwrap_or(0.0),
            discount_pct: l.discount_pct.unwrap_or(0.0),
            discount_amt: l.discount_amt.unwrap_or(0.0),
            line_tax: l.tax.unwrap_or(0.0),
        })
        .collect();
    let (calc, subtotal, total_tax) = compute_totals(&raw, payload.doc_tax);
    let per_line_tax = raw.iter().map(|l| l.line_tax).sum::<f64>().abs() > 0.005;

    for (idx, (l, c)) in payload.lines.iter().zip(&calc).enumerate() {
        let line_no = l.line_no.unwrap_or((idx + 1) as i32);
        if let Err(e) = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_inv_line
               (batch_id, line_no, supplier_sku, description, uom, qty,
                unit_price_excl, discount_pct, discount_amt, line_net, sales_tax, line_total,
                doc_y, doc_h)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(id)
        .bind(line_no)
        .bind(l.supplier_sku.as_deref().filter(|s| !s.is_empty()))
        .bind(l.description.as_deref().filter(|s| !s.is_empty()))
        .bind(l.uom.as_deref().filter(|s| !s.is_empty()))
        .bind(l.qty.unwrap_or(0.0))
        .bind(l.unit_price.unwrap_or(0.0))
        .bind(l.discount_pct.unwrap_or(0.0))
        .bind(l.discount_amt.unwrap_or(0.0))
        .bind(c.net)
        .bind(c.tax)
        .bind(c.total)
        .bind(l.doc_y.filter(|v| v.is_finite()))
        .bind(l.doc_h.filter(|v| v.is_finite()))
        .execute(&mut *tx)
        .await
        {
            error!("save_lines insert failed: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Save failed");
        }
    }

    // Header: printed grand total + subtotal + SST + currency. Advance draft →
    // extracted; any edit to the lines resets the self-check verdict.
    let next_state = if record_state == "draft" { "extracted" } else { record_state.as_str() };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch
            SET doc_total = $2,
                doc_subtotal = $3,
                doc_tax = $4,
                tax_per_line = $5,
                currency = COALESCE($6, currency),
                source_provider = COALESCE(source_provider, 'manual'),
                record_state = $7,
                validation_status = 'pending',
                computed_total = NULL,
                total_variance = NULL,
                validated_at = NULL,
                validated_by = NULL
          WHERE id = $1",
    )
    .bind(id)
    .bind(payload.stated_total)
    .bind(subtotal)
    .bind(total_tax)
    .bind(per_line_tax)
    .bind(payload.currency.as_deref().filter(|s| !s.is_empty()))
    .bind(next_state)
    .execute(&mut *tx)
    .await
    {
        error!("save_lines header update failed: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Save failed");
    }

    if let Err(e) = tx.commit().await {
        error!("save_lines commit failed: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Save failed");
    }

    // Money as strings: the WORM canonicalizer (RFC 8785 JCS) forbids
    // floating-point in audit payloads — they have no canonical form.
    audit_item(
        &state,
        &user,
        &db_ctx,
        id,
        AuditAction::RecordUpdated,
        json!({
            "lines": payload.lines.len(),
            "stated_total": payload.stated_total.map(|v| format!("{v:.2}")),
        }),
    )
    .await;

    json_ok(json!({ "redirect": format!("/recon/{id}") }))
}

/// POST /recon/{id}/validate — the self-check. Compute Σ(line subtotals) from
/// the stored lines and compare to the printed total. Sets computed_total,
/// total_variance and validation_status (passed | exception) on the batch.
async fn validate_totals(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT doc_total::float8 AS stated,
                COALESCE((SELECT SUM(line_total) FROM recon_inv_line WHERE batch_id = $1), 0)::float8 AS computed,
                (SELECT COUNT(*) FROM recon_inv_line WHERE batch_id = $1) AS n
         FROM recon_batch WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await;

    let row = match row {
        Ok(Some(r)) => r,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Batch not found"),
        Err(e) => {
            error!("validate load failed: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Validation failed");
        }
    };
    let stated: Option<f64> = row.try_get("stated").ok().flatten();
    let computed: f64 = row.try_get("computed").unwrap_or(0.0);
    let n: i64 = row.try_get("n").unwrap_or(0);

    if n == 0 {
        return json_error(StatusCode::BAD_REQUEST, "No extracted lines to validate — enter the invoice lines first");
    }
    let Some(stated) = stated else {
        return json_error(StatusCode::BAD_REQUEST, "No printed invoice total to compare against — enter it first");
    };

    let computed = (computed * 100.0).round() / 100.0;
    let variance = ((computed - stated) * 100.0).round() / 100.0;
    let status = if variance.abs() <= VALIDATION_TOLERANCE { "passed" } else { "exception" };

    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch
            SET computed_total = $2, total_variance = $3,
                validation_status = $4, validated_at = NOW(), validated_by = $5
          WHERE id = $1",
    )
    .bind(id)
    .bind(computed)
    .bind(variance)
    .bind(status)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!("validate update failed: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Validation failed");
    }

    // Money as strings: the WORM canonicalizer (RFC 8785 JCS) forbids
    // floating-point in audit payloads — they have no canonical form.
    audit_item(
        &state,
        &user,
        &db_ctx,
        id,
        AuditAction::RecordUpdated,
        json!({
            "self_check": status,
            "computed_total": format!("{computed:.2}"),
            "stated_total": format!("{stated:.2}"),
            "variance": format!("{variance:.2}"),
        }),
    )
    .await;

    json_ok(json!({
        "status": status,
        "computed_total": computed,
        "stated_total": stated,
        "variance": variance,
        "redirect": format!("/recon/{id}"),
    }))
}

// ── Part 2: matcher ─────────────────────────────────────────────────────────
//
// Links a validated invoice to the M3 pool, then reconciles it line-by-line.
// Normalization happens BEFORE the compare (the BRD's exceptions): supplier SKU
// → LSEO SKU via vendor_item_alias, supplier UOM → base UOM via pack factor,
// and supplier lines consolidated per LSEO SKU. Both sides carry SST-inclusive
// line totals in the transaction currency, so the compare is same-currency; the
// FX-to-MYR conversion belongs to the later DE/PV posting, not here.

const MATCH_AMT_TOL: f64 = 0.05; // rounding — treated as an exact match
const MATCH_QTY_TOL: f64 = 0.001;
const MATCH_PRICE_VAR_PCT: f64 = 0.02; // ≤2% residual auto-classifies as price variance

fn round2(x: f64) -> f64 {
    (x * 100.0).round() / 100.0
}

/// Base invoice number used for pool linkage: upper-cased, with M3's suffix /
/// slash edits dropped — `I2512676-A` → `I2512676`, `4110123708/709` →
/// `4110123708`. This is what makes the invoice↔voucher link n:m.
fn canon_invoice(s: &str) -> String {
    let up = s.trim().to_ascii_uppercase();
    let cut = up.find(['-', '/']).unwrap_or(up.len());
    up[..cut].trim().to_string()
}

/// One reconciled LSEO-SKU group: the invoice side (possibly several
/// consolidated supplier lines) against the M3 side (possibly several vouchers).
#[derive(Default)]
struct SkuAgg {
    inv_ids: Vec<Uuid>,
    inv_qty: f64,
    inv_amt: f64,
    m3_ids: Vec<Uuid>,
    m3_qty: f64,
    m3_amt: f64,
}

/// POST /recon/{id}/match — link the M3 pool to this invoice and reconcile.
async fn run_match(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // 1. Batch header — need the invoice number to find its pool lines.
    let hdr = match vortex_plugin_sdk::sqlx::query(
        "SELECT supplier_no, invoice_no, record_state FROM recon_batch WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return json_error(StatusCode::NOT_FOUND, "Batch not found"),
        Err(e) => {
            error!("match header load failed: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Match failed");
        }
    };
    let supplier_no: Option<String> = hdr.try_get("supplier_no").ok().flatten();
    let invoice_no: Option<String> = hdr.try_get("invoice_no").ok().flatten();
    let Some(inv_no) = invoice_no.filter(|s| !s.trim().is_empty()) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "Invoice number is required to match — extract it first",
        );
    };
    let canon = canon_invoice(&inv_no);

    // 2. Link unlinked pool lines for this invoice (canonical no. + supplier).
    let candidates = vortex_plugin_sdk::sqlx::query(
        "SELECT id, invoice_no FROM recon_m3_line
          WHERE batch_id IS NULL
            AND ($1::text IS NULL OR supplier_no IS NULL OR supplier_no = $1)",
    )
    .bind(&supplier_no)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut linked = 0u32;
    for c in &candidates {
        let cid: Uuid = c.get("id");
        let cno: Option<String> = c.try_get("invoice_no").ok().flatten();
        if cno.as_deref().map(canon_invoice).as_deref() == Some(canon.as_str()) {
            if vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_m3_line SET batch_id = $2 WHERE id = $1 AND batch_id IS NULL",
            )
            .bind(cid)
            .bind(id)
            .execute(&db)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or(0)
                > 0
            {
                linked += 1;
            }
        }
    }

    // 3. Invoice lines. Preload this supplier's aliases (SKU + pack factor).
    let inv_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT id, supplier_sku, description, qty::float8 AS qty, line_total::float8 AS amt
           FROM recon_inv_line WHERE batch_id = $1",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    if inv_lines.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "No extracted invoice lines to match");
    }

    let mut alias: std::collections::HashMap<String, (String, f64)> = std::collections::HashMap::new();
    if let Some(sup) = supplier_no.as_deref() {
        let rows = vortex_plugin_sdk::sqlx::query(
            "SELECT supplier_sku, lseo_sku, COALESCE(pack_factor, 1)::float8 AS pf
               FROM vendor_item_alias WHERE supplier_no = $1 AND active",
        )
        .bind(sup)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        for r in &rows {
            let ssku: String = r.try_get("supplier_sku").unwrap_or_default();
            let lsku: String = r.try_get("lseo_sku").unwrap_or_default();
            let pf: f64 = r.try_get("pf").unwrap_or(1.0);
            if !ssku.is_empty() {
                alias.insert(ssku, (lsku, pf));
            }
        }
    }

    // Aggregate the invoice side by resolved LSEO SKU (consolidation), and stamp
    // the normalized values back onto each line for the later DE preview.
    let mut agg: std::collections::BTreeMap<String, SkuAgg> = std::collections::BTreeMap::new();
    for l in &inv_lines {
        let lid: Uuid = l.get("id");
        // Alias key: the printed item code, else the description (same fallback
        // the GL builder uses — description-only invoices would otherwise put
        // every line in one "UNKNOWN" bucket).
        let trimmed = |c: &str| -> Option<String> {
            l.try_get::<Option<String>, _>(c).ok().flatten()
                // Clamp to the width of the columns this key is written into.
                .map(|s| s.trim().chars().take(200).collect::<String>())
                .filter(|s| !s.is_empty())
        };
        let ssku: Option<String> = trimmed("supplier_sku").or_else(|| trimmed("description"));
        let qty: f64 = l.try_get("qty").ok().flatten().unwrap_or(0.0);
        let amt: f64 = l.try_get("amt").ok().flatten().unwrap_or(0.0);
        // Resolve: alias wins; else assume the supplier already prints LSEO codes.
        let (lseo_sku, pack) = ssku
            .as_deref()
            .and_then(|s| alias.get(s).cloned())
            .or_else(|| ssku.clone().map(|s| (s, 1.0)))
            .unwrap_or_else(|| ("UNKNOWN".to_string(), 1.0));
        let qty_base = round2(qty * pack);
        let unit_incl = if qty_base != 0.0 { round2(amt / qty_base) } else { 0.0 };
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_inv_line
                SET norm_lseo_sku = $2, norm_qty_base = $3, norm_unit_incl = $4
              WHERE id = $1",
        )
        .bind(lid)
        .bind(&lseo_sku)
        .bind(qty_base)
        .bind(unit_incl)
        .execute(&db)
        .await;
        let e = agg.entry(lseo_sku).or_default();
        e.inv_ids.push(lid);
        e.inv_qty += qty_base;
        e.inv_amt += amt;
    }

    // 4. M3 side (only the lines now linked to this batch).
    let m3_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT id, lseo_sku, qty::float8 AS qty, line_total::float8 AS amt
           FROM recon_m3_line WHERE batch_id = $1",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    for m in &m3_lines {
        let mid: Uuid = m.get("id");
        let sku: String = m.try_get("lseo_sku").ok().flatten().unwrap_or_else(|| "UNKNOWN".into());
        let qty: f64 = m.try_get("qty").ok().flatten().unwrap_or(0.0);
        let amt: f64 = m.try_get("amt").ok().flatten().unwrap_or(0.0);
        let e = agg.entry(sku).or_default();
        e.m3_ids.push(mid);
        e.m3_qty += qty;
        e.m3_amt += amt;
    }

    // 5. Reconcile each SKU group → one recon_match row. Rebuild from scratch so
    // the action is idempotent.
    if let Err(e) = vortex_plugin_sdk::sqlx::query("DELETE FROM recon_match WHERE batch_id = $1")
        .bind(id)
        .execute(&db)
        .await
    {
        error!("match clear failed: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Match failed");
    }

    let mut counts = std::collections::BTreeMap::<&str, i64>::new();
    for (sku, a) in &agg {
        let inv_n = a.inv_ids.len();
        let m3_n = a.m3_ids.len();
        let inv_amt = round2(a.inv_amt);
        let m3_amt = round2(a.m3_amt);
        let delta_qty = round2(a.inv_qty - a.m3_qty);
        let delta_amt = round2(inv_amt - m3_amt);

        let (status, confidence, note): (&str, f64, String) = if inv_n > 0 && m3_n == 0 {
            ("unmatched", 0.0, "on invoice, no matching M3 line".to_string())
        } else if inv_n == 0 && m3_n > 0 {
            ("unmatched", 0.0, "in M3 pool, not on invoice".to_string())
        } else {
            let n = format!(
                "inv {inv_n}×Σ{inv_amt:.2} · m3 {m3_n}×Σ{m3_amt:.2}",
            );
            let var_band = MATCH_AMT_TOL.max(MATCH_PRICE_VAR_PCT * m3_amt.abs());
            if delta_amt.abs() <= MATCH_AMT_TOL && delta_qty.abs() <= MATCH_QTY_TOL {
                ("matched", 1.0, n)
            } else if delta_qty.abs() <= MATCH_QTY_TOL && delta_amt.abs() <= var_band {
                ("price_variance", 0.9, n)
            } else {
                ("needs_review", 0.5, n)
            }
        };
        *counts.entry(status).or_default() += 1;

        let _ = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_match
                (batch_id, inv_line_id, m3_line_id, status, confidence,
                 delta_qty, delta_amount, reason_code, note, created_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(id)
        .bind(a.inv_ids.first().copied())
        .bind(a.m3_ids.first().copied())
        .bind(status)
        .bind(confidence)
        .bind(delta_qty)
        .bind(delta_amt)
        .bind(sku)
        .bind(&note)
        .bind(user.id)
        .execute(&db)
        .await;
    }

    // 6. Advance the lifecycle: extracted → matched.
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch SET record_state = 'matched'
          WHERE id = $1 AND record_state IN ('draft', 'extracted')",
    )
    .bind(id)
    .execute(&db)
    .await;

    let clean = counts.get("needs_review").copied().unwrap_or(0)
        + counts.get("unmatched").copied().unwrap_or(0)
        == 0;
    audit_item(
        &state,
        &user,
        &db_ctx,
        id,
        AuditAction::RecordUpdated,
        json!({
            "matched": counts.get("matched").copied().unwrap_or(0),
            "price_variance": counts.get("price_variance").copied().unwrap_or(0),
            "needs_review": counts.get("needs_review").copied().unwrap_or(0),
            "unmatched": counts.get("unmatched").copied().unwrap_or(0),
            "pool_lines_linked": linked,
        }),
    )
    .await;

    json_ok(json!({
        "linked": linked,
        "groups": agg.len(),
        "clean": clean,
        "matched": counts.get("matched").copied().unwrap_or(0),
        "price_variance": counts.get("price_variance").copied().unwrap_or(0),
        "needs_review": counts.get("needs_review").copied().unwrap_or(0),
        "unmatched": counts.get("unmatched").copied().unwrap_or(0),
        "redirect": format!("/recon/{id}"),
    }))
}

// ── AI OCR extraction (provider config + per-invoice extract) ────────────────

/// (default_base_url, default_model) for a provider preset. `custom` requires
/// the tenant to supply a base URL.
fn ai_preset(provider: &str) -> (&'static str, &'static str) {
    match provider {
        "anthropic" => ("https://api.anthropic.com", "claude-sonnet-5"),
        "openai" => ("https://api.openai.com/v1", "gpt-4o"),
        "deepseek" => ("https://api.deepseek.com/v1", "deepseek-chat"),
        _ => ("", ""), // custom
    }
}

/// Load + decrypt the active provider config. `Ok(None)` = not configured yet.
/// Look up the rate card for a provider+model and compute the cost of a set of
/// token counts. Returns `(cost, currency)`; cost is 0 with currency `USD` when
/// no rate is configured (tokens are still logged so the gap is visible).
/// The Anthropic Message Batches API bills ~50% of the synchronous price.
const BATCH_DISCOUNT: f64 = 0.5;

async fn compute_ai_cost(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    provider: &str,
    model: &str,
    usage: crate::ai::Usage,
    batch: bool,
) -> (f64, String) {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT input_per_mtok::float8 AS inp, output_per_mtok::float8 AS outp, currency
           FROM recon_ai_pricing WHERE provider = $1 AND model = $2",
    )
    .bind(provider)
    .bind(model)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    match row {
        Some(r) => {
            let inp: f64 = r.try_get("inp").unwrap_or(0.0);
            let outp: f64 = r.try_get("outp").unwrap_or(0.0);
            let currency: String = r.try_get("currency").unwrap_or_else(|_| "USD".into());
            let mut cost = (usage.input_tokens as f64 / 1_000_000.0) * inp
                + (usage.output_tokens as f64 / 1_000_000.0) * outp;
            if batch {
                cost *= BATCH_DISCOUNT;
            }
            (cost, currency)
        }
        None => (0.0, "USD".into()),
    }
}

/// Best-effort: freeze this extraction's tokens + derived cost into the usage
/// log. Never propagates errors — cost accounting must not break extraction.
async fn log_ai_usage(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    batch_id: Uuid,
    provider: &str,
    model: &str,
    usage: crate::ai::Usage,
    actor: Option<Uuid>,
    batch: bool,
) {
    let (cost, currency) = compute_ai_cost(db, provider, model, usage, batch).await;
    let mode = if batch { "batch" } else { "ondemand" };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO recon_ai_usage
            (batch_id, provider, model, input_tokens, output_tokens, cost, currency, created_by, mode)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)",
    )
    .bind(batch_id)
    .bind(provider)
    .bind(model)
    .bind(usage.input_tokens as i64)
    .bind(usage.output_tokens as i64)
    .bind(cost)
    .bind(&currency)
    .bind(actor)
    .bind(mode)
    .execute(db)
    .await
    {
        error!("recon ai-usage log failed: {e}");
    }
}

/// Superadmin-only per-invoice cost chip for the record page. Sums this batch's
/// extraction calls (a batch may be re-extracted). Empty string when the viewer
/// isn't a superadmin or the invoice has no logged extraction.
async fn ai_cost_chip(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    batch_id: Uuid,
    user: &AuthUser,
) -> String {
    if !user.is_system_admin() {
        return String::new();
    }
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT COUNT(*) AS calls,
                COALESCE(SUM(input_tokens),0)  AS inp,
                COALESCE(SUM(output_tokens),0) AS outp,
                COALESCE(SUM(cost),0)::float8  AS cost, MAX(currency) AS cur,
                BOOL_OR(mode = 'batch') AS any_batch
           FROM recon_ai_usage WHERE batch_id = $1",
    )
    .bind(batch_id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let Some(r) = row else { return String::new() };
    let calls: i64 = r.try_get("calls").unwrap_or(0);
    if calls == 0 {
        return String::new();
    }
    let inp: i64 = r.try_get("inp").unwrap_or(0);
    let outp: i64 = r.try_get("outp").unwrap_or(0);
    let cost: f64 = r.try_get("cost").unwrap_or(0.0);
    let cur: String = r.try_get::<Option<String>, _>("cur").ok().flatten().unwrap_or_else(|| "USD".into());
    let any_batch: bool = r.try_get("any_batch").unwrap_or(false);
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let extra = if calls > 1 { format!(" · {calls} runs") } else { String::new() };
    let mode_badge = if any_batch {
        r#"<span class="badge badge-success badge-sm">batch</span>"#
    } else {
        r#"<span class="badge badge-ghost badge-sm">on-demand</span>"#
    };
    format!(
        r##"<div class="alert bg-base-100 border border-base-300 py-2 mb-4 text-sm flex-wrap gap-x-4 gap-y-1">
  <span class="badge badge-ghost badge-sm">AI cost</span>
  <span><b>{cur} {cost:.4}</b>{extra}</span>
  {mode_badge}
  <span class="opacity-60">{inp} in · {outp} out tokens</span>
  <a href="/recon/ai/usage" class="link link-hover text-xs ml-auto">Usage &amp; cost →</a>
</div>"##,
        cur = esc(&cur), cost = cost, extra = extra, mode_badge = mode_badge, inp = inp, outp = outp,
    )
}

/// Load the active extraction correction rules that apply to a supplier:
/// global rules (supplier_no IS NULL) plus that supplier's own rules. Oldest
/// first, so newer corrections read last and take precedence in the prompt.
async fn load_extract_hints(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    supplier_no: Option<&str>,
) -> Vec<String> {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT hint FROM recon_extract_hint
          WHERE active AND (supplier_no IS NULL OR supplier_no = $1)
          ORDER BY created_at",
    )
    .bind(supplier_no.filter(|s| !s.is_empty()))
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .filter_map(|r| r.try_get::<String, _>("hint").ok())
        .filter(|h| !h.trim().is_empty())
        .collect()
}

/// The on-record "Teach the extractor" card: the correction rules already
/// learned for this supplier (with a toggle to retire each), plus a box to type
/// a new correction and re-extract. Empty when there's no scan to re-run.
async fn render_feedback_card(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    id: Uuid,
    supplier_no: &str,
    has_scan: bool,
) -> String {
    if !has_scan {
        return String::new();
    }
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    // Learned rules that apply to THIS invoice (this supplier + global), plus
    // whether each is a global rule, so the UI can label them.
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, hint, supplier_no, active FROM recon_extract_hint
          WHERE supplier_no IS NULL OR supplier_no = $1
          ORDER BY active DESC, created_at DESC",
    )
    .bind(if supplier_no.is_empty() { None } else { Some(supplier_no) })
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut learned = String::new();
    for r in &rows {
        let hid: Uuid = r.get("id");
        let hint: String = r.try_get("hint").unwrap_or_default();
        let scope_global = r.try_get::<Option<String>, _>("supplier_no").ok().flatten().is_none();
        let active: bool = r.try_get("active").unwrap_or(true);
        let badge = if scope_global {
            r#"<span class="badge badge-info badge-xs">global</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-xs">this supplier</span>"#
        };
        let (row_cls, btn_label, dot) = if active {
            ("", "Retire", "text-success")
        } else {
            ("opacity-40", "Restore", "opacity-40")
        };
        learned.push_str(&format!(
            r##"<li class="flex items-start gap-2 py-1 {row_cls}">
<span class="mt-1 {dot}">•</span>
<span class="flex-1 text-sm">{hint} {badge}</span>
<button type="button" class="btn btn-ghost btn-xs" onclick="reconToggleHint('{hid}')">{btn_label}</button>
</li>"##,
            row_cls = row_cls, dot = dot, hint = esc(&hint), badge = badge, hid = hid, btn_label = btn_label,
        ));
    }
    let learned_block = if learned.is_empty() {
        r#"<p class="text-xs opacity-50">No rules learned yet for this supplier. Your first correction becomes one.</p>"#.to_string()
    } else {
        format!(r#"<ul class="divide-y divide-base-200 mb-3">{learned}</ul>"#)
    };
    let supplier_note = if supplier_no.is_empty() {
        "This invoice has no supplier code yet, so a correction saves as a global rule until the supplier is identified."
    } else {
        "Saved for this supplier and applied to every future extraction of their invoices."
    };

    format!(
        r##"<details class="card bg-base-100 shadow mb-6"><summary class="card-body cursor-pointer py-3 flex-row items-center gap-2">
  <span class="card-title text-base">🧠 Teach the extractor</span>
  <span class="text-xs opacity-60 font-normal">correct a wrong extraction — remembered for next time</span>
</summary>
<div class="card-body pt-0">
  <div class="mb-3"><div class="text-xs font-semibold opacity-60 mb-1">Learned rules</div>{learned_block}</div>
  <label class="text-xs font-semibold opacity-60">Your correction</label>
  <textarea id="recon-feedback" rows="3" maxlength="2000" class="textarea textarea-bordered w-full text-sm mt-1"
    placeholder="e.g. The discount is the 4th column, not tax. / Supplier code is the digits after 'Akaun No'. / Ignore the summary block at the bottom."></textarea>
  <div class="flex items-center justify-between flex-wrap gap-2 mt-2">
    <label class="label cursor-pointer gap-2 py-0">
      <input type="checkbox" id="recon-feedback-global" class="checkbox checkbox-xs"/>
      <span class="label-text text-xs">Apply to all suppliers (global rule)</span>
    </label>
    <button type="button" id="recon-reextract-btn" class="btn btn-sm btn-secondary" onclick="reconReextract('{id}')">Save correction &amp; re-extract</button>
  </div>
  <p class="text-xs opacity-50 mt-2">{supplier_note}</p>
</div></details>"##,
        learned_block = learned_block, id = id, supplier_note = supplier_note,
    )
}

async fn load_ai_config(
    db: &vortex_plugin_sdk::sqlx::PgPool,
) -> Result<Option<crate::ai::AiConfig>, String> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT provider, model, base_url, api_key_enc, image_locate
           FROM recon_ai_config WHERE active ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| format!("config load failed: {e}"))?;
    let Some(row) = row else { return Ok(None) };

    let image_locate: bool = row.try_get("image_locate").unwrap_or(false);
    let provider: String = row.try_get("provider").unwrap_or_else(|_| "anthropic".into());
    let model: String = row.try_get("model").unwrap_or_default();
    let base_url_raw: Option<String> = row.try_get("base_url").ok().flatten();
    let enc: Option<Vec<u8>> = row.try_get("api_key_enc").ok().flatten();

    let api_key = match enc {
        Some(blob) => {
            let key = vortex_plugin_sdk::security::crypto::master_key();
            vortex_plugin_sdk::security::crypto::decrypt_str(&blob, &key)
                .map_err(|_| "API key could not be decrypted (VORTEX_SECRET_KEY changed?)".to_string())?
        }
        None => String::new(),
    };
    let base_url = base_url_raw
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| ai_preset(&provider).0.to_string());

    Ok(Some(crate::ai::AiConfig { provider, model, base_url, api_key, image_locate }))
}

/// GET /recon/ai — provider settings form.
///
/// Superadmin-only: the AI provider config holds the (encrypted) LLM API
/// key and the extraction cost lever, so it is gated to the System
/// Administrator role. The menu entry is hidden for everyone else, and this
/// route rejects direct navigation independently of the menu.
async fn ai_config_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html(vortex_plugin_sdk::framework::ui::forbidden_page("AI Extraction"))).into_response();
    }
    let esc = vortex_plugin_sdk::framework::ui::html_escape;

    // All stored provider profiles.
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, provider, model, base_url, api_key_hint, active, image_locate, batch_auto
           FROM recon_ai_config ORDER BY active DESC, name, updated_at DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    // Optional edit target (?edit=<id>): prefill the form from that row.
    let edit_id: Option<Uuid> = q.get("edit").and_then(|s| s.parse().ok());
    let editing = edit_id.and_then(|eid| {
        rows.iter().find(|r| r.get::<Uuid, _>("id") == eid)
    });

    // ── Saved-providers table ────────────────────────────────────────────
    let mut list = String::new();
    for r in &rows {
        let cid: Uuid = r.get("id");
        let name: String = r.try_get::<Option<String>, _>("name").ok().flatten().unwrap_or_default();
        let provider: String = r.try_get("provider").unwrap_or_default();
        let model: String = r.try_get("model").unwrap_or_default();
        let hint: Option<String> = r.try_get::<Option<String>, _>("api_key_hint").ok().flatten();
        let active: bool = r.try_get("active").unwrap_or(false);
        let locate: bool = r.try_get("image_locate").unwrap_or(false);
        let key_badge = match &hint {
            Some(h) => format!(r#"<span class="badge badge-success badge-xs">…{}</span>"#, esc(h)),
            None => r#"<span class="badge badge-error badge-xs">no key</span>"#.to_string(),
        };
        let active_cell = if active {
            r#"<span class="badge badge-primary badge-sm">● In use</span>"#.to_string()
        } else {
            format!(r#"<form method="post" action="/recon/ai/{cid}/activate" class="inline"><button class="btn btn-xs btn-outline">Use this</button></form>"#, cid = cid)
        };
        let locate_cell = if locate { "🎯" } else { "" };
        list.push_str(&format!(
            r##"<tr class="hover {rowcls}">
<td class="font-medium">{name}</td>
<td class="text-sm">{provider}</td>
<td class="font-mono text-xs">{model}</td>
<td>{key_badge}</td>
<td class="text-center">{locate_cell}</td>
<td>{active_cell}</td>
<td class="text-right whitespace-nowrap">
  <button type="button" class="btn btn-xs btn-ghost" onclick="reconTestSaved('{cid}')">Test</button>
  <a href="/recon/ai?edit={cid}" class="btn btn-xs btn-ghost">Edit</a>
  <form method="post" action="/recon/ai/{cid}/delete" class="inline" onsubmit="return confirm('Delete this provider profile?')"><button class="btn btn-xs btn-ghost text-error">Delete</button></form>
</td></tr>"##,
            rowcls = if active { "bg-primary/5" } else { "" },
            name = esc(&name), provider = esc(&provider), model = esc(&model),
            key_badge = key_badge, locate_cell = locate_cell, active_cell = active_cell, cid = cid,
        ));
    }
    let list_block = if list.is_empty() {
        r#"<tr><td colspan="7" class="text-center opacity-60 py-6">No providers yet — add one below.</td></tr>"#.to_string()
    } else {
        list
    };

    // ── Add / edit form ──────────────────────────────────────────────────
    let cur_provider = editing
        .and_then(|r| r.try_get::<String, _>("provider").ok())
        .unwrap_or_else(|| "anthropic".into());
    let cur_name: String = editing.and_then(|r| r.try_get::<Option<String>, _>("name").ok().flatten()).unwrap_or_default();
    let cur_model: String = editing
        .and_then(|r| r.try_get::<String, _>("model").ok())
        .unwrap_or_else(|| ai_preset(&cur_provider).1.to_string());
    let cur_base: String = editing.and_then(|r| r.try_get::<Option<String>, _>("base_url").ok().flatten()).unwrap_or_default();
    let cur_hint: Option<String> = editing.and_then(|r| r.try_get::<Option<String>, _>("api_key_hint").ok().flatten());
    let cur_locate: bool = editing.map(|r| r.try_get::<bool, _>("image_locate").unwrap_or(false)).unwrap_or(false);
    let cur_batch_auto: bool = editing.map(|r| r.try_get::<bool, _>("batch_auto").unwrap_or(false)).unwrap_or(false);
    let is_edit = editing.is_some();
    let edit_cid = edit_id.map(|e| e.to_string()).unwrap_or_default();

    let opt = |val: &str, label: &str| {
        format!(r##"<option value="{v}"{sel}>{l}</option>"##, v = val, l = label,
            sel = if cur_provider == val { " selected" } else { "" })
    };
    let key_state = match &cur_hint {
        Some(h) => format!(r##"<span class="badge badge-success badge-sm">key set (…{h})</span> — leave blank to keep it"##, h = esc(h)),
        None => r##"<span class="badge badge-ghost badge-sm">no key set</span>"##.to_string(),
    };
    let form_title = if is_edit { "Edit provider" } else { "Add a provider" };
    let submit_label = if is_edit { "Save changes" } else { "Add provider" };
    let cancel_link = if is_edit { r#"<a href="/recon/ai" class="btn btn-ghost">Cancel</a>"# } else { "" };

    let content = format!(
        r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<div class="flex items-center justify-between flex-wrap gap-2 mb-1">
  <h1 class="text-2xl font-bold">AI Extraction</h1>
  <a href="/recon/ai/usage" class="btn btn-sm btn-outline">Usage &amp; cost →</a>
</div>
<p class="opacity-60 text-sm mb-4">Store several provider profiles (each with its own key) and switch the one used to OCR invoices. The <b>● In use</b> profile is what extraction runs against.</p>
<div id="ai-test-result" class="mb-4"></div>

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <h2 class="card-title text-lg mb-2">Saved providers</h2>
  <div class="overflow-x-auto"><table class="table table-sm">
    <thead><tr><th>Name</th><th>Provider</th><th>Model</th><th>Key</th><th class="text-center" title="Locate lines on images">🎯</th><th>Status</th><th></th></tr></thead>
    <tbody>{list_block}</tbody>
  </table></div>
</div></div>

<div class="card bg-base-100 shadow max-w-2xl"><div class="card-body">
  <h2 class="card-title text-lg mb-2">{form_title}</h2>
  <form method="post" action="/recon/ai" class="flex flex-col gap-4">
    <input type="hidden" name="config_id" value="{edit_cid}"/>
    <div>
      <label class="label"><span class="label-text">Name</span></label>
      <input name="name" value="{cur_name}" class="input input-bordered w-full" placeholder="e.g. Claude Prod / DeepSeek cheap"/>
    </div>
    <div>
      <label class="label"><span class="label-text">Provider</span></label>
      <select name="provider" class="select select-bordered w-full">{o_anthropic}{o_openai}{o_deepseek}{o_custom}</select>
      <p class="text-xs opacity-50 mt-1">Anthropic (Claude) handles PDF <b>and</b> images. OpenAI / DeepSeek / custom need a <b>vision-capable</b> model and accept images only.</p>
    </div>
    <div>
      <label class="label"><span class="label-text">Model</span></label>
      <input name="model" value="{cur_model}" class="input input-bordered w-full" placeholder="e.g. claude-opus-4-8 / gpt-4o"/>
    </div>
    <div>
      <label class="label"><span class="label-text">Base URL <span class="opacity-50">(optional — blank uses the provider default)</span></span></label>
      <input name="base_url" value="{cur_base}" class="input input-bordered w-full font-mono text-sm" placeholder="{base_ph}"/>
    </div>
    <div>
      <label class="label"><span class="label-text">API Key</span></label>
      <input name="api_key" type="password" autocomplete="off" class="input input-bordered w-full font-mono" placeholder="paste key to set / update"/>
      <p class="text-xs opacity-60 mt-1">{key_state}</p>
    </div>
    <label class="label cursor-pointer justify-start gap-3">
      <input type="checkbox" name="active" value="1" class="checkbox checkbox-sm" {active_chk}/>
      <span class="label-text">Use this profile for extraction (makes it the active one)</span>
    </label>
    <div class="divider my-0"></div>
    <label class="label cursor-pointer justify-start gap-3 items-start">
      <input type="checkbox" name="image_locate" value="1" class="checkbox checkbox-sm mt-1" {locate_chk}/>
      <span class="label-text">Locate lines on <b>image</b> scans
        <span class="block text-xs opacity-60 font-normal mt-0.5">Asks the model for each line's position on an image so clicking a line zooms to it. Extra vision tokens (higher cost per image). PDFs locate for free. Off by default.</span>
      </span>
    </label>
    <label class="label cursor-pointer justify-start gap-3 items-start">
      <input type="checkbox" name="batch_auto" value="1" class="checkbox checkbox-sm mt-1" {batch_chk}/>
      <span class="label-text">Auto-submit the batch queue <span class="opacity-50">(Anthropic only)</span>
        <span class="block text-xs opacity-60 font-normal mt-0.5">When on, a background job submits queued invoices to the batch API on a schedule (~every 2 min) — fully hands-off. Off = you submit batches manually from <a href="/recon/batch" class="link">Batch Extraction</a>. Either way, urgent invoices use Extract now.</span>
      </span>
    </label>
    <div class="alert alert-warning text-sm"><span>⚠ Extraction sends the invoice image/PDF to the selected external provider. Use a key scoped to this workload.</span></div>
    <div class="flex gap-2 flex-wrap">
      <button type="submit" class="btn btn-primary">{submit_label}</button>
      <button type="button" class="btn btn-outline" onclick="reconTestProvider()">Test connection</button>
      {cancel_link}
    </div>
  </form>
</div></div>
<script>
window.__aiTest=function(body){{
  var el=document.getElementById('ai-test-result');
  el.innerHTML='<div class="alert text-sm"><span><span class="loading loading-spinner loading-xs"></span> Testing connection…</span></div>';
  el.scrollIntoView({{block:'nearest'}});
  fetch('/recon/ai/test',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(body)}})
    .then(function(r){{return r.json();}})
    .then(function(j){{
      var ok=!!j.ok, cls=ok?'alert-success':'alert-error', pre=ok?'✓ ':'✗ ';
      var msg=(j.message||j.error||'No response').replace(/&/g,'&amp;').replace(/</g,'&lt;');
      el.innerHTML='<div class="alert '+cls+' text-sm"><span>'+pre+msg+'</span></div>';
    }})
    .catch(function(){{ el.innerHTML='<div class="alert alert-error text-sm"><span>✗ Test could not run.</span></div>'; }});
}};
window.reconTestProvider=function(){{
  var cid=(document.querySelector('input[name=config_id]')||{{}}).value;
  __aiTest({{
    provider:document.querySelector('select[name=provider]').value,
    model:document.querySelector('input[name=model]').value,
    base_url:document.querySelector('input[name=base_url]').value,
    api_key:document.querySelector('input[name=api_key]').value,
    config_id:(cid?cid:null)
  }});
}};
window.reconTestSaved=function(cid){{ __aiTest({{config_id:cid}}); }};
</script>"##,
        list_block = list_block,
        form_title = form_title, submit_label = submit_label, cancel_link = cancel_link,
        edit_cid = esc(&edit_cid), cur_name = esc(&cur_name),
        o_anthropic = opt("anthropic", "Anthropic — Claude"),
        o_openai = opt("openai", "OpenAI"),
        o_deepseek = opt("deepseek", "DeepSeek"),
        o_custom = opt("custom", "Custom (OpenAI-compatible)"),
        cur_model = esc(&cur_model),
        cur_base = esc(&cur_base),
        base_ph = ai_preset(&cur_provider).0,
        key_state = key_state,
        // New profiles default to active if none exists yet; editing keeps state.
        active_chk = if is_edit {
            if editing.map(|r| r.try_get::<bool, _>("active").unwrap_or(false)).unwrap_or(false) { "checked" } else { "" }
        } else if rows.is_empty() { "checked" } else { "" },
        locate_chk = if cur_locate { "checked" } else { "" },
        batch_chk = if cur_batch_auto { "checked" } else { "" },
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "AI Extraction", &content)).into_response()
}

/// POST /recon/ai — save provider config. The API key is encrypted at rest;
/// a blank key field keeps the existing one.
async fn ai_config_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html(vortex_plugin_sdk::framework::ui::forbidden_page("AI Extraction"))).into_response();
    }
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let config_id: Option<Uuid> = get("config_id").filter(|s| !s.is_empty()).and_then(|s| s.parse().ok());
    let provider = get("provider").unwrap_or_else(|| "anthropic".into());
    let name = get("name").filter(|s| !s.is_empty()).unwrap_or_else(|| {
        // Fall back to a readable default label.
        match provider.as_str() {
            "anthropic" => "Anthropic".into(),
            "openai" => "OpenAI".into(),
            "deepseek" => "DeepSeek".into(),
            _ => "Custom".into(),
        }
    });
    let model = get("model").filter(|s| !s.is_empty()).unwrap_or_else(|| ai_preset(&provider).1.to_string());
    let base_url = get("base_url").filter(|s| !s.is_empty());
    let api_key = get("api_key").filter(|s| !s.is_empty());
    let active = pairs.iter().any(|(n, v)| n == "active" && v == "1");
    let image_locate = pairs.iter().any(|(n, v)| n == "image_locate" && v == "1");
    let batch_auto = pairs.iter().any(|(n, v)| n == "batch_auto" && v == "1");

    // Encrypt the key only if a new one was supplied.
    let (enc, hint): (Option<Vec<u8>>, Option<String>) = match &api_key {
        Some(k) => {
            let key = vortex_plugin_sdk::security::crypto::master_key();
            match vortex_plugin_sdk::security::crypto::encrypt_str(k, &key) {
                Ok(blob) => {
                    let h: String = k.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect();
                    (Some(blob), Some(h))
                }
                Err(e) => {
                    error!("api key encryption failed: {e} — is VORTEX_SECRET_KEY set?");
                    return (StatusCode::INTERNAL_SERVER_ERROR, "Encryption failed").into_response();
                }
            }
        }
        None => (None, None),
    };

    // First profile ever must be active, or the extractor has nothing to use.
    let total: i64 = vortex_plugin_sdk::sqlx::query_scalar("SELECT COUNT(*) FROM recon_ai_config")
        .fetch_one(&db)
        .await
        .unwrap_or(0);
    let make_active = active || total == 0;

    // Update the named profile if editing, else insert a new one.
    let res = if let Some(id) = config_id {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_ai_config
                SET name=$2, provider=$3, model=$4, base_url=$5, active=$6,
                    api_key_enc = COALESCE($7, api_key_enc),
                    api_key_hint = COALESCE($8, api_key_hint),
                    image_locate=$10, batch_auto=$11, updated_by=$9, updated_at=NOW()
              WHERE id=$1",
        )
        .bind(id)
        .bind(&name).bind(&provider).bind(&model).bind(&base_url).bind(make_active)
        .bind(&enc).bind(&hint).bind(user.id).bind(image_locate).bind(batch_auto)
        .execute(&db)
        .await
    } else {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_ai_config
                (name, provider, model, base_url, active, api_key_enc, api_key_hint, updated_by, image_locate, batch_auto)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&name).bind(&provider).bind(&model).bind(&base_url).bind(make_active)
        .bind(&enc).bind(&hint).bind(user.id).bind(image_locate).bind(batch_auto)
        .execute(&db)
        .await
    };
    if let Err(e) = res {
        error!("ai config save failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }

    // Enforce a single active profile: if this one is active, stand the others
    // down. (Match by identity when editing; else by the just-inserted latest.)
    if make_active {
        let keep: Option<Uuid> = match config_id {
            Some(id) => Some(id),
            None => vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT id FROM recon_ai_config ORDER BY updated_at DESC LIMIT 1",
            )
            .fetch_optional(&db)
            .await
            .ok()
            .flatten(),
        };
        if let Some(keep) = keep {
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_ai_config SET active=false WHERE id <> $1",
            )
            .bind(keep)
            .execute(&db)
            .await;
        }
    }

    // Audit — provider/model only, NEVER the key.
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("recon_ai_config", "singleton")
        .with_details(json!({
            "provider": provider, "model": model,
            "key_updated": api_key.is_some(), "active": active,
        }));
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
    Redirect::to("/recon/ai").into_response()
}

#[derive(serde::Deserialize)]
struct TestProviderPayload {
    #[serde(default)]
    provider: String,
    #[serde(default)]
    model: String,
    #[serde(default)]
    base_url: String,
    #[serde(default)]
    api_key: String,
    /// When the key field is blank and we're editing/testing a saved profile,
    /// reuse that profile's stored key instead of asking the admin to re-enter.
    #[serde(default)]
    config_id: Option<Uuid>,
}

/// POST /recon/ai/test — ping a provider with the given (or stored) credentials
/// to verify connectivity, key, and model name before saving. Superadmin only.
async fn ai_config_test(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    vortex_plugin_sdk::axum::Json(p): vortex_plugin_sdk::axum::Json<TestProviderPayload>,
) -> Response {
    if !user.is_system_admin() {
        return json_error(StatusCode::FORBIDDEN, "Superadmin only");
    }
    let provider = if p.provider.trim().is_empty() { "anthropic".to_string() } else { p.provider.trim().to_string() };
    let model = if p.model.trim().is_empty() { ai_preset(&provider).1.to_string() } else { p.model.trim().to_string() };
    let base_url = {
        let b = p.base_url.trim();
        if b.is_empty() { ai_preset(&provider).0.to_string() } else { b.to_string() }
    };

    // Key: the typed one, else the stored key of the profile under test.
    let api_key = if !p.api_key.trim().is_empty() {
        p.api_key.trim().to_string()
    } else if let Some(cid) = p.config_id {
        let enc: Option<Vec<u8>> = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT api_key_enc FROM recon_ai_config WHERE id = $1",
        )
        .bind(cid)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten()
        .flatten();
        match enc {
            Some(blob) => {
                let key = vortex_plugin_sdk::security::crypto::master_key();
                match vortex_plugin_sdk::security::crypto::decrypt_str(&blob, &key) {
                    Ok(k) => k,
                    Err(_) => return json_error(StatusCode::BAD_REQUEST, "Stored key could not be decrypted (VORTEX_SECRET_KEY changed?)."),
                }
            }
            None => return json_error(StatusCode::BAD_REQUEST, "No stored key — paste a key to test."),
        }
    } else {
        return json_error(StatusCode::BAD_REQUEST, "Paste an API key to test.");
    };

    let cfg = crate::ai::AiConfig { provider, model, base_url, api_key, image_locate: false };
    match crate::ai::test_connection(&cfg).await {
        Ok(msg) => json_ok(json!({ "ok": true, "message": msg })),
        Err(msg) => json_ok(json!({ "ok": false, "message": msg })),
    }
}

/// POST /recon/ai/{cid}/activate — make this the single active provider profile.
async fn ai_config_activate(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(cid): Path<Uuid>,
) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html(vortex_plugin_sdk::framework::ui::forbidden_page("AI Extraction"))).into_response();
    }
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_ai_config SET active = (id = $1), updated_at = NOW()",
    )
    .bind(cid)
    .execute(&db)
    .await;
    if let Err(e) = res {
        error!("ai config activate failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Failed").into_response();
    }
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("recon_ai_config", cid.to_string())
        .with_details(json!({ "action": "activate_provider" }));
    let _ = state.audit.log(entry).await;
    Redirect::to("/recon/ai").into_response()
}

/// POST /recon/ai/{cid}/delete — remove a provider profile. If it was the
/// active one, promote the most-recently-updated survivor so extraction keeps
/// working.
async fn ai_config_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(cid): Path<Uuid>,
) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html(vortex_plugin_sdk::framework::ui::forbidden_page("AI Extraction"))).into_response();
    }
    let was_active: bool = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT active FROM recon_ai_config WHERE id = $1",
    )
    .bind(cid)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false);

    if let Err(e) = vortex_plugin_sdk::sqlx::query("DELETE FROM recon_ai_config WHERE id = $1")
        .bind(cid)
        .execute(&db)
        .await
    {
        error!("ai config delete failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Delete failed").into_response();
    }
    // Promote a survivor if we just deleted the active profile.
    if was_active {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_ai_config SET active = true
              WHERE id = (SELECT id FROM recon_ai_config ORDER BY updated_at DESC LIMIT 1)",
        )
        .execute(&db)
        .await;
    }
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("recon_ai_config", cid.to_string())
        .with_details(json!({ "action": "delete_provider" }));
    let _ = state.audit.log(entry).await;
    Redirect::to("/recon/ai").into_response()
}

/// GET /recon/ai/usage — superadmin-only AI token usage + extraction cost.
/// Totals, per-model breakdown, an editable rate card, and recent calls.
async fn ai_usage_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html(vortex_plugin_sdk::framework::ui::forbidden_page("AI Usage & Cost"))).into_response();
    }
    let esc = vortex_plugin_sdk::framework::ui::html_escape;

    // Headline totals.
    let tot = vortex_plugin_sdk::sqlx::query(
        "SELECT COUNT(*) AS calls,
                COALESCE(SUM(input_tokens),0)  AS inp,
                COALESCE(SUM(output_tokens),0) AS outp,
                COALESCE(SUM(cost),0)::float8  AS cost,
                MAX(currency) AS cur
           FROM recon_ai_usage",
    )
    .fetch_one(&db)
    .await
    .ok();
    let (calls, sum_in, sum_out, sum_cost, cur) = match &tot {
        Some(r) => (
            r.try_get::<i64, _>("calls").unwrap_or(0),
            r.try_get::<i64, _>("inp").unwrap_or(0),
            r.try_get::<i64, _>("outp").unwrap_or(0),
            r.try_get::<f64, _>("cost").unwrap_or(0.0),
            r.try_get::<Option<String>, _>("cur").ok().flatten().unwrap_or_else(|| "USD".into()),
        ),
        None => (0, 0, 0, 0.0, "USD".into()),
    };
    // 30-day cost.
    let cost_30: f64 = vortex_plugin_sdk::sqlx::query_scalar::<_, Option<f64>>(
        "SELECT SUM(cost)::float8 FROM recon_ai_usage WHERE created_at >= NOW() - INTERVAL '30 days'",
    )
    .fetch_one(&db)
    .await
    .ok()
    .flatten()
    .unwrap_or(0.0);
    let avg_cost = if calls > 0 { sum_cost / calls as f64 } else { 0.0 };

    let stat = |title: &str, value: String, desc: &str| {
        format!(
            r#"<div class="stat bg-base-100 rounded-box shadow"><div class="stat-title">{t}</div><div class="stat-value text-2xl">{v}</div><div class="stat-desc">{d}</div></div>"#,
            t = esc(title), v = esc(&value), d = esc(desc),
        )
    };
    let fmt_tok = |n: i64| {
        if n >= 1_000_000 { format!("{:.2}M", n as f64 / 1e6) }
        else if n >= 1_000 { format!("{:.1}k", n as f64 / 1e3) }
        else { n.to_string() }
    };
    let kpis = format!(
        r#"<div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-3 mb-6">{}{}{}{}{}{}</div>"#,
        stat("Extractions", calls.to_string(), "AI calls logged"),
        stat("Input tokens", fmt_tok(sum_in), "prompt + document"),
        stat("Output tokens", fmt_tok(sum_out), "model response"),
        stat("Total cost", format!("{cur} {sum_cost:.2}"), "all time"),
        stat("Last 30 days", format!("{cur} {cost_30:.2}"), "rolling cost"),
        stat("Avg / invoice", format!("{cur} {avg_cost:.4}"), "cost per extraction"),
    );

    // On-demand vs batch split (+ estimated batch savings).
    let mode_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT mode, COUNT(*) AS n, COALESCE(SUM(cost),0)::float8 AS cost
           FROM recon_ai_usage GROUP BY mode",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let (mut od_n, mut od_cost, mut b_n, mut b_cost) = (0i64, 0.0f64, 0i64, 0.0f64);
    for r in &mode_rows {
        let m: String = r.try_get("mode").unwrap_or_default();
        let n: i64 = r.try_get("n").unwrap_or(0);
        let c: f64 = r.try_get("cost").unwrap_or(0.0);
        if m == "batch" { b_n = n; b_cost = c; } else { od_n = n; od_cost = c; }
    }
    // Batch is billed at ~50%, so what you paid on batch is also roughly what
    // you saved versus running those same invoices on demand.
    let saved = b_cost;
    let mode_split = format!(
        r#"<div class="flex flex-wrap gap-3 mb-6">
  <div class="badge badge-lg badge-outline gap-2">On-demand <span class="font-mono">{cur} {od:.2}</span> <span class="opacity-60">· {odn}</span></div>
  <div class="badge badge-lg badge-outline gap-2">Batch <span class="font-mono">{cur} {b:.2}</span> <span class="opacity-60">· {bn}</span></div>
  <div class="badge badge-lg badge-success gap-2">Saved via batch ≈ <span class="font-mono">{cur} {saved:.2}</span></div>
</div>"#,
        cur = esc(&cur), od = od_cost, odn = od_n, b = b_cost, bn = b_n, saved = saved,
    );

    // Per-model breakdown.
    let by_model = vortex_plugin_sdk::sqlx::query(
        "SELECT provider, model, COUNT(*) AS calls,
                COALESCE(SUM(input_tokens),0)  AS inp,
                COALESCE(SUM(output_tokens),0) AS outp,
                COALESCE(SUM(cost),0)::float8  AS cost, MAX(currency) AS cur
           FROM recon_ai_usage GROUP BY provider, model ORDER BY cost DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut model_rows = String::new();
    for r in &by_model {
        let provider: String = r.try_get("provider").unwrap_or_default();
        let model: String = r.try_get("model").unwrap_or_default();
        let c: i64 = r.try_get("calls").unwrap_or(0);
        let inp: i64 = r.try_get("inp").unwrap_or(0);
        let outp: i64 = r.try_get("outp").unwrap_or(0);
        let cost: f64 = r.try_get("cost").unwrap_or(0.0);
        let mcur: String = r.try_get::<Option<String>, _>("cur").ok().flatten().unwrap_or_else(|| "USD".into());
        model_rows.push_str(&format!(
            r#"<tr class="hover"><td class="text-sm">{prov}</td><td class="font-mono text-xs">{model}</td><td class="text-right">{c}</td><td class="text-right font-mono text-xs">{inp}</td><td class="text-right font-mono text-xs">{outp}</td><td class="text-right font-mono text-sm">{mcur} {cost:.4}</td></tr>"#,
            prov = esc(&provider), model = esc(&model), c = c,
            inp = fmt_tok(inp), outp = fmt_tok(outp), mcur = esc(&mcur), cost = cost,
        ));
    }
    if model_rows.is_empty() {
        model_rows.push_str(r#"<tr><td colspan="6" class="text-center opacity-60 py-6">No extractions logged yet.</td></tr>"#);
    }

    // Editable rate card. Each row is its own tiny form → save one at a time.
    let pricing = vortex_plugin_sdk::sqlx::query(
        "SELECT provider, model, input_per_mtok::float8 AS inp, output_per_mtok::float8 AS outp, currency
           FROM recon_ai_pricing ORDER BY provider, model",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut price_rows = String::new();
    for r in &pricing {
        let provider: String = r.try_get("provider").unwrap_or_default();
        let model: String = r.try_get("model").unwrap_or_default();
        let inp: f64 = r.try_get("inp").unwrap_or(0.0);
        let outp: f64 = r.try_get("outp").unwrap_or(0.0);
        let pcur: String = r.try_get("currency").unwrap_or_else(|_| "USD".into());
        price_rows.push_str(&format!(
            r##"<tr class="hover"><form method="post" action="/recon/ai/pricing" class="contents">
<input type="hidden" name="provider" value="{prov}"/>
<td class="text-sm">{prov}</td>
<td class="font-mono text-xs">{model}<input type="hidden" name="model" value="{model}"/></td>
<td><input name="input_per_mtok" value="{inp}" class="input input-bordered input-xs w-24 text-right font-mono"/></td>
<td><input name="output_per_mtok" value="{outp}" class="input input-bordered input-xs w-24 text-right font-mono"/></td>
<td><input name="currency" value="{pcur}" class="input input-bordered input-xs w-16 text-center"/></td>
<td><button type="submit" class="btn btn-xs btn-outline">Save</button></td>
</form></tr>"##,
            prov = esc(&provider), model = esc(&model), inp = inp, outp = outp, pcur = esc(&pcur),
        ));
    }

    // Recent calls.
    let recent = vortex_plugin_sdk::sqlx::query(
        "SELECT u.created_at, u.model, u.mode, u.input_tokens, u.output_tokens, u.cost::float8 AS cost, u.currency,
                b.code AS batch_code, u.batch_id
           FROM recon_ai_usage u LEFT JOIN recon_batch b ON b.id = u.batch_id
          ORDER BY u.created_at DESC LIMIT 20",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut recent_rows = String::new();
    for r in &recent {
        let model: String = r.try_get("model").unwrap_or_default();
        let mode: String = r.try_get("mode").unwrap_or_else(|_| "ondemand".into());
        let inp: i64 = r.try_get("input_tokens").unwrap_or(0);
        let outp: i64 = r.try_get("output_tokens").unwrap_or(0);
        let cost: f64 = r.try_get("cost").unwrap_or(0.0);
        let rcur: String = r.try_get("currency").unwrap_or_else(|_| "USD".into());
        let code: Option<String> = r.try_get("batch_code").ok().flatten();
        let bid: Option<Uuid> = r.try_get("batch_id").ok().flatten();
        let when: Option<vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>> = r.try_get("created_at").ok();
        let inv_cell = match (bid, &code) {
            (Some(b), Some(c)) => format!(r#"<a href="/recon/{b}" class="link link-hover font-mono text-xs">{c}</a>"#, b = b, c = esc(c)),
            _ => "<span class=\"opacity-50\">—</span>".to_string(),
        };
        let mode_badge = if mode == "batch" {
            r#"<span class="badge badge-success badge-xs">batch</span>"#
        } else {
            r#"<span class="badge badge-ghost badge-xs">on-demand</span>"#
        };
        recent_rows.push_str(&format!(
            r#"<tr class="hover"><td class="text-xs opacity-70">{when}</td><td>{inv}</td><td>{mode_badge}</td><td class="font-mono text-xs">{model}</td><td class="text-right font-mono text-xs">{inp}</td><td class="text-right font-mono text-xs">{outp}</td><td class="text-right font-mono text-sm">{rcur} {cost:.4}</td></tr>"#,
            mode_badge = mode_badge,
            when = when.map(|w| w.format("%Y-%m-%d %H:%M").to_string()).unwrap_or_default(),
            inv = inv_cell, model = esc(&model), inp = fmt_tok(inp), outp = fmt_tok(outp), rcur = esc(&rcur), cost = cost,
        ));
    }
    if recent_rows.is_empty() {
        recent_rows.push_str(r#"<tr><td colspan="7" class="text-center opacity-60 py-6">No extractions logged yet — run one from an invoice.</td></tr>"#);
    }

    let content = format!(
        r##"<div class="mb-4"><a href="/recon/ai" class="link link-hover text-sm">← AI Extraction</a></div>
<h1 class="text-2xl font-bold mb-1">AI Usage &amp; Cost</h1>
<p class="opacity-60 text-sm mb-6">Token usage and extraction cost for OCR runs. Costs are computed from the rate card below and frozen onto each call, so past figures don't move when you edit rates.</p>
{kpis}
{mode_split}
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <h2 class="card-title text-lg mb-3">By model</h2>
  <div class="overflow-x-auto"><table class="table table-sm">
  <thead><tr><th>Provider</th><th>Model</th><th class="text-right">Calls</th><th class="text-right">Input</th><th class="text-right">Output</th><th class="text-right">Cost</th></tr></thead>
  <tbody>{model_rows}</tbody></table></div>
</div></div>
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <h2 class="card-title text-lg mb-1">Rate card</h2>
  <p class="text-xs opacity-60 mb-3">Cost per 1,000,000 tokens. Seeded with approximate list prices — set these to your negotiated rates. New models: run an extraction once, then a row appears to price (until then its calls log at 0 cost).</p>
  <div class="overflow-x-auto"><table class="table table-sm">
  <thead><tr><th>Provider</th><th>Model</th><th>Input /Mtok</th><th>Output /Mtok</th><th>Currency</th><th></th></tr></thead>
  <tbody>{price_rows}</tbody></table></div>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body">
  <h2 class="card-title text-lg mb-3">Recent extractions</h2>
  <div class="overflow-x-auto"><table class="table table-sm">
  <thead><tr><th>When</th><th>Invoice</th><th>Mode</th><th>Model</th><th class="text-right">Input</th><th class="text-right">Output</th><th class="text-right">Cost</th></tr></thead>
  <tbody>{recent_rows}</tbody></table></div>
</div></div>"##,
        kpis = kpis, mode_split = mode_split, model_rows = model_rows, price_rows = price_rows, recent_rows = recent_rows,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "AI Usage & Cost", &content)).into_response()
}

/// POST /recon/ai/pricing — upsert one rate-card row (superadmin only).
async fn ai_pricing_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let _ = (&state, &db_ctx);
    if !user.is_system_admin() {
        return (StatusCode::FORBIDDEN, Html(vortex_plugin_sdk::framework::ui::forbidden_page("AI Usage & Cost"))).into_response();
    }
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let provider = get("provider").unwrap_or_default();
    let model = get("model").unwrap_or_default();
    if provider.is_empty() || model.is_empty() {
        return (StatusCode::BAD_REQUEST, "provider and model required").into_response();
    }
    let inp = get("input_per_mtok").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0).max(0.0);
    let outp = get("output_per_mtok").and_then(|s| s.parse::<f64>().ok()).unwrap_or(0.0).max(0.0);
    let currency = get("currency").filter(|s| !s.is_empty()).unwrap_or_else(|| "USD".into());

    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO recon_ai_pricing (provider, model, input_per_mtok, output_per_mtok, currency, updated_at)
         VALUES ($1,$2,$3,$4,$5,NOW())
         ON CONFLICT (provider, model)
         DO UPDATE SET input_per_mtok=$3, output_per_mtok=$4, currency=$5, updated_at=NOW()",
    )
    .bind(&provider)
    .bind(&model)
    .bind(inp)
    .bind(outp)
    .bind(&currency)
    .execute(&db)
    .await;
    if let Err(e) = res {
        error!("ai pricing save failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    Redirect::to("/recon/ai/usage").into_response()
}

/// POST /recon/{id}/extract — OCR the batch's attached scan into the grid.
/// Reusable OCR extraction for one batch — used by the manual "Extract with AI"
/// button and by auto-capture on upload/ingest. Loads the attached scan, calls
/// the configured provider, and populates the invoice lines + header.
pub async fn extract_batch(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    db_name: &str,
    id: Uuid,
    actor: Option<(Uuid, &str)>,
) -> Result<usize, String> {
    // 1. The attached scan.
    let att = vortex_plugin_sdk::sqlx::query(
        "SELECT store_fname, mimetype FROM ir_attachment
          WHERE res_model = 'recon.batch' AND res_id = $1
          ORDER BY created_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let att = att.ok_or_else(|| "No scanned invoice attached to extract".to_string())?;
    let store_fname: String = att.try_get("store_fname").ok().flatten().unwrap_or_default();
    let mime: String = att
        .try_get("mimetype")
        .ok()
        .flatten()
        .unwrap_or_else(|| "application/pdf".into());
    if store_fname.is_empty() {
        return Err("Attachment has no stored file".into());
    }

    // 2. Blob from the FileStore.
    let bytes = match state.files.get(db_name, &store_fname).await {
        Ok(Some(b)) => b,
        Ok(None) => return Err("Stored scan not found".into()),
        Err(e) => return Err(format!("Could not read the scan: {e}")),
    };

    // 3. Provider config.
    let cfg = match load_ai_config(db).await {
        Ok(Some(c)) => c,
        Ok(None) => {
            return Err("AI extraction is not configured — set a provider and key in Configuration ▸ AI Extraction.".into())
        }
        Err(e) => return Err(format!("Config error: {e}")),
    };
    let provider = cfg.provider.clone();
    let model = cfg.model.clone();

    // 3b. Self-learning knowledge base: pull active correction rules for this
    // invoice's supplier plus any global rules, and feed them into the prompt.
    // (On a first extraction the supplier may still be unknown — then only
    // global rules apply; supplier rules kick in on re-extract / next invoice.)
    let supplier_no: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT supplier_no FROM recon_batch WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten()
            .flatten();
    let hints = load_extract_hints(db, supplier_no.as_deref()).await;

    // 4. Extract.
    let (ex, usage) = crate::ai::extract(&cfg, &bytes, &mime, &hints).await?;

    // Live "Extract now" / ingest path → on-demand pricing (batch = false).
    let n = persist_extraction(state, db, db_name, id, &ex, usage, &provider, &model, actor, false).await?;
    // Advance the queue/batch state machine: this invoice is now extracted.
    let _ = vortex_plugin_sdk::sqlx::query("UPDATE recon_batch SET ai_extract_state = 'done' WHERE id = $1")
        .bind(id)
        .execute(db)
        .await;
    Ok(n)
}

/// Persist an extraction result (from the live call OR a completed batch) onto a
/// recon_batch: replace its lines, patch the header, reset the self-check, log
/// token usage/cost, and audit. Returns the number of lines written.
async fn persist_extraction(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    db_name: &str,
    id: Uuid,
    ex: &crate::ai::Extracted,
    usage: crate::ai::Usage,
    provider: &str,
    model: &str,
    actor: Option<(Uuid, &str)>,
    batch: bool,
) -> Result<usize, String> {
    // Persist: replace lines, patch header, reset the self-check.
    let mut tx = db.begin().await.map_err(|e| format!("Save failed: {e}"))?;
    if let Err(e) = vortex_plugin_sdk::sqlx::query("DELETE FROM recon_inv_line WHERE batch_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
    {
        return Err(format!("Save failed: {e}"));
    }
    // Same net + tax-allocation model as manual save, so discounts and both
    // SST layouts reconcile identically whether keyed or AI-extracted.
    let raw: Vec<RawLine> = ex
        .lines
        .iter()
        .map(|l| RawLine {
            qty: l.qty.unwrap_or(0.0),
            unit_price: l.unit_price.unwrap_or(0.0),
            discount_pct: l.discount_pct.unwrap_or(0.0),
            discount_amt: l.discount_amt.unwrap_or(0.0),
            line_tax: l.tax.unwrap_or(0.0),
        })
        .collect();
    let (calc, subtotal, total_tax) = compute_totals(&raw, ex.tax_total);
    let per_line_tax = raw.iter().map(|l| l.line_tax).sum::<f64>().abs() > 0.005;

    for (idx, (l, c)) in ex.lines.iter().zip(&calc).enumerate() {
        let line_no = l.line_no.map(|n| n as i32).unwrap_or((idx + 1) as i32);
        if let Err(e) = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_inv_line
               (batch_id, line_no, supplier_sku, description, uom, qty,
                unit_price_excl, discount_pct, discount_amt, line_net, sales_tax, line_total,
                doc_y, doc_h)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(id)
        .bind(line_no)
        .bind(l.supplier_sku.as_deref().filter(|s| !s.is_empty()))
        .bind(l.description.as_deref().filter(|s| !s.is_empty()))
        .bind(l.uom.as_deref().filter(|s| !s.is_empty()))
        .bind(l.qty.unwrap_or(0.0))
        .bind(l.unit_price.unwrap_or(0.0))
        .bind(l.discount_pct.unwrap_or(0.0))
        .bind(l.discount_amt.unwrap_or(0.0))
        .bind(c.net)
        .bind(c.tax)
        .bind(c.total)
        // Line-locate band (image scans + image_locate only); None otherwise.
        .bind(l.doc_y.filter(|v| v.is_finite()))
        .bind(l.doc_h.filter(|v| v.is_finite()))
        .execute(&mut *tx)
        .await
        {
            return Err(format!("Save failed: {e}"));
        }
    }
    // Prefer the printed subtotal/tax if the model returned them; else the
    // computed figures (which already reconcile to the grand total).
    let doc_subtotal = ex.subtotal.unwrap_or(subtotal);
    let doc_tax = ex.tax_total.unwrap_or(total_tax);

    // Header: fill each field only when the model returned it (don't wipe good
    // data with a null). Advance draft → extracted; reset the self-check verdict.
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch SET
            supplier_no  = COALESCE(NULLIF($2,''), supplier_no),
            supplier_name= COALESCE(NULLIF($3,''), supplier_name),
            invoice_no   = COALESCE(NULLIF($4,''), invoice_no),
            invoice_date = COALESCE($5::date, invoice_date),
            currency     = COALESCE(NULLIF($6,''), currency),
            doc_total    = COALESCE($7, doc_total),
            doc_subtotal = $8,
            doc_tax      = $9,
            tax_per_line = $10,
            source_provider = 'ocr_vision',
            record_state = CASE WHEN record_state = 'draft' THEN 'extracted' ELSE record_state END,
            validation_status = 'pending', computed_total = NULL, total_variance = NULL,
            validated_at = NULL, validated_by = NULL
          WHERE id = $1",
    )
    .bind(id)
    .bind(ex.supplier_no.as_deref().unwrap_or(""))
    .bind(ex.supplier_name.as_deref().unwrap_or(""))
    .bind(ex.invoice_no.as_deref().unwrap_or(""))
    // Only pass a date that looks like YYYY-MM-DD — a garbled OCR date must not
    // fail the ::date cast and roll back an otherwise-good extraction.
    .bind(ex.invoice_date.as_deref().filter(|s| {
        s.len() == 10 && s.as_bytes()[4] == b'-' && s.as_bytes()[7] == b'-'
            && s.bytes().all(|b| b.is_ascii_digit() || b == b'-')
    }))
    .bind(ex.currency.as_deref().unwrap_or(""))
    .bind(ex.doc_total)
    .bind(doc_subtotal)
    .bind(doc_tax)
    .bind(per_line_tax)
    .execute(&mut *tx)
    .await
    {
        return Err(format!("Save failed: {e}"));
    }
    tx.commit().await.map_err(|e| format!("Save failed: {e}"))?;

    // Record token usage + cost for this extraction (best-effort — a logging
    // failure must never fail an otherwise-good extraction). Cost is derived
    // from the editable rate card and frozen onto the row.
    log_ai_usage(db, id, provider, model, usage, actor.map(|(uid, _)| uid), batch).await;

    let mut entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_database(db_name)
        .with_resource("recon_batch", id.to_string())
        .with_details(json!({
            "ai_extract": true, "provider": provider, "model": model,
            "mode": if batch { "batch" } else { "ondemand" },
            "lines": ex.lines.len(),
            "input_tokens": usage.input_tokens as i64,
            "output_tokens": usage.output_tokens as i64,
            "doc_total": ex.doc_total.map(|v| format!("{v:.2}")),
        }));
    match actor {
        Some((uid, uname)) => entry = entry.with_user(UserId(uid)).with_username(uname),
        None => entry = entry.with_username("recon-ingest"),
    }
    let _ = state.audit.log(entry).await;

    Ok(ex.lines.len())
}

/// POST /recon/{id}/extract — manual "Extract with AI". Runs in the BACKGROUND
/// and returns immediately: OCR on a long invoice can take ~30s, and a
/// synchronous request that long gets dropped by proxies/browsers ("network
/// error"). The page polls the batch and refreshes when the lines land.
async fn ai_extract(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // Fail fast on the obvious pre-conditions so the user gets an immediate,
    // clear error rather than a silent no-op.
    let has_scan: bool = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ir_attachment WHERE res_model='recon.batch' AND res_id=$1)",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(false);
    if !has_scan {
        return json_error(StatusCode::BAD_REQUEST, "No scanned invoice attached to extract");
    }
    match load_ai_config(&db).await {
        Ok(Some(c)) if !c.api_key.trim().is_empty() => {}
        _ => return json_error(StatusCode::BAD_REQUEST, "AI extraction is not configured — set a provider and key in Configuration ▸ AI Extraction."),
    }

    // Atomically CLAIM the invoice for on-demand extraction: mark it
    // 'processing' and unlink it from any batch. This is the double-extraction
    // guard — the batch submitter only picks 'queued' rows, and the batch
    // completer only persists rows still linked to its batch, so once claimed
    // here it can't also be extracted by a batch. Refuse if it's already being
    // extracted (a running Extract-now, or already submitted to a batch).
    let claimed = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch SET ai_extract_state='processing', ai_batch_id=NULL
          WHERE id=$1 AND ai_extract_state <> 'processing'",
    )
    .bind(id)
    .execute(&db)
    .await;
    match claimed {
        Ok(r) if r.rows_affected() == 1 => {}
        Ok(_) => return json_error(StatusCode::CONFLICT, "This invoice is already being extracted — please wait for it to finish."),
        Err(e) => {
            error!("extract claim failed: {e}");
            return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not start extraction");
        }
    }

    let st = state.clone();
    let db_name = db_ctx.db_name.clone();
    let (uid, uname) = (user.id, user.username.clone());
    tokio::spawn(async move {
        let Ok(cp) = st.pool_manager.get_pool(&db_name).await else { return };
        let db = cp.pool().clone();
        if let Err(e) = extract_batch(&st, &db, &db_name, id, Some((uid, &uname))).await {
            vortex_plugin_sdk::tracing::warn!(batch = %id, "manual extract failed: {e}");
            // Release the claim so the record shows a clear failure, not a stuck
            // "processing" state.
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_batch SET ai_extract_state='error' WHERE id=$1 AND ai_extract_state='processing'",
            )
            .bind(id)
            .execute(&db)
            .await;
        }
    });
    json_ok(json!({ "status": "started" }))
}

#[derive(serde::Deserialize)]
struct FeedbackPayload {
    #[serde(default)]
    feedback: String,
    /// When true the rule applies to ALL suppliers, not just this invoice's.
    #[serde(default)]
    global: bool,
}

/// POST /recon/{id}/reextract — record a reviewer correction into the learning
/// knowledge base, then re-run extraction with it (and all prior rules for this
/// supplier) applied. Body: {feedback, global}.
async fn reextract_with_feedback(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::Json(payload): vortex_plugin_sdk::axum::Json<FeedbackPayload>,
) -> Response {
    let feedback = payload.feedback.trim().to_string();
    if feedback.is_empty() {
        return json_error(StatusCode::BAD_REQUEST, "Type the correction before re-extracting.");
    }
    if feedback.len() > 2000 {
        return json_error(StatusCode::BAD_REQUEST, "Correction is too long (2000 char max).");
    }
    let has_scan: bool = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM ir_attachment WHERE res_model='recon.batch' AND res_id=$1)",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(false);
    if !has_scan {
        return json_error(StatusCode::BAD_REQUEST, "No scanned invoice attached to extract");
    }
    match load_ai_config(&db).await {
        Ok(Some(c)) if !c.api_key.trim().is_empty() => {}
        _ => return json_error(StatusCode::BAD_REQUEST, "AI extraction is not configured — set a provider and key in Configuration ▸ AI Extraction."),
    }

    // Scope: this invoice's supplier, unless the reviewer flags it global.
    let supplier_no: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT supplier_no FROM recon_batch WHERE id = $1")
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
            .flatten();
    let scope = if payload.global {
        None
    } else {
        supplier_no.filter(|s| !s.is_empty())
    };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO recon_extract_hint (supplier_no, hint, source_batch_id, created_by)
         VALUES ($1,$2,$3,$4)",
    )
    .bind(scope.as_deref())
    .bind(&feedback)
    .bind(id)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!("save extract hint failed: {e}");
        return json_error(StatusCode::INTERNAL_SERVER_ERROR, "Could not save the correction");
    }

    // Audit the learning event (WORM). Details are strings only.
    audit_item(
        &state,
        &user,
        &db_ctx,
        id,
        AuditAction::RecordUpdated,
        json!({
            "action": "extraction_feedback",
            "scope": scope.as_deref().unwrap_or("global"),
            "feedback": feedback.chars().take(200).collect::<String>(),
        }),
    )
    .await;

    // Re-run extraction in the background (the newly-saved rule is picked up by
    // extract_batch, which loads the knowledge base itself).
    let st = state.clone();
    let db_name = db_ctx.db_name.clone();
    let (uid, uname) = (user.id, user.username.clone());
    tokio::spawn(async move {
        let Ok(cp) = st.pool_manager.get_pool(&db_name).await else { return };
        let db = cp.pool().clone();
        if let Err(e) = extract_batch(&st, &db, &db_name, id, Some((uid, &uname))).await {
            vortex_plugin_sdk::tracing::warn!(batch = %id, "feedback re-extract failed: {e}");
        }
    });
    json_ok(json!({ "status": "started" }))
}

/// POST /recon/hint/{hid}/toggle — deactivate (or reactivate) a learned rule.
async fn toggle_extract_hint(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(hid): Path<Uuid>,
) -> Response {
    let _ = &user;
    let row = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_extract_hint SET active = NOT active WHERE id = $1
         RETURNING active, source_batch_id",
    )
    .bind(hid)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    match row {
        Some(r) => {
            let active: bool = r.try_get("active").unwrap_or(false);
            json_ok(json!({ "active": active }))
        }
        None => json_error(StatusCode::NOT_FOUND, "Rule not found"),
    }
}

/// GET /recon/{id}/extract-status — line count, so the page can poll for the
/// background extraction to finish.
async fn extract_status(Db(db): Db, Path(id): Path<Uuid>) -> Response {
    let n: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM recon_inv_line WHERE batch_id = $1",
    )
    .bind(id)
    .fetch_one(&db)
    .await
    .unwrap_or(0);
    json_ok(json!({ "lines": n }))
}

/// Fire-and-forget auto-extraction after a scan lands (upload / ingest), but
/// ONLY when a provider + key is configured — otherwise leave it for the manual
/// button so we don't make pointless failing API calls.
// ── Remote invoice pickup (SFTP/FTP auto-ingest) ─────────────────────────────

fn guess_ct(name: &str) -> &'static str {
    let n = name.to_ascii_lowercase();
    if n.ends_with(".pdf") {
        "application/pdf"
    } else if n.ends_with(".png") {
        "image/png"
    } else if n.ends_with(".jpg") || n.ends_with(".jpeg") {
        "image/jpeg"
    } else {
        "application/octet-stream"
    }
}

/// Load + decrypt one source into a connect-ready [`crate::ingest::RemoteConfig`].
async fn load_ingest_source(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    id: Uuid,
) -> Result<crate::ingest::RemoteConfig, String> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT protocol, host, port, username, password_enc, private_key_enc,
                remote_dir, processed_dir, file_pattern
           FROM recon_ingest_source WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "source not found".to_string())?;

    let key = vortex_plugin_sdk::security::crypto::master_key();
    let dec = |col: &str| -> Option<String> {
        row.try_get::<Option<Vec<u8>>, _>(col)
            .ok()
            .flatten()
            .and_then(|b| vortex_plugin_sdk::security::crypto::decrypt_str(&b, &key).ok())
    };
    let remote_dir: String = row.try_get("remote_dir").unwrap_or_else(|_| "/".into());
    let processed_dir: Option<String> = row.try_get("processed_dir").ok().flatten();
    let processed_dir = processed_dir
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("{}/processed", remote_dir.trim_end_matches('/')));

    Ok(crate::ingest::RemoteConfig {
        protocol: row.try_get("protocol").unwrap_or_else(|_| "sftp".into()),
        host: row.try_get("host").unwrap_or_default(),
        port: row.try_get::<i32, _>("port").unwrap_or(22) as u16,
        username: row.try_get("username").ok().flatten().unwrap_or_default(),
        password: dec("password_enc"),
        private_key: dec("private_key_enc"),
        remote_dir,
        processed_dir,
        pattern: row.try_get("file_pattern").unwrap_or_else(|_| "*.pdf".into()),
    })
}

/// The shared pickup pipeline: fetch → import each as a draft batch → move the
/// imported files to the processed folder → record the run. Used by both the
/// manual "Fetch now" and the scheduled poller.
pub async fn run_ingest(
    state: &AppState,
    pool: &vortex_plugin_sdk::orm::ConnectionPool,
    db_name: &str,
    id: Uuid,
    actor: Option<(Uuid, &str)>,
    trigger: &str,
) -> (bool, i64, String) {
    let db = pool.pool();
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_ingest_source SET last_status='running', last_run_at=NOW() WHERE id=$1",
    )
    .bind(id)
    .execute(db)
    .await;
    let run_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO recon_ingest_run (source_id, trigger) VALUES ($1,$2) RETURNING id",
    )
    .bind(id)
    .bind(trigger)
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    // Any failure records an 'error' run + source status and returns.
    let finish_err = |msg: String| async move {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_ingest_source SET last_status='error', last_message=$2 WHERE id=$1",
        )
        .bind(id)
        .bind(&msg)
        .execute(db)
        .await;
        if let Some(rid) = run_id {
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_ingest_run SET finished_at=NOW(), status='error', message=$2 WHERE id=$1",
            )
            .bind(rid)
            .bind(&msg)
            .execute(db)
            .await;
        }
        (false, 0i64, msg)
    };

    let cfg = match load_ingest_source(db, id).await {
        Ok(c) => c,
        Err(e) => return finish_err(e).await,
    };
    let files = match crate::ingest::fetch_files(&cfg).await {
        Ok(f) => f,
        Err(e) => return finish_err(e).await,
    };

    // Pulled files queue for batch extraction (cheaper, async) — same as
    // manual upload. The batch submitter/poller does the OCR.
    let mut imported = Vec::new();
    for f in &files {
        if let Some(bid) =
            create_scan_batch(state, pool, db_name, actor, &f.name, Some(guess_ct(&f.name)), &f.data, &cfg.protocol).await
        {
            imported.push(f.name.clone());
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_batch SET ai_extract_state = 'queued' WHERE id = $1",
            )
            .bind(bid)
            .execute(db)
            .await;
        }
    }
    let n = imported.len() as i64;
    if !imported.is_empty() {
        if let Err(e) = crate::ingest::move_to_processed(&cfg, &imported).await {
            error!("ingest: move-to-processed failed: {e}");
        }
    }
    let msg = format!("{n} file(s) imported from {}:{}", cfg.host, cfg.remote_dir);
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_ingest_source SET last_status='ok', last_count=$2, last_message=$3 WHERE id=$1",
    )
    .bind(id)
    .bind(n as i32)
    .bind(&msg)
    .execute(db)
    .await;
    if let Some(rid) = run_id {
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_ingest_run SET finished_at=NOW(), status='ok', files_imported=$2, message=$3 WHERE id=$1",
        )
        .bind(rid)
        .bind(n as i32)
        .bind(&msg)
        .execute(db)
        .await;
    }
    (true, n, msg)
}

/// The scheduled poller entry point: for every active tenant DB, run any ingest
/// source whose poll interval has elapsed. Called from `Plugin::scheduled_actions`.
/// Build the batch document for one queued invoice: its stored scan bytes,
/// mimetype and the supplier's learned hints. `None` if the scan is missing.
async fn load_batch_doc(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    db_name: &str,
    id: Uuid,
) -> Option<crate::ai::BatchDoc> {
    let att = vortex_plugin_sdk::sqlx::query(
        "SELECT store_fname, mimetype FROM ir_attachment
          WHERE res_model = 'recon.batch' AND res_id = $1 ORDER BY created_at DESC LIMIT 1",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;
    let store_fname: String = att.try_get("store_fname").ok().flatten().unwrap_or_default();
    if store_fname.is_empty() {
        return None;
    }
    let mime: String = att.try_get("mimetype").ok().flatten().unwrap_or_else(|| "application/pdf".into());
    let bytes = state.files.get(db_name, &store_fname).await.ok().flatten()?;
    let supplier_no: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT supplier_no FROM recon_batch WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten()
            .flatten();
    let hints = load_extract_hints(db, supplier_no.as_deref()).await;
    Some(crate::ai::BatchDoc { custom_id: id.to_string(), bytes, mime, hints })
}

/// Submit queued invoices (or a given set) to the Anthropic Message Batches
/// API. Returns (batch row id, submitted count). Anthropic-only.
async fn submit_queued_batch(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    db_name: &str,
    actor: Option<Uuid>,
    ids: Option<Vec<Uuid>>,
) -> Result<(Uuid, usize), String> {
    let cfg = load_ai_config(db)
        .await
        .map_err(|e| format!("Config error: {e}"))?
        .ok_or_else(|| "AI extraction is not configured — set a provider in AI Extraction.".to_string())?;
    if cfg.provider != "anthropic" {
        return Err("Batch extraction needs the active provider to be Anthropic (Claude). Switch the active profile in AI Extraction, or use Extract now.".into());
    }
    if cfg.api_key.trim().is_empty() {
        return Err("The active Anthropic profile has no API key.".into());
    }

    let candidate_ids: Vec<Uuid> = match ids {
        Some(v) => v,
        None => vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT id FROM recon_batch WHERE ai_extract_state = 'queued' AND active ORDER BY created_at LIMIT 200",
        )
        .fetch_all(db)
        .await
        .map_err(|e| format!("Query failed: {e}"))?,
    };
    if candidate_ids.is_empty() {
        return Err("Nothing is queued for extraction.".into());
    }
    // Cap one batch at 100 documents to keep the request size sane (Anthropic
    // allows far more, but base64 scans are large). The rest stay queued.
    let capped = candidate_ids.len() > 100;
    let use_ids: Vec<Uuid> = candidate_ids.into_iter().take(100).collect();

    let mut docs = Vec::new();
    let mut doc_ids = Vec::new();
    for id in &use_ids {
        if let Some(d) = load_batch_doc(state, db, db_name, *id).await {
            docs.push(d);
            doc_ids.push(*id);
        }
    }
    if docs.is_empty() {
        return Err("Queued invoices have no readable scans.".into());
    }

    let provider_batch_id = crate::ai::submit_batch(&cfg, &docs).await?;

    let batch_uuid: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO recon_ai_batch (provider_batch_id, provider, model, status, total, created_by)
         VALUES ($1,$2,$3,'submitted',$4,$5) RETURNING id",
    )
    .bind(&provider_batch_id)
    .bind(&cfg.provider)
    .bind(&cfg.model)
    .bind(docs.len() as i32)
    .bind(actor)
    .fetch_one(db)
    .await
    .map_err(|e| format!("Save failed: {e}"))?;

    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE recon_batch SET ai_batch_id = $1, ai_extract_state = 'processing' WHERE id = ANY($2)",
    )
    .bind(batch_uuid)
    .bind(&doc_ids)
    .execute(db)
    .await;

    if capped {
        vortex_plugin_sdk::tracing::info!(db = %db_name, "recon batch capped at 100; remaining stay queued");
    }
    let mut entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_database(db_name)
        .with_resource("recon_ai_batch", batch_uuid.to_string())
        .with_details(json!({
            "action": "submit_batch",
            "provider_batch_id": provider_batch_id,
            "count": docs.len() as i64,
        }));
    if let Some(uid) = actor {
        entry = entry.with_user(UserId(uid));
    }
    let _ = state.audit.log(entry).await;

    Ok((batch_uuid, docs.len()))
}

/// Poll open batches for one tenant; persist results of any that finished, then
/// (if enabled) auto-submit the current queue. Best-effort throughout.
async fn complete_batches(state: &AppState, db: &vortex_plugin_sdk::sqlx::PgPool, db_name: &str) {
    // Polling needs the Anthropic key — use the active profile.
    let cfg = match load_ai_config(db).await {
        Ok(Some(c)) if c.provider == "anthropic" && !c.api_key.trim().is_empty() => c,
        _ => return,
    };
    let open: Vec<(Uuid, String)> = match vortex_plugin_sdk::sqlx::query(
        "SELECT id, provider_batch_id FROM recon_ai_batch WHERE status = 'submitted'",
    )
    .fetch_all(db)
    .await
    {
        Ok(rows) => rows
            .iter()
            .filter_map(|r| {
                let id: Uuid = r.get("id");
                let pid: Option<String> = r.try_get("provider_batch_id").ok().flatten();
                pid.map(|p| (id, p))
            })
            .collect(),
        Err(_) => return,
    };

    for (batch_uuid, provider_batch_id) in open {
        let status = match crate::ai::poll_batch(&cfg, &provider_batch_id).await {
            Ok(s) => s,
            Err(e) => {
                vortex_plugin_sdk::tracing::warn!(db = %db_name, "recon batch poll failed: {e}");
                continue;
            }
        };
        if !status.ended {
            continue;
        }
        let Some(url) = status.results_url.clone() else { continue };
        let results = match crate::ai::fetch_batch_results(&cfg, &url).await {
            Ok(r) => r,
            Err(e) => {
                vortex_plugin_sdk::tracing::warn!(db = %db_name, "recon batch results failed: {e}");
                continue;
            }
        };
        let (mut ok, mut err) = (0i32, 0i32);
        for res in results {
            let Ok(id) = res.custom_id.parse::<Uuid>() else { continue };
            // Skip if the invoice no longer belongs to THIS batch (e.g. an
            // "Extract now" claimed it in the meantime) — prevents double
            // extraction / double cost.
            let owned: bool = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM recon_batch WHERE id=$1 AND ai_batch_id=$2)",
            )
            .bind(id)
            .bind(batch_uuid)
            .fetch_one(db)
            .await
            .unwrap_or(false);
            if !owned {
                continue;
            }
            let persisted = match res.outcome {
                Ok((ex, usage)) => {
                    // Batch results → discounted batch pricing (batch = true).
                    persist_extraction(state, db, db_name, id, &ex, usage, &cfg.provider, &cfg.model, None, true)
                        .await
                        .is_ok()
                }
                Err(_) => false,
            };
            let new_state = if persisted { "done" } else { "error" };
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE recon_batch SET ai_extract_state = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(new_state)
            .execute(db)
            .await;
            if persisted { ok += 1 } else { err += 1 }
        }
        let _ = vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_ai_batch SET status='ended', succeeded=$2, errored=$3, ended_at=NOW() WHERE id=$1",
        )
        .bind(batch_uuid)
        .bind(ok)
        .bind(err)
        .execute(db)
        .await;
    }

    // Optional scheduled auto-submit of whatever is queued now.
    let auto: bool = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT batch_auto FROM recon_ai_config WHERE active ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
    .unwrap_or(false);
    if auto {
        let queued: i64 = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT COUNT(*) FROM recon_batch WHERE ai_extract_state = 'queued' AND active",
        )
        .fetch_one(db)
        .await
        .unwrap_or(0);
        if queued > 0 {
            match submit_queued_batch(state, db, db_name, None, None).await {
                Ok((_, n)) => vortex_plugin_sdk::tracing::info!(db = %db_name, count = n, "recon auto-submitted batch"),
                Err(e) => vortex_plugin_sdk::tracing::warn!(db = %db_name, "recon auto-submit failed: {e}"),
            }
        }
    }
}

/// Scheduled entrypoint: complete/auto-submit batches across all tenants.
pub async fn poll_batches_all_tenants(state: &AppState) {
    let mut dbs: Vec<String> = match &state.master_db {
        Some(master) => vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT name FROM managed_databases WHERE state = 'active' ORDER BY name",
        )
        .fetch_all(master)
        .await
        .unwrap_or_default(),
        None => Vec::new(),
    };
    for d in state.pool_manager.list_databases().await {
        if !dbs.contains(&d) {
            dbs.push(d);
        }
    }
    if !dbs.contains(&state.default_db) {
        dbs.push(state.default_db.clone());
    }
    for db_name in dbs {
        let Ok(cp) = state.pool_manager.get_pool(&db_name).await else { continue };
        // Skip DBs without the batch table.
        let has: bool = vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM information_schema.tables WHERE table_name='recon_ai_batch')",
        )
        .fetch_one(cp.pool())
        .await
        .unwrap_or(false);
        if !has {
            continue;
        }
        complete_batches(state, cp.pool(), &db_name).await;
    }
}

pub async fn poll_all_tenants(state: &AppState) {
    // Registry of provisioned tenants (when a master DB exists) UNION the
    // currently-pooled DBs (covers deployments without a master registry, e.g.
    // a single tenant served directly), plus the default DB. Deduped.
    let mut dbs: Vec<String> = match &state.master_db {
        Some(master) => vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT name FROM managed_databases WHERE state = 'active' ORDER BY name",
        )
        .fetch_all(master)
        .await
        .unwrap_or_default(),
        None => Vec::new(),
    };
    for d in state.pool_manager.list_databases().await {
        if !dbs.contains(&d) {
            dbs.push(d);
        }
    }
    if !dbs.contains(&state.default_db) {
        dbs.push(state.default_db.clone());
    }

    for db_name in dbs {
        let Ok(cp) = state.pool_manager.get_pool(&db_name).await else { continue };
        // Sources due to run (skip whole DB if the table isn't there).
        let due: Vec<Uuid> = match vortex_plugin_sdk::sqlx::query_scalar(
            "SELECT id FROM recon_ingest_source
              WHERE active AND (last_run_at IS NULL
                 OR last_run_at < NOW() - make_interval(mins => poll_interval_min))",
        )
        .fetch_all(cp.pool())
        .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        for id in due {
            let (ok, n, msg) = run_ingest(state, &cp, &db_name, id, None, "schedule").await;
            if !ok {
                vortex_plugin_sdk::tracing::warn!(db = %db_name, "recon ingest poll failed: {msg}");
            } else if n > 0 {
                vortex_plugin_sdk::tracing::info!(db = %db_name, count = n, "recon ingest picked up files");
            }
        }
    }
}

/// GET /recon/ingest — list configured sources with their last poll outcome.
async fn ingest_list(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, protocol, host, remote_dir, active, poll_interval_min,
                last_status, last_run_at, last_message, last_count
           FROM recon_ingest_source ORDER BY created_at",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let body: String = if rows.is_empty() {
        r##"<tr><td colspan="6" class="text-center opacity-60 py-6">No sources yet. Add one to auto-pick-up invoices from an SFTP/FTP folder.</td></tr>"##.to_string()
    } else {
        rows.iter().map(|r| {
            let id: Uuid = r.get("id");
            let name: String = r.try_get("name").unwrap_or_default();
            let proto: String = r.try_get("protocol").unwrap_or_default();
            let host: String = r.try_get("host").unwrap_or_default();
            let dir: String = r.try_get("remote_dir").unwrap_or_default();
            let active: bool = r.try_get("active").unwrap_or(false);
            let poll: i32 = r.try_get("poll_interval_min").unwrap_or(0);
            let status: Option<String> = r.try_get("last_status").ok().flatten();
            let msg: Option<String> = r.try_get("last_message").ok().flatten();
            let badge = match status.as_deref() {
                Some("ok") => "<span class=\"badge badge-success badge-sm\">ok</span>",
                Some("error") => "<span class=\"badge badge-error badge-sm\">error</span>",
                Some("running") => "<span class=\"badge badge-warning badge-sm\">running</span>",
                _ => "<span class=\"badge badge-ghost badge-sm\">—</span>",
            };
            format!(
                r##"<tr>
  <td><a href="/recon/ingest/{id}" class="link link-hover font-medium">{name}</a>
      {inactive}</td>
  <td><code>{proto}</code> {host}<span class="opacity-50">{dir}</span></td>
  <td>every {poll}m</td>
  <td>{badge}<div class="text-xs opacity-60">{msg}</div></td>
  <td class="text-right">
    <form method="post" action="/recon/ingest/{id}/fetch" class="inline"><button class="btn btn-xs btn-primary">Fetch now</button></form>
    <a href="/recon/ingest/{id}" class="btn btn-xs btn-ghost">Edit</a>
    <form method="post" action="/recon/ingest/{id}/delete" class="inline" onsubmit="return confirm('Delete this source?')"><button class="btn btn-xs btn-ghost text-error">Delete</button></form>
  </td>
</tr>"##,
                id = id, name = esc(&name), proto = esc(&proto), host = esc(&host),
                dir = esc(&dir), poll = poll, badge = badge,
                msg = esc(msg.as_deref().unwrap_or("")),
                inactive = if active { "" } else { " <span class=\"badge badge-ghost badge-xs\">disabled</span>" },
            )
        }).collect()
    };

    let content = format!(
        r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<div class="flex justify-between items-center mb-1">
  <h1 class="text-2xl font-bold">Auto-Pickup Sources</h1>
  <a href="/recon/ingest/new" class="btn btn-sm btn-primary">+ Add source</a>
</div>
<p class="opacity-60 text-sm mb-6">Poll an SFTP / FTP / FTPS folder for new invoice PDFs; each is imported as a draft and the remote file is moved to a processed subfolder.</p>
<div class="card bg-base-100 shadow"><div class="card-body p-0">
  <table class="table">
    <thead><tr><th>Name</th><th>Connection</th><th>Poll</th><th>Last run</th><th></th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</div></div>"##,
        body = body,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Auto-Pickup Sources", &content)).into_response()
}

/// Shared source form (create + edit). `id` empty = create.
fn render_ingest_form(
    id: &str,
    v: &std::collections::HashMap<&str, String>,
    key_hint: Option<&str>,
) -> String {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let g = |k: &str| esc(v.get(k).map(|s| s.as_str()).unwrap_or(""));
    let proto = v.get("protocol").map(|s| s.as_str()).unwrap_or("sftp");
    let opt = |val: &str, label: &str| {
        format!(r##"<option value="{val}"{s}>{label}</option>"##,
            val = val, label = label, s = if proto == val { " selected" } else { "" })
    };
    let sel = |k: &str, checked_default: bool| {
        let on = v.get(k).map(|s| s == "1").unwrap_or(checked_default);
        if on { "checked" } else { "" }
    };
    let key_state = match key_hint {
        Some(h) => format!(r##"<span class="badge badge-success badge-sm">secret set (…{})</span> — blank keeps it"##, esc(h)),
        None => r##"<span class="badge badge-ghost badge-sm">no secret set</span>"##.to_string(),
    };
    format!(
        r##"<div class="mb-4"><a href="/recon/ingest" class="link link-hover text-sm">← Auto-Pickup Sources</a></div>
<h1 class="text-2xl font-bold mb-6">{title}</h1>
<form method="post" action="/recon/ingest" class="card bg-base-100 shadow max-w-2xl"><div class="card-body flex flex-col gap-3">
  <input type="hidden" name="id" value="{id}"/>
  <div><label class="label"><span class="label-text">Name</span></label>
    <input name="name" value="{name}" class="input input-bordered w-full" placeholder="Vendor drop"/></div>
  <div class="grid grid-cols-3 gap-3">
    <div><label class="label"><span class="label-text">Protocol</span></label>
      <select name="protocol" class="select select-bordered w-full">{o_sftp}{o_ftp}{o_ftps}</select></div>
    <div class="col-span-2"><label class="label"><span class="label-text">Host</span></label>
      <input name="host" value="{host}" class="input input-bordered w-full" placeholder="sftp.vendor.com"/></div>
  </div>
  <div class="grid grid-cols-3 gap-3">
    <div><label class="label"><span class="label-text">Port</span></label>
      <input name="port" value="{port}" class="input input-bordered w-full" placeholder="22"/></div>
    <div class="col-span-2"><label class="label"><span class="label-text">Username</span></label>
      <input name="username" value="{username}" class="input input-bordered w-full"/></div>
  </div>
  <div><label class="label"><span class="label-text">Password</span></label>
    <input name="password" type="password" autocomplete="off" class="input input-bordered w-full font-mono" placeholder="paste to set / update"/>
    <p class="text-xs opacity-60 mt-1">{key_state}</p></div>
  <div><label class="label"><span class="label-text">SFTP private key (PEM, optional — used instead of password)</span></label>
    <textarea name="private_key" rows="3" class="textarea textarea-bordered w-full font-mono text-xs" placeholder="-----BEGIN OPENSSH PRIVATE KEY----- … (blank keeps existing)"></textarea></div>
  <div class="grid grid-cols-2 gap-3">
    <div><label class="label"><span class="label-text">Remote folder</span></label>
      <input name="remote_dir" value="{remote_dir}" class="input input-bordered w-full font-mono" placeholder="/inbox"/></div>
    <div><label class="label"><span class="label-text">Processed folder <span class="opacity-50">(blank = &lt;folder&gt;/processed)</span></span></label>
      <input name="processed_dir" value="{processed_dir}" class="input input-bordered w-full font-mono" placeholder="/inbox/processed"/></div>
  </div>
  <div class="grid grid-cols-2 gap-3">
    <div><label class="label"><span class="label-text">File pattern</span></label>
      <input name="file_pattern" value="{file_pattern}" class="input input-bordered w-full font-mono" placeholder="*.pdf"/></div>
    <div><label class="label"><span class="label-text">Poll every (minutes)</span></label>
      <input name="poll_interval_min" value="{poll}" class="input input-bordered w-full" placeholder="15"/></div>
  </div>
  <label class="label cursor-pointer justify-start gap-3">
    <input type="checkbox" name="active" value="1" class="checkbox checkbox-sm" {active}/>
    <span class="label-text">Enabled (include in the scheduled poll)</span></label>
  <div class="alert alert-warning text-sm"><span>⚠ Credentials are stored encrypted. The connection reaches an external server — use a least-privilege account.</span></div>
  <div class="flex gap-2"><button type="submit" class="btn btn-primary">Save</button>
    <a href="/recon/ingest" class="btn btn-ghost">Cancel</a></div>
</div></form>"##,
        title = if id.is_empty() { "Add source" } else { "Edit source" },
        id = esc(id),
        name = g("name"), host = g("host"), port = g("port"), username = g("username"),
        remote_dir = g("remote_dir"), processed_dir = g("processed_dir"),
        file_pattern = g("file_pattern"), poll = g("poll_interval_min"),
        o_sftp = opt("sftp", "SFTP (SSH)"), o_ftp = opt("ftp", "FTP"), o_ftps = opt("ftps", "FTPS (FTP+TLS)"),
        key_state = key_state, active = sel("active", true),
    )
}

/// GET /recon/ingest/new
async fn ingest_new_form(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let mut v = std::collections::HashMap::new();
    v.insert("protocol", "sftp".to_string());
    v.insert("port", "22".to_string());
    v.insert("remote_dir", "/".to_string());
    v.insert("file_pattern", "*.pdf".to_string());
    v.insert("poll_interval_min", "15".to_string());
    v.insert("active", "1".to_string());
    let content = render_ingest_form("", &v, None);
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Add source", &content)).into_response()
}

/// GET /recon/ingest/{id}
async fn ingest_edit_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT name, protocol, host, port, username, remote_dir, processed_dir,
                file_pattern, poll_interval_min, active, key_hint
           FROM recon_ingest_source WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(r) = row else { return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let mut v = std::collections::HashMap::new();
    v.insert("name", r.try_get::<String, _>("name").unwrap_or_default());
    v.insert("protocol", r.try_get::<String, _>("protocol").unwrap_or_else(|_| "sftp".into()));
    v.insert("host", r.try_get::<String, _>("host").unwrap_or_default());
    v.insert("port", r.try_get::<i32, _>("port").unwrap_or(22).to_string());
    v.insert("username", r.try_get::<Option<String>, _>("username").ok().flatten().unwrap_or_default());
    v.insert("remote_dir", r.try_get::<String, _>("remote_dir").unwrap_or_default());
    v.insert("processed_dir", r.try_get::<Option<String>, _>("processed_dir").ok().flatten().unwrap_or_default());
    v.insert("file_pattern", r.try_get::<String, _>("file_pattern").unwrap_or_default());
    v.insert("poll_interval_min", r.try_get::<i32, _>("poll_interval_min").unwrap_or(15).to_string());
    v.insert("active", if r.try_get::<bool, _>("active").unwrap_or(true) { "1" } else { "0" }.to_string());
    let key_hint: Option<String> = r.try_get("key_hint").ok().flatten();
    let content = render_ingest_form(&id.to_string(), &v, key_hint.as_deref());
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Edit source", &content)).into_response()
}

/// POST /recon/ingest — create or update a source (encrypted secrets).
async fn ingest_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let id = get("id").filter(|s| !s.is_empty()).and_then(|s| Uuid::parse_str(&s).ok());
    let protocol = get("protocol").unwrap_or_else(|| "sftp".into());
    let name = get("name").filter(|s| !s.is_empty()).unwrap_or_else(|| "Vendor drop".into());
    let host = get("host").unwrap_or_default();
    let port: i32 = get("port").and_then(|s| s.parse().ok()).unwrap_or(if protocol == "sftp" { 22 } else { 21 });
    let username = get("username");
    let remote_dir = get("remote_dir").filter(|s| !s.is_empty()).unwrap_or_else(|| "/".into());
    let processed_dir = get("processed_dir").filter(|s| !s.is_empty());
    let file_pattern = get("file_pattern").filter(|s| !s.is_empty()).unwrap_or_else(|| "*.pdf".into());
    let poll: i32 = get("poll_interval_min").and_then(|s| s.parse().ok()).unwrap_or(15).max(1);
    let active = pairs.iter().any(|(n, v)| n == "active" && v == "1");
    let password = get("password").filter(|s| !s.is_empty());
    let private_key = get("private_key").filter(|s| !s.is_empty());

    let key = vortex_plugin_sdk::security::crypto::master_key();
    let enc = |s: &str| vortex_plugin_sdk::security::crypto::encrypt_str(s, &key).ok();
    let pw_enc = password.as_deref().and_then(enc);
    let pk_enc = private_key.as_deref().and_then(enc);
    let hint = private_key.as_deref().or(password.as_deref()).map(|s| {
        s.chars().rev().take(4).collect::<Vec<_>>().into_iter().rev().collect::<String>()
    });

    let res = if let Some(id) = id {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE recon_ingest_source SET name=$2, protocol=$3, host=$4, port=$5, username=$6,
                    remote_dir=$7, processed_dir=$8, file_pattern=$9, poll_interval_min=$10, active=$11,
                    password_enc=COALESCE($12, password_enc),
                    private_key_enc=COALESCE($13, private_key_enc),
                    key_hint=COALESCE($14, key_hint), updated_by=$15, updated_at=NOW()
              WHERE id=$1",
        )
        .bind(id).bind(&name).bind(&protocol).bind(&host).bind(port).bind(&username)
        .bind(&remote_dir).bind(&processed_dir).bind(&file_pattern).bind(poll).bind(active)
        .bind(&pw_enc).bind(&pk_enc).bind(&hint).bind(user.id).execute(&db).await
    } else {
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_ingest_source
                (name, protocol, host, port, username, remote_dir, processed_dir, file_pattern,
                 poll_interval_min, active, password_enc, private_key_enc, key_hint, updated_by)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
        )
        .bind(&name).bind(&protocol).bind(&host).bind(port).bind(&username).bind(&remote_dir)
        .bind(&processed_dir).bind(&file_pattern).bind(poll).bind(active)
        .bind(&pw_enc).bind(&pk_enc).bind(&hint).bind(user.id).execute(&db).await
    };
    if let Err(e) = res {
        error!("ingest source save failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("recon_ingest_source", id.map(|i| i.to_string()).unwrap_or_else(|| "new".into()))
        .with_details(json!({"protocol": protocol, "host": host, "secret_updated": pw_enc.is_some() || pk_enc.is_some()}));
    let _ = state.audit.log(entry).await;
    Redirect::to("/recon/ingest").into_response()
}

/// POST /recon/ingest/{id}/fetch — pull now (inline; the person waits).
async fn ingest_fetch_now(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let _ = run_ingest(&state, &db_ctx.pool, &db_ctx.db_name, id, Some((user.id, &user.username)), "manual").await;
    let _ = &db;
    Redirect::to("/recon/ingest").into_response()
}

/// POST /recon/ingest/{id}/delete
async fn ingest_delete(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM recon_ingest_source WHERE id=$1")
        .bind(id)
        .execute(&db)
        .await;
    let entry = AuditEntry::new(AuditAction::ConfigChanged, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("recon_ingest_source", id.to_string())
        .with_details(json!({"deleted": true}));
    let _ = state.audit.log(entry).await;
    Redirect::to("/recon/ingest").into_response()
}

/// GET /recon/verify — the QA worklist: every uploaded invoice with its
/// captured-vs-M3 status, so staff can sweep a whole batch at a glance.
async fn verify_worklist(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT b.id, b.code, b.invoice_no, b.supplier_name, b.supplier_no,
                b.currency, b.doc_total::float8 AS pdf,
                (SELECT SUM(m.line_total)::float8 FROM recon_m3_line m
                   WHERE b.invoice_no IS NOT NULL
                     AND regexp_replace(upper(COALESCE(m.invoice_no,'')), '[-/].*$', '')
                       = regexp_replace(upper(b.invoice_no), '[-/].*$', '')) AS m3
           FROM recon_batch b
          WHERE b.active
          ORDER BY b.created_at DESC
          LIMIT 500",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let (mut n_ok, mut n_bad, mut n_nom3, mut n_nocap) = (0i64, 0i64, 0i64, 0i64);
    let body: String = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let code: Option<String> = r.try_get("code").ok().flatten();
            let inv: Option<String> = r.try_get("invoice_no").ok().flatten();
            let sup: Option<String> = r.try_get("supplier_name").ok().flatten();
            let sup_no: Option<String> = r.try_get("supplier_no").ok().flatten();
            let cur: Option<String> = r.try_get("currency").ok().flatten();
            let pdf: Option<f64> = r.try_get("pdf").ok().flatten();
            let m3: Option<f64> = r.try_get("m3").ok().flatten();
            let cur = cur.unwrap_or_default();

            let (badge, detail) = if pdf.is_none() {
                n_nocap += 1;
                ("<span class=\"badge badge-ghost badge-sm\">Not captured</span>".to_string(),
                 "invoice total not extracted yet".to_string())
            } else if m3.is_none() {
                n_nom3 += 1;
                ("<span class=\"badge badge-error badge-outline badge-sm\">No M3 entry</span>".to_string(),
                 "not found in M3".to_string())
            } else {
                let (p, m) = (pdf.unwrap_or(0.0), m3.unwrap_or(0.0));
                let diff = ((p - m) * 100.0).round() / 100.0;
                if diff.abs() <= 0.005 {
                    n_ok += 1;
                    ("<span class=\"badge badge-success badge-sm\">✓ Captured</span>".to_string(), String::new())
                } else {
                    n_bad += 1;
                    (format!("<span class=\"badge badge-error badge-sm\">⚠ {diff:+.2}</span>"),
                     format!("invoice {p:.2} vs M3 {m:.2}"))
                }
            };
            format!(
                r##"<tr>
  <td><a href="/recon/{id}" class="link link-hover font-mono text-sm">{code}</a></td>
  <td>{inv}</td>
  <td>{sup}</td>
  <td class="text-right font-mono">{pdf}</td>
  <td class="text-right font-mono">{m3}</td>
  <td>{badge}<div class="text-xs opacity-60">{detail}</div></td>
</tr>"##,
                id = id,
                code = esc(code.as_deref().unwrap_or("—")),
                inv = esc(inv.as_deref().unwrap_or("—")),
                sup = esc(sup.as_deref().or(sup_no.as_deref()).unwrap_or("—")),
                pdf = pdf.map(|v| format!("{cur} {v:.2}")).unwrap_or_else(|| "—".into()),
                m3 = m3.map(|v| format!("{cur} {v:.2}")).unwrap_or_else(|| "—".into()),
                badge = badge, detail = esc(&detail),
            )
        })
        .collect();

    let content = format!(
        r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<h1 class="text-2xl font-bold mb-1">Verification Worklist</h1>
<p class="opacity-60 text-sm mb-4">Every uploaded invoice checked against what was keyed into M3. Click any row to review or correct.</p>
<div class="flex gap-2 flex-wrap mb-4">
  <div class="badge badge-success badge-lg">✓ {ok} captured</div>
  <div class="badge badge-error badge-lg">⚠ {bad} discrepancy</div>
  <div class="badge badge-error badge-outline badge-lg">{nom3} no M3</div>
  <div class="badge badge-ghost badge-lg">{nocap} not captured</div>
</div>
<div class="card bg-base-100 shadow"><div class="card-body p-0">
  <table class="table">
    <thead><tr><th>Ref</th><th>Invoice No</th><th>Supplier</th>
      <th class="text-right">Invoice total</th><th class="text-right">M3 total</th><th>Status</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</div></div>"##,
        ok = n_ok, bad = n_bad, nom3 = n_nom3, nocap = n_nocap, body = body,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Verification Worklist", &content)).into_response()
}

/// POST /recon/{id}/map — remember that this invoice's item code is the same
/// item as an M3 SKU. Saves a `vendor_item_alias` so the next upload from this
/// supplier auto-matches. Form: `supplier_sku` (invoice code) + `lseo_sku` (M3 code).
async fn save_item_alias(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let supplier_sku = get("supplier_sku").filter(|s| !s.is_empty());
    let lseo_sku = get("lseo_sku").filter(|s| !s.is_empty());
    let (Some(supplier_sku), Some(lseo_sku)) = (supplier_sku, lseo_sku) else {
        return (StatusCode::BAD_REQUEST, "Pick an M3 item to map to").into_response();
    };

    // Supplier is taken from the batch so the alias is scoped to this vendor.
    let supplier_no: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT supplier_no FROM recon_batch WHERE id=$1")
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
            .flatten();
    let supplier_no = supplier_no.filter(|s| !s.trim().is_empty()).unwrap_or_else(|| "*".into());

    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO vendor_item_alias (id, supplier_no, supplier_sku, lseo_sku, active)
         VALUES (gen_random_uuid(), $1, $2, $3, true)
         ON CONFLICT (supplier_no, supplier_sku)
         DO UPDATE SET lseo_sku = EXCLUDED.lseo_sku, active = true",
    )
    .bind(&supplier_no)
    .bind(&supplier_sku)
    .bind(&lseo_sku)
    .execute(&db)
    .await;
    if let Err(e) = res {
        error!("save item alias failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Map failed").into_response();
    }
    audit_item(
        &state,
        &user,
        &db_ctx,
        id,
        AuditAction::RecordUpdated,
        json!({"item_alias": {"supplier": supplier_no, "supplier_sku": supplier_sku, "lseo_sku": lseo_sku}}),
    )
    .await;
    Redirect::to(&format!("/recon/{id}")).into_response()
}

// ── GL double-entry generation ───────────────────────────────────────────────

struct GlLine {
    account: String,
    account_name: String,
    detail: String,
    debit: f64,
    credit: f64,
    // Grouping / mapping key for a goods line: the vendor's printed item code
    // when the invoice has one, else the description (many vendors print
    // description-only invoices — without the fallback every line would collapse
    // into a single goods row).
    item_key: Option<String>,
    key_is_sku: bool,          // false = the key above is a description
    lseo_sku: Option<String>,  // matched LSEO SKU (via vendor_item_alias)
    unmapped: bool,            // goods resolved via the default account
}

/// Build the balanced double-entry for a batch: Dr goods (per product's mapped
/// GL account, SST-inclusive), Dr price-variance for any rounding residual, and
/// Cr the AP account for the invoice total. Empty until the invoice has a total.
async fn build_gl_entry(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    batch_id: Uuid,
    supplier_no: &str,
    doc_total: Option<f64>,
) -> Vec<GlLine> {
    let Some(total) = doc_total else { return Vec::new() };
    let total = round2(total);

    let cfg = vortex_plugin_sdk::sqlx::query(
        "SELECT default_goods_code, default_ap_code, default_variance_code
           FROM recon_gl_config ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();
    let get = |k: &str| cfg.as_ref().and_then(|r| r.try_get::<Option<String>, _>(k).ok().flatten()).unwrap_or_default();
    let goods_default = get("default_goods_code");
    let ap_default = get("default_ap_code");
    let var_default = get("default_variance_code");

    // Mapping rules.
    let maps = vortex_plugin_sdk::sqlx::query(
        "SELECT match_type, match_value, gl_code FROM recon_gl_map WHERE active",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut sku_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut desc_map: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let mut prefix_map: Vec<(String, String)> = Vec::new();
    let mut supplier_ap: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for m in &maps {
        let (t, v, c): (String, String, String) = (
            m.try_get("match_type").unwrap_or_default(),
            m.try_get("match_value").unwrap_or_default(),
            m.try_get("gl_code").unwrap_or_default(),
        );
        match t.as_str() {
            "sku" => { sku_map.insert(v, c); }
            "desc" => { desc_map.insert(v, c); }
            "prefix" => prefix_map.push((v, c)),
            "supplier_ap" => { supplier_ap.insert(v, c); }
            _ => {}
        }
    }

    // Account names.
    let accts = vortex_plugin_sdk::sqlx::query("SELECT code, name FROM recon_gl_account")
        .fetch_all(db)
        .await
        .unwrap_or_default();
    let mut name_of: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    for a in &accts {
        if let (Ok(c), Ok(n)) = (a.try_get::<String, _>("code"), a.try_get::<String, _>("name")) {
            name_of.insert(c, n);
        }
    }
    let nm = |code: &str| name_of.get(code).cloned().unwrap_or_default();

    // Vendor item code → LSEO SKU (self-learning alias). Match this supplier's
    // aliases plus wildcard ('*') ones (used when the batch has no supplier code).
    let sup = if supplier_no.trim().is_empty() { "*" } else { supplier_no };
    let mut sku_alias: std::collections::HashMap<String, String> = std::collections::HashMap::new();
    let al = vortex_plugin_sdk::sqlx::query(
        "SELECT supplier_sku, lseo_sku FROM vendor_item_alias WHERE (supplier_no = $1 OR supplier_no = '*') AND active",
    )
    .bind(sup)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    for r in &al {
        if let (Ok(k), Ok(v)) = (r.try_get::<String, _>("supplier_sku"), r.try_get::<String, _>("lseo_sku")) {
            sku_alias.insert(k, v);
        }
    }

    // Invoice products (SST-inclusive amount), one group per distinct item.
    // Key on the printed item code; vendors that print none fall back to the
    // description so each item still gets its own GL line.
    let prods = vortex_plugin_sdk::sqlx::query(
        "SELECT left(COALESCE(NULLIF(btrim(supplier_sku), ''), btrim(description), ''), 200) AS code,
                (NULLIF(btrim(supplier_sku), '') IS NOT NULL) AS is_sku,
                MAX(description) AS desc,
                SUM(line_total)::float8 AS amt
           FROM recon_inv_line WHERE batch_id = $1
          GROUP BY 1, 2
          ORDER BY SUM(line_total) DESC NULLS LAST",
    )
    .bind(batch_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();

    let mut lines: Vec<GlLine> = Vec::new();
    let mut goods_sum = 0.0;
    for p in &prods {
        let code: String = p.try_get("code").unwrap_or_default();
        let is_sku: bool = p.try_get("is_sku").unwrap_or(false);
        let desc: Option<String> = p.try_get("desc").ok().flatten();
        let amt = round2(p.try_get::<Option<f64>, _>("amt").ok().flatten().unwrap_or(0.0));
        // Resolve: exact key (SKU rule, or description rule) → longest prefix → default.
        let exact = if is_sku { sku_map.get(&code) } else { desc_map.get(&code) };
        let (gl, unmapped) = if code.is_empty() {
            (goods_default.clone(), true)
        } else if let Some(c) = exact {
            (c.clone(), false)
        } else if let Some((_, c)) =
            prefix_map.iter().filter(|(pfx, _)| code.starts_with(pfx.as_str())).max_by_key(|(pfx, _)| pfx.len())
        {
            (c.clone(), false)
        } else {
            (goods_default.clone(), true)
        };
        goods_sum += amt;
        lines.push(GlLine {
            account: gl.clone(),
            account_name: nm(&gl),
            detail: desc.unwrap_or_default(),
            debit: amt,
            credit: 0.0,
            item_key: (!code.is_empty()).then(|| code.clone()),
            key_is_sku: is_sku,
            lseo_sku: sku_alias.get(&code).cloned(),
            unmapped,
        });
    }

    // Rounding / price-variance residual so the entry balances to the invoice total.
    let residual = round2(total - round2(goods_sum));
    if residual.abs() > 0.005 {
        lines.push(GlLine {
            account: var_default.clone(),
            account_name: nm(&var_default),
            detail: "Price variance / rounding".into(),
            lseo_sku: None,
            debit: if residual > 0.0 { residual } else { 0.0 },
            credit: if residual < 0.0 { -residual } else { 0.0 },
            item_key: None,
            key_is_sku: false,
            unmapped: false,
        });
    }

    // Cr the AP account (supplier override, else default) for the invoice total.
    let ap = supplier_ap.get(supplier_no).cloned().filter(|s| !s.is_empty()).unwrap_or(ap_default);
    lines.push(GlLine {
        account: ap.clone(),
        account_name: nm(&ap),
        detail: "Trade creditors (AP)".into(),
        lseo_sku: None,
        debit: 0.0,
        credit: total,
        item_key: None,
        key_is_sku: false,
        unmapped: false,
    });
    lines
}

/// GET /recon/gl — GL configuration: defaults, accounts, mapping rules.
async fn gl_config_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let cfg = vortex_plugin_sdk::sqlx::query(
        "SELECT default_goods_code, default_ap_code, default_variance_code, default_sst_code
           FROM recon_gl_config ORDER BY updated_at DESC LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let d = |k: &str| cfg.as_ref().and_then(|r| r.try_get::<Option<String>, _>(k).ok().flatten()).unwrap_or_default();

    let accts = vortex_plugin_sdk::sqlx::query("SELECT code, name, kind FROM recon_gl_account WHERE active ORDER BY code")
        .fetch_all(&db).await.unwrap_or_default();
    let acct_opts: String = accts.iter().map(|a| {
        let c: String = a.try_get("code").unwrap_or_default();
        let n: String = a.try_get("name").unwrap_or_default();
        format!(r##"<option value="{c}">{c} — {n}</option>"##, c = esc(&c), n = esc(&n))
    }).collect();
    let acct_rows: String = accts.iter().map(|a| {
        let c: String = a.try_get("code").unwrap_or_default();
        let n: String = a.try_get("name").unwrap_or_default();
        let k: Option<String> = a.try_get("kind").ok().flatten();
        format!("<tr><td><code>{c}</code></td><td>{n}</td><td class=\"opacity-60\">{k}</td></tr>",
            c = esc(&c), n = esc(&n), k = esc(k.as_deref().unwrap_or("")))
    }).collect();

    let skus = vortex_plugin_sdk::sqlx::query("SELECT sku, COALESCE(description,'') AS d FROM recon_sku_master WHERE active ORDER BY sku LIMIT 500")
        .fetch_all(&db).await.unwrap_or_default();
    let sku_rows: String = skus.iter().map(|s| {
        let c: String = s.try_get("sku").unwrap_or_default();
        let d: String = s.try_get("d").unwrap_or_default();
        format!("<tr><td><code>{c}</code></td><td>{d}</td></tr>", c = esc(&c), d = esc(&d))
    }).collect();

    let rules = vortex_plugin_sdk::sqlx::query(
        "SELECT id, match_type, match_value, gl_code FROM recon_gl_map WHERE active ORDER BY match_type, match_value",
    ).fetch_all(&db).await.unwrap_or_default();
    let rule_rows: String = rules.iter().map(|r| {
        let rid: Uuid = r.get("id");
        let t: String = r.try_get("match_type").unwrap_or_default();
        let v: String = r.try_get("match_value").unwrap_or_default();
        let g: String = r.try_get("gl_code").unwrap_or_default();
        let tl = match t.as_str() { "sku" => "SKU", "desc" => "Description", "prefix" => "Prefix", "supplier_ap" => "Supplier AP", _ => &t };
        format!(r##"<tr><td>{tl}</td><td><code>{v}</code></td><td><code>{g}</code></td>
  <td class="text-right"><form method="post" action="/recon/gl/rule/{rid}/delete" class="inline"><button class="btn btn-xs btn-ghost text-error">Delete</button></form></td></tr>"##,
            tl = tl, v = esc(&v), g = esc(&g), rid = rid)
    }).collect();

    let content = format!(
        r##"<div class="mb-4"><a href="/recon" class="link link-hover text-sm">← Reconciliation</a></div>
<h1 class="text-2xl font-bold mb-1">GL Mapping</h1>
<p class="opacity-60 text-sm mb-6">How invoices become an M3 double-entry: which account each product posts to, and the default AP / variance accounts.</p>

<div class="card bg-base-100 shadow mb-6 max-w-2xl"><div class="card-body">
  <h2 class="card-title text-base">Default accounts</h2>
  <form method="post" action="/recon/gl/defaults" class="grid grid-cols-2 gap-3">
    <label class="flex flex-col gap-1"><span class="text-xs opacity-60">Goods (Dr, fallback)</span>
      <input name="default_goods_code" value="{gd}" class="input input-bordered input-sm font-mono"/></label>
    <label class="flex flex-col gap-1"><span class="text-xs opacity-60">Trade Creditors / AP (Cr)</span>
      <input name="default_ap_code" value="{ap}" class="input input-bordered input-sm font-mono"/></label>
    <label class="flex flex-col gap-1"><span class="text-xs opacity-60">Price variance / rounding</span>
      <input name="default_variance_code" value="{vr}" class="input input-bordered input-sm font-mono"/></label>
    <label class="flex flex-col gap-1"><span class="text-xs opacity-60">SST input tax (optional)</span>
      <input name="default_sst_code" value="{sst}" class="input input-bordered input-sm font-mono"/></label>
    <div class="col-span-2"><button class="btn btn-sm btn-primary">Save defaults</button></div>
  </form>
</div></div>

<div class="grid lg:grid-cols-2 gap-6">
  <div class="card bg-base-100 shadow"><div class="card-body">
    <h2 class="card-title text-base">Accounts</h2>
    <form method="post" action="/recon/gl/account" class="flex gap-2 flex-wrap items-end mb-2">
      <input name="code" placeholder="Code" class="input input-bordered input-sm font-mono w-28"/>
      <input name="name" placeholder="Name" class="input input-bordered input-sm flex-1"/>
      <input name="kind" placeholder="kind" class="input input-bordered input-sm w-24"/>
      <button class="btn btn-sm btn-primary">Add</button>
    </form>
    <div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Kind</th></tr></thead><tbody>{acct_rows}</tbody></table></div>
  </div></div>

  <div class="card bg-base-100 shadow"><div class="card-body">
    <h2 class="card-title text-base">SKU master <span class="font-normal opacity-50 text-sm">LSEO item codes</span></h2>
    <form method="post" action="/recon/gl/sku" class="flex gap-2 flex-wrap items-end mb-2">
      <input name="sku" placeholder="SKU" class="input input-bordered input-sm font-mono w-40"/>
      <input name="description" placeholder="Description" class="input input-bordered input-sm flex-1"/>
      <button class="btn btn-sm btn-primary">Add</button>
    </form>
    <div class="overflow-x-auto" style="max-height:16rem"><table class="table table-sm"><thead><tr><th>SKU</th><th>Description</th></tr></thead><tbody>{sku_rows}</tbody></table></div>
  </div></div>

  <div class="card bg-base-100 shadow"><div class="card-body">
    <h2 class="card-title text-base">Mapping rules</h2>
    <form method="post" action="/recon/gl/rule" class="flex gap-2 flex-wrap items-end mb-2">
      <select name="match_type" class="select select-bordered select-sm">
        <option value="sku">SKU (exact)</option><option value="desc">Description (exact)</option><option value="prefix">Prefix</option><option value="supplier_ap">Supplier AP</option>
      </select>
      <input name="match_value" placeholder="item code / description / prefix / supplier" class="input input-bordered input-sm flex-1"/>
      <select name="gl_code" class="select select-bordered select-sm"><option value="">account…</option>{acct_opts}</select>
      <button class="btn btn-sm btn-primary">Add</button>
    </form>
    <div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Type</th><th>Value</th><th>Account</th><th></th></tr></thead><tbody>{rule_rows}</tbody></table></div>
  </div></div>
</div>"##,
        gd = esc(&d("default_goods_code")), ap = esc(&d("default_ap_code")),
        vr = esc(&d("default_variance_code")), sst = esc(&d("default_sst_code")),
        acct_rows = acct_rows, acct_opts = acct_opts, rule_rows = rule_rows, sku_rows = sku_rows,
    );
    let _ = &state; let _ = &db_ctx;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "GL Mapping", &content)).into_response()
}

async fn gl_save_defaults(Db(db): Db, Extension(user): Extension<AuthUser>, Form(pairs): Form<Vec<(String, String)>>) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string()).filter(|s| !s.is_empty());
    let existing: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM recon_gl_config ORDER BY updated_at DESC LIMIT 1").fetch_optional(&db).await.ok().flatten();
    let (g, a, v, s) = (get("default_goods_code"), get("default_ap_code"), get("default_variance_code"), get("default_sst_code"));
    let res = if let Some(id) = existing {
        vortex_plugin_sdk::sqlx::query("UPDATE recon_gl_config SET default_goods_code=$2, default_ap_code=$3, default_variance_code=$4, default_sst_code=$5, updated_by=$6, updated_at=NOW() WHERE id=$1")
            .bind(id).bind(&g).bind(&a).bind(&v).bind(&s).bind(user.id).execute(&db).await
    } else {
        vortex_plugin_sdk::sqlx::query("INSERT INTO recon_gl_config (default_goods_code, default_ap_code, default_variance_code, default_sst_code, updated_by) VALUES ($1,$2,$3,$4,$5)")
            .bind(&g).bind(&a).bind(&v).bind(&s).bind(user.id).execute(&db).await
    };
    if res.is_err() { return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response(); }
    Redirect::to("/recon/gl").into_response()
}

async fn gl_add_account(Db(db): Db, Form(pairs): Form<Vec<(String, String)>>) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let code = get("code").filter(|s| !s.is_empty());
    let name = get("name").filter(|s| !s.is_empty());
    if let (Some(c), Some(n)) = (code, name) {
        let _ = vortex_plugin_sdk::sqlx::query("INSERT INTO recon_gl_account (code, name, kind) VALUES ($1,$2,$3) ON CONFLICT (code) DO UPDATE SET name=EXCLUDED.name, kind=EXCLUDED.kind")
            .bind(&c).bind(&n).bind(get("kind").filter(|s| !s.is_empty())).execute(&db).await;
    }
    Redirect::to("/recon/gl").into_response()
}

async fn gl_add_rule(Db(db): Db, Extension(user): Extension<AuthUser>, Form(pairs): Form<Vec<(String, String)>>) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let (t, v, g) = (get("match_type"), get("match_value").filter(|s| !s.is_empty()), get("gl_code").filter(|s| !s.is_empty()));
    if let (Some(t), Some(v), Some(g)) = (t, v, g) {
        let _ = vortex_plugin_sdk::sqlx::query("INSERT INTO recon_gl_map (id, match_type, match_value, gl_code, active, updated_by) VALUES (gen_random_uuid(),$1,$2,$3,true,$4) ON CONFLICT (match_type, match_value) DO UPDATE SET gl_code=EXCLUDED.gl_code, active=true")
            .bind(&t).bind(&v).bind(&g).bind(user.id).execute(&db).await;
    }
    Redirect::to("/recon/gl").into_response()
}

async fn gl_delete_rule(Db(db): Db, Path(rid): Path<Uuid>) -> Response {
    let _ = vortex_plugin_sdk::sqlx::query("DELETE FROM recon_gl_map WHERE id=$1").bind(rid).execute(&db).await;
    Redirect::to("/recon/gl").into_response()
}

async fn gl_add_sku(Db(db): Db, Form(pairs): Form<Vec<(String, String)>>) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    if let Some(sku) = get("sku").filter(|s| !s.is_empty()) {
        let _ = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO recon_sku_master (sku, description) VALUES ($1,$2) ON CONFLICT (sku) DO UPDATE SET description=EXCLUDED.description, active=true",
        )
        .bind(&sku).bind(get("description").filter(|s| !s.is_empty())).execute(&db).await;
    }
    Redirect::to("/recon/gl").into_response()
}

/// POST /recon/{id}/glmap — remember which GL account an invoice item posts to.
async fn save_gl_map(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().find(|(n, _)| n == k).map(|(_, v)| v.trim().to_string());
    let sku = get("supplier_sku").filter(|s| !s.is_empty());
    let gl = get("gl_code").filter(|s| !s.is_empty());
    let (Some(sku), Some(gl)) = (sku, gl) else {
        return (StatusCode::BAD_REQUEST, "Pick a GL account").into_response();
    };
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO recon_gl_map (id, match_type, match_value, gl_code, active, updated_by)
         VALUES (gen_random_uuid(), 'sku', $1, $2, true, $3)
         ON CONFLICT (match_type, match_value)
         DO UPDATE SET gl_code = EXCLUDED.gl_code, active = true, updated_by = EXCLUDED.updated_by, updated_at = NOW()",
    )
    .bind(&sku)
    .bind(&gl)
    .bind(user.id)
    .execute(&db)
    .await;
    if let Err(e) = res {
        error!("save gl map failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Map failed").into_response();
    }
    audit_item(&state, &user, &db_ctx, id, AuditAction::RecordUpdated,
        json!({"gl_map": {"sku": sku, "gl_code": gl}})).await;
    Redirect::to(&format!("/recon/{id}")).into_response()
}

/// POST /recon/{id}/glmap-bulk — save many item→GL mappings in one submit. The
/// form emits parallel `sku` / `gl_code` fields (order preserved), so we pair
/// each SKU with the account chosen right after it.
async fn save_gl_map_bulk(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    // Supplier scopes the vendor-code → LSEO-SKU alias.
    let supplier_no: String = vortex_plugin_sdk::sqlx::query_scalar("SELECT supplier_no FROM recon_batch WHERE id=$1")
        .bind(id).fetch_optional(&db).await.ok().flatten().flatten()
        .filter(|s: &String| !s.trim().is_empty()).unwrap_or_else(|| "*".into());

    let mut tx = match db.begin().await {
        Ok(t) => t,
        Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response(),
    };
    // Each goods line emits, in order: vendor + keykind (hidden), lseo_sku, gl_code.
    // keykind says whether `vendor` is the printed item code or the description
    // fallback, which selects the recon_gl_map rule type written below.
    let mut cur_vendor: Option<String> = None;
    let mut cur_kind = String::from("sku");
    let mut saved = 0u32;
    for (n, v) in &pairs {
        match n.as_str() {
            "vendor" => cur_vendor = Some(v.trim().to_string()),
            "keykind" => cur_kind = if v.trim() == "desc" { "desc".into() } else { "sku".into() },
            "lseo_sku" => {
                if let (Some(vendor), ls) = (cur_vendor.as_ref(), v.trim()) {
                    if !vendor.is_empty() && !ls.is_empty() {
                        let _ = vortex_plugin_sdk::sqlx::query(
                            "INSERT INTO vendor_item_alias (id, supplier_no, supplier_sku, lseo_sku, active)
                             VALUES (gen_random_uuid(), $1, $2, $3, true)
                             ON CONFLICT (supplier_no, supplier_sku)
                             DO UPDATE SET lseo_sku = EXCLUDED.lseo_sku, active = true",
                        )
                        .bind(&supplier_no).bind(vendor).bind(ls).execute(&mut *tx).await;
                    }
                }
            }
            "gl_code" => {
                if let Some(vendor) = cur_vendor.take() {
                    let gl = v.trim();
                    if !vendor.is_empty() && !gl.is_empty() {
                        if vortex_plugin_sdk::sqlx::query(
                            "INSERT INTO recon_gl_map (id, match_type, match_value, gl_code, active, updated_by)
                             VALUES (gen_random_uuid(), $4, $1, $2, true, $3)
                             ON CONFLICT (match_type, match_value)
                             DO UPDATE SET gl_code = EXCLUDED.gl_code, active = true, updated_at = NOW()",
                        )
                        .bind(&vendor).bind(gl).bind(user.id).bind(&cur_kind).execute(&mut *tx).await.is_ok()
                        {
                            saved += 1;
                        }
                    }
                }
            }
            _ => {}
        }
    }
    if tx.commit().await.is_err() {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    audit_item(&state, &user, &db_ctx, id, AuditAction::RecordUpdated,
        json!({"gl_map_bulk": saved})).await;
    Redirect::to(&format!("/recon/{id}")).into_response()
}

/// GET /recon/{id}/gl.csv — the balanced double-entry as a CSV voucher for M3.
async fn gl_csv(Db(db): Db, Path(id): Path<Uuid>) -> Response {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT code, invoice_no, supplier_no, doc_total::float8 AS pdf FROM recon_batch WHERE id=$1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(r) = row else { return (StatusCode::NOT_FOUND, "Not found").into_response() };
    let code: String = r.try_get("code").ok().flatten().unwrap_or_default();
    let inv: String = r.try_get("invoice_no").ok().flatten().unwrap_or_default();
    let supplier: String = r.try_get("supplier_no").ok().flatten().unwrap_or_default();
    let pdf: Option<f64> = r.try_get("pdf").ok().flatten();
    let lines = build_gl_entry(&db, id, &supplier, pdf).await;

    let esc_csv = |s: &str| {
        if s.contains([',', '"', '\n']) { format!("\"{}\"", s.replace('"', "\"\"")) } else { s.to_string() }
    };
    let mut out = String::from("Invoice,Supplier,SKU,Account,Account Name,Detail,Debit,Credit\n");
    for l in &lines {
        // Prefer the matched LSEO SKU; fall back to the vendor's printed code.
        // A description-derived key is NOT a SKU — leave the column blank there.
        let sku = l.lseo_sku.as_deref().filter(|s| !s.is_empty())
            .or_else(|| l.key_is_sku.then(|| l.item_key.as_deref()).flatten())
            .unwrap_or("");
        out.push_str(&format!(
            "{},{},{},{},{},{},{},{}\n",
            esc_csv(&inv), esc_csv(&supplier), esc_csv(sku), esc_csv(&l.account), esc_csv(&l.account_name),
            esc_csv(&l.detail),
            if l.debit != 0.0 { format!("{:.2}", l.debit) } else { String::new() },
            if l.credit != 0.0 { format!("{:.2}", l.credit) } else { String::new() },
        ));
    }
    let fname = format!("gl_{}.csv", if inv.is_empty() { code } else { inv });
    (
        [
            (vortex_plugin_sdk::axum::http::header::CONTENT_TYPE, "text/csv".to_string()),
            (vortex_plugin_sdk::axum::http::header::CONTENT_DISPOSITION, format!("attachment; filename=\"{fname}\"")),
            // The voucher content changes as mappings are edited — never serve a
            // stale cached download.
            (vortex_plugin_sdk::axum::http::header::CACHE_CONTROL, "no-store".to_string()),
        ],
        out,
    )
        .into_response()
}

async fn audit_item(
    state: &AppState,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    id: Uuid,
    action: AuditAction,
    details: vortex_plugin_sdk::serde_json::Value,
) {
    let entry = AuditEntry::new(action, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("recon_batch", id.to_string())
        .with_details(details);
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}

/// GET /p/recon — anonymous public board: aggregate counts only,
/// no record detail. The tenant comes from the request Host.
async fn public_board(Db(db): Db, Extension(db_ctx): Extension<DatabaseContext>) -> Response {
    let (total, done): (i64, i64) = vortex_plugin_sdk::sqlx::query_as(
        "SELECT COUNT(*), COUNT(*) FILTER (WHERE record_state = 'approved')
         FROM recon_batch WHERE active",
    )
    .fetch_one(&db)
    .await
    .unwrap_or((0, 0));

    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    Html(format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head><title>Reconciliation — Public Board</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/tailwind.css?v=21" rel="stylesheet"/>
<link href="/static/vortex.css?v=18" rel="stylesheet"/>
<script src="/static/vortex.js?v=18" defer></script>
</head><body class="min-h-screen bg-base-200 flex items-center justify-center">
<div class="card bg-base-100 shadow-xl"><div class="card-body text-center">
<h1 class="text-2xl font-bold">Reconciliation</h1>
<p class="opacity-60 text-sm">Public status board — {tenant}</p>
<div class="stats mt-4"><div class="stat"><div class="stat-title">Items</div>
<div class="stat-value">{total}</div></div>
<div class="stat"><div class="stat-title">Done</div>
<div class="stat-value text-success">{done}</div></div></div>
</div></div></body></html>"##,
        tenant = esc(&db_ctx.db_name), total = total, done = done,
    ))
    .into_response()
}
