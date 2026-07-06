//! Accounting handlers — chart of accounts, journals, and journal entries.
//! Posting and reversal go through [`crate::service`], the same API adopting
//! modules use, so the UI can never do something an integration cannot.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::service;

pub fn accounting_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting", get(list_moves))
        .route("/accounting/moves/new", get(new_move_form))
        .route("/accounting/moves/create", post(create_move))
        .route("/accounting/moves/{id}", get(move_detail))
        .route("/accounting/moves/{id}", post(update_move))
        .route("/accounting/moves/{id}/lines", post(add_line))
        .route("/accounting/moves/{id}/lines/{line_id}/delete", post(delete_line))
        .route("/accounting/moves/{id}/post", post(post_move))
        .route("/accounting/moves/{id}/reverse", post(reverse_move))
        .route("/accounting/moves/{id}/cancel", post(cancel_move))
        .route("/accounting/accounts", get(list_accounts))
        .route("/accounting/accounts/new", get(new_account_form))
        .route("/accounting/accounts/create", post(create_account))
        .route("/accounting/accounts/{id}", get(edit_account))
        .route("/accounting/accounts/{id}", post(update_account))
        .route("/accounting/journals", get(list_journals))
        .route("/accounting/journals/{id}", get(edit_journal))
        .route("/accounting/journals/{id}", post(update_journal))
}

// ─────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────

pub(crate) fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=7" rel="stylesheet"/>
<script src="/static/vortex.js?v=7" defer></script>
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

pub(crate) fn render_sidebar(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    vortex_plugin_sdk::framework::build_sidebar(
        "accounting",
        display_name,
        &initials,
        &db_ctx.installed_modules,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
    )
}

pub(crate) async fn default_company(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

pub(crate) fn opt_str<'a>(form: &'a HashMap<String, String>, key: &str) -> Option<&'a str> {
    form.get(key).map(|s| s.trim()).filter(|s| !s.is_empty())
}

pub(crate) fn dec_or_zero(form: &HashMap<String, String>, key: &str) -> Decimal {
    form.get(key)
        .and_then(|s| s.trim().parse::<Decimal>().ok())
        .unwrap_or(Decimal::ZERO)
}

pub(crate) fn date_or_today(form: &HashMap<String, String>, key: &str) -> vortex_plugin_sdk::chrono::NaiveDate {
    form.get(key)
        .and_then(|s| s.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok())
        .unwrap_or_else(|| vortex_plugin_sdk::chrono::Utc::now().date_naive())
}

pub(crate) fn money(d: Decimal) -> String {
    d.round_dp(2).to_string()
}

fn state_badge(state: &str) -> &'static str {
    match state {
        "draft" => r#"<span class="badge badge-ghost">Draft</span>"#,
        "posted" => r#"<span class="badge badge-success">Posted</span>"#,
        "cancelled" => r#"<span class="badge badge-error">Cancelled</span>"#,
        _ => r#"<span class="badge">?</span>"#,
    }
}

const ACCOUNT_TYPES: &[(&str, &str)] = &[
    ("asset_cash", "Cash"),
    ("asset_bank", "Bank"),
    ("asset_receivable", "Receivable"),
    ("asset_current", "Current Asset"),
    ("asset_fixed", "Fixed Asset"),
    ("asset_non_current", "Non-current Asset"),
    ("liability_payable", "Payable"),
    ("liability_current", "Current Liability"),
    ("liability_non_current", "Non-current Liability"),
    ("equity", "Equity"),
    ("income", "Income"),
    ("income_other", "Other Income"),
    ("expense", "Expense"),
    ("expense_depreciation", "Depreciation"),
    ("expense_direct_cost", "Cost of Revenue"),
];

fn account_type_label(t: &str) -> &'static str {
    ACCOUNT_TYPES
        .iter()
        .find(|(k, _)| *k == t)
        .map(|(_, l)| *l)
        .unwrap_or("?")
}

fn account_type_options(selected: Option<&str>) -> String {
    let mut out = String::new();
    for (value, label) in ACCOUNT_TYPES {
        let sel = if Some(*value) == selected { " selected" } else { "" };
        out.push_str(&format!(r#"<option value="{value}"{sel}>{label}</option>"#));
    }
    out
}

/// `<option>` list of active accounts (`code — name`).
async fn account_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM acc_account WHERE active ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">— account —</option>"#);
    for row in rows {
        let id: Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let sel = if Some(id) == selected { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{code} — {name}</option>"#,
            id = id,
            sel = sel,
            code = esc(&code),
            name = esc(&name)
        ));
    }
    out
}

async fn journal_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM acc_journal WHERE active ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let sel = if Some(id) == selected { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{code} — {name}</option>"#,
            id = id,
            sel = sel,
            code = esc(&code),
            name = esc(&name)
        ));
    }
    out
}

/// `<option>` list of active contacts, for the optional line partner.
async fn partner_options(db: &vortex_plugin_sdk::sqlx::PgPool, selected: Option<Uuid>) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name FROM contacts WHERE active ORDER BY name LIMIT 500",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">— partner —</option>"#);
    for row in rows {
        let id: Uuid = row.get("id");
        let name: String = row.get("name");
        let sel = if Some(id) == selected { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{name}</option>"#,
            id = id,
            sel = sel,
            name = esc(&name)
        ));
    }
    out
}

pub(crate) async fn audit_move(
    state: &AppState,
    db_ctx: &DatabaseContext,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user_id: Uuid,
    username: &str,
    id: Uuid,
    action: &str,
) {
    let number: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT number FROM acc_move WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user_id))
    .with_username(username)
    .with_database(&db_ctx.db_name)
    .with_resource("acc_move", id.to_string())
    .with_resource_name(number.as_deref().unwrap_or("draft"))
    .with_details(json!({ "action": action }));
    let _ = state.audit.log(entry).await;
}

/// Like [`audit_move`], but with a field-level diff the history panel
/// renders as from→to rows. Every document mutation goes through this.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn audit_move_changes(
    state: &AppState,
    db_ctx: &DatabaseContext,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user_id: Uuid,
    username: &str,
    id: Uuid,
    action: &str,
    changes: Vec<vortex_plugin_sdk::serde_json::Value>,
) {
    let number: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT number FROM acc_move WHERE id = $1")
            .bind(id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user_id))
    .with_username(username)
    .with_database(&db_ctx.db_name)
    .with_resource("acc_move", id.to_string())
    .with_resource_name(number.as_deref().unwrap_or("draft"))
    .with_details(json!({ "action": action, "changes": changes }));
    let _ = state.audit.log(entry).await;
}

pub(crate) fn redirect(to: &str) -> Response {
    vortex_plugin_sdk::axum::response::Redirect::to(to).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Journal entries — list
// ─────────────────────────────────────────────────────────────────────────

async fn list_moves(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let config = ListConfig::new("Journal Entries", "acc_move")
        .custom_from(
            "acc_move m JOIN acc_journal j ON j.id = m.journal_id \
             LEFT JOIN contacts p ON p.id = m.partner_id",
        )
        .custom_select(
            "m.id, COALESCE(m.number, '/') AS number, j.code AS journal_code, \
             m.move_date::text AS move_date, COALESCE(m.ref, '') AS ref, \
             COALESCE(p.name, '') AS partner_name, m.move_type, m.state, \
             m.total_amount::text AS total_amount",
        )
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("m.number"))
        .column(
            ListColumn::new("journal_code", "Journal")
                .sortable()
                .filterable(&[
                    ("SAL", "Sales"),
                    ("PUR", "Purchases"),
                    ("BNK", "Bank"),
                    ("CSH", "Cash"),
                    ("GEN", "Miscellaneous"),
                ])
                .sql_expr("j.code"),
        )
        .column(ListColumn::new("move_date", "Date").sortable().sql_expr("m.move_date"))
        .column(ListColumn::new("ref", "Reference").searchable().sql_expr("m.ref"))
        .column(ListColumn::new("partner_name", "Partner").searchable().sql_expr("p.name"))
        .column(ListColumn::new("total_amount", "Total").sortable().sql_expr("m.total_amount"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[
                    ("draft", "Draft"),
                    ("posted", "Posted"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("draft", "Draft", "badge-ghost"),
                    ("posted", "Posted", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("m.state"),
        )
        .detail_url("/accounting/moves/{id}")
        .create("New Journal Entry", "/accounting/moves/new")
        .default_sort("move_date")
        .group_by_options(&[("journal_code", "Journal"), ("state", "Status")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "journal entries list query failed");
            return Html("<h1>Failed to load journal entries</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/accounting");
    Html(page_shell(&sidebar, "Journal Entries", &list_html)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Journal entries — create draft
// ─────────────────────────────────────────────────────────────────────────

async fn new_move_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let journals = journal_options(&db, None).await;

    let content = format!(
        r#"<div class="max-w-xl">
<a href="/accounting" class="btn btn-ghost btn-sm mb-4">← Back to Journal Entries</a>
<h1 class="text-2xl font-bold mb-6">New Journal Entry</h1>
<form method="POST" action="/accounting/moves/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Journal *</span></label>
<select name="journal_id" class="select select-bordered select-sm" required>{journals}</select>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Date</span></label>
<input name="move_date" type="date" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Reference</span></label>
<input name="ref" class="input input-bordered input-sm" placeholder="e.g. WO/000042"/>
</div>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Narration</span></label>
<textarea name="narration" class="textarea textarea-bordered textarea-sm" rows="2"></textarea>
</div>
<button type="submit" class="btn btn-primary btn-sm">Create Draft</button>
</div></div>
</form>
<p class="text-sm opacity-60 mt-4">Lines are added on the entry page; the entry can be posted once debits equal credits.</p>
</div>"#,
        journals = journals,
    );
    Html(page_shell(&sidebar, "New Journal Entry", &content)).into_response()
}

async fn create_move(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let Some(journal_id) = form.get("journal_id").and_then(|s| s.parse::<Uuid>().ok()) else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
            "Journal is required",
        )
            .into_response();
    };
    let move_date = date_or_today(&form, "move_date");
    let company_id = default_company(&db).await;

    let created: Result<Uuid, vortex_plugin_sdk::sqlx::Error> =
        vortex_plugin_sdk::sqlx::query_scalar(
            "INSERT INTO acc_move \
                (journal_id, move_date, ref, narration, move_type, company_id, created_by, updated_by) \
             VALUES ($1, $2, $3, $4, 'entry', $5, $6, $6) RETURNING id",
        )
        .bind(journal_id)
        .bind(move_date)
        .bind(opt_str(&form, "ref"))
        .bind(opt_str(&form, "narration"))
        .bind(company_id)
        .bind(user.id)
        .fetch_one(&db)
        .await;

    match created {
        Ok(id) => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "created").await;
            redirect(&format!("/accounting/moves/{id}"))
        }
        Err(e) => {
            error!(error = %e, "journal entry creation failed");
            (
                vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to create journal entry",
            )
                .into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Journal entries — detail
// ─────────────────────────────────────────────────────────────────────────

async fn move_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT m.number, m.move_date::text AS move_date, m.ref, m.narration, m.state, \
                m.move_type, m.payment_state, m.reversed_move_id, m.origin_ref, \
                j.code AS journal_code, j.name AS journal_name, \
                p.name AS partner_name \
         FROM acc_move m \
         JOIN acc_journal j ON j.id = m.journal_id \
         LEFT JOIN contacts p ON p.id = m.partner_id \
         WHERE m.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND,
            "Journal entry not found",
        )
            .into_response();
    };

    let number: Option<String> = head.get("number");
    let number = number.unwrap_or_else(|| "/".to_string());
    let move_date: String = head.get("move_date");
    let ref_: Option<String> = head.get("ref");
    let narration: Option<String> = head.get("narration");
    let move_state: String = head.get("state");
    let journal_code: String = head.get("journal_code");
    let journal_name: String = head.get("journal_name");
    let partner_name: Option<String> = head.get("partner_name");
    let payment_state: String = head.get("payment_state");
    let reversed_move_id: Option<Uuid> = head.get("reversed_move_id");
    let origin_ref: Option<String> = head.get("origin_ref");
    let is_draft = move_state == "draft";

    // Lines + totals
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.name, l.debit, l.credit, a.code AS account_code, \
                a.name AS account_name, p.name AS partner_name \
         FROM acc_move_line l \
         JOIN acc_account a ON a.id = l.account_id \
         LEFT JOIN contacts p ON p.id = l.partner_id \
         WHERE l.move_id = $1 ORDER BY l.sequence, l.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut debit_total = Decimal::ZERO;
    let mut credit_total = Decimal::ZERO;
    let mut lines_html = String::new();
    for row in &line_rows {
        let line_id: Uuid = row.get("id");
        let account_code: String = row.get("account_code");
        let account_name: String = row.get("account_name");
        let label: Option<String> = row.get("name");
        let line_partner: Option<String> = row.get("partner_name");
        let debit: Decimal = row.get("debit");
        let credit: Decimal = row.get("credit");
        debit_total += debit;
        credit_total += credit;
        let delete_btn = if is_draft {
            format!(
                r#"<form method="POST" action="/accounting/moves/{id}/lines/{line_id}/delete" style="display:inline">
<button class="btn btn-ghost btn-xs text-error" onclick="return confirm('Remove this line?')">✕</button></form>"#
            )
        } else {
            String::new()
        };
        lines_html.push_str(&format!(
            r#"<tr>
<td class="font-mono text-xs">{code}</td>
<td>{account}</td>
<td>{label}</td>
<td>{partner}</td>
<td class="text-right font-mono">{debit}</td>
<td class="text-right font-mono">{credit}</td>
<td>{delete_btn}</td>
</tr>"#,
            code = esc(&account_code),
            account = esc(&account_name),
            label = esc(label.as_deref().unwrap_or("")),
            partner = esc(line_partner.as_deref().unwrap_or("")),
            debit = if debit.is_zero() { String::new() } else { money(debit) },
            credit = if credit.is_zero() { String::new() } else { money(credit) },
            delete_btn = delete_btn,
        ));
    }

    let diff = (debit_total - credit_total).round_dp(2);
    let balance_banner = if is_draft {
        if line_rows.len() >= 2 && diff.is_zero() && !debit_total.is_zero() {
            r#"<div class="alert alert-success py-2 my-3 text-sm">Balanced — ready to post.</div>"#
                .to_string()
        } else {
            format!(
                r#"<div class="alert alert-warning py-2 my-3 text-sm">Not postable yet — debits {d}, credits {c} (difference {diff}).</div>"#,
                d = money(debit_total),
                c = money(credit_total),
                diff = money(diff),
            )
        }
    } else {
        String::new()
    };

    // Add-line form (drafts only)
    let add_line_form = if is_draft {
        let accounts = account_options(&db, None).await;
        let partners = partner_options(&db, None).await;
        format!(
            r#"<div class="card bg-base-100 shadow mt-4"><div class="card-body py-4">
<h3 class="font-semibold mb-2">Add Line</h3>
<form method="POST" action="/accounting/moves/{id}/lines" class="grid grid-cols-12 gap-2 items-end">
<div class="form-control col-span-4">
<label class="label py-0"><span class="label-text-alt">Account *</span></label>
<select name="account_id" class="select select-bordered select-sm" required>{accounts}</select>
</div>
<div class="form-control col-span-2">
<label class="label py-0"><span class="label-text-alt">Label</span></label>
<input name="name" class="input input-bordered input-sm"/>
</div>
<div class="form-control col-span-2">
<label class="label py-0"><span class="label-text-alt">Partner</span></label>
<select name="partner_id" class="select select-bordered select-sm">{partners}</select>
</div>
<div class="form-control col-span-1">
<label class="label py-0"><span class="label-text-alt">Debit</span></label>
<input name="debit" type="number" step="0.01" min="0" class="input input-bordered input-sm"/>
</div>
<div class="form-control col-span-1">
<label class="label py-0"><span class="label-text-alt">Credit</span></label>
<input name="credit" type="number" step="0.01" min="0" class="input input-bordered input-sm"/>
</div>
<div class="col-span-2">
<button class="btn btn-primary btn-sm w-full">Add</button>
</div>
</form>
</div></div>"#
        )
    } else {
        String::new()
    };

    // Action buttons
    let mut actions = String::new();
    if is_draft {
        actions.push_str(&format!(
            r#"<form method="POST" action="/accounting/moves/{id}/post" style="display:inline">
<button class="btn btn-success btn-sm">Post</button></form>
<form method="POST" action="/accounting/moves/{id}/cancel" style="display:inline" class="ml-2">
<button class="btn btn-ghost btn-sm" onclick="return confirm('Cancel this draft entry?')">Cancel</button></form>"#
        ));
    } else if move_state == "posted" && payment_state != "reversed" {
        actions.push_str(&format!(
            r#"<form method="POST" action="/accounting/moves/{id}/reverse" style="display:inline">
<button class="btn btn-warning btn-sm" onclick="return confirm('Post a reversal of this entry?')">Reverse</button></form>"#
        ));
    }

    let reversal_note = match reversed_move_id {
        Some(rev) => format!(
            r#"<div class="alert alert-info py-2 my-3 text-sm">This entry reverses <a class="link" href="/accounting/moves/{rev}">another entry</a>.</div>"#
        ),
        None if payment_state == "reversed" => {
            r#"<div class="alert alert-info py-2 my-3 text-sm">This entry has been reversed.</div>"#
                .to_string()
        }
        None => String::new(),
    };

    // Draft header edit
    let header_block = if is_draft {
        format!(
            r#"<form method="POST" action="/accounting/moves/{id}" class="grid grid-cols-3 gap-3 items-end">
<div class="form-control">
<label class="label py-0"><span class="label-text-alt">Date</span></label>
<input name="move_date" type="date" value="{date}" class="input input-bordered input-sm"/>
</div>
<div class="form-control">
<label class="label py-0"><span class="label-text-alt">Reference</span></label>
<input name="ref" value="{ref_}" class="input input-bordered input-sm"/>
</div>
<div><button class="btn btn-outline btn-sm">Save Header</button></div>
<div class="form-control col-span-3">
<label class="label py-0"><span class="label-text-alt">Narration</span></label>
<textarea name="narration" class="textarea textarea-bordered textarea-sm" rows="2">{narration}</textarea>
</div>
</form>"#,
            date = esc(&move_date),
            ref_ = esc(ref_.as_deref().unwrap_or("")),
            narration = esc(narration.as_deref().unwrap_or("")),
        )
    } else {
        format!(
            r#"<div class="grid grid-cols-3 gap-4 text-sm">
<div><span class="opacity-60">Date</span><br/>{date}</div>
<div><span class="opacity-60">Reference</span><br/>{ref_}</div>
<div><span class="opacity-60">Partner</span><br/>{partner}</div>
<div class="col-span-3"><span class="opacity-60">Narration</span><br/>{narration}</div>
</div>"#,
            date = esc(&move_date),
            ref_ = esc(ref_.as_deref().unwrap_or("—")),
            partner = esc(partner_name.as_deref().unwrap_or("—")),
            narration = esc(narration.as_deref().unwrap_or("—")),
        )
    };

    let origin_block = origin_ref
        .map(|o| {
            format!(
                r#"<div class="text-xs opacity-60 mt-2">Origin: <span class="font-mono">{}</span></div>"#,
                esc(&o)
            )
        })
        .unwrap_or_default();

    let history_panel = vortex_plugin_sdk::framework::render_audit_trail(&db, "acc_move", id).await;

    let content = format!(
        r#"<div class="max-w-5xl">
<a href="/accounting" class="btn btn-ghost btn-sm mb-4">← Back to Journal Entries</a>
<div class="flex items-center justify-between mb-4">
<h1 class="text-2xl font-bold">{number} <span class="text-base opacity-60 font-normal">{journal_code} · {journal_name}</span> {badge}</h1>
<div>{actions}</div>
</div>
{reversal_note}
<div class="card bg-base-100 shadow"><div class="card-body py-4">
{header_block}
{origin_block}
</div></div>
{balance_banner}
<div class="card bg-base-100 shadow mt-4"><div class="card-body py-4">
<h3 class="font-semibold mb-2">Lines</h3>
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Code</th><th>Account</th><th>Label</th><th>Partner</th><th class="text-right">Debit</th><th class="text-right">Credit</th><th></th></tr></thead>
<tbody>{lines}</tbody>
<tfoot><tr class="font-bold"><td colspan="4">Totals</td>
<td class="text-right font-mono">{debit_total}</td>
<td class="text-right font-mono">{credit_total}</td><td></td></tr></tfoot>
</table></div>
</div></div>
{add_line_form}
<div class="mt-6">{history}</div>
</div>"#,
        number = esc(&number),
        journal_code = esc(&journal_code),
        journal_name = esc(&journal_name),
        badge = state_badge(&move_state),
        actions = actions,
        reversal_note = reversal_note,
        header_block = header_block,
        origin_block = origin_block,
        balance_banner = balance_banner,
        lines = lines_html,
        debit_total = money(debit_total),
        credit_total = money(credit_total),
        add_line_form = add_line_form,
        history = history_panel,
    );

    Html(page_shell(&sidebar, &format!("Entry {number}"), &content)).into_response()
}

async fn update_move(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let move_date = date_or_today(&form, "move_date");
    let result = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET move_date = $2, ref = $3, narration = $4, updated_by = $5 \
         WHERE id = $1 AND state = 'draft'",
    )
    .bind(id)
    .bind(move_date)
    .bind(opt_str(&form, "ref"))
    .bind(opt_str(&form, "narration"))
    .bind(user.id)
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "journal entry header update failed");
    }
    redirect(&format!("/accounting/moves/{id}"))
}

// ─────────────────────────────────────────────────────────────────────────
// Journal entries — lines
// ─────────────────────────────────────────────────────────────────────────

async fn add_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let Some(account_id) = form.get("account_id").and_then(|s| s.parse::<Uuid>().ok()) else {
        return redirect(&format!("/accounting/moves/{id}"));
    };
    let debit = dec_or_zero(&form, "debit");
    let credit = dec_or_zero(&form, "credit");
    if (debit.is_zero() && credit.is_zero())
        || (!debit.is_zero() && !credit.is_zero())
        || debit.is_sign_negative()
        || credit.is_sign_negative()
    {
        return redirect(&format!("/accounting/moves/{id}"));
    }
    let partner_id = form
        .get("partner_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<Uuid>().ok());
    let company_id = default_company(&db).await;

    // Only draft moves accept lines (the DB trigger also guards this).
    let result = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_move_line \
            (move_id, sequence, account_id, partner_id, name, debit, credit, company_id) \
         SELECT $1, COALESCE(MAX(l.sequence), 0) + 10, $2, $3, $4, $5, $6, $7 \
         FROM acc_move m LEFT JOIN acc_move_line l ON l.move_id = m.id \
         WHERE m.id = $1 AND m.state = 'draft' \
         GROUP BY m.id",
    )
    .bind(id)
    .bind(account_id)
    .bind(partner_id)
    .bind(opt_str(&form, "name"))
    .bind(debit.round_dp(2))
    .bind(credit.round_dp(2))
    .bind(company_id)
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "journal line insert failed");
    }
    redirect(&format!("/accounting/moves/{id}"))
}

async fn delete_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path((id, line_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let result = vortex_plugin_sdk::sqlx::query(
        "DELETE FROM acc_move_line l USING acc_move m \
         WHERE l.id = $1 AND l.move_id = $2 AND m.id = l.move_id AND m.state = 'draft'",
    )
    .bind(line_id)
    .bind(id)
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "journal line delete failed");
    }
    redirect(&format!("/accounting/moves/{id}"))
}

// ─────────────────────────────────────────────────────────────────────────
// Journal entries — lifecycle (through the service API)
// ─────────────────────────────────────────────────────────────────────────

async fn post_move(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match service::post_move(&db, &state.pool, id, user.id).await {
        Ok(number) => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "posted").await;
            vortex_plugin_sdk::tracing::info!(number = %number, "journal entry posted");
            redirect(&format!("/accounting/moves/{id}"))
        }
        Err(e) => (
            vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                r#"<p>Cannot post: {}</p><p><a href="/accounting/moves/{id}">← back to the entry</a></p>"#,
                vortex_plugin_sdk::framework::html_escape(&e.to_string())
            )),
        )
            .into_response(),
    }
}

async fn reverse_move(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    match service::reverse_move(&db, &state.pool, id, today, user.id).await {
        Ok(reversal_id) => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "reversed").await;
            redirect(&format!("/accounting/moves/{reversal_id}"))
        }
        Err(e) => (
            vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                r#"<p>Cannot reverse: {}</p><p><a href="/accounting/moves/{id}">← back to the entry</a></p>"#,
                vortex_plugin_sdk::framework::html_escape(&e.to_string())
            )),
        )
            .into_response(),
    }
}

async fn cancel_move(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let result = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_move SET state = 'cancelled', updated_by = $2 \
         WHERE id = $1 AND state = 'draft'",
    )
    .bind(id)
    .bind(user.id)
    .execute(&db)
    .await;
    match result {
        Ok(r) if r.rows_affected() > 0 => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "cancelled").await;
        }
        Ok(_) => {}
        Err(e) => error!(error = %e, "journal entry cancel failed"),
    }
    redirect(&format!("/accounting/moves/{id}"))
}

// ─────────────────────────────────────────────────────────────────────────
// Chart of accounts
// ─────────────────────────────────────────────────────────────────────────

async fn list_accounts(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };

    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let type_filters: Vec<(&str, &str)> = ACCOUNT_TYPES.to_vec();
    let config = ListConfig::new("Chart of Accounts", "acc_account")
        .custom_select(
            "id, code, name, account_type, \
             CASE WHEN reconcile THEN 'yes' ELSE 'no' END AS reconcile, \
             CASE WHEN active THEN 'yes' ELSE 'no' END AS active",
        )
        .column(ListColumn::new("code", "Code").sortable().code())
        .column(ListColumn::new("name", "Account").sortable().searchable())
        .column(
            ListColumn::new("account_type", "Type")
                .filterable(&type_filters)
                .sortable(),
        )
        .column(ListColumn::new("reconcile", "Reconcilable").bool_badge("Yes", "badge-info", "—", "badge-ghost"))
        .column(ListColumn::new("active", "Active").bool_badge("Active", "badge-success", "Archived", "badge-ghost"))
        .detail_url("/accounting/accounts/{id}")
        .create("New Account", "/accounting/accounts/new")
        .default_sort("code")
        .group_by_options(&[("account_type", "Type")]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "chart of accounts list failed");
            return Html("<h1>Failed to load accounts</h1>").into_response();
        }
    };
    let list_html = render_list(&config, &result, &params, "/accounting/accounts");
    Html(page_shell(&sidebar, "Chart of Accounts", &list_html)).into_response()
}

fn account_form(action: &str, values: Option<(&str, &str, &str, bool, bool)>) -> String {
    let (code, name, account_type, reconcile, active) =
        values.unwrap_or(("", "", "", false, true));
    let esc = vortex_plugin_sdk::framework::html_escape;
    format!(
        r#"<form method="POST" action="{action}">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Code *</span></label>
<input name="code" value="{code}" class="input input-bordered input-sm font-mono" required maxlength="16"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" value="{name}" class="input input-bordered input-sm" required maxlength="160"/>
</div>
</div>
<div class="grid grid-cols-3 gap-3 items-end">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type *</span></label>
<select name="account_type" class="select select-bordered select-sm" required>{type_options}</select>
</div>
<div class="form-control mb-3">
<label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="reconcile" value="1" class="checkbox checkbox-sm"{reconcile_checked}/><span class="label-text">Reconcilable (AR/AP)</span></label>
</div>
<div class="form-control mb-3">
<label class="label cursor-pointer justify-start gap-2"><input type="checkbox" name="active" value="1" class="checkbox checkbox-sm"{active_checked}/><span class="label-text">Active</span></label>
</div>
</div>
<button type="submit" class="btn btn-primary btn-sm">Save</button>
</div></div>
</form>"#,
        action = action,
        code = esc(code),
        name = esc(name),
        type_options = account_type_options(if account_type.is_empty() {
            None
        } else {
            Some(account_type)
        }),
        reconcile_checked = if reconcile { " checked" } else { "" },
        active_checked = if active { " checked" } else { "" },
    )
}

async fn new_account_form(
    State(state): State<Arc<AppState>>,
    Db(_db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let content = format!(
        r#"<div class="max-w-xl">
<a href="/accounting/accounts" class="btn btn-ghost btn-sm mb-4">← Back to Chart of Accounts</a>
<h1 class="text-2xl font-bold mb-6">New Account</h1>
{form}
</div>"#,
        form = account_form("/accounting/accounts/create", None),
    );
    Html(page_shell(&sidebar, "New Account", &content)).into_response()
}

async fn create_account(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let (Some(code), Some(name), Some(account_type)) = (
        opt_str(&form, "code"),
        opt_str(&form, "name"),
        opt_str(&form, "account_type"),
    ) else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
            "Code, name and type are required",
        )
            .into_response();
    };
    let result = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_account (code, name, account_type, reconcile, active, created_by, updated_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $6)",
    )
    .bind(code)
    .bind(name)
    .bind(account_type)
    .bind(form.contains_key("reconcile"))
    .bind(form.contains_key("active"))
    .bind(user.id)
    .execute(&db)
    .await;
    match result {
        Ok(_) => redirect("/accounting/accounts"),
        Err(e) => {
            error!(error = %e, "account creation failed");
            (
                vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "Failed to create account (duplicate code or invalid type?)",
            )
                .into_response()
        }
    }
}

async fn edit_account(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let Some(row) = vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, account_type, reconcile, active FROM acc_account WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND,
            "Account not found",
        )
            .into_response();
    };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let account_type: String = row.get("account_type");
    let reconcile: bool = row.get("reconcile");
    let active: bool = row.get("active");

    let content = format!(
        r#"<div class="max-w-xl">
<a href="/accounting/accounts" class="btn btn-ghost btn-sm mb-4">← Back to Chart of Accounts</a>
<h1 class="text-2xl font-bold mb-6">{code} — {name} <span class="badge badge-ghost">{type_label}</span></h1>
{form}
</div>"#,
        code = vortex_plugin_sdk::framework::html_escape(&code),
        name = vortex_plugin_sdk::framework::html_escape(&name),
        type_label = account_type_label(&account_type),
        form = account_form(
            &format!("/accounting/accounts/{id}"),
            Some((&code, &name, &account_type, reconcile, active)),
        ),
    );
    Html(page_shell(&sidebar, "Edit Account", &content)).into_response()
}

async fn update_account(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let result = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_account SET code = COALESCE($2, code), name = COALESCE($3, name), \
            account_type = COALESCE($4, account_type), reconcile = $5, active = $6, \
            updated_by = $7 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(opt_str(&form, "code"))
    .bind(opt_str(&form, "name"))
    .bind(opt_str(&form, "account_type"))
    .bind(form.contains_key("reconcile"))
    .bind(form.contains_key("active"))
    .bind(user.id)
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "account update failed");
    }
    redirect("/accounting/accounts")
}

// ─────────────────────────────────────────────────────────────────────────
// Journals
// ─────────────────────────────────────────────────────────────────────────

async fn list_journals(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT j.id, j.code, j.name, j.journal_type, a.code AS account_code, \
                (SELECT COUNT(*) FROM acc_move m WHERE m.journal_id = j.id) AS move_count \
         FROM acc_journal j LEFT JOIN acc_account a ON a.id = j.default_account_id \
         WHERE j.active ORDER BY j.code",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut body = String::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let journal_type: String = row.get("journal_type");
        let account_code: Option<String> = row.get("account_code");
        let move_count: i64 = row.get("move_count");
        body.push_str(&format!(
            r#"<tr class="hover cursor-pointer" onclick="window.location='/accounting/journals/{id}'">
<td class="font-mono">{code}</td><td>{name}</td><td><span class="badge badge-ghost">{jtype}</span></td>
<td class="font-mono">{account}</td><td class="text-right">{count}</td></tr>"#,
            id = id,
            code = esc(&code),
            name = esc(&name),
            jtype = esc(&journal_type),
            account = esc(account_code.as_deref().unwrap_or("—")),
            count = move_count,
        ));
    }

    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-6">Journals</h1>
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="overflow-x-auto"><table class="table table-sm">
<thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Default Account</th><th class="text-right">Entries</th></tr></thead>
<tbody>{body}</tbody></table></div>
</div></div>
<p class="text-sm opacity-60 mt-4">Entry numbers come from the journal type's yearly sequence, e.g. SAL/2026/00042.</p>"#,
        body = body,
    );
    Html(page_shell(&sidebar, "Journals", &content)).into_response()
}

async fn edit_journal(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let Some(row) = vortex_plugin_sdk::sqlx::query(
        "SELECT code, name, journal_type, default_account_id, note FROM acc_journal WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND,
            "Journal not found",
        )
            .into_response();
    };
    let code: String = row.get("code");
    let name: String = row.get("name");
    let journal_type: String = row.get("journal_type");
    let default_account_id: Option<Uuid> = row.get("default_account_id");
    let note: Option<String> = row.get("note");
    let accounts = account_options(&db, default_account_id).await;

    let content = format!(
        r#"<div class="max-w-xl">
<a href="/accounting/journals" class="btn btn-ghost btn-sm mb-4">← Back to Journals</a>
<h1 class="text-2xl font-bold mb-6">{code} — {name} <span class="badge badge-ghost">{jtype}</span></h1>
<form method="POST" action="/accounting/journals/{id}">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" value="{name}" class="input input-bordered input-sm" required maxlength="120"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Default Account</span></label>
<select name="default_account_id" class="select select-bordered select-sm">{accounts}</select>
</div>
<div class="form-control mb-4">
<label class="label"><span class="label-text">Note</span></label>
<textarea name="note" class="textarea textarea-bordered textarea-sm" rows="2">{note}</textarea>
</div>
<button type="submit" class="btn btn-primary btn-sm">Save</button>
</div></div>
</form>
</div>"#,
        id = id,
        code = esc(&code),
        name = esc(&name),
        jtype = esc(&journal_type),
        accounts = accounts,
        note = esc(note.as_deref().unwrap_or("")),
    );
    Html(page_shell(&sidebar, "Edit Journal", &content)).into_response()
}

async fn update_journal(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let default_account_id = form
        .get("default_account_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<Uuid>().ok());
    let result = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_journal SET name = COALESCE($2, name), default_account_id = $3, note = $4 \
         WHERE id = $1",
    )
    .bind(id)
    .bind(opt_str(&form, "name"))
    .bind(default_account_id)
    .bind(opt_str(&form, "note"))
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "journal update failed");
    }
    redirect("/accounting/journals")
}
