//! Phase 6 UI — year-end close wizard, account statement groups.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::closing;
use crate::handlers::{page_shell, render_sidebar};

pub fn closing_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/year-end", get(year_end_page))
        .route("/accounting/year-end/{id}/close", post(close_year))
        .route("/accounting/year-end/{id}/reopen", post(reopen_year))
        .route("/accounting/account-groups", get(groups_page))
        .route("/accounting/account-groups/assign", post(assign_group))
}

const ESC: fn(&str) -> String = vortex_plugin_sdk::framework::html_escape;

async fn year_end_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let years = vortex_plugin_sdk::sqlx::query(
        "SELECT f.id, f.code, f.date_from, f.date_to, f.state, m.number AS closing_number, \
                (SELECT COUNT(*) FROM acc_move d \
                 WHERE d.state = 'draft' AND d.move_date BETWEEN f.date_from AND f.date_to) AS drafts \
         FROM acc_fiscal_year f LEFT JOIN acc_move m ON m.id = f.closing_move_id \
         ORDER BY f.date_from DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut trs = String::new();
    for y in &years {
        let id: Uuid = y.get("id");
        let st: String = y.get("state");
        let drafts: i64 = y.get("drafts");
        let profit = closing::period_profit(&db, y.get("date_from"), y.get("date_to"))
            .await
            .unwrap_or_default();
        let action = if st == "open" {
            let disabled = if drafts > 0 { "disabled" } else { "" };
            format!(
                "<form method=\"post\" action=\"/accounting/year-end/{id}/close\" \
                 onsubmit=\"return confirm('Close this fiscal year? P&amp;L will be zeroed into Retained Earnings and the lock date advanced.')\">\
                 <button class=\"btn btn-xs btn-primary\" {disabled}>Close year</button></form>"
            )
        } else {
            format!(
                "<form method=\"post\" action=\"/accounting/year-end/{id}/reopen\" \
                 onsubmit=\"return confirm('Reopen? The closing entry will be reversed.')\">\
                 <button class=\"btn btn-xs btn-outline\">Reopen</button></form>"
            )
        };
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{} → {}</td><td class=\"text-right font-mono\">{}</td>\
             <td>{}</td><td><span class=\"badge badge-sm {}\">{}</span></td><td>{}</td><td>{}</td></tr>",
            ESC(&y.get::<String, _>("code")),
            y.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("date_from"),
            y.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("date_to"),
            profit,
            if drafts > 0 { format!("{drafts} draft(s) ⚠") } else { "—".into() },
            if st == "closed" { "badge-success" } else { "badge-ghost" },
            ESC(&st),
            ESC(y.get::<Option<String>, _>("closing_number").as_deref().unwrap_or("—")),
            action,
        ));
    }
    let locks = vortex_plugin_sdk::sqlx::query(
        "SELECT lock_date, tax_lock_date FROM acc_config ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let (lock, tax_lock) = locks
        .map(|r| {
            (
                r.get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("lock_date"),
                r.get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("tax_lock_date"),
            )
        })
        .unwrap_or((None, None));
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Year-End Close</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<p class="text-sm">General lock: <b>{}</b> · Tax lock (documents): <b>{}</b>
 — edit in <a href="/accounting/settings" class="link">Settings</a>.</p>
<p class="text-xs opacity-60 mt-1">Closing posts one entry zeroing every P&L account into Retained Earnings (3900),
flags the year closed and advances the general lock to the year end. All drafts inside the year must be resolved first.</p>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Year</th><th>Window</th><th class="text-right">Profit</th>
<th>Drafts</th><th>State</th><th>Closing entry</th><th></th></tr></thead>
<tbody>{trs}</tbody></table>
<p class="text-xs opacity-60 mt-2">Statements: <a class="link" href="/reports/accounting.sofp">SOFP</a> ·
<a class="link" href="/reports/accounting.sopl">SOPL</a> ·
<a class="link" href="/reports/accounting.socie">SOCIE</a> ·
<a class="link" href="/reports/accounting.cashflow">Cash Flows</a></p>
</div></div>"##,
        lock.map(|d| d.to_string()).unwrap_or_else(|| "not set".into()),
        tax_lock.map(|d| d.to_string()).unwrap_or_else(|| "not set".into()),
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Year-End Close", &content)).into_response()
}

async fn close_year(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match closing::close_fiscal_year(&db, &state.pool, user.id, id, true).await {
        Ok(mv) => {
            audit_close(&state, &user, &db_ctx, "fiscal_year_closed", json!({"id": id, "closing_move": mv})).await;
            Redirect::to("/accounting/year-end").into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!("<p>{}</p>", ESC(&e.to_string()))),
        )
            .into_response(),
    }
}

async fn reopen_year(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match closing::reopen_fiscal_year(&db, &state.pool, user.id, id).await {
        Ok(()) => {
            audit_close(&state, &user, &db_ctx, "fiscal_year_reopened", json!({"id": id})).await;
            Redirect::to("/accounting/year-end").into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!("<p>{}</p>", ESC(&e.to_string()))),
        )
            .into_response(),
    }
}

async fn groups_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let accounts = vortex_plugin_sdk::sqlx::query(
        "SELECT a.id, a.code, a.name, a.account_type, g.name AS group_name \
         FROM acc_account a LEFT JOIN acc_account_group g ON g.id = a.group_id \
         WHERE a.active ORDER BY a.code",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let groups = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, section FROM acc_account_group ORDER BY sequence",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let gopts: String = groups
        .iter()
        .map(|g| {
            format!(
                "<option value=\"{}\">{} ({})</option>",
                g.get::<Uuid, _>("id"),
                ESC(&g.get::<String, _>("name")),
                ESC(&g.get::<String, _>("section")),
            )
        })
        .collect();
    let mut trs = String::new();
    for a in &accounts {
        let id: Uuid = a.get("id");
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
             <td><form method=\"post\" action=\"/accounting/account-groups/assign\" class=\"flex gap-1\">\
             <input type=\"hidden\" name=\"account_id\" value=\"{id}\"/>\
             <select name=\"group_id\" class=\"select select-bordered select-xs\">{gopts}</select>\
             <button class=\"btn btn-xs\">Set</button></form></td></tr>",
            ESC(&a.get::<String, _>("code")),
            ESC(&a.get::<String, _>("name")),
            ESC(&a.get::<String, _>("account_type")),
            ESC(a.get::<Option<String>, _>("group_name").as_deref().unwrap_or("—")),
        ));
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Statement Groups</h1>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<p class="text-xs opacity-60 mb-3">Groups drive where each account lands on the SOFP/SOPL note structure.
Defaults are seeded from the account type; override per account here.</p>
<table class="table table-sm"><thead><tr><th>Code</th><th>Account</th><th>Type</th><th>Group</th><th></th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Statement Groups", &content)).into_response()
}

async fn assign_group(
    Db(db): Db,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).and_then(|(_, v)| v.parse::<Uuid>().ok());
    let (Some(account), Some(group)) = (get("account_id"), get("group_id")) else {
        return (StatusCode::BAD_REQUEST, "account and group required").into_response();
    };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_account SET group_id = $2 WHERE id = $1",
    )
    .bind(account)
    .bind(group)
    .execute(&db)
    .await
    {
        error!("group assign failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    Redirect::to("/accounting/account-groups").into_response()
}

async fn audit_close(
    state: &AppState,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    action: &str,
    details: vortex_plugin_sdk::serde_json::Value,
) {
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("acc_closing", action.to_string())
        .with_details(details);
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}
