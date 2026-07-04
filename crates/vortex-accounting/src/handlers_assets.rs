//! Phase 5 UI — analytic dimensions, budgets, recurring entries,
//! fixed-asset register.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::handlers::{page_shell, render_sidebar};
use crate::{assets, recurring};

pub fn asset_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/dimensions", get(dimensions_page))
        .route("/accounting/dimensions", post(dimension_create))
        .route("/accounting/budgets", get(budgets_page))
        .route("/accounting/budgets", post(budget_create))
        .route("/accounting/budgets/{id}/lines", post(budget_line_add))
        .route("/accounting/recurring", get(recurring_page))
        .route("/accounting/recurring", post(recurring_create))
        .route("/accounting/recurring/{id}/generate", post(recurring_generate))
        .route("/accounting/assets", get(assets_page))
        .route("/accounting/assets", post(asset_create))
        .route("/accounting/assets/{id}", get(asset_detail))
        .route("/accounting/assets/{id}/confirm", post(asset_confirm))
        .route("/accounting/assets/{id}/dispose", post(asset_dispose))
}

const ESC: fn(&str) -> String = vortex_plugin_sdk::framework::html_escape;

fn err_page(e: impl std::fmt::Display) -> Response {
    (StatusCode::UNPROCESSABLE_ENTITY, Html(format!("<p>{}</p>", ESC(&e.to_string()))))
        .into_response()
}

// ─── Dimensions ──────────────────────────────────────────────────────────

async fn dimensions_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT dim_type, code, name, active FROM acc_dimension ORDER BY dim_type, code",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let trs: String = rows
        .iter()
        .map(|r| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                ESC(&r.get::<String, _>("dim_type")),
                ESC(&r.get::<String, _>("code")),
                ESC(&r.get::<String, _>("name")),
                if r.get::<bool, _>("active") { "✓" } else { "—" },
            )
        })
        .collect();
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Analytic Dimensions</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Type</span>
<select name="dim_type" class="select select-bordered select-sm">
<option value="project">Project</option><option value="department">Department</option></select></label>
<label class="form-control"><span class="label-text mb-1">Code</span>
<input name="code" required maxlength="24" class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">Name</span>
<input name="name" required class="input input-bordered input-sm"/></label>
<button class="btn btn-primary btn-sm">Add</button>
</form>
<p class="text-xs opacity-60 mt-2">Tag journal-entry lines with a project/department; posted tags are immutable — retag via a reclass entry.</p>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Type</th><th>Code</th><th>Name</th><th>Active</th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Dimensions", &content)).into_response()
}

async fn dimension_create(
    Db(db): Db,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let dim_type = get("dim_type").unwrap_or("project");
    let (Some(code), Some(name)) = (get("code"), get("name")) else {
        return (StatusCode::BAD_REQUEST, "code and name required").into_response();
    };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_dimension (dim_type, code, name) VALUES ($1, $2, $3) \
         ON CONFLICT (company_id, dim_type, code) DO UPDATE SET name = EXCLUDED.name, active = TRUE",
    )
    .bind(dim_type)
    .bind(code)
    .bind(name)
    .execute(&db)
    .await
    {
        error!("dimension insert failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    Redirect::to("/accounting/dimensions").into_response()
}

// ─── Budgets ─────────────────────────────────────────────────────────────

async fn budgets_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let selected: Option<Uuid> = q.get("id").and_then(|s| s.parse().ok());
    let budgets = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, date_from, date_to, state FROM acc_budget ORDER BY date_from DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let list: String = budgets
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            format!(
                "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/budgets?id={id}'\">\
                 <td>{}</td><td>{} → {}</td><td>{}</td></tr>",
                ESC(&r.get::<String, _>("name")),
                r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("date_from"),
                r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("date_to"),
                ESC(&r.get::<String, _>("state")),
            )
        })
        .collect();
    let mut detail = String::new();
    if let Some(bid) = selected {
        let lines = vortex_plugin_sdk::sqlx::query(
            "SELECT bl.period, a.code, a.name AS account, d.code AS project, bl.amount, \
                    COALESCE((SELECT SUM(l.debit - l.credit) FROM acc_move_line l \
                              JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
                              WHERE l.account_id = bl.account_id \
                                AND date_trunc('month', m.move_date) = bl.period \
                                AND (bl.project_id IS NULL OR l.project_id = bl.project_id)), 0) AS actual \
             FROM acc_budget_line bl \
             JOIN acc_account a ON a.id = bl.account_id \
             LEFT JOIN acc_dimension d ON d.id = bl.project_id \
             WHERE bl.budget_id = $1 ORDER BY bl.period, a.code",
        )
        .bind(bid)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        let trs: String = lines
            .iter()
            .map(|r| {
                let amount: Decimal = r.get("amount");
                let mut actual: Decimal = r.get("actual");
                let code: String = r.get("code");
                // Income accounts accrue on the credit side.
                if code.starts_with('4') {
                    actual = -actual;
                }
                format!(
                    "<tr><td>{}</td><td>{} {}</td><td>{}</td>\
                     <td class=\"text-right font-mono\">{}</td>\
                     <td class=\"text-right font-mono\">{}</td>\
                     <td class=\"text-right font-mono {}\">{}</td></tr>",
                    r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("period"),
                    ESC(&code),
                    ESC(&r.get::<String, _>("account")),
                    ESC(r.get::<Option<String>, _>("project").as_deref().unwrap_or("—")),
                    amount,
                    actual,
                    if actual > amount { "text-error" } else { "" },
                    actual - amount,
                )
            })
            .collect();
        let accounts = account_options(&db).await;
        let projects = dimension_options(&db, "project").await;
        detail = format!(
            r##"<div class="card bg-base-100 shadow mt-4"><div class="card-body p-4">
<h2 class="font-bold mb-2">Budget vs Actual</h2>
<table class="table table-sm"><thead><tr><th>Month</th><th>Account</th><th>Project</th>
<th class="text-right">Budget</th><th class="text-right">Actual</th><th class="text-right">Variance</th></tr></thead>
<tbody>{trs}</tbody></table>
<form method="post" action="/accounting/budgets/{bid}/lines" class="flex gap-3 items-end flex-wrap mt-3">
<label class="form-control"><span class="label-text mb-1">Month</span>
<input name="period" type="month" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">Account</span>
<select name="account_id" class="select select-bordered select-sm">{accounts}</select></label>
<label class="form-control"><span class="label-text mb-1">Project</span>
<select name="project_id" class="select select-bordered select-sm"><option value="">—</option>{projects}</select></label>
<label class="form-control"><span class="label-text mb-1">Amount</span>
<input name="amount" type="number" step="0.01" required class="input input-bordered input-sm"/></label>
<button class="btn btn-primary btn-sm">Add line</button>
</form></div></div>"##,
        );
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Budgets</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/budgets" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Name</span>
<input name="name" required class="input input-bordered input-sm" placeholder="FY2026 Opex"/></label>
<label class="form-control"><span class="label-text mb-1">From</span>
<input name="date_from" type="date" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">To</span>
<input name="date_to" type="date" required class="input input-bordered input-sm"/></label>
<button class="btn btn-primary btn-sm">Create</button>
</form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Name</th><th>Period</th><th>State</th></tr></thead>
<tbody>{list}</tbody></table></div></div>
{detail}"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Budgets", &content)).into_response()
}

async fn budget_create(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let (Some(name), Some(from), Some(to)) = (get("name"), get("date_from"), get("date_to"))
    else {
        return (StatusCode::BAD_REQUEST, "name and dates required").into_response();
    };
    let id: Result<Uuid, _> = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_budget (name, date_from, date_to, created_by) \
         VALUES ($1, $2::date, $3::date, $4) RETURNING id",
    )
    .bind(name)
    .bind(from)
    .bind(to)
    .bind(user.id)
    .fetch_one(&db)
    .await;
    match id {
        Ok(id) => Redirect::to(&format!("/accounting/budgets?id={id}")).into_response(),
        Err(e) => err_page(e),
    }
}

async fn budget_line_add(
    Db(db): Db,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let Some(account): Option<Uuid> = get("account_id").and_then(|s| s.parse().ok()) else {
        return (StatusCode::BAD_REQUEST, "account required").into_response();
    };
    // <input type=month> submits YYYY-MM.
    let Some(period) = get("period").map(|p| format!("{p}-01")) else {
        return (StatusCode::BAD_REQUEST, "period required").into_response();
    };
    let project: Option<Uuid> = get("project_id").and_then(|s| s.parse().ok());
    let Some(amount): Option<Decimal> = get("amount").and_then(|s| s.parse().ok()) else {
        return (StatusCode::BAD_REQUEST, "amount required").into_response();
    };
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_budget_line (budget_id, account_id, period, project_id, amount) \
         VALUES ($1, $2, $3::date, $4, $5) \
         ON CONFLICT (budget_id, account_id, period, project_id) \
         DO UPDATE SET amount = EXCLUDED.amount",
    )
    .bind(id)
    .bind(account)
    .bind(&period)
    .bind(project)
    .bind(amount)
    .execute(&db)
    .await
    {
        return err_page(e);
    }
    Redirect::to(&format!("/accounting/budgets?id={id}")).into_response()
}

// ─── Recurring ───────────────────────────────────────────────────────────

async fn recurring_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT r.id, r.name, r.interval_months, r.next_date, r.auto_post, r.active, \
                m.number AS last_number \
         FROM acc_recurring r LEFT JOIN acc_move m ON m.id = r.last_move_id \
         ORDER BY r.next_date",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let trs: String = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            format!(
                "<tr><td>{}</td><td>every {} mo</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                 <td><form method=\"post\" action=\"/accounting/recurring/{id}/generate\">\
                 <button class=\"btn btn-xs btn-outline\">Generate now</button></form></td></tr>",
                ESC(&r.get::<String, _>("name")),
                r.get::<i32, _>("interval_months"),
                r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("next_date"),
                if r.get::<bool, _>("auto_post") { "auto-post" } else { "draft" },
                ESC(r.get::<Option<String>, _>("last_number").as_deref().unwrap_or("—")),
                if r.get::<bool, _>("active") { "✓" } else { "ended" },
            )
        })
        .collect();
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Recurring Entries</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/recurring" class="grid gap-3">
<div class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Name</span>
<input name="name" required class="input input-bordered input-sm" placeholder="Office rent"/></label>
<label class="form-control"><span class="label-text mb-1">Every (months)</span>
<input name="interval_months" type="number" min="1" max="12" value="1" class="input input-bordered input-sm w-24"/></label>
<label class="form-control"><span class="label-text mb-1">First date</span>
<input name="next_date" type="date" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">End date</span>
<input name="end_date" type="date" class="input input-bordered input-sm"/></label>
<label class="label cursor-pointer gap-2"><span class="label-text">Auto-post</span>
<input type="checkbox" name="auto_post" class="toggle toggle-primary toggle-sm"/></label>
</div>
<label class="form-control"><span class="label-text mb-1">Line template (JSON)</span>
<textarea name="lines" rows="3" required class="textarea textarea-bordered textarea-sm font-mono"
placeholder='[{{"account_code":"6000","name":"Rent","debit":2500,"credit":0}},{{"account_code":"1100","name":"Rent","debit":0,"credit":2500}}]'></textarea></label>
<div><button class="btn btn-primary btn-sm">Create</button></div>
</form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Name</th><th>Interval</th><th>Next</th>
<th>Posting</th><th>Last entry</th><th>Active</th><th></th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Recurring Entries", &content)).into_response()
}

async fn recurring_create(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let (Some(name), Some(next_date), Some(lines)) = (get("name"), get("next_date"), get("lines"))
    else {
        return (StatusCode::BAD_REQUEST, "name, first date and template required").into_response();
    };
    let parsed: vortex_plugin_sdk::serde_json::Value =
        match vortex_plugin_sdk::serde_json::from_str(lines) {
            Ok(v) => v,
            Err(e) => return err_page(format!("template is not valid JSON: {e}")),
        };
    if !parsed.is_array() {
        return err_page("template must be a JSON array of lines");
    }
    let interval: i32 = get("interval_months").and_then(|s| s.parse().ok()).unwrap_or(1);
    let auto_post = get("auto_post").is_some();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_recurring \
            (name, interval_months, next_date, end_date, auto_post, lines, created_by) \
         VALUES ($1, $2, $3::date, NULLIF($4, '')::date, $5, $6, $7)",
    )
    .bind(name)
    .bind(interval)
    .bind(next_date)
    .bind(get("end_date").unwrap_or(""))
    .bind(auto_post)
    .bind(&parsed)
    .bind(user.id)
    .execute(&db)
    .await
    {
        return err_page(e);
    }
    Redirect::to("/accounting/recurring").into_response()
}

async fn recurring_generate(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let next: Option<vortex_plugin_sdk::chrono::NaiveDate> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT next_date FROM acc_recurring WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(date) = next else {
        return (StatusCode::NOT_FOUND, "recurring entry not found").into_response();
    };
    match recurring::generate_occurrence(&db, &state.pool, user.id, id, date).await {
        Ok(move_id) => {
            audit_p5(&state, &user, &db_ctx, "recurring_generated", json!({"id": id, "move": move_id})).await;
            Redirect::to(&format!("/accounting/moves/{move_id}")).into_response()
        }
        Err(e) => err_page(e),
    }
}

// ─── Fixed assets ────────────────────────────────────────────────────────

async fn assets_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT a.id, a.name, a.cost, a.life_months, a.start_date, a.state, \
                COALESCE((SELECT SUM(d.amount) FROM acc_asset_depreciation d \
                          WHERE d.asset_id = a.id AND d.state = 'posted'), 0) AS accumulated \
         FROM acc_asset a ORDER BY a.created_at DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let trs: String = rows
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let cost: Decimal = r.get("cost");
            let acc: Decimal = r.get("accumulated");
            format!(
                "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/assets/{id}'\">\
                 <td>{}</td><td class=\"text-right font-mono\">{}</td>\
                 <td class=\"text-right font-mono\">{}</td><td class=\"text-right font-mono\">{}</td>\
                 <td>{} mo</td><td><span class=\"badge badge-sm\">{}</span></td></tr>",
                ESC(&r.get::<String, _>("name")),
                cost,
                acc,
                cost - acc,
                r.get::<i32, _>("life_months"),
                ESC(&r.get::<String, _>("state")),
            )
        })
        .collect();
    let accounts = account_options(&db).await;
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Fixed Assets</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/assets" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Name</span>
<input name="name" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">Cost</span>
<input name="cost" type="number" step="0.01" required class="input input-bordered input-sm w-28"/></label>
<label class="form-control"><span class="label-text mb-1">Salvage</span>
<input name="salvage_value" type="number" step="0.01" value="0" class="input input-bordered input-sm w-24"/></label>
<label class="form-control"><span class="label-text mb-1">Life (months)</span>
<input name="life_months" type="number" min="1" required class="input input-bordered input-sm w-24"/></label>
<label class="form-control"><span class="label-text mb-1">Start</span>
<input name="start_date" type="date" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">Cost account</span>
<select name="asset_account_id" class="select select-bordered select-sm">{accounts}</select></label>
<button class="btn btn-primary btn-sm">Create draft</button>
</form>
<p class="text-xs opacity-60 mt-2">Accumulated-depreciation account 1600 and expense 7000 are used by default. Confirm generates the straight-line schedule; the monthly run posts due periods.</p>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Asset</th><th class="text-right">Cost</th>
<th class="text-right">Accum. Dep.</th><th class="text-right">NBV</th><th>Life</th><th>State</th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Fixed Assets", &content)).into_response()
}

async fn asset_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let Some(name) = get("name") else {
        return (StatusCode::BAD_REQUEST, "name required").into_response();
    };
    let cost: Option<Decimal> = get("cost").and_then(|s| s.parse().ok());
    let salvage: Decimal = get("salvage_value").and_then(|s| s.parse().ok()).unwrap_or_default();
    let life: Option<i32> = get("life_months").and_then(|s| s.parse().ok());
    let start: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        get("start_date").and_then(|s| s.parse().ok());
    let (Some(cost), Some(life), Some(start)) = (cost, life, start) else {
        return (StatusCode::BAD_REQUEST, "cost, life and start date required").into_response();
    };
    let asset_account: Option<Uuid> = get("asset_account_id").and_then(|s| s.parse().ok());
    // Default accounts: 1600 accumulated depreciation, 7000 expense,
    // 1500 cost (when the form sends none).
    let dep_account: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '1600' LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let exp_account: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '7000' LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let default_asset: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '1500' LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let (Some(dep_account), Some(exp_account), Some(asset_account)) =
        (dep_account, exp_account, asset_account.or(default_asset))
    else {
        return err_page("asset accounts 1500/1600/7000 missing from the chart");
    };
    let id: Result<Uuid, _> = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_asset (name, asset_account_id, depreciation_account_id, \
             expense_account_id, cost, salvage_value, life_months, start_date, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id",
    )
    .bind(name)
    .bind(asset_account)
    .bind(dep_account)
    .bind(exp_account)
    .bind(cost)
    .bind(salvage)
    .bind(life)
    .bind(start)
    .bind(user.id)
    .fetch_one(&db)
    .await;
    match id {
        Ok(id) => {
            audit_p5(&state, &user, &db_ctx, "asset_created", json!({"id": id, "name": name})).await;
            Redirect::to(&format!("/accounting/assets/{id}")).into_response()
        }
        Err(e) => err_page(e),
    }
}

async fn asset_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let Some(a) = vortex_plugin_sdk::sqlx::query(
        "SELECT name, cost, salvage_value, life_months, start_date, state FROM acc_asset WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (StatusCode::NOT_FOUND, "asset not found").into_response();
    };
    let asset_state: String = a.get("state");
    let schedule = vortex_plugin_sdk::sqlx::query(
        "SELECT d.seq, d.dep_date, d.amount, d.cumulative, d.state, m.number \
         FROM acc_asset_depreciation d LEFT JOIN acc_move m ON m.id = d.move_id \
         WHERE d.asset_id = $1 ORDER BY d.seq",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let trs: String = schedule
        .iter()
        .map(|r| {
            format!(
                "<tr><td>{}</td><td>{}</td><td class=\"text-right font-mono\">{}</td>\
                 <td class=\"text-right font-mono\">{}</td><td>{}</td><td>{}</td></tr>",
                r.get::<i32, _>("seq"),
                r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("dep_date"),
                r.get::<Decimal, _>("amount"),
                r.get::<Decimal, _>("cumulative"),
                ESC(&r.get::<String, _>("state")),
                ESC(r.get::<Option<String>, _>("number").as_deref().unwrap_or("—")),
            )
        })
        .collect();
    let actions = match asset_state.as_str() {
        "draft" => format!(
            "<form method=\"post\" action=\"/accounting/assets/{id}/confirm\">\
             <button class=\"btn btn-sm btn-primary\">Confirm (generate schedule)</button></form>"
        ),
        "running" | "fully_depreciated" => format!(
            "<form method=\"post\" action=\"/accounting/assets/{id}/dispose\" class=\"flex gap-2 items-end\">\
             <label class=\"form-control\"><span class=\"label-text mb-1\">Proceeds</span>\
             <input name=\"proceeds\" type=\"number\" step=\"0.01\" value=\"0\" class=\"input input-bordered input-sm w-28\"/></label>\
             <button class=\"btn btn-sm btn-error btn-outline\">Dispose</button></form>"
        ),
        _ => String::new(),
    };
    let content = format!(
        r##"<div class="mb-2"><a href="/accounting/assets" class="link link-hover text-sm">← Fixed Assets</a></div>
<div class="flex justify-between items-center mb-4">
<h1 class="text-2xl font-bold">{} <span class="badge">{}</span></h1>{actions}</div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<p class="text-sm opacity-70 mb-3">Cost {} · salvage {} · {} months from {}</p>
<table class="table table-sm"><thead><tr><th>#</th><th>Date</th><th class="text-right">Amount</th>
<th class="text-right">Cumulative</th><th>State</th><th>Entry</th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
        ESC(&a.get::<String, _>("name")),
        ESC(&asset_state),
        a.get::<Decimal, _>("cost"),
        a.get::<Decimal, _>("salvage_value"),
        a.get::<i32, _>("life_months"),
        a.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("start_date"),
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Asset", &content)).into_response()
}

async fn asset_confirm(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match assets::confirm_asset(&db, id).await {
        Ok(n) => {
            audit_p5(&state, &user, &db_ctx, "asset_confirmed", json!({"id": id, "periods": n})).await;
            Redirect::to(&format!("/accounting/assets/{id}")).into_response()
        }
        Err(e) => err_page(e),
    }
}

async fn asset_dispose(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let proceeds: Decimal = pairs
        .iter()
        .rev()
        .find(|(k, _)| k == "proceeds")
        .and_then(|(_, v)| v.trim().parse().ok())
        .unwrap_or_default();
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    match assets::dispose_asset(&db, &state.pool, user.id, id, proceeds, today).await {
        Ok(move_id) => {
            audit_p5(&state, &user, &db_ctx, "asset_disposed",
                json!({"id": id, "move": move_id, "proceeds": proceeds.to_string()})).await;
            Redirect::to(&format!("/accounting/moves/{move_id}")).into_response()
        }
        Err(e) => err_page(e),
    }
}

// ─── Shared option lists ─────────────────────────────────────────────────

async fn account_options(db: &vortex_plugin_sdk::sqlx::PgPool) -> String {
    vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM acc_account WHERE active ORDER BY code",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| {
        format!(
            "<option value=\"{}\">{} {}</option>",
            r.get::<Uuid, _>("id"),
            ESC(&r.get::<String, _>("code")),
            ESC(&r.get::<String, _>("name")),
        )
    })
    .collect()
}

async fn dimension_options(db: &vortex_plugin_sdk::sqlx::PgPool, dim_type: &str) -> String {
    vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, name FROM acc_dimension WHERE active AND dim_type = $1 ORDER BY code",
    )
    .bind(dim_type)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| {
        format!(
            "<option value=\"{}\">{} {}</option>",
            r.get::<Uuid, _>("id"),
            ESC(&r.get::<String, _>("code")),
            ESC(&r.get::<String, _>("name")),
        )
    })
    .collect()
}

async fn audit_p5(
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
        .with_resource("acc_assets", action.to_string())
        .with_details(details);
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}
