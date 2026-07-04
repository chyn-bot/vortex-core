//! Banking UI — statement import + matching workbench, PDC register,
//! contra wizard.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::banking;
use crate::handlers::{page_shell, render_sidebar};

pub fn banking_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/bank-statements", get(statements_page))
        .route("/accounting/bank-statements/import", post(import_statement))
        .route("/accounting/bank-statements/{id}", get(workbench))
        .route("/accounting/bank-statements/{id}/auto-match", post(auto_match))
        .route("/accounting/bank-statements/{id}/finalize", post(finalize))
        .route("/accounting/bank-statements/{id}/match/{line}/{gl}", post(match_one))
        .route("/accounting/bank-statements/{id}/counterpart/{line}", post(counterpart))
        .route("/accounting/pdc", get(pdc_page))
        .route("/accounting/pdc/create", post(pdc_create))
        .route("/accounting/pdc/{id}/clear", post(pdc_clear))
        .route("/accounting/pdc/{id}/bounce", post(pdc_bounce))
        .route("/accounting/contra", get(contra_page))
        .route("/accounting/contra", post(contra_run))
}

const ESC: fn(&str) -> String = vortex_plugin_sdk::framework::html_escape;

async fn statements_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT s.id, s.name, s.statement_date, s.state, j.code AS journal, \
                COUNT(l.id) AS lines, COUNT(l.matched_line_id) AS matched \
         FROM acc_bank_statement s \
         JOIN acc_journal j ON j.id = s.journal_id \
         LEFT JOIN acc_bank_statement_line l ON l.statement_id = s.id \
         GROUP BY s.id, s.name, s.statement_date, s.state, j.code \
         ORDER BY s.statement_date DESC LIMIT 100",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut trs = String::new();
    for r in &rows {
        let id: Uuid = r.get("id");
        trs.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/bank-statements/{id}'\">\
             <td>{}</td><td>{}</td><td>{}</td><td>{}/{}</td><td><span class=\"badge badge-sm {}\">{}</span></td></tr>",
            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("statement_date"),
            ESC(r.get::<Option<String>, _>("name").as_deref().unwrap_or("Statement")),
            ESC(&r.get::<String, _>("journal")),
            r.get::<i64, _>("matched"),
            r.get::<i64, _>("lines"),
            if r.get::<String, _>("state") == "reconciled" { "badge-success" } else { "badge-ghost" },
            r.get::<String, _>("state"),
        ));
    }
    let journals = vortex_plugin_sdk::sqlx::query(
        "SELECT code, name FROM acc_journal WHERE journal_type IN ('bank','cash') AND active",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let jopts: String = journals
        .iter()
        .map(|r| format!("<option value=\"{0}\">{0} — {1}</option>", ESC(&r.get::<String, _>("code")), ESC(&r.get::<String, _>("name"))))
        .collect();
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Bank Statements</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/bank-statements/import" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Journal</span>
<select name="journal_code" class="select select-bordered select-sm">{jopts}</select></label>
<label class="form-control grow"><span class="label-text mb-1">CSV (date,description,amount)</span>
<textarea name="csv" rows="3" required class="textarea textarea-bordered textarea-sm font-mono" placeholder="2026-07-01,MAYBANK TRANSFER,1500.00"></textarea></label>
<button class="btn btn-primary btn-sm">Import</button>
</form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Date</th><th>Name</th><th>Journal</th><th>Matched</th><th>State</th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Bank Statements", &content)).into_response()
}

async fn import_statement(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.as_str());
    let journal_code = get("journal_code").unwrap_or("BNK");
    let csv = get("csv").unwrap_or("");
    let parsed = match banking::parse_statement_csv(csv) {
        Ok(p) => p,
        Err(e) => return (StatusCode::BAD_REQUEST, Html(format!("<p>Import failed: {}</p>", ESC(&e)))).into_response(),
    };
    let journal_id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_journal WHERE code = $1 AND active LIMIT 1",
    )
    .bind(journal_code)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(journal_id) = journal_id else {
        return (StatusCode::BAD_REQUEST, "Unknown journal").into_response();
    };
    // Archive the raw CSV as evidence.
    let sid: Uuid = match vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_bank_statement (journal_id, name, statement_date, created_by) \
         VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(journal_id)
    .bind(format!("Import {}", parsed[0].0))
    .bind(parsed.last().map(|l| l.0))
    .bind(user.id)
    .fetch_one(&db)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!("statement insert failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Import failed").into_response();
        }
    };
    let key = format!("bank-statements/{sid}.csv");
    let _ = state.files.put(&db_ctx.db_name, &key, csv.as_bytes(), Some("text/csv")).await;
    let _ = vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_bank_statement SET file_key = $2 WHERE id = $1",
    )
    .bind(sid)
    .bind(&key)
    .execute(&db)
    .await;
    for (date, desc, amount) in &parsed {
        let _ = vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_bank_statement_line (statement_id, line_date, description, amount) \
             VALUES ($1, $2, $3, $4)",
        )
        .bind(sid)
        .bind(date)
        .bind(desc)
        .bind(amount)
        .execute(&db)
        .await;
    }
    audit_banking(&state, &user, &db_ctx, "statement_imported", json!({"id": sid, "lines": parsed.len()})).await;
    Redirect::to(&format!("/accounting/bank-statements/{sid}")).into_response()
}

async fn workbench(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT b.id, b.line_date, b.description, b.amount, b.matched_line_id, \
                m.number AS matched_number \
         FROM acc_bank_statement_line b \
         LEFT JOIN acc_move_line gl ON gl.id = b.matched_line_id \
         LEFT JOIN acc_move m ON m.id = gl.move_id \
         WHERE b.statement_id = $1 ORDER BY b.line_date, b.created_at",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let suggestions = banking::auto_match_suggestions(&db, id).await.unwrap_or_default();
    let expense_acc: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_account WHERE code = '6000' LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let mut trs = String::new();
    for l in &lines {
        let lid: Uuid = l.get("id");
        let matched: Option<Uuid> = l.get("matched_line_id");
        let action = match matched {
            Some(_) => format!(
                "<span class=\"badge badge-success badge-sm\">matched {}</span>",
                ESC(l.get::<Option<String>, _>("matched_number").as_deref().unwrap_or(""))
            ),
            None => {
                let suggestion = suggestions.iter().find(|(sl, _, _)| *sl == lid);
                let mut a = String::new();
                if let Some((_, gl, score)) = suggestion {
                    a.push_str(&format!(
                        "<form method=\"post\" action=\"/accounting/bank-statements/{id}/match/{lid}/{gl}\" class=\"inline\">\
                         <button class=\"btn btn-xs btn-primary\">Match (score {score})</button></form> "
                    ));
                }
                if let Some(exp) = expense_acc {
                    a.push_str(&format!(
                        "<form method=\"post\" action=\"/accounting/bank-statements/{id}/counterpart/{lid}?account={exp}\" class=\"inline\">\
                         <button class=\"btn btn-xs btn-ghost\" title=\"Post to Operating Expenses and match\">Quick expense</button></form>"
                    ));
                }
                a
            }
        };
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td class=\"text-right font-mono\">{}</td><td>{}</td></tr>",
            l.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("line_date"),
            ESC(&l.get::<String, _>("description")),
            l.get::<Decimal, _>("amount"),
            action,
        ));
    }
    let content = format!(
        r##"<div class="mb-2"><a href="/accounting/bank-statements" class="link link-hover text-sm">← Bank Statements</a></div>
<div class="flex justify-between items-center mb-4"><h1 class="text-2xl font-bold">Reconciliation Workbench</h1>
<div class="flex gap-2">
<form method="post" action="/accounting/bank-statements/{id}/auto-match"><button class="btn btn-sm btn-outline">Auto-match all</button></form>
<form method="post" action="/accounting/bank-statements/{id}/finalize"><button class="btn btn-sm btn-primary">Finalize</button></form>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Date</th><th>Description</th><th class="text-right">Amount</th><th>Match</th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Bank Reconciliation", &content)).into_response()
}

async fn auto_match(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Ok(suggestions) = banking::auto_match_suggestions(&db, id).await {
        for (line, gl, score) in suggestions {
            if score >= 60 {
                let _ = banking::match_line(&db, line, gl, user.id).await;
            }
        }
    }
    Redirect::to(&format!("/accounting/bank-statements/{id}")).into_response()
}

async fn match_one(
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((id, line, gl)): Path<(Uuid, Uuid, Uuid)>,
) -> Response {
    let _ = banking::match_line(&db, line, gl, user.id).await;
    Redirect::to(&format!("/accounting/bank-statements/{id}")).into_response()
}

async fn counterpart(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path((id, line)): Path<(Uuid, Uuid)>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let Some(account) = q.get("account").and_then(|s| s.parse::<Uuid>().ok()) else {
        return (StatusCode::BAD_REQUEST, "account required").into_response();
    };
    match banking::quick_counterpart(&db, &state.pool, user.id, line, account).await {
        Ok(_) => Redirect::to(&format!("/accounting/bank-statements/{id}")).into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!("<p>{}</p>", ESC(&e.to_string()))),
        )
            .into_response(),
    }
}

async fn finalize(Db(db): Db, Path(id): Path<Uuid>) -> Response {
    match banking::finalize_statement(&db, id).await {
        Ok(()) => Redirect::to("/accounting/bank-statements").into_response(),
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!("<p>{}</p>", ESC(&e.to_string()))),
        )
            .into_response(),
    }
}

// ─── PDC ─────────────────────────────────────────────────────────────────

async fn pdc_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT p.id, p.direction, p.cheque_no, p.bank_name, p.amount, p.maturity_date, \
                p.state, c.name AS partner \
         FROM acc_pdc p JOIN contacts c ON c.id = p.partner_id \
         ORDER BY p.maturity_date DESC LIMIT 200",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut trs = String::new();
    for r in &rows {
        let id: Uuid = r.get("id");
        let st: String = r.get("state");
        let actions = if st == "holding" {
            format!(
                "<form method=\"post\" action=\"/accounting/pdc/{id}/clear\" class=\"inline\"><button class=\"btn btn-xs btn-primary\">Clear</button></form> \
                 <form method=\"post\" action=\"/accounting/pdc/{id}/bounce\" class=\"inline\"><button class=\"btn btn-xs btn-error btn-outline\">Bounce</button></form>"
            )
        } else {
            String::new()
        };
        trs.push_str(&format!(
            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"text-right font-mono\">{}</td>\
             <td>{}</td><td><span class=\"badge badge-sm\">{}</span></td><td>{}</td></tr>",
            ESC(&r.get::<String, _>("cheque_no")),
            ESC(&r.get::<String, _>("partner")),
            ESC(&r.get::<String, _>("direction")),
            r.get::<Decimal, _>("amount"),
            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("maturity_date"),
            ESC(&st),
            actions,
        ));
    }
    let partners = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name FROM contacts WHERE active ORDER BY name LIMIT 500",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let popts: String = partners
        .iter()
        .map(|r| format!("<option value=\"{}\">{}</option>", r.get::<Uuid, _>("id"), ESC(&r.get::<String, _>("name"))))
        .collect();
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Post-dated Cheques</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/pdc/create" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Direction</span>
<select name="direction" class="select select-bordered select-sm">
<option value="received">Received (customer)</option><option value="issued">Issued (vendor)</option></select></label>
<label class="form-control"><span class="label-text mb-1">Partner</span>
<select name="partner_id" class="select select-bordered select-sm">{popts}</select></label>
<label class="form-control"><span class="label-text mb-1">Cheque No.</span>
<input name="cheque_no" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">Amount</span>
<input name="amount" type="number" step="0.01" required class="input input-bordered input-sm"/></label>
<label class="form-control"><span class="label-text mb-1">Maturity</span>
<input name="maturity_date" type="date" required class="input input-bordered input-sm"/></label>
<button class="btn btn-primary btn-sm">Record</button>
</form>
<p class="text-xs opacity-60 mt-2">Matured cheques clear to bank automatically each day; bounce reverses the holding entry.</p>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Cheque</th><th>Partner</th><th>Dir</th>
<th class="text-right">Amount</th><th>Maturity</th><th>State</th><th></th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Post-dated Cheques", &content)).into_response()
}

async fn pdc_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let direction = get("direction").unwrap_or("received");
    let Some(partner_id) = get("partner_id").and_then(|s| s.parse().ok()) else {
        return (StatusCode::BAD_REQUEST, "partner required").into_response();
    };
    let cheque_no = get("cheque_no").unwrap_or_default();
    let Some(amount) = get("amount").and_then(|s| s.parse::<Decimal>().ok()) else {
        return (StatusCode::BAD_REQUEST, "amount required").into_response();
    };
    let Some(maturity) = get("maturity_date").and_then(|s| s.parse().ok()) else {
        return (StatusCode::BAD_REQUEST, "maturity date required").into_response();
    };
    match banking::record_pdc(
        &db, &state.pool, user.id, None, direction, partner_id, cheque_no,
        get("bank_name"), amount, maturity, get("memo"),
        vortex_plugin_sdk::chrono::Utc::now().date_naive(),
    )
    .await
    {
        Ok(id) => {
            audit_banking(&state, &user, &db_ctx, "pdc_recorded", json!({"id": id, "cheque": cheque_no})).await;
            Redirect::to("/accounting/pdc").into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!("<p>{}</p>", ESC(&e.to_string()))),
        )
            .into_response(),
    }
}

async fn pdc_clear(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    match banking::clear_pdc(&db, &state.pool, user.id, id, today).await {
        Ok(_) => {
            audit_banking(&state, &user, &db_ctx, "pdc_cleared", json!({"id": id})).await;
            Redirect::to("/accounting/pdc").into_response()
        }
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, Html(format!("<p>{}</p>", ESC(&e.to_string())))).into_response(),
    }
}

async fn pdc_bounce(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    match banking::bounce_pdc(&db, &state.pool, user.id, id, today).await {
        Ok(()) => {
            audit_banking(&state, &user, &db_ctx, "pdc_bounced", json!({"id": id})).await;
            Redirect::to("/accounting/pdc").into_response()
        }
        Err(e) => (StatusCode::UNPROCESSABLE_ENTITY, Html(format!("<p>{}</p>", ESC(&e.to_string())))).into_response(),
    }
}

// ─── Contra ──────────────────────────────────────────────────────────────

async fn contra_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let partner: Option<Uuid> = q.get("partner_id").and_then(|s| s.parse().ok());
    let partners = vortex_plugin_sdk::sqlx::query(
        "SELECT DISTINCT c.id, c.name FROM contacts c \
         JOIN acc_move m ON m.partner_id = c.id AND m.state = 'posted' \
         WHERE m.payment_state <> 'paid' ORDER BY c.name LIMIT 500",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let popts: String = partners
        .iter()
        .map(|r| {
            let id: Uuid = r.get("id");
            let sel = if Some(id) == partner { " selected" } else { "" };
            format!("<option value=\"{id}\"{sel}>{}</option>", ESC(&r.get::<String, _>("name")))
        })
        .collect();

    let mut docs_html = String::new();
    if let Some(pid) = partner {
        let docs = vortex_plugin_sdk::sqlx::query(
            "SELECT id, number, move_type, amount_residual FROM acc_move \
             WHERE partner_id = $1 AND state = 'posted' AND payment_state <> 'paid' \
               AND move_type IN ('customer_invoice', 'vendor_bill') \
             ORDER BY move_type, invoice_date",
        )
        .bind(pid)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        let mut rows = String::new();
        for d in &docs {
            let id: Uuid = d.get("id");
            let mt: String = d.get("move_type");
            let field = if mt == "customer_invoice" { "ar" } else { "ap" };
            rows.push_str(&format!(
                "<tr><td><input type=\"checkbox\" name=\"{field}\" value=\"{id}\" class=\"checkbox checkbox-sm\" checked/></td>\
                 <td>{}</td><td>{}</td><td class=\"text-right font-mono\">{}</td></tr>",
                ESC(d.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                ESC(&mt),
                d.get::<Decimal, _>("amount_residual"),
            ));
        }
        docs_html = format!(
            r##"<form method="post" action="/accounting/contra">
<input type="hidden" name="partner_id" value="{pid}"/>
<table class="table table-sm"><thead><tr><th></th><th>Number</th><th>Type</th><th class="text-right">Open</th></tr></thead>
<tbody>{rows}</tbody></table>
<button class="btn btn-primary btn-sm mt-3">Post Contra</button></form>"##,
        );
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">AR / AP Contra</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="get" class="flex gap-3 items-end">
<label class="form-control"><span class="label-text mb-1">Partner</span>
<select name="partner_id" class="select select-bordered select-sm">{popts}</select></label>
<button class="btn btn-sm btn-outline">Load open documents</button></form></div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">{docs_html}</div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Contra", &content)).into_response()
}

async fn contra_run(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let partner: Option<Uuid> = pairs
        .iter()
        .find(|(k, _)| k == "partner_id")
        .and_then(|(_, v)| v.parse().ok());
    let Some(partner) = partner else {
        return (StatusCode::BAD_REQUEST, "partner required").into_response();
    };
    let ar: Vec<Uuid> = pairs.iter().filter(|(k, _)| k == "ar").filter_map(|(_, v)| v.parse().ok()).collect();
    let ap: Vec<Uuid> = pairs.iter().filter(|(k, _)| k == "ap").filter_map(|(_, v)| v.parse().ok()).collect();
    match banking::contra(
        &db, &state.pool, user.id, None, partner, &ar, &ap,
        vortex_plugin_sdk::chrono::Utc::now().date_naive(),
    )
    .await
    {
        Ok(move_id) => {
            audit_banking(&state, &user, &db_ctx, "contra_posted", json!({"move": move_id})).await;
            Redirect::to(&format!("/accounting/moves/{move_id}")).into_response()
        }
        Err(e) => (
            StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!("<p>{}</p>", ESC(&e.to_string()))),
        )
            .into_response(),
    }
}

async fn audit_banking(
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
        .with_resource("acc_banking", action.to_string())
        .with_details(details);
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}
