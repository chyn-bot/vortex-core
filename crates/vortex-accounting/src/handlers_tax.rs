//! Malaysian tax setup UI — tax configs, fiscal years, company tax
//! identity, partner tax profiles. All forms via the form engine.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::handlers::{page_shell, render_sidebar};

pub fn tax_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/taxes", get(list_taxes))
        .route("/accounting/taxes/{id}", get(edit_tax_config))
        .route("/accounting/taxes/{id}", post(save_tax_config))
        .route("/accounting/fiscal-years", get(list_fiscal_years))
        .route("/accounting/fiscal-years/new", get(new_fiscal_year))
        .route("/accounting/fiscal-years/create", post(create_fiscal_year))
        .route("/accounting/fiscal-years/{id}", get(edit_fiscal_year))
        .route("/accounting/fiscal-years/{id}", post(update_fiscal_year))
        .route("/accounting/settings", get(edit_settings))
        .route("/accounting/settings/{id}", post(save_settings))
        .route("/accounting/tax-profiles", get(list_tax_profiles))
        .route("/accounting/tax-profiles/by-contact/{contact_id}", get(profile_by_contact))
        .route("/accounting/tax-profiles/{id}", get(edit_tax_profile))
        .route("/accounting/tax-profiles/{id}", post(save_tax_profile))
        .route("/accounting/tax-profiles/{id}/search-tin", post(search_tin_action))
        .route("/accounting/tax-profiles/{id}/validate-tin", post(validate_tin_action))
}

// ─── Forms (declared once — render + validate + save derive) ────────────

fn tax_config_form() -> FormConfig {
    FormConfig::new("Tax Configuration", "acc_tax_config", "/accounting/taxes")
        .section("Accounting")
        .field(FormField::many2one("tax_account_id", "Tax GL Account", "acc_account"))
        .section("Malaysia / SST")
        .field(FormField::select("sst_category", "SST Category", &[
            ("sales_tax_5", "Sales Tax 5%"),
            ("sales_tax_10", "Sales Tax 10%"),
            ("service_tax_6", "Service Tax 6%"),
            ("service_tax_8", "Service Tax 8%"),
            ("exempt", "Exempt"),
            ("zero_rated", "Zero-rated"),
            ("out_of_scope", "Out of scope"),
        ]).required())
        .field(FormField::select("myinvois_tax_type", "MyInvois Tax Type", &[
            ("01", "01 — Sales Tax"),
            ("02", "02 — Service Tax"),
            ("E", "E — Exempt"),
            ("06", "06 — Not applicable"),
        ]).required())
        .field(FormField::text("exemption_reason", "Exemption Reason")
            .help("Required by LHDN when the category is exempt"))
}

fn fiscal_year_form() -> FormConfig {
    FormConfig::new("Fiscal Year", "acc_fiscal_year", "/accounting/fiscal-years")
        .field(FormField::text("code", "Code").required().placeholder("FY2026"))
        .field(FormField::date("date_from", "From").required())
        .field(FormField::date("date_to", "To").required())
}

fn settings_form() -> FormConfig {
    FormConfig::new("Accounting Settings", "acc_config", "/accounting/settings")
        .section("Company Tax Identity (LHDN / MyInvois)")
        .field(FormField::text("company_tin", "TIN").placeholder("C1234567890"))
        .field(FormField::select("company_id_type", "ID Type", &[
            ("BRN", "BRN — Business Registration"),
            ("NRIC", "NRIC"),
            ("PASSPORT", "Passport"),
            ("ARMY", "Army ID"),
        ]))
        .field(FormField::text("company_id_value", "ID Value").placeholder("201901012345"))
        .field(FormField::text("company_sst_registration", "SST Registration No."))
        .field(FormField::text("company_msic_code", "MSIC Code").placeholder("62010"))
        .field(FormField::textarea("company_business_activity", "Business Activity"))
        .field(FormField::number("sst_period_months", "SST Taxable Period (months)")
            .default("2").help("2 = bi-monthly (standard)"))
        .section("Default Accounts")
        .field(FormField::many2one("receivable_account_id", "Receivable", "acc_account"))
        .field(FormField::many2one("payable_account_id", "Payable", "acc_account"))
        .field(FormField::many2one("tax_account_id", "Tax (fallback)", "acc_account"))
        .field(FormField::many2one("income_account_id", "Income", "acc_account"))
        .field(FormField::many2one("expense_account_id", "Expense", "acc_account"))
        .section("Period Control")
        .field(FormField::date("lock_date", "Lock Date")
            .help("Posting on or before this date is rejected"))
        .field(FormField::date("tax_lock_date", "Tax Lock Date")
            .help("Documents (invoices/bills) on or before this date cannot post — freeze after SST-02 filing"))
        .field(FormField::number("fiscal_year_end_month", "Fiscal Year-End Month")
            .default("12").help("1-12; 12 = December year end"))
        .section("Credit & Ageing")
        .field(FormField::select("credit_limit_policy", "Credit Limit Policy", &[
            ("off", "Off"),
            ("warn", "Warn (post anyway, log a warning)"),
            ("block", "Block (reject posting over the limit)"),
        ]).help("Checked against contacts.credit_limit when posting customer invoices"))
        .field(FormField::json("aging_buckets", "Ageing Buckets (days)")
            .placeholder("[30, 60, 90, 120]")
            .help("Upper bounds for aged AR/AP report columns, JSON array of days"))
}

fn tax_profile_form() -> FormConfig {
    FormConfig::new("Partner Tax Profile", "acc_partner_tax_profile", "/accounting/tax-profiles")
        .section("LHDN Identity")
        .field(FormField::text("tin", "TIN").placeholder("C1234567890 / IG12345678901"))
        .field(FormField::select("id_type", "ID Type", &[
            ("BRN", "BRN — Business Registration"),
            ("NRIC", "NRIC"),
            ("PASSPORT", "Passport"),
            ("ARMY", "Army ID"),
        ]))
        .field(FormField::text("id_value", "ID Value"))
        .field(FormField::text("sst_registration", "SST Registration No."))
        .field(FormField::text("msic_code", "MSIC Code"))
        .section("e-Invoice")
        .field(FormField::text("einvoice_email", "e-Invoice Email"))
        .field(FormField::checkbox("einvoice_optout", "Consolidated only (no individual e-invoice)"))
}

// ─── Taxes ───────────────────────────────────────────────────────────────

async fn list_taxes(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    // Ensure every active tax has a config row so edit links exist.
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_tax_config (tax_id) \
         SELECT t.id FROM taxes t \
         WHERE t.active AND NOT EXISTS \
            (SELECT 1 FROM acc_tax_config c WHERE c.tax_id = t.id)",
    )
    .execute(&db)
    .await
    {
        error!("tax config backfill failed: {e}");
    }

    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT c.id, t.name, t.amount, t.type_tax_use, c.sst_category, \
                c.myinvois_tax_type, a.code AS account_code \
         FROM acc_tax_config c \
         JOIN taxes t ON t.id = c.tax_id \
         LEFT JOIN acc_account a ON a.id = c.tax_account_id \
         WHERE t.active \
         ORDER BY t.type_tax_use, t.name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let esc = vortex_plugin_sdk::framework::html_escape;
    let mut trs = String::new();
    for r in &rows {
        let id: Uuid = r.get("id");
        trs.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/taxes/{id}'\">\
             <td>{}</td><td>{}%</td><td>{}</td><td><span class=\"badge badge-ghost\">{}</span></td>\
             <td>{}</td><td><code>{}</code></td></tr>",
            esc(&r.get::<String, _>("name")),
            r.get::<vortex_plugin_sdk::rust_decimal::Decimal, _>("amount").normalize(),
            esc(&r.get::<String, _>("type_tax_use")),
            esc(&r.get::<String, _>("sst_category")),
            esc(&r.get::<String, _>("myinvois_tax_type")),
            esc(r.get::<Option<String>, _>("account_code").as_deref().unwrap_or("—")),
        ));
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Tax Setup</h1>
        <div class="card bg-base-100 shadow"><div class="card-body p-4 overflow-x-auto">
        <table class="table table-sm"><thead><tr><th>Tax</th><th>Rate</th><th>Use</th>
        <th>SST Category</th><th>MyInvois</th><th>GL Account</th></tr></thead>
        <tbody>{trs}</tbody></table>
        <p class="text-xs opacity-60 mt-2">Rates and names are managed in the commerce tax
        registry; this page controls how each tax posts and reports.</p></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Tax Setup", &content)).into_response()
}

async fn edit_tax_config(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let tax_name: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT t.name FROM acc_tax_config c JOIN taxes t ON t.id = c.tax_id WHERE c.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(tax_name) = tax_name else {
        return (StatusCode::NOT_FOUND, "Tax configuration not found").into_response();
    };
    let values = match load_record(&db, &tax_config_form(), id).await {
        Ok(Some(v)) => v,
        _ => return (StatusCode::NOT_FOUND, "Tax configuration not found").into_response(),
    };
    let form =
        render_form(&db, &tax_config_form(), FormMode::Edit, Some(&id.to_string()), &values, &[])
            .await;
    let content = format!(
        "<div class=\"mb-2\"><a href=\"/accounting/taxes\" class=\"link link-hover text-sm\">← Tax Setup</a></div>\
         <p class=\"text-lg font-semibold mb-2\">{}</p>{form}",
        vortex_plugin_sdk::framework::html_escape(&tax_name),
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Tax Configuration", &content)).into_response()
}

async fn save_tax_config(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match execute_form_save(&db, &tax_config_form(), &pairs, Some(id)).await {
        Ok(SaveOutcome::Saved(_)) => {
            audit_setup(&state, &user, &db_ctx, "acc_tax_config", id).await;
            Redirect::to("/accounting/taxes").into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let form = render_form(
                &db, &tax_config_form(), FormMode::Edit, Some(&id.to_string()), &values, &errors,
            )
            .await;
            let sidebar = render_sidebar(&state, &user, &db_ctx);
            Html(page_shell(&sidebar, "Tax Configuration", &form)).into_response()
        }
        Err(e) => {
            error!("tax config save failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response()
        }
    }
}

// ─── Fiscal years ────────────────────────────────────────────────────────

async fn list_fiscal_years(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, date_from, date_to, state FROM acc_fiscal_year ORDER BY date_from DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let esc = vortex_plugin_sdk::framework::html_escape;
    let mut trs = String::new();
    for r in &rows {
        let id: Uuid = r.get("id");
        let st: String = r.get("state");
        let badge = if st == "open" { "badge-success" } else { "badge-neutral" };
        trs.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/fiscal-years/{id}'\">\
             <td>{}</td><td>{}</td><td>{}</td><td><span class=\"badge {badge}\">{}</span></td></tr>",
            esc(&r.get::<String, _>("code")),
            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("date_from"),
            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("date_to"),
            esc(&st),
        ));
    }
    if trs.is_empty() {
        trs = "<tr><td colspan=\"4\" class=\"text-center opacity-60 py-6\">No fiscal years yet — postings are only limited by the lock date until one exists.</td></tr>".into();
    }
    let content = format!(
        r##"<div class="flex justify-between items-center mb-6">
        <h1 class="text-2xl font-bold">Fiscal Years</h1>
        <a href="/accounting/fiscal-years/new" class="btn btn-primary btn-sm">+ New</a></div>
        <div class="card bg-base-100 shadow"><div class="card-body p-4">
        <table class="table table-sm"><thead><tr><th>Code</th><th>From</th><th>To</th><th>State</th></tr></thead>
        <tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Fiscal Years", &content)).into_response()
}

async fn new_fiscal_year(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let form = render_form(
        &db, &fiscal_year_form(), FormMode::Create, None, &Default::default(), &[],
    )
    .await;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "New Fiscal Year", &form)).into_response()
}

/// Overlap-validated save shared by create and update.
async fn save_fiscal_year(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    pairs: &[(String, String)],
    record: Option<Uuid>,
) -> Response {
    // Pre-validate the overlap (the schema deliberately has no GiST
    // exclusion — see migration 004).
    let get = |k: &str| pairs.iter().rev().find(|(pk, _)| pk == k).map(|(_, v)| v.trim());
    let from: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        get("date_from").and_then(|s| s.parse().ok());
    let to: Option<vortex_plugin_sdk::chrono::NaiveDate> =
        get("date_to").and_then(|s| s.parse().ok());
    if let (Some(f), Some(t)) = (from, to) {
        if t <= f {
            let errors = vec![vortex_plugin_sdk::framework::form::FieldError {
                field: "date_to".into(),
                message: "End must be after start".into(),
            }];
            return rerender_fy(state, db, user, db_ctx, pairs, record, errors).await;
        }
        match crate::tax::fiscal_year_overlapping(db, None, f, t, record).await {
            Ok(true) => {
                let errors = vec![vortex_plugin_sdk::framework::form::FieldError {
                    field: "date_from".into(),
                    message: "Overlaps an existing fiscal year".into(),
                }];
                return rerender_fy(state, db, user, db_ctx, pairs, record, errors).await;
            }
            Ok(false) => {}
            Err(e) => {
                error!("overlap check failed: {e}");
                return (StatusCode::INTERNAL_SERVER_ERROR, "Validation failed").into_response();
            }
        }
    }

    match execute_form_save(db, &fiscal_year_form(), pairs, record).await {
        Ok(SaveOutcome::Saved(id)) => {
            audit_setup(state, user, db_ctx, "acc_fiscal_year", id).await;
            Redirect::to("/accounting/fiscal-years").into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let mode = if record.is_some() { FormMode::Edit } else { FormMode::Create };
            let rid = record.map(|r| r.to_string());
            let form =
                render_form(db, &fiscal_year_form(), mode, rid.as_deref(), &values, &errors).await;
            let sidebar = render_sidebar(state, user, db_ctx);
            Html(page_shell(&sidebar, "Fiscal Year", &form)).into_response()
        }
        Err(e) => {
            error!("fiscal year save failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response()
        }
    }
}

async fn rerender_fy(
    state: &AppState,
    db: &vortex_plugin_sdk::sqlx::PgPool,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    pairs: &[(String, String)],
    record: Option<Uuid>,
    errors: Vec<vortex_plugin_sdk::framework::form::FieldError>,
) -> Response {
    let mut values = vortex_plugin_sdk::framework::form::FormValues::new();
    for f in fiscal_year_form().fields() {
        if let Some((_, v)) = pairs.iter().rev().find(|(k, _)| k == &f.name) {
            values.insert(f.name.clone(), v.trim().to_string());
        }
    }
    let mode = if record.is_some() { FormMode::Edit } else { FormMode::Create };
    let rid = record.map(|r| r.to_string());
    let form = render_form(db, &fiscal_year_form(), mode, rid.as_deref(), &values, &errors).await;
    let sidebar = render_sidebar(state, user, db_ctx);
    Html(page_shell(&sidebar, "Fiscal Year", &form)).into_response()
}

async fn create_fiscal_year(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    save_fiscal_year(&state, &db, &user, &db_ctx, &pairs, None).await
}

async fn edit_fiscal_year(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let values = match load_record(&db, &fiscal_year_form(), id).await {
        Ok(Some(v)) => v,
        _ => return (StatusCode::NOT_FOUND, "Fiscal year not found").into_response(),
    };
    let st: Option<String> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT state FROM acc_fiscal_year WHERE id = $1")
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();
    let state_note = if st.as_deref() == Some("closed") {
        "<div class=\"alert alert-warning mb-4\"><span>This fiscal year is closed — postings into it are rejected.</span></div>"
    } else {
        ""
    };
    let form =
        render_form(&db, &fiscal_year_form(), FormMode::Edit, Some(&id.to_string()), &values, &[])
            .await;
    let content = format!(
        "<div class=\"mb-2\"><a href=\"/accounting/fiscal-years\" class=\"link link-hover text-sm\">← Fiscal Years</a></div>{state_note}{form}",
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Fiscal Year", &content)).into_response()
}

async fn update_fiscal_year(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    save_fiscal_year(&state, &db, &user, &db_ctx, &pairs, Some(id)).await
}

// ─── Settings (company tax identity + defaults) ─────────────────────────

async fn settings_row_id(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_config ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten()
}

async fn edit_settings(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let Some(id) = settings_row_id(&db).await else {
        return (StatusCode::NOT_FOUND, "No accounting configuration row").into_response();
    };
    let values = match load_record(&db, &settings_form(), id).await {
        Ok(Some(v)) => v,
        _ => return (StatusCode::NOT_FOUND, "No accounting configuration row").into_response(),
    };
    let form =
        render_form(&db, &settings_form(), FormMode::Edit, Some(&id.to_string()), &values, &[])
            .await;
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Accounting Settings", &form)).into_response()
}

async fn save_settings(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match execute_form_save(&db, &settings_form(), &pairs, Some(id)).await {
        Ok(SaveOutcome::Saved(_)) => {
            audit_setup(&state, &user, &db_ctx, "acc_config", id).await;
            Redirect::to("/accounting/settings").into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let form = render_form(
                &db, &settings_form(), FormMode::Edit, Some(&id.to_string()), &values, &errors,
            )
            .await;
            let sidebar = render_sidebar(&state, &user, &db_ctx);
            Html(page_shell(&sidebar, "Accounting Settings", &form)).into_response()
        }
        Err(e) => {
            error!("settings save failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response()
        }
    }
}

// ─── Partner tax profiles ────────────────────────────────────────────────

async fn list_tax_profiles(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT ct.id AS contact_id, ct.name, p.tin, p.sst_registration, p.einvoice_optout \
         FROM contacts ct \
         LEFT JOIN acc_partner_tax_profile p ON p.contact_id = ct.id \
         WHERE COALESCE(ct.active, true) \
         ORDER BY ct.name LIMIT 500",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let esc = vortex_plugin_sdk::framework::html_escape;
    let mut trs = String::new();
    for r in &rows {
        let cid: Uuid = r.get("contact_id");
        let tin: Option<String> = r.try_get("tin").ok().flatten();
        let optout: Option<bool> = r.try_get("einvoice_optout").ok().flatten();
        trs.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location='/accounting/tax-profiles/by-contact/{cid}'\">\
             <td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
            esc(&r.get::<String, _>("name")),
            esc(tin.as_deref().unwrap_or("—")),
            esc(r.get::<Option<String>, _>("sst_registration").as_deref().unwrap_or("—")),
            if optout == Some(true) { "consolidated" } else { "" },
        ));
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Partner Tax Profiles</h1>
        <div class="card bg-base-100 shadow"><div class="card-body p-4">
        <table class="table table-sm"><thead><tr><th>Partner</th><th>TIN</th>
        <th>SST No.</th><th>e-Invoice</th></tr></thead><tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Partner Tax Profiles", &content)).into_response()
}

async fn profile_by_contact(
    Db(db): Db,
    Path(contact_id): Path<Uuid>,
) -> Response {
    // Upsert the profile row, then redirect to its edit form.
    let _ = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_partner_tax_profile (contact_id) \
         SELECT $1 WHERE NOT EXISTS \
            (SELECT 1 FROM acc_partner_tax_profile WHERE contact_id = $1)",
    )
    .bind(contact_id)
    .execute(&db)
    .await;
    let id: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_partner_tax_profile WHERE contact_id = $1 LIMIT 1",
    )
    .bind(contact_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    match id {
        Some(id) => Redirect::to(&format!("/accounting/tax-profiles/{id}")).into_response(),
        None => (StatusCode::NOT_FOUND, "Contact not found").into_response(),
    }
}

async fn edit_tax_profile(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let partner: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT ct.name FROM acc_partner_tax_profile p \
         JOIN contacts ct ON ct.id = p.contact_id WHERE p.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(partner) = partner else {
        return (StatusCode::NOT_FOUND, "Profile not found").into_response();
    };
    let values = match load_record(&db, &tax_profile_form(), id).await {
        Ok(Some(v)) => v,
        _ => return (StatusCode::NOT_FOUND, "Profile not found").into_response(),
    };
    let form =
        render_form(&db, &tax_profile_form(), FormMode::Edit, Some(&id.to_string()), &values, &[])
            .await;
    // Banner from a just-run LHDN TIN action (?tin_check=…).
    let esc = vortex_plugin_sdk::framework::html_escape;
    let banner = match q.get("tin_check").map(String::as_str) {
        Some("found") => r#"<div class="alert alert-success mb-3">TIN found at LHDN and filled in below — save to keep it.</div>"#.to_string(),
        Some("notfound") => r#"<div class="alert alert-warning mb-3">LHDN has no TIN matching this ID / name.</div>"#.to_string(),
        Some("valid") => r#"<div class="alert alert-success mb-3">LHDN confirms this TIN belongs to this ID.</div>"#.to_string(),
        Some("invalid") => r#"<div class="alert alert-error mb-3">LHDN says this TIN does NOT match this ID — check both.</div>"#.to_string(),
        _ => q
            .get("tin_error")
            .map(|m| format!(r#"<div class="alert alert-error mb-3">{}</div>"#, esc(m)))
            .unwrap_or_default(),
    };
    let lhdn_actions = format!(
        r#"<div class="card bg-base-100 shadow mt-4 max-w-2xl"><div class="card-body p-4">
<h2 class="font-bold mb-1">LHDN Taxpayer Lookup</h2>
<p class="text-xs opacity-60 mb-2">Uses the MyInvois API credentials from e-Invoice Settings. Save the profile first — the lookup reads the stored ID type + value.</p>
<div class="flex gap-2">
<form method="post" action="/accounting/tax-profiles/{id}/search-tin"><button class="btn btn-sm btn-outline">Search TIN by ID</button></form>
<form method="post" action="/accounting/tax-profiles/{id}/validate-tin"><button class="btn btn-sm btn-outline">Validate stored TIN</button></form>
</div></div></div>"#,
    );
    let content = format!(
        "<div class=\"mb-2\"><a href=\"/accounting/tax-profiles\" class=\"link link-hover text-sm\">← Partner Tax Profiles</a></div>\
         <p class=\"text-lg font-semibold mb-2\">{}</p>{banner}{form}{lhdn_actions}",
        esc(&partner),
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Partner Tax Profile", &content)).into_response()
}

async fn search_tin_action(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match crate::einvois::flow::search_tin_for_profile(&db, id).await {
        Ok(Some(tin)) => {
            if let Err(e) = vortex_plugin_sdk::sqlx::query(
                "UPDATE acc_partner_tax_profile SET tin = $2 WHERE id = $1",
            )
            .bind(id)
            .bind(&tin)
            .execute(&db)
            .await
            {
                error!("tin save failed: {e}");
                return Redirect::to(&format!(
                    "/accounting/tax-profiles/{id}?tin_error=found+but+saving+failed"
                ))
                .into_response();
            }
            audit_setup(&state, &user, &db_ctx, "acc_tin_found", id).await;
            Redirect::to(&format!("/accounting/tax-profiles/{id}?tin_check=found")).into_response()
        }
        Ok(None) => {
            Redirect::to(&format!("/accounting/tax-profiles/{id}?tin_check=notfound")).into_response()
        }
        Err(e) => Redirect::to(&format!(
            "/accounting/tax-profiles/{id}?tin_error={}",
            urlencoding_lite(&e)
        ))
        .into_response(),
    }
}

async fn validate_tin_action(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match crate::einvois::flow::validate_tin_for_profile(&db, id).await {
        Ok(true) => {
            audit_setup(&state, &user, &db_ctx, "acc_tin_validated", id).await;
            Redirect::to(&format!("/accounting/tax-profiles/{id}?tin_check=valid")).into_response()
        }
        Ok(false) => {
            Redirect::to(&format!("/accounting/tax-profiles/{id}?tin_check=invalid")).into_response()
        }
        Err(e) => Redirect::to(&format!(
            "/accounting/tax-profiles/{id}?tin_error={}",
            urlencoding_lite(&e)
        ))
        .into_response(),
    }
}

/// Percent-encode enough for a query-string value (no external dep).
fn urlencoding_lite(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' => (b as char).to_string(),
            b' ' => "+".to_string(),
            _ => format!("%{b:02X}"),
        })
        .collect()
}

async fn save_tax_profile(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match execute_form_save(&db, &tax_profile_form(), &pairs, Some(id)).await {
        Ok(SaveOutcome::Saved(_)) => {
            audit_setup(&state, &user, &db_ctx, "acc_partner_tax_profile", id).await;
            Redirect::to("/accounting/tax-profiles").into_response()
        }
        Ok(SaveOutcome::Invalid { values, errors }) => {
            let form = render_form(
                &db, &tax_profile_form(), FormMode::Edit, Some(&id.to_string()), &values, &errors,
            )
            .await;
            let sidebar = render_sidebar(&state, &user, &db_ctx);
            Html(page_shell(&sidebar, "Partner Tax Profile", &form)).into_response()
        }
        Err(e) => {
            error!("tax profile save failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response()
        }
    }
}

// ─── Shared ──────────────────────────────────────────────────────────────

async fn audit_setup(
    state: &AppState,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    resource: &str,
    id: Uuid,
) {
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource(resource, id.to_string());
    if let Err(e) = state.audit.log(entry).await {
        error!("audit write failed: {e}");
    }
}
