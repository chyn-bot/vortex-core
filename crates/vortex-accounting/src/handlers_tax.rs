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
        .route("/accounting/tax-profiles/by-contact/{contact_id}/save", post(save_profile_inline))
        .route(
            "/accounting/tax-profiles/by-contact/{contact_id}/search-tin",
            post(search_tin_inline),
        )
        .route("/accounting/partner-banks/{contact_id}/add", post(add_partner_bank))
        .route("/accounting/partner-banks/{bank_id}/delete", post(delete_partner_bank))
        .route("/accounting/settings/logo", post(upload_logo))
        .route("/accounting/company-logo", get(serve_logo))
        .route("/accounting/banks", get(banks_page))
        .route("/accounting/banks", post(bank_create))
        .route("/accounting/banks/{id}/toggle", post(bank_toggle))
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
        .section("Registered Address & Contact (appears on e-invoices as the seller)")
        .field(FormField::text("company_address1", "Address Line 1").placeholder("Level 10, Menara ABC"))
        .field(FormField::text("company_address2", "Address Line 2").placeholder("Jalan Sultan Ismail"))
        .field(FormField::text("company_postcode", "Postcode").placeholder("50450"))
        .field(FormField::text("company_city", "City").placeholder("Kuala Lumpur"))
        .field(FormField::select("company_state_code", "State (LHDN code)", &[
            ("01", "01 — Johor"),
            ("02", "02 — Kedah"),
            ("03", "03 — Kelantan"),
            ("04", "04 — Melaka"),
            ("05", "05 — Negeri Sembilan"),
            ("06", "06 — Pahang"),
            ("07", "07 — Pulau Pinang"),
            ("08", "08 — Perak"),
            ("09", "09 — Perlis"),
            ("10", "10 — Selangor"),
            ("11", "11 — Terengganu"),
            ("12", "12 — Sabah"),
            ("13", "13 — Sarawak"),
            ("14", "14 — W.P. Kuala Lumpur"),
            ("15", "15 — W.P. Labuan"),
            ("16", "16 — W.P. Putrajaya"),
            ("17", "17 — Not applicable"),
        ]).default("14"))
        .field(FormField::text("company_country_code", "Country Code").default("MYS")
            .help("ISO 3166-1 alpha-3, MYS for Malaysia"))
        .field(FormField::text("company_phone", "Phone").placeholder("0312345678")
            .help("LHDN requires a contact number on the seller party"))
        .field(FormField::text("company_email", "Email"))
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
        .section("Control Accounts")
        .field(FormField::many2one("receivable_account_id", "Receivable Account", "acc_account")
            .help("Partner-specific AR control account (e.g. 1210 Non-trade Receivables); empty = company default"))
        .field(FormField::many2one("payable_account_id", "Payable Account", "acc_account")
            .help("Partner-specific AP control account (e.g. 2010 Non-trade Payables); empty = company default"))
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
    // Logo upload card (multipart, outside the form engine).
    let has_logo = matches!(state.files.get(&db_ctx.db_name, LOGO_KEY).await, Ok(Some(_)));
    let preview = if has_logo {
        r#"<img src="/accounting/company-logo" alt="Current logo" class="max-h-16 mb-2 rounded"/>"#
    } else {
        r#"<p class="text-sm opacity-60 mb-2">No logo yet.</p>"#
    };
    let logo_card = format!(
        r#"<div class="card bg-base-100 shadow mt-4 max-w-2xl"><div class="card-body p-4">
<h2 class="font-bold mb-1">Company Logo</h2>
<p class="text-xs opacity-60 mb-2">Printed on invoices, credit notes and other documents. PNG or JPEG, up to 512 KB.</p>
{preview}
<form method="post" action="/accounting/settings/logo" enctype="multipart/form-data" data-no-guard class="flex gap-2 items-center">
<input type="file" name="logo" accept="image/png,image/jpeg" required class="file-input file-input-bordered file-input-sm"/>
<button class="btn btn-sm btn-primary">Upload</button>
</form></div></div>"#,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Accounting Settings", &format!("{form}{logo_card}")))
        .into_response()
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
            // Land back on the customer, not on an accounting list —
            // the profile is an extension of the contact record.
            let contact: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT contact_id FROM acc_partner_tax_profile WHERE id = $1",
            )
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();
            match contact {
                Some(c) => Redirect::to(&format!("/contacts/{c}")).into_response(),
                None => Redirect::to("/accounting/tax-profiles").into_response(),
            }
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

/// Upsert the profile row for a contact and write the inline-panel
/// fields. Returns the profile id.
pub(crate) async fn upsert_profile_fields(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    contact_id: Uuid,
    pairs: &[(String, String)],
) -> Result<Uuid, String> {
    let get = |k: &str| {
        pairs
            .iter()
            .rev()
            .find(|(pk, _)| pk == k)
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    };
    let id_type = get("id_type").filter(|t| matches!(*t, "BRN" | "NRIC" | "PASSPORT" | "ARMY"));
    let optout = pairs.iter().any(|(k, _)| k == "einvoice_optout");
    // The unique key is (contact_id, company_id) with nullable company,
    // so ON CONFLICT can't target contact_id — insert-if-missing, then
    // update (same pattern as profile_by_contact).
    vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_partner_tax_profile (contact_id) \
         SELECT $1 WHERE NOT EXISTS \
            (SELECT 1 FROM acc_partner_tax_profile WHERE contact_id = $1)",
    )
    .bind(contact_id)
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;
    let uuid = |k: &str| get(k).and_then(|s| s.parse::<Uuid>().ok());
    let id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "UPDATE acc_partner_tax_profile SET \
            tin = $2, id_type = $3, id_value = $4, sst_registration = $5, \
            msic_code = $6, einvoice_email = $7, einvoice_optout = $8, \
            receivable_account_id = $9, payable_account_id = $10 \
         WHERE contact_id = $1 RETURNING id",
    )
    .bind(contact_id)
    .bind(get("tin"))
    .bind(id_type)
    .bind(get("id_value"))
    .bind(get("sst_registration"))
    .bind(get("msic_code"))
    .bind(get("einvoice_email"))
    .bind(optout)
    .bind(uuid("receivable_account_id"))
    .bind(uuid("payable_account_id"))
    .fetch_one(db)
    .await
    .map_err(|e| e.to_string())?;
    Ok(id)
}

/// POST from the inline panel on the contact page: save and stay there.
async fn save_profile_inline(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(contact_id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    match upsert_profile_fields(&db, contact_id, &pairs).await {
        Ok(id) => {
            audit_setup(&state, &user, &db_ctx, "acc_partner_tax_profile", id).await;
            Redirect::to(&format!("/contacts/{contact_id}")).into_response()
        }
        Err(e) => {
            error!("inline tax profile save failed: {e}");
            (StatusCode::UNPROCESSABLE_ENTITY, "Save failed").into_response()
        }
    }
}

/// Inline "Search TIN": save the form first (the button submits the
/// same fields), then look up LHDN and store the TIN. Success returns
/// to the contact; failures land on the full profile page, which
/// renders the explanation banner.
async fn search_tin_inline(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(contact_id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let profile = match upsert_profile_fields(&db, contact_id, &pairs).await {
        Ok(p) => p,
        Err(e) => {
            error!("inline tax profile save failed: {e}");
            return (StatusCode::UNPROCESSABLE_ENTITY, "Save failed").into_response();
        }
    };
    match crate::einvois::flow::search_tin_for_profile(&db, profile).await {
        Ok(Some(tin)) => {
            let _ = vortex_plugin_sdk::sqlx::query(
                "UPDATE acc_partner_tax_profile SET tin = $2 WHERE id = $1",
            )
            .bind(profile)
            .bind(&tin)
            .execute(&db)
            .await;
            audit_setup(&state, &user, &db_ctx, "acc_tin_found", profile).await;
            Redirect::to(&format!("/contacts/{contact_id}")).into_response()
        }
        Ok(None) => Redirect::to(&format!(
            "/accounting/tax-profiles/{profile}?tin_check=notfound"
        ))
        .into_response(),
        Err(e) => Redirect::to(&format!(
            "/accounting/tax-profiles/{profile}?tin_error={}",
            urlencoding_lite(&e)
        ))
        .into_response(),
    }
}

/// Add a bank account from the contact page's Accounting panel. The
/// button submits the whole record-form, so the accounting/tax fields
/// are saved too before adding the bank row — nothing typed is lost.
async fn add_partner_bank(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(contact_id): Path<Uuid>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    if pairs.iter().any(|(k, _)| k == "__acc_tax_panel") {
        if let Err(e) = upsert_profile_fields(&db, contact_id, &pairs).await {
            error!("profile save during bank add failed: {e}");
        }
    }
    let get = |k: &str| {
        pairs
            .iter()
            .rev()
            .find(|(pk, _)| pk == k)
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    };
    let bank_id: Option<Uuid> = get("bank_id").and_then(|s| s.parse().ok());
    let (Some(bank_id), Some(account_number)) = (bank_id, get("bank_account_number")) else {
        return (
            StatusCode::BAD_REQUEST,
            "Pick a bank and enter the account number",
        )
            .into_response();
    };
    // Name + SWIFT flow from the bank master (Setup ▸ Banks).
    let bank = vortex_plugin_sdk::sqlx::query(
        "SELECT name, swift_code FROM acc_bank WHERE id = $1 AND active",
    )
    .bind(bank_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(bank) = bank else {
        return (StatusCode::BAD_REQUEST, "Unknown or inactive bank").into_response();
    };
    let bank_name: String = bank.get("name");
    let swift: Option<String> = bank.get("swift_code");
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_partner_bank \
            (contact_id, bank_id, bank_name, account_number, account_holder, swift_code, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(contact_id)
    .bind(bank_id)
    .bind(&bank_name)
    .bind(account_number)
    .bind(get("bank_account_holder"))
    .bind(swift)
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!("partner bank insert failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response();
    }
    // Contact history: show what was added.
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("contact", contact_id.to_string())
        .with_details(vortex_plugin_sdk::serde_json::json!({ "changes": [{
            "field": "Bank Account",
            "from": "",
            "to": format!("{bank_name} {account_number}"),
        }]}));
    let _ = state.audit.log(entry).await;
    Redirect::to(&format!("/contacts/{contact_id}")).into_response()
}

async fn delete_partner_bank(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(bank_id): Path<Uuid>,
) -> Response {
    let row = vortex_plugin_sdk::sqlx::query(
        "DELETE FROM acc_partner_bank WHERE id = $1 \
         RETURNING contact_id, bank_name, account_number",
    )
    .bind(bank_id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let Some(row) = row else {
        return (StatusCode::NOT_FOUND, "Bank account not found").into_response();
    };
    let contact_id: Uuid = row.get("contact_id");
    let entry = AuditEntry::new(AuditAction::RecordUpdated, AuditSeverity::Info)
        .with_user(UserId(user.id))
        .with_username(&user.username)
        .with_database(&db_ctx.db_name)
        .with_resource("contact", contact_id.to_string())
        .with_details(vortex_plugin_sdk::serde_json::json!({ "changes": [{
            "field": "Bank Account",
            "from": format!("{} {}", row.get::<String, _>("bank_name"), row.get::<String, _>("account_number")),
            "to": "",
        }]}));
    let _ = state.audit.log(entry).await;
    Redirect::to(&format!("/contacts/{contact_id}")).into_response()
}

// ─── Company logo (FileStore-backed, printed on documents) ───────────────

const LOGO_KEY: &str = "company/logo";
const LOGO_MAX_BYTES: usize = 512 * 1024;

/// PNG or JPEG by magic bytes; anything else is refused.
fn logo_content_type(data: &[u8]) -> Option<&'static str> {
    if data.starts_with(&[0x89, b'P', b'N', b'G']) {
        Some("image/png")
    } else if data.starts_with(&[0xFF, 0xD8, 0xFF]) {
        Some("image/jpeg")
    } else {
        None
    }
}

async fn upload_logo(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    mut multipart: vortex_plugin_sdk::axum::extract::Multipart,
) -> Response {
    let mut data: Option<Vec<u8>> = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        if field.name() == Some("logo") {
            if let Ok(bytes) = field.bytes().await {
                data = Some(bytes.to_vec());
            }
        }
    }
    let Some(data) = data.filter(|d| !d.is_empty()) else {
        return flash_redirect("/accounting/settings", FlashKind::Error, "No file received.");
    };
    if data.len() > LOGO_MAX_BYTES {
        return flash_redirect(
            "/accounting/settings",
            FlashKind::Error,
            "Logo too large — keep it under 512 KB.",
        );
    }
    let Some(content_type) = logo_content_type(&data) else {
        return flash_redirect(
            "/accounting/settings",
            FlashKind::Error,
            "Unsupported format — upload a PNG or JPEG.",
        );
    };
    if let Err(e) = state
        .files
        .put(&db_ctx.db_name, LOGO_KEY, &data, Some(content_type))
        .await
    {
        error!("logo store failed: {e}");
        return flash_redirect("/accounting/settings", FlashKind::Error, "Storing the logo failed.");
    }
    audit_setup(&state, &user, &db_ctx, "acc_company_logo", Uuid::nil()).await;
    flash_redirect(
        "/accounting/settings",
        FlashKind::Success,
        "Logo saved — it now prints on invoices and other documents.",
    )
}

async fn serve_logo(
    State(state): State<Arc<AppState>>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    match state.files.get(&db_ctx.db_name, LOGO_KEY).await {
        Ok(Some(data)) => {
            let ct = logo_content_type(&data).unwrap_or("application/octet-stream");
            (
                [
                    (vortex_plugin_sdk::axum::http::header::CONTENT_TYPE, ct),
                    (
                        vortex_plugin_sdk::axum::http::header::CACHE_CONTROL,
                        "private, max-age=300",
                    ),
                ],
                data,
            )
                .into_response()
        }
        _ => (StatusCode::NOT_FOUND, "No logo uploaded").into_response(),
    }
}

// ─── Bank master ─────────────────────────────────────────────────────────

async fn banks_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT b.id, b.name, b.swift_code, b.active, \
                (SELECT COUNT(*) FROM acc_partner_bank pb WHERE pb.bank_id = b.id) AS in_use \
         FROM acc_bank b ORDER BY b.name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut trs = String::new();
    for r in &rows {
        let id: Uuid = r.get("id");
        let active: bool = r.get("active");
        trs.push_str(&format!(
            "<tr><td>{}</td><td class=\"font-mono\">{}</td><td>{}</td>\
             <td><span class=\"badge badge-sm {}\">{}</span></td>\
             <td><form method=\"post\" action=\"/accounting/banks/{id}/toggle\">\
             <button class=\"btn btn-xs btn-ghost\">{}</button></form></td></tr>",
            esc(&r.get::<String, _>("name")),
            esc(r.get::<Option<String>, _>("swift_code").as_deref().unwrap_or("—")),
            r.get::<i64, _>("in_use"),
            if active { "badge-success" } else { "badge-ghost" },
            if active { "active" } else { "inactive" },
            if active { "Deactivate" } else { "Activate" },
        ));
    }
    let content = format!(
        r##"<h1 class="text-2xl font-bold mb-6">Banks</h1>
<div class="card bg-base-100 shadow mb-4"><div class="card-body p-4">
<form method="post" action="/accounting/banks" class="flex gap-3 items-end flex-wrap">
<label class="form-control"><span class="label-text mb-1">Name</span>
<input name="name" required class="input input-bordered input-sm" placeholder="Bank of Nova Scotia"/></label>
<label class="form-control"><span class="label-text mb-1">SWIFT / BIC</span>
<input name="swift_code" class="input input-bordered input-sm" placeholder="NOSCMYKL"/></label>
<button class="btn btn-primary btn-sm">Add Bank</button>
</form>
<p class="text-xs opacity-60 mt-2">The bank picker on contact records lists active banks; the SWIFT code fills in automatically. Malaysian banks are pre-seeded.</p>
</div></div>
<div class="card bg-base-100 shadow"><div class="card-body p-4">
<table class="table table-sm"><thead><tr><th>Bank</th><th>SWIFT</th><th>In use</th><th>Status</th><th></th></tr></thead>
<tbody>{trs}</tbody></table></div></div>"##,
    );
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Banks", &content)).into_response()
}

async fn bank_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Form(pairs): Form<Vec<(String, String)>>,
) -> Response {
    let get = |k: &str| {
        pairs
            .iter()
            .rev()
            .find(|(pk, _)| pk == k)
            .map(|(_, v)| v.trim())
            .filter(|v| !v.is_empty())
    };
    let Some(name) = get("name") else {
        return (StatusCode::BAD_REQUEST, "name required").into_response();
    };
    match vortex_plugin_sdk::sqlx::query_scalar::<_, Uuid>(
        "INSERT INTO acc_bank (name, swift_code) VALUES ($1, $2) \
         ON CONFLICT (name) DO UPDATE SET active = TRUE, \
            swift_code = COALESCE(EXCLUDED.swift_code, acc_bank.swift_code) \
         RETURNING id",
    )
    .bind(name)
    .bind(get("swift_code"))
    .fetch_one(&db)
    .await
    {
        Ok(id) => {
            audit_setup(&state, &user, &db_ctx, "acc_bank", id).await;
            Redirect::to("/accounting/banks").into_response()
        }
        Err(e) => {
            error!("bank create failed: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, "Save failed").into_response()
        }
    }
}

async fn bank_toggle(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(e) =
        vortex_plugin_sdk::sqlx::query("UPDATE acc_bank SET active = NOT active WHERE id = $1")
            .bind(id)
            .execute(&db)
            .await
    {
        error!("bank toggle failed: {e}");
        return (StatusCode::INTERNAL_SERVER_ERROR, "Toggle failed").into_response();
    }
    audit_setup(&state, &user, &db_ctx, "acc_bank", id).await;
    Redirect::to("/accounting/banks").into_response()
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
