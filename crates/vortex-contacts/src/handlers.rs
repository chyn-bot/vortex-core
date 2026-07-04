//! Contacts CRUD handlers — simple list + create demonstrating
//! routes, audit logging, and sequence generation through the
//! core primitives, rendered inside the platform's sidebar shell.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::serde_json::json;
use vortex_plugin_sdk::tracing::{error, info};
use vortex_plugin_sdk::uuid::Uuid;

/// The contact sequence spec — auto-generated codes like `CNT/000001`.
const CONTACT_SEQ: vortex_plugin_sdk::orm::sequence::SequenceSpec =
    vortex_plugin_sdk::orm::sequence::SequenceSpec::new("contacts.code", "CNT")
        .with_padding(6);

/// Build the contacts route set.
pub fn contacts_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/contacts", get(list_contacts))
        .route("/contacts/new", get(new_contact_form))
        .route("/contacts/create", post(create_contact))
        .route("/contacts/{id}", get(edit_contact))
        .route("/contacts/{id}", post(update_contact))
        .route("/contacts/{id}/archive", post(archive_contact))
        .route("/contacts/{id}/unarchive", post(unarchive_contact))
        .route("/contacts/{id}/status/{state}", post(change_contact_status))
}

/// Wrap page content in the platform's full HTML shell with sidebar,
/// navbar, DaisyUI theme, and mobile-responsive layout.
fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
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

/// GET /contacts — list all contacts with search, filter, sort, pagination.
async fn list_contacts(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };

    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = vortex_plugin_sdk::framework::build_sidebar(
        "contacts",
        display_name,
        &initials,
        &installed,
        user.roles.contains(&"system_administrator".to_string()),
        &state.plugin_registry,
        &user.roles,
    );

    let config = ListConfig::new("Contacts", "contacts")
        .custom_from(
            "contacts c \
             LEFT JOIN countries co ON co.id = c.country_id \
             LEFT JOIN states st ON st.id = c.state_id"
        )
        .custom_select(
            "c.id, c.code, c.name, c.email, c.phone, c.mobile, \
             c.contact_type, c.is_company, c.city, \
             co.name AS country_name, st.name AS state_name, \
             c.active"
        )
        .column(ListColumn::new("code", "Code").sortable().code().sql_expr("c.code"))
        .column(ListColumn::new("name", "Name").sortable().searchable().sql_expr("c.name"))
        .column(ListColumn::new("email", "Email").searchable().sql_expr("c.email"))
        .column(ListColumn::new("phone", "Phone").sql_expr("c.phone"))
        .column(ListColumn::new("mobile", "Mobile").sql_expr("c.mobile"))
        .column(
            ListColumn::new("contact_type", "Type")
                .sortable()
                .filterable(&[
                    ("customer", "Customer"),
                    ("supplier", "Supplier"),
                    ("both", "Both"),
                    ("other", "Other"),
                ])
                .badge(&[
                    ("customer", "Customer", "badge-info"),
                    ("supplier", "Supplier", "badge-secondary"),
                    ("both", "Both", "badge-accent"),
                    ("other", "Other", "badge-ghost"),
                ])
                .sql_expr("c.contact_type"),
        )
        .column(ListColumn::new("city", "City").searchable().sql_expr("c.city"))
        .column(ListColumn::new("state_name", "State").sortable().sql_expr("st.name"))
        .column(ListColumn::new("country_name", "Country").sortable().searchable().sql_expr("co.name"))
        .column(
            ListColumn::new("is_company", "Company").bool_badge(
                "Company",
                "badge-primary",
                "Individual",
                "badge-ghost",
            ).sql_expr("c.is_company"),
        )
        .column(
            ListColumn::new("active", "Status").bool_badge(
                "Active",
                "badge-success",
                "Archived",
                "badge-warning",
            )
            .sql_expr("c.active"),
        )
        .detail_url("/contacts/{id}")
        .create("New Contact", "/contacts/new")
        .pivot_url("/pivot/contacts?rows=contact_type")
        .default_sort("name")
        .group_by_options(&[
            ("contact_type", "Type"),
            ("country_name", "Country"),
            ("active", "Status"),
        ]);

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "contacts list query failed");
            return Html("<h1>Failed to load contacts</h1>").into_response();
        }
    };

    let list_html = render_list(&config, &result, &params, "/contacts");

    // Create modal (stays outside the list component — it's page-specific)
    let create_modal = r#"<!-- Quick-create modal (linked from the list's create button) -->
<div id="contacts-new" style="display:none"></div>"#;

    let content = format!("{}{}", list_html, create_modal);
    Html(page_shell(&sidebar, "Contacts", &content)).into_response()
}

/// GET /contacts/new — create form. Mirrors the edit form's full field set so
/// every column can be populated at creation time, not only after first save.
/// (The status bar, approval panel, audit history, and delete action are
/// intentionally absent — they only apply once the record exists.)
async fn new_contact_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = vortex_plugin_sdk::framework::build_sidebar(
        "contacts", display_name, &initials, &installed,
        user.roles.contains(&"system_administrator".to_string()),
        &state.plugin_registry, &user.roles,
    );

    // Country dropdown, same source as the edit form. States load on demand
    // via /api/states/{country_id} once a country is picked.
    let countries_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, alpha3, name FROM countries WHERE active = true ORDER BY name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut country_options = String::from(r#"<option value="">-- Select Country --</option>"#);
    for cr in &countries_rows {
        let cid: Uuid = cr.get("id");
        let cname: String = cr.get("name");
        let ccode: Option<String> = cr.try_get("alpha3").ok();
        country_options.push_str(&format!(
            r#"<option value="{id}">{name} ({code})</option>"#,
            id = cid,
            name = vortex_plugin_sdk::framework::html_escape(&cname),
            code = vortex_plugin_sdk::framework::html_escape(ccode.as_deref().unwrap_or("")),
        ));
    }

    let content = format!(
        r#"<a href="/contacts" class="btn btn-ghost btn-sm mb-2">← Back to Contacts</a>
<h1 class="text-2xl font-bold mb-6">New Contact</h1>

<form method="POST" action="/contacts/create">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

<!-- Left column -->
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg mb-4">General</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" required/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="contact_type" class="select select-bordered select-sm">
<option value="customer">Customer</option>
<option value="supplier">Supplier</option>
<option value="both">Both</option>
<option value="other">Other</option>
</select>
</div>
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="is_company" class="checkbox checkbox-sm"/>
<span class="label-text">Is a Company</span>
</label>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">VAT Number</span></label>
<input name="vat_number" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Credit Limit</span></label>
<input name="credit_limit" type="number" step="0.01" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" checked/>
<span class="label-text">Active</span>
</label>
</div>
</div>
</div>

<!-- Right column -->
<div class="space-y-6">
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg mb-4">Contact Info</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Email</span></label>
<input name="email" type="email" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Phone</span></label>
<input name="phone" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Mobile</span></label>
<input name="mobile" class="input input-bordered input-sm"/>
</div>
</div>
</div>

<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg mb-4">Address</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Street</span></label>
<input name="street" class="input input-bordered input-sm" placeholder="Address line 1"/>
<input name="street2" class="input input-bordered input-sm mt-1" placeholder="Address line 2"/>
<input name="street3" class="input input-bordered input-sm mt-1" placeholder="Address line 3"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Country</span></label>
<select name="country_id" id="country-select" class="select select-bordered select-sm"
  onchange="loadStates(this.value)">
{country_options}
</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">State / Province</span></label>
<select name="state_id" id="state-select" class="select select-bordered select-sm">
<option value="">-- Select State --</option>
</select>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">City</span></label>
<input name="city" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">ZIP</span></label>
<input name="zip" class="input input-bordered input-sm"/>
</div>
</div>
<script>
async function loadStates(countryId) {{
  var sel = document.getElementById('state-select');
  sel.innerHTML = '<option value="">Loading...</option>';
  if (!countryId) {{
    sel.innerHTML = '<option value="">-- Select State --</option>';
    return;
  }}
  try {{
    var res = await fetch('/api/states/' + countryId);
    if (!res.ok) {{
      sel.innerHTML = '<option value="">Error loading states</option>';
      return;
    }}
    var states = await res.json();
    sel.innerHTML = '<option value="">-- Select State --</option>';
    for (var i = 0; i < states.length; i++) {{
      var opt = document.createElement('option');
      opt.value = states[i].id;
      opt.textContent = states[i].name + ' (' + states[i].code + ')';
      sel.appendChild(opt);
    }}
    if (states.length === 0) {{
      sel.innerHTML = '<option value="">No states available</option>';
    }}
  }} catch(e) {{
    sel.innerHTML = '<option value="">Error: ' + e.message + '</option>';
  }}
}}
</script>
</div>
</div>
</div>
</div>

<div class="form-control mt-4">
<label class="label"><span class="label-text">Notes</span></label>
<textarea name="notes" class="textarea textarea-bordered" rows="3"></textarea>
</div>

<div class="mt-6 flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Create</button>
<a href="/contacts" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</form>"#,
        country_options = country_options,
    );

    Html(page_shell(&sidebar, "New Contact", &content)).into_response()
}

/// POST /contacts/create — create a new contact with auto-generated
/// code and audit trail, then redirect back to the list.
async fn create_contact(
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
    let contact_type = form.get("contact_type").cloned().unwrap_or("customer".into());

    let country_id: Option<Uuid> = form
        .get("country_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());
    let state_id: Option<Uuid> = form
        .get("state_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    // Generate a unique contact code via the core sequence service.
    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &CONTACT_SEQ).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "sequence generation failed");
            return (
                vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate contact code",
            ).into_response();
        }
    };

    // Default company
    let company_id: Uuid = match vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM companies LIMIT 1",
    )
    .fetch_one(&db)
    .await
    {
        Ok(id) => id,
        Err(e) => {
            error!(error = %e, "failed to look up default company");
            return (
                vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "No company found",
            ).into_response();
        }
    };

    let contact_id = Uuid::now_v7();
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO contacts (id, company_id, name, code, email, phone, mobile, \
         street, street2, street3, city, zip, country_id, state_id, \
         contact_type, is_company, vat_number, credit_limit, notes, active, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, \
         $15, $16, $17, $18, $19, $20, $21)",
    )
    .bind(contact_id)
    .bind(company_id)
    .bind(&name)
    .bind(&code)
    .bind(form.get("email").filter(|s| !s.is_empty()))
    .bind(form.get("phone").filter(|s| !s.is_empty()))
    .bind(form.get("mobile").filter(|s| !s.is_empty()))
    .bind(form.get("street").filter(|s| !s.is_empty()))
    .bind(form.get("street2").filter(|s| !s.is_empty()))
    .bind(form.get("street3").filter(|s| !s.is_empty()))
    .bind(form.get("city").filter(|s| !s.is_empty()))
    .bind(form.get("zip").filter(|s| !s.is_empty()))
    .bind(country_id)
    .bind(state_id)
    .bind(&contact_type)
    .bind(form.contains_key("is_company"))
    .bind(form.get("vat_number").filter(|s| !s.is_empty()))
    .bind(
        form.get("credit_limit")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0),
    )
    .bind(form.get("notes").filter(|s| !s.is_empty()))
    .bind(form.contains_key("active"))
    .bind(user.id)
    .execute(&db)
    .await
    {
        error!(error = %e, "contact insert failed");
        return (
            vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to create contact: {e}"),
        ).into_response();
    }

    // Audit: log the creation via the WORM ledger.
    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("contact", contact_id.to_string())
    .with_resource_name(&name)
    .with_details(json!({
        "code": code,
        "contact_type": contact_type,
    }));
    if let Err(e) = state.audit.log(audit_entry).await {
        error!(error = %e, "audit log for contact creation failed");
    }

    info!(code = %code, name = %name, "contact created");

    // Redirect back to the list.
    vortex_plugin_sdk::axum::response::Redirect::to("/contacts").into_response()
}

/// GET /contacts/:id — edit form for an existing contact.
async fn edit_contact(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = vortex_plugin_sdk::framework::build_sidebar(
        "contacts", display_name, &initials, &installed,
        user.roles.contains(&"system_administrator".to_string()),
        &state.plugin_registry, &user.roles,
    );

    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT id, name, code, email, phone, mobile, \
         street, street2, street3, city, zip, \
         country_id, state_id, \
         contact_type, is_company, vat_number, credit_limit, notes, active, record_state \
         FROM contacts WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Contact not found").into_response(),
        Err(e) => {
            error!(error = %e, "contact fetch failed");
            return (vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR, "DB error").into_response();
        }
    };

    let name: String = row.get("name");
    let code: Option<String> = row.try_get("code").ok();
    let email: Option<String> = row.try_get("email").ok();
    let phone: Option<String> = row.try_get("phone").ok();
    let mobile: Option<String> = row.try_get("mobile").ok();
    let street: Option<String> = row.try_get("street").ok();
    let street2: Option<String> = row.try_get("street2").ok();
    let street3: Option<String> = row.try_get("street3").ok();
    let city: Option<String> = row.try_get("city").ok();
    let zip: Option<String> = row.try_get("zip").ok();
    let country_id: Option<Uuid> = row.try_get("country_id").ok();
    let state_id: Option<Uuid> = row.try_get("state_id").ok();
    let contact_type: String = row.get("contact_type");
    let is_company: bool = row.try_get("is_company").unwrap_or(false);
    let vat_number: Option<String> = row.try_get("vat_number").ok();
    let credit_limit: Option<f64> = row.try_get::<rust_decimal::Decimal, _>("credit_limit").ok().and_then(|d| d.to_string().parse().ok());
    let notes: Option<String> = row.try_get("notes").ok();
    let active: bool = row.try_get("active").unwrap_or(true);
    let record_state: String = row.try_get("record_state").unwrap_or_else(|_| "draft".to_string());

    // Load countries for dropdown
    let countries_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, alpha3, name FROM countries WHERE active = true ORDER BY name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut country_options = String::from(r#"<option value="">-- Select Country --</option>"#);
    for cr in &countries_rows {
        let cid: Uuid = cr.get("id");
        let cname: String = cr.get("name");
        let ccode: Option<String> = cr.try_get("alpha3").ok();
        let selected = if country_id == Some(cid) { " selected" } else { "" };
        country_options.push_str(&format!(
            r#"<option value="{id}"{sel}>{name} ({code})</option>"#,
            id = cid,
            sel = selected,
            name = vortex_plugin_sdk::framework::html_escape(&cname),
            code = vortex_plugin_sdk::framework::html_escape(ccode.as_deref().unwrap_or("")),
        ));
    }

    // Load states for the selected country
    let mut state_options = String::from(r#"<option value="">-- Select State --</option>"#);
    if let Some(cid) = country_id {
        let states_rows = vortex_plugin_sdk::sqlx::query(
            "SELECT id, code, name FROM states WHERE country_id = $1 AND active = true ORDER BY name",
        )
        .bind(cid)
        .fetch_all(&db)
        .await
        .unwrap_or_default();

        for sr in &states_rows {
            let sid: Uuid = sr.get("id");
            let sname: String = sr.get("name");
            let scode: String = sr.get("code");
            let selected = if state_id == Some(sid) { " selected" } else { "" };
            state_options.push_str(&format!(
                r#"<option value="{id}"{sel}>{name} ({code})</option>"#,
                id = sid, sel = selected,
                name = vortex_plugin_sdk::framework::html_escape(&sname),
                code = vortex_plugin_sdk::framework::html_escape(&scode),
            ));
        }
    }

    let esc = vortex_plugin_sdk::framework::html_escape;

    let sel = |val: &str, opt: &str| if val == opt { "selected" } else { "" };

    // Per-record audit trail (reusable core widget over the WORM ledger).
    let history_panel = vortex_plugin_sdk::framework::render_audit_trail(&db, "contact", id).await;

    // Status section: display-only progress bar + role-gated transition
    // buttons, plus a lock banner when the current stage is locked.
    let status_change_base = format!("/contacts/{}/status", id);
    let bar = contact_status(&db).await;
    let is_locked = bar.is_locked(&record_state);
    let bar_html = bar.render(&record_state, &status_change_base);
    let action_buttons = vortex_plugin_sdk::framework::StageActions::from_db(&db, "contacts")
        .await
        .render(&record_state, &user.roles, &status_change_base);

    // On-record approval panel: shows pending step/progress and an
    // approve/reject form when this user is an eligible approver. Empty
    // unless an approval is in flight for this contact.
    let approval_panel = vortex_plugin_sdk::framework::approval::render_for_record(
        &db, "contacts", id, user.id, &user.roles,
    )
    .await;
    let lock_banner = if is_locked {
        r#"<div class="alert alert-warning mb-4"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"/></svg><span>This contact is locked in its current stage. Fields are read-only — use the buttons to change its status.</span></div>"#
    } else {
        ""
    };
    let status_bar = format!(
        r#"<div class="flex flex-wrap items-center justify-between gap-3">{bar}{buttons}</div>{banner}"#,
        bar = bar_html,
        buttons = action_buttons,
        banner = lock_banner,
    );
    let form_disabled = if is_locked { " disabled" } else { "" };

    // Archive / un-archive control. "Delete" here is a soft delete (active =
    // false), so we name it honestly: active records get an Archive button,
    // already-archived records get an Un-archive button that restores them.
    let archive_button = if active {
        format!(
            r#"<form method="POST" action="/contacts/{id}/archive" onsubmit="return confirm('Archive this contact?')">
<button class="btn btn-warning btn-sm btn-outline">Archive</button>
</form>"#,
            id = id,
        )
    } else {
        format!(
            r#"<form method="POST" action="/contacts/{id}/unarchive">
<button class="btn btn-success btn-sm btn-outline">Un-archive</button>
</form>"#,
            id = id,
        )
    };

    let content = format!(
        r#"<div class="flex items-center justify-between mb-6">
<div>
<a href="/contacts" class="btn btn-ghost btn-sm mb-2">← Back to Contacts</a>
<h1 class="text-2xl font-bold">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span></h1>
</div>
{archive_button}
</div>

{status_bar}

{approval_panel}

<form method="POST" action="/contacts/{id}">
<fieldset class="contents"{form_disabled}>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">

<!-- Left column -->
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg mb-4">General</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name_val}" required/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="contact_type" class="select select-bordered select-sm">
<option value="customer" {sel_cust}>Customer</option>
<option value="supplier" {sel_supp}>Supplier</option>
<option value="both" {sel_both}>Both</option>
<option value="other" {sel_other}>Other</option>
</select>
</div>
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="is_company" class="checkbox checkbox-sm" {is_company_checked}/>
<span class="label-text">Is a Company</span>
</label>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">VAT Number</span></label>
<input name="vat_number" class="input input-bordered input-sm" value="{vat}"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Credit Limit</span></label>
<input name="credit_limit" type="number" step="0.01" class="input input-bordered input-sm" value="{credit}"/>
</div>
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" {active_checked}/>
<span class="label-text">Active</span>
</label>
</div>
</div>
</div>

<!-- Right column -->
<div class="space-y-6">
<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg mb-4">Contact Info</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Email</span></label>
<input name="email" type="email" class="input input-bordered input-sm" value="{email_val}"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Phone</span></label>
<input name="phone" class="input input-bordered input-sm" value="{phone_val}"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Mobile</span></label>
<input name="mobile" class="input input-bordered input-sm" value="{mobile_val}"/>
</div>
</div>
</div>

<div class="card bg-base-100 shadow">
<div class="card-body">
<h2 class="card-title text-lg mb-4">Address</h2>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Street</span></label>
<input name="street" class="input input-bordered input-sm" value="{street_val}" placeholder="Address line 1"/>
<input name="street2" class="input input-bordered input-sm mt-1" value="{street2_val}" placeholder="Address line 2"/>
<input name="street3" class="input input-bordered input-sm mt-1" value="{street3_val}" placeholder="Address line 3"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Country</span></label>
<select name="country_id" id="country-select" class="select select-bordered select-sm"
  onchange="loadStates(this.value)">
{country_options}
</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">State / Province</span></label>
<select name="state_id" id="state-select" class="select select-bordered select-sm">
{state_options}
</select>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">City</span></label>
<input name="city" class="input input-bordered input-sm" value="{city_val}"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">ZIP</span></label>
<input name="zip" class="input input-bordered input-sm" value="{zip_val}"/>
</div>
</div>
<script>
async function loadStates(countryId) {{
  var sel = document.getElementById('state-select');
  sel.innerHTML = '<option value="">Loading...</option>';
  if (!countryId) {{
    sel.innerHTML = '<option value="">-- Select State --</option>';
    return;
  }}
  try {{
    var res = await fetch('/api/states/' + countryId);
    if (!res.ok) {{
      sel.innerHTML = '<option value="">Error loading states</option>';
      return;
    }}
    var states = await res.json();
    sel.innerHTML = '<option value="">-- Select State --</option>';
    for (var i = 0; i < states.length; i++) {{
      var opt = document.createElement('option');
      opt.value = states[i].id;
      opt.textContent = states[i].name + ' (' + states[i].code + ')';
      sel.appendChild(opt);
    }}
    if (states.length === 0) {{
      sel.innerHTML = '<option value="">No states available</option>';
    }}
  }} catch(e) {{
    sel.innerHTML = '<option value="">Error: ' + e.message + '</option>';
  }}
}}
</script>
</div>
</div>
{history_panel}
</div>
</div>

<div class="form-control mt-4">
<label class="label"><span class="label-text">Notes</span></label>
<textarea name="notes" class="textarea textarea-bordered" rows="3">{notes_val}</textarea>
</div>

<div class="mt-6 flex gap-2">
<button type="submit" class="btn btn-primary btn-sm">Save</button>
<a href="/contacts" class="btn btn-ghost btn-sm">Cancel</a>
</div>
</fieldset>
</form>"#,
        id = id,
        name = esc(&name),
        code = esc(code.as_deref().unwrap_or("")),
        name_val = esc(&name),
        email_val = esc(email.as_deref().unwrap_or("")),
        phone_val = esc(phone.as_deref().unwrap_or("")),
        mobile_val = esc(mobile.as_deref().unwrap_or("")),
        street_val = esc(street.as_deref().unwrap_or("")),
        street2_val = esc(street2.as_deref().unwrap_or("")),
        street3_val = esc(street3.as_deref().unwrap_or("")),
        city_val = esc(city.as_deref().unwrap_or("")),
        zip_val = esc(zip.as_deref().unwrap_or("")),
        country_options = country_options,
        state_options = state_options,
        vat = esc(vat_number.as_deref().unwrap_or("")),
        credit = credit_limit.map(|c| format!("{:.2}", c)).unwrap_or_default(),
        notes_val = esc(notes.as_deref().unwrap_or("")),
        sel_cust = sel(&contact_type, "customer"),
        sel_supp = sel(&contact_type, "supplier"),
        sel_both = sel(&contact_type, "both"),
        sel_other = sel(&contact_type, "other"),
        is_company_checked = if is_company { "checked" } else { "" },
        active_checked = if active { "checked" } else { "" },
        history_panel = history_panel,
        status_bar = status_bar,
        approval_panel = approval_panel,
        form_disabled = form_disabled,
        archive_button = archive_button,
    );

    // Panels other plugins contribute to the contact record (e.g.
    // accounting's Malaysian tax identity card).
    let panels =
        vortex_plugin_sdk::framework::render_record_panels(&state, &db, "contacts", id).await;
    let content = format!("{content}{panels}");

    Html(page_shell(&sidebar, &format!("Edit {}", name), &content)).into_response()
}

/// The contact model's tracked fields — Vortex's `tracking=True` analogue.
/// Declared once; the framework snapshots these before a save and posts a
/// field-level diff to the audit trail after. Add a `.text()/.money()/…`
/// line here and the field is tracked — no handler changes needed.
fn contact_tracker() -> vortex_plugin_sdk::framework::Tracker {
    use vortex_plugin_sdk::framework::Tracker;
    Tracker::new("contacts")
        .text("name", "Name")
        .text("email", "Email")
        .text("phone", "Phone")
        .text("mobile", "Mobile")
        .text("street", "Street")
        .text("street2", "Street 2")
        .text("street3", "Street 3")
        .text("city", "City")
        .text("zip", "ZIP")
        .text("vat_number", "VAT Number")
        .text("notes", "Notes")
        .selection("contact_type", "Type")
        .boolean("is_company", "Company", "Company", "Individual")
        .boolean("active", "Status", "Active", "Archived")
        .money("credit_limit", "Credit Limit")
        .reference("country_id", "Country", "countries")
        .reference("state_id", "State", "states")
}

/// Load the contacts status bar from the user-managed `record_stages` table.
/// Stages are data, not code — admins add/reorder/recolour them in Settings.
async fn contact_status(db: &vortex_plugin_sdk::sqlx::PgPool) -> vortex_plugin_sdk::framework::StatusBar {
    vortex_plugin_sdk::framework::StatusBar::from_db(db, "contacts", "contacts", "record_state").await
}

/// POST /contacts/:id/status/:state — move a contact to a new stage.
async fn change_contact_status(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path((id, new_state)): Path<(Uuid, String)>,
) -> Response {
    let row = vortex_plugin_sdk::sqlx::query("SELECT name, record_state FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten();
    let (name, current) = match row {
        Some(r) => (r.get::<String, _>("name"), r.get::<String, _>("record_state")),
        None => return (vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND, "Contact not found").into_response(),
    };

    // Server-side role gate: resolve the exact button the user would press
    // (mirrors the rendered buttons); `None` means they may not transition.
    let actions = vortex_plugin_sdk::framework::StageActions::from_db(&db, "contacts").await;
    let Some(action) = actions.action_for(&current, &new_state, &user.roles) else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::FORBIDDEN,
            "You are not allowed to make this transition.",
        )
            .into_response();
    };

    // If the button requires approval, create a request instead of moving the
    // record. The transition is applied later, once approvers sign off.
    if let Some(action_id) = action.id {
        use vortex_plugin_sdk::framework::approval;
        if approval::requires_approval(&db, action_id).await {
            match approval::create_request(
                &db,
                &state.db, // primary pool — the durable job queue lives here
                &state.audit,
                &db_ctx.db_name,
                approval::NewRequest {
                    model: "contacts",
                    record_id: id,
                    action_id,
                    status_table: "contacts",
                    status_column: "record_state",
                    from_stage: &current,
                    target_stage: &new_state,
                    resource_name: &name,
                    requested_by: user.id,
                    requested_by_name: &user.username,
                },
            )
            .await
            {
                Ok(_) => {}
                Err(e) => info!(error = %e, "approval request not created"),
            }
            return vortex_plugin_sdk::axum::response::Redirect::to(&format!("/contacts/{id}")).into_response();
        }
    }

    match contact_status(&db)
        .await
        .apply(
            &db, &state.audit, &db_ctx.db_name,
            user.id, &user.username, "contact", id, &name, &new_state,
        )
        .await
    {
        Ok(()) => vortex_plugin_sdk::axum::response::Redirect::to(&format!("/contacts/{id}")).into_response(),
        Err(e) => {
            error!(error = %e, "contact status change failed");
            (
                vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
                format!("Could not change status: {e}"),
            )
                .into_response()
        }
    }
}

/// POST /contacts/:id — update an existing contact.
async fn update_contact(
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

    // Refuse field edits while the contact sits in a locked stage. The UI
    // also disables the inputs, but enforce it server-side regardless.
    let current_state: String = vortex_plugin_sdk::sqlx::query_scalar("SELECT record_state FROM contacts WHERE id = $1")
        .bind(id)
        .fetch_optional(&db)
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    if contact_status(&db).await.is_locked(&current_state) {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::FORBIDDEN,
            "This contact is locked and cannot be edited. Change its status first.",
        )
            .into_response();
    }

    let country_id: Option<Uuid> = form
        .get("country_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());
    let state_id: Option<Uuid> = form
        .get("state_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse().ok());

    // Snapshot tracked fields BEFORE the update (Odoo-style `tracking=True`).
    let before = contact_tracker().snapshot(&db, id).await;

    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE contacts SET \
         name = $1, email = $2, phone = $3, mobile = $4, \
         street = $5, street2 = $6, street3 = $7, \
         city = $8, zip = $9, \
         country_id = $10, state_id = $11, \
         contact_type = $12, is_company = $13, vat_number = $14, \
         credit_limit = $15, notes = $16, active = $17, \
         updated_by = $18, updated_at = NOW() \
         WHERE id = $19",
    )
    .bind(&name)
    .bind(form.get("email").filter(|s| !s.is_empty()))
    .bind(form.get("phone").filter(|s| !s.is_empty()))
    .bind(form.get("mobile").filter(|s| !s.is_empty()))
    .bind(form.get("street").filter(|s| !s.is_empty()))
    .bind(form.get("street2").filter(|s| !s.is_empty()))
    .bind(form.get("street3").filter(|s| !s.is_empty()))
    .bind(form.get("city").filter(|s| !s.is_empty()))
    .bind(form.get("zip").filter(|s| !s.is_empty()))
    .bind(country_id)
    .bind(state_id)
    .bind(form.get("contact_type").map(|s| s.as_str()).unwrap_or("customer"))
    .bind(form.contains_key("is_company"))
    .bind(form.get("vat_number").filter(|s| !s.is_empty()))
    .bind(
        form.get("credit_limit")
            .and_then(|s| s.parse::<f64>().ok())
            .unwrap_or(0.0),
    )
    .bind(form.get("notes").filter(|s| !s.is_empty()))
    .bind(form.contains_key("active"))
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "contact update failed");
        return (
            vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to update: {e}"),
        ).into_response();
    }

    // Diff the tracked fields against the snapshot and post the change set
    // to the tenant WORM ledger — one call, no hand-written diff logic.
    contact_tracker()
        .log_update(
            &state.audit, &db, &db_ctx.db_name,
            user.id, &user.username, "contact", id, &name, &before, &form,
        )
        .await;

    info!(id = %id, name = %name, "contact updated");
    vortex_plugin_sdk::axum::response::Redirect::to("/contacts").into_response()
}

/// POST /contacts/:id/archive — archive a contact (soft delete: active = false).
async fn archive_contact(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE contacts SET active = false, updated_by = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "contact archive failed");
        return (
            vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to archive: {e}"),
        ).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("contact", id.to_string())
    .with_details(json!({ "changes": [{ "field": "active", "from": "Active", "to": "Archived" }] }));
    let _ = state.audit.log(audit_entry).await;

    info!(id = %id, "contact archived");
    // Return to the record so the Un-archive button is immediately visible.
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/contacts/{id}")).into_response()
}

/// POST /contacts/:id/unarchive — restore an archived contact (active = true).
async fn unarchive_contact(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "UPDATE contacts SET active = true, updated_by = $1, updated_at = NOW() WHERE id = $2",
    )
    .bind(user.id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "contact unarchive failed");
        return (
            vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to un-archive: {e}"),
        ).into_response();
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordUpdated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("contact", id.to_string())
    .with_details(json!({ "changes": [{ "field": "active", "from": "Archived", "to": "Active" }] }));
    let _ = state.audit.log(audit_entry).await;

    info!(id = %id, "contact un-archived");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/contacts/{id}")).into_response()
}
