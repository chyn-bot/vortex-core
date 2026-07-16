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

/// Built-in contact fields a custom field can be anchored *after* (rendered
/// inline right below that field). Any other anchor — or none — falls to the
/// bottom "Custom Fields" section, so nothing is ever silently dropped.
const CONTACT_ANCHORS: &[&str] = &[
    "name", "contact_type", "vat_number", "credit_limit", "email", "phone", "mobile", "notes",
];

/// The custom-field HTML for a contact form: one inline group per anchor plus
/// the bottom section for everything unplaced. `record_id` is `None` on create.
struct ContactCustom {
    name: String,
    contact_type: String,
    vat_number: String,
    credit_limit: String,
    email: String,
    phone: String,
    mobile: String,
    notes: String,
    /// Bottom "Custom Fields" card (unanchored + anchors this form can't place).
    bottom: String,
}

async fn contact_custom(db: &vortex_plugin_sdk::sqlx::PgPool, record_id: Option<&str>) -> ContactCustom {
    use vortex_plugin_sdk::framework::custom_fields as cf;
    let g = |anchor: &'static str| cf::render_anchor_group(db, "contacts", record_id, anchor);
    let bottom_inner = cf::render_unplaced_section(db, "contacts", record_id, CONTACT_ANCHORS).await;
    ContactCustom {
        name: g("name").await,
        contact_type: g("contact_type").await,
        vat_number: g("vat_number").await,
        credit_limit: g("credit_limit").await,
        email: g("email").await,
        phone: g("phone").await,
        mobile: g("mobile").await,
        notes: g("notes").await,
        bottom: if bottom_inner.is_empty() {
            String::new()
        } else {
            format!(
                r#"<div class="card bg-base-100 shadow mt-6"><div class="card-body">{bottom_inner}</div></div>"#
            )
        },
    }
}

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
        .route("/contacts/{id}/duplicate", post(duplicate_contact))
        .route("/contacts/{id}/status/{state}", post(change_contact_status))
}

/// Wrap page content in the platform's full HTML shell with sidebar,
/// navbar, DaisyUI theme, and mobile-responsive layout.
fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script src="/static/theme-init.js?v=20"></script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=20" rel="stylesheet"/>
<script src="/static/vortex.js?v=20" defer></script>
<script src="/static/vendor/tailwind.js"></script>
</head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden">
<button type="button" data-sidebar-toggle class="btn btn-ghost btn-sm btn-square">
<svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg>
</button>
<a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">vor</span><span class="opacity-60">tex</span></a>
</div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" data-sidebar-close></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
{content}
</main></div></body></html>"##,
        title = title,
        sidebar = sidebar,
        content = content,
    )
}

/// Wrap a fully-rendered page in a Response carrying a *strict* CSP —
/// `script-src 'self'` with NO `'unsafe-inline'`. Use only for pages proven
/// free of inline `<script>` and inline `on*=` handlers: all behaviour is
/// delegated through `/static/vortex.js` (see the CSP-safe delegated handlers
/// there). `security_headers_middleware` preserves this handler-set CSP
/// instead of applying the permissive global default.
fn strict_csp_page(html: String) -> Response {
    use vortex_plugin_sdk::axum::http::{header, HeaderValue};
    let mut resp = Html(html).into_response();
    resp.headers_mut().insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(
            "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; \
             connect-src 'self'; img-src 'self' data: https://*.tile.openstreetmap.org; \
             font-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'",
        ),
    );
    resp
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
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
        &db_ctx.custom_apps_html,
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
        // Country is not free-text searchable: it lives on the joined
        // `countries` table, and an OR against a post-join column defeats
        // the contacts trigram indexes that make search fast at 12M rows.
        .column(ListColumn::new("country_name", "Country").sortable().sql_expr("co.name"))
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
        // The two LEFT JOINs are many-to-one on FK→PK, so they preserve
        // base cardinality: COUNT(join) == reltuples(contacts). This lets
        // large unfiltered browses skip the full-scan COUNT(*). c.id gives
        // a stable tiebreaker for LIMIT/OFFSET paging. Backed by
        // idx_contacts_name_browse (name, id) — see migration.
        .count_estimate_from("contacts")
        .tiebreak("c.id")
        // Free-text search routes through a trigram-indexed id-prefilter on
        // the base table so ILIKE '%…%' uses idx_contacts_*_coalesce_trgm
        // instead of scanning 12M joined rows. All searchable columns above
        // (name, email, city) are contacts columns — required by prefilter.
        .search_prefilter("contacts c")
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
        user.is_admin(),
        &state.plugin_registry, &user.roles,
        &db_ctx.custom_apps_html,
    );

    // Country dropdown, same source as the edit form. Malaysia is
    // preselected (home market) with its states preloaded, so the
    // natural entry order street → postcode → city → state works
    // without first scrolling to the country; picking another country
    // reloads states via /api/states/{country_id}.
    let countries_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, code, alpha3, name FROM countries WHERE active = true ORDER BY name",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let default_country: Option<Uuid> = countries_rows
        .iter()
        .find(|cr| cr.try_get::<String, _>("alpha3").ok().as_deref() == Some("MYS"))
        .map(|cr| cr.get("id"));
    let mut country_options = String::from(r#"<option value="">-- Select Country --</option>"#);
    for cr in &countries_rows {
        let cid: Uuid = cr.get("id");
        let cname: String = cr.get("name");
        let ccode: Option<String> = cr.try_get("alpha3").ok();
        let sel = if default_country == Some(cid) { " selected" } else { "" };
        country_options.push_str(&format!(
            r#"<option value="{id}"{sel}>{name} ({code})</option>"#,
            id = cid,
            sel = sel,
            name = vortex_plugin_sdk::framework::html_escape(&cname),
            code = vortex_plugin_sdk::framework::html_escape(ccode.as_deref().unwrap_or("")),
        ));
    }
    // Preload the default country's states server-side.
    let mut state_options = String::from(r#"<option value="">-- Select State --</option>"#);
    if let Some(country) = default_country {
        let state_rows = vortex_plugin_sdk::sqlx::query(
            "SELECT id, code, name FROM states WHERE country_id = $1 AND active = true ORDER BY name",
        )
        .bind(country)
        .fetch_all(&db)
        .await
        .unwrap_or_default();
        for sr in &state_rows {
            state_options.push_str(&format!(
                r#"<option value="{}">{} ({})</option>"#,
                sr.get::<Uuid, _>("id"),
                vortex_plugin_sdk::framework::html_escape(&sr.get::<String, _>("name")),
                vortex_plugin_sdk::framework::html_escape(&sr.get::<String, _>("code")),
            ));
        }
    }

    // Admin-defined custom fields (Initiative #2). Anchored fields render inline
    // right after their built-in field; the rest fall to the bottom section. A
    // field added in Settings ▸ Custom Fields shows here without a code change.
    let cc = contact_custom(&db, None).await;

    // Field groups — identical field markup to before, now wrapped as flat
    // sheet sections (see vortex_plugin_sdk::framework::form_section_raw) instead
    // of floating cards, so the whole form reads as one Odoo-style sheet.
    let general = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" required/>
</div>
{cf_name}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="contact_type" class="select select-bordered select-sm">
<option value="customer">Customer</option>
<option value="supplier">Supplier</option>
<option value="both">Both</option>
<option value="other">Other</option>
</select>
</div>
{cf_ctype}
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
{cf_vat}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Credit Limit</span></label>
<input name="credit_limit" type="number" step="0.01" class="input input-bordered input-sm"/>
</div>
{cf_credit}
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" checked/>
<span class="label-text">Active</span>
</label>
</div>"#,
        cf_name = cc.name,
        cf_ctype = cc.contact_type,
        cf_vat = cc.vat_number,
        cf_credit = cc.credit_limit,
    );

    let contact_info = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Email</span></label>
<input name="email" type="email" autocomplete="email" class="input input-bordered input-sm"/>
</div>
{cf_email}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Phone</span></label>
<input name="phone" type="tel" inputmode="tel" class="input input-bordered input-sm"/>
</div>
{cf_phone}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Mobile</span></label>
<input name="mobile" type="tel" inputmode="tel" class="input input-bordered input-sm"/>
</div>
{cf_mobile}"#,
        cf_email = cc.email,
        cf_phone = cc.phone,
        cf_mobile = cc.mobile,
    );

    let address = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Street</span></label>
<input name="street" autocomplete="address-line1" class="input input-bordered input-sm" placeholder="Address line 1"/>
<input name="street2" autocomplete="address-line2" class="input input-bordered input-sm mt-1" placeholder="Address line 2"/>
<input name="street3" autocomplete="address-line3" class="input input-bordered input-sm mt-1" placeholder="Address line 3"/>
</div>
<div class="grid grid-cols-3 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Postcode</span></label>
<input name="zip" autocomplete="postal-code" inputmode="numeric" class="input input-bordered input-sm" placeholder="50450"/>
</div>
<div class="form-control mb-3 col-span-2">
<label class="label"><span class="label-text">City</span></label>
<input name="city" autocomplete="address-level2" class="input input-bordered input-sm"/>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">State / Province</span></label>
<select name="state_id" id="state-select" autocomplete="address-level1" class="select select-bordered select-sm">
{state_options}
</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Country</span></label>
<select name="country_id" id="country-select" class="select select-bordered select-sm"
  data-load-states data-states-target="state-select">
{country_options}
</select>
</div>"#,
    );

    let notes = format!(
        r#"<div class="form-control">
<label class="label"><span class="label-text">Notes</span></label>
<textarea name="notes" class="textarea textarea-bordered" rows="3"></textarea>
</div>
{cf_notes}"#,
        cf_notes = cc.notes,
    );

    // Two columns of flat sections inside one sheet (masonry-ish via the
    // existing 2-col grid), then full-width Notes + any bottom-anchored custom
    // fields, all in a single centered container.
    let inner = format!(
        r#"<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 gap-x-10">{general}<div class="space-y-6">{contact_info}{address}</div></div>{notes}{bottom}"#,
        general = vortex_plugin_sdk::framework::form_section_raw("General", &general),
        contact_info = vortex_plugin_sdk::framework::form_section_raw("Contact Info", &contact_info),
        address = vortex_plugin_sdk::framework::form_section_raw("Address", &address),
        notes = vortex_plugin_sdk::framework::form_section_raw("Notes", &notes),
        bottom = cc.bottom,
    );

    let content = vortex_plugin_sdk::framework::render_form_sheet(&vortex_plugin_sdk::framework::FormSheet {
        max_width: vortex_plugin_sdk::framework::SHEET_WIDTH,
        back_href: "/contacts",
        control_row: "",
        form_attrs: r#"method="POST" action="/contacts/create""#,
        title: "New Contact",
        inner: &inner,
        footer: r#"<a href="/contacts" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create</button>"#,
        below: "",
    });

    strict_csp_page(page_shell(&sidebar, "New Contact", &content))
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

    // Persist admin-defined custom field values (Initiative #2). Non-fatal: the
    // contact exists either way, so a custom-value hiccup only gets logged.
    let custom_pairs: Vec<(String, String)> = form.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    if let Err(e) = vortex_plugin_sdk::framework::custom_fields::save_values(
        &db, "contacts", contact_id, &custom_pairs,
    )
    .await
    {
        error!(error = %e, "custom field save failed");
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
/// Build a "back to list" href that preserves the caller's list state
/// (search / sort / page) by reading it off the `Referer`.
///
/// Same-origin navigation from the list carries the full query string under
/// our `strict-origin-when-cross-origin` referrer policy, so a record opened
/// from `/contacts?search=…&page=3` returns to that exact view. The result
/// is **only ever** a path+query on `list_path` — a referer pointing
/// anywhere else falls back to the bare list path, so this can't be turned
/// into an open redirect. The caller still HTML-escapes the value before
/// embedding it, since the query portion is attacker-influenceable.
fn list_return_href(headers: &vortex_plugin_sdk::axum::http::HeaderMap, list_path: &str) -> String {
    let referer = match headers.get("referer").and_then(|v| v.to_str().ok()) {
        Some(r) => r,
        None => return list_path.to_string(),
    };
    // Reduce an absolute referer (scheme://host/path?q) to path+query.
    let path_and_query = match referer.find("://") {
        Some(i) => match referer[i + 3..].find('/') {
            Some(j) => &referer[i + 3 + j..],
            None => return list_path.to_string(),
        },
        None => referer, // already relative
    };
    // Honor it only when the path is exactly the list path.
    let path = path_and_query
        .split(|c| c == '?' || c == '#')
        .next()
        .unwrap_or("");
    if path == list_path {
        path_and_query.to_string()
    } else {
        list_path.to_string()
    }
}

async fn edit_contact(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    headers: vortex_plugin_sdk::axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    // Preserve the caller's list state (search/sort/page) on "Back to
    // Contacts" — derived from the Referer so a record opened from a
    // filtered/searched list returns to that same view, not page 1.
    let back_href = list_return_href(&headers, "/contacts");
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = vortex_plugin_sdk::framework::build_sidebar(
        "contacts", display_name, &initials, &installed,
        user.is_admin(),
        &state.plugin_registry, &user.roles,
        &db_ctx.custom_apps_html,
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

    // On-record activity stream: schedule tasks, assign to a colleague for
    // review, mark complete — plus messages and attachments. Core primitive,
    // same slot on every module's record page.
    let activity_panel = vortex_plugin_sdk::framework::render_chatter_panel("contacts", id);

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
            r#"<form method="POST" action="/contacts/{id}/archive" data-confirm="Archive this contact?">
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

    // Panels other plugins contribute to the contact record (e.g.
    // accounting's Malaysian tax identity) — slotted into the form
    // grid right below the Address card.
    let record_panels =
        vortex_plugin_sdk::framework::render_record_panels(&state, &db, "contacts", id).await;

    // "Invite to portal" — the host's external portal lives at /portal; from a
    // customer record an admin can provision self-service access. Shown only to
    // admins, only for customers; the label reflects whether a login exists.
    let portal_button = if user.is_admin() && matches!(contact_type.as_str(), "customer" | "both") {
        let has_login = vortex_plugin_sdk::sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM users WHERE contact_id = $1 AND is_portal = true",
        )
        .bind(id)
        .fetch_one(&db)
        .await
        .map(|n| n > 0)
        .unwrap_or(false);
        let label = if has_login { "Portal access" } else { "Invite to portal" };
        format!(
            r#"<a href="/settings/portal-users/contact/{id}" class="btn btn-sm btn-outline">{label}</a>"#,
            id = id, label = label,
        )
    } else {
        String::new()
    };

    // Admin-defined custom fields (Initiative #2), prefilled from stored values.
    // Anchored ones render inline after their field; the rest sit at the bottom.
    let ids = id.to_string();
    let cc = contact_custom(&db, Some(&ids)).await;

    // Field groups — identical field markup (values preserved) to before, now
    // flat sheet sections instead of floating cards.
    let general = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Name *</span></label>
<input name="name" class="input input-bordered input-sm" value="{name_val}" required/>
</div>
{cf_name}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="contact_type" class="select select-bordered select-sm">
<option value="customer" {sel_cust}>Customer</option>
<option value="supplier" {sel_supp}>Supplier</option>
<option value="both" {sel_both}>Both</option>
<option value="other" {sel_other}>Other</option>
</select>
</div>
{cf_ctype}
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
{cf_vat}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Credit Limit</span></label>
<input name="credit_limit" type="number" step="0.01" class="input input-bordered input-sm" value="{credit}"/>
</div>
{cf_credit}
<div class="form-control mb-3">
<label class="cursor-pointer label justify-start gap-3">
<input type="checkbox" name="active" class="checkbox checkbox-sm" {active_checked}/>
<span class="label-text">Active</span>
</label>
</div>"#,
        name_val = esc(&name),
        vat = esc(vat_number.as_deref().unwrap_or("")),
        credit = credit_limit.map(|c| format!("{:.2}", c)).unwrap_or_default(),
        cf_name = cc.name,
        cf_ctype = cc.contact_type,
        cf_vat = cc.vat_number,
        cf_credit = cc.credit_limit,
        sel_cust = sel(&contact_type, "customer"),
        sel_supp = sel(&contact_type, "supplier"),
        sel_both = sel(&contact_type, "both"),
        sel_other = sel(&contact_type, "other"),
        is_company_checked = if is_company { "checked" } else { "" },
        active_checked = if active { "checked" } else { "" },
    );

    let contact_info = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Email</span></label>
<input name="email" type="email" autocomplete="email" class="input input-bordered input-sm" value="{email_val}"/>
</div>
{cf_email}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Phone</span></label>
<input name="phone" type="tel" inputmode="tel" class="input input-bordered input-sm" value="{phone_val}"/>
</div>
{cf_phone}
<div class="form-control mb-3">
<label class="label"><span class="label-text">Mobile</span></label>
<input name="mobile" type="tel" inputmode="tel" class="input input-bordered input-sm" value="{mobile_val}"/>
</div>
{cf_mobile}"#,
        email_val = esc(email.as_deref().unwrap_or("")),
        phone_val = esc(phone.as_deref().unwrap_or("")),
        mobile_val = esc(mobile.as_deref().unwrap_or("")),
        cf_email = cc.email,
        cf_phone = cc.phone,
        cf_mobile = cc.mobile,
    );

    let address = format!(
        r#"<div class="form-control mb-3">
<label class="label"><span class="label-text">Street</span></label>
<input name="street" autocomplete="address-line1" class="input input-bordered input-sm" value="{street_val}" placeholder="Address line 1"/>
<input name="street2" autocomplete="address-line2" class="input input-bordered input-sm mt-1" value="{street2_val}" placeholder="Address line 2"/>
<input name="street3" autocomplete="address-line3" class="input input-bordered input-sm mt-1" value="{street3_val}" placeholder="Address line 3"/>
</div>
<div class="grid grid-cols-3 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Postcode</span></label>
<input name="zip" autocomplete="postal-code" inputmode="numeric" class="input input-bordered input-sm" value="{zip_val}" placeholder="50450"/>
</div>
<div class="form-control mb-3 col-span-2">
<label class="label"><span class="label-text">City</span></label>
<input name="city" autocomplete="address-level2" class="input input-bordered input-sm" value="{city_val}"/>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">State / Province</span></label>
<select name="state_id" id="state-select" autocomplete="address-level1" class="select select-bordered select-sm">
{state_options}
</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Country</span></label>
<select name="country_id" id="country-select" class="select select-bordered select-sm"
  data-load-states data-states-target="state-select">
{country_options}
</select>
</div>"#,
        street_val = esc(street.as_deref().unwrap_or("")),
        street2_val = esc(street2.as_deref().unwrap_or("")),
        street3_val = esc(street3.as_deref().unwrap_or("")),
        zip_val = esc(zip.as_deref().unwrap_or("")),
        city_val = esc(city.as_deref().unwrap_or("")),
        state_options = state_options,
        country_options = country_options,
    );

    let notes = format!(
        r#"<div class="form-control">
<label class="label"><span class="label-text">Notes</span></label>
<textarea name="notes" class="textarea textarea-bordered" rows="3">{notes_val}</textarea>
</div>
{cf_notes}"#,
        notes_val = esc(notes.as_deref().unwrap_or("")),
        cf_notes = cc.notes,
    );

    // Header (back link, name, action buttons), status bar, and approval panel
    // stay above the sheet; the field area is wrapped as one Odoo-style sheet
    // inside the record form. The <fieldset class="contents"> disable-wrapper
    // encloses both the sheet and its footer so a locked record is fully
    // read-only, so this form builds the sheet inline rather than via
    // render_form_sheet (which owns its own <form>). Chatter/history sit below.
    let content = format!(
        r#"<div class="max-w-6xl mx-auto">
<div class="flex items-center justify-between mb-6">
<div>
<a href="{back_href}" class="btn btn-ghost btn-sm mb-2">← Back to Contacts</a>
<h1 class="text-2xl font-bold">{name} <span class="text-base-content/40 font-mono text-sm">{code}</span></h1>
</div>
<div class="flex items-center gap-2">
{portal_button}
{duplicate_button}
{archive_button}
</div>
</div>

{status_bar}

{approval_panel}

<form method="POST" action="/contacts/{id}" id="record-form">
<fieldset class="contents"{form_disabled}>
<div class="bg-base-100 rounded-lg shadow-sm border border-base-300 p-6 md:p-8">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 gap-x-10">
{general}
<div class="space-y-6">{contact_info}{address}</div>
<div class="lg:col-span-2">{record_panels}</div>
</div>
{notes}
{bottom}
</div>
<div class="flex justify-end gap-2 mt-4">
<a href="{back_href}" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary">Save</button>
</div>
</fieldset>
</form>
</div>

{activity_panel}

{history_panel}"#,
        id = id,
        back_href = esc(&back_href),
        activity_panel = activity_panel,
        name = esc(&name),
        code = esc(code.as_deref().unwrap_or("")),
        general = vortex_plugin_sdk::framework::form_section_raw("General", &general),
        contact_info = vortex_plugin_sdk::framework::form_section_raw("Contact Info", &contact_info),
        address = vortex_plugin_sdk::framework::form_section_raw("Address", &address),
        notes = vortex_plugin_sdk::framework::form_section_raw("Notes", &notes),
        record_panels = record_panels,
        bottom = cc.bottom,
        history_panel = history_panel,
        status_bar = status_bar,
        approval_panel = approval_panel,
        form_disabled = form_disabled,
        duplicate_button = duplicate_button(&format!("/contacts/{id}/duplicate")),
        archive_button = archive_button,
        portal_button = portal_button,
    );

    strict_csp_page(page_shell(&sidebar, &format!("Edit {}", name), &content))
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

    // Panel fields ride in on the same form (form="record-form") —
    // hand the submission to contributing plugins' save hooks.
    let pairs: Vec<(String, String)> =
        form.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    let panel_ctx = vortex_plugin_sdk::framework::PanelSaveCtx {
        user_id: user.id,
        username: user.username.clone(),
        db_name: db_ctx.db_name.clone(),
    };
    vortex_plugin_sdk::framework::handle_record_panel_saves(
        &state, &db, "contacts", id, &pairs, &panel_ctx,
    )
    .await;

    // Persist admin-defined custom field values (Initiative #2) from the same
    // submission. Non-fatal — the contact update already succeeded.
    if let Err(e) = vortex_plugin_sdk::framework::custom_fields::save_values(
        &db, "contacts", id, &pairs,
    )
    .await
    {
        error!(error = %e, "custom field save failed");
    }

    info!(id = %id, name = %name, "contact updated");
    // Stay on the record — one Save now persists contact + panel
    // fields, and returning here makes that visible.
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/contacts/{id}")).into_response()
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

/// POST /contacts/:id/duplicate — copy the contact into a fresh, active
/// draft: new sequence code, name marked "(copy)", lifecycle reset.
async fn duplicate_contact(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    // Draw a fresh contact code — `code` is unique per company, so the
    // copy can never reuse the source's number.
    let code = match vortex_plugin_sdk::orm::sequence::next(&state.pool, &CONTACT_SEQ).await {
        Ok(c) => c,
        Err(e) => {
            error!(error = %e, "duplicate sequence draw failed");
            return (
                vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Failed to generate contact code",
            ).into_response();
        }
    };

    // Lifecycle columns fall back to their DB defaults: the duplicate
    // comes out active (even when the source is archived) and back at the
    // initial `record_state`. `updated_by` is a stale editor stamp — the
    // copy hasn't been edited yet. `created_by` is stamped by execute().
    // Tags (`contact_tag_rel`) are copied separately below — the rel table
    // has a composite PK and no `id` column, so `ChildCopy` doesn't apply.
    // Cross-plugin record-panel data (e.g. accounting's tax identity)
    // belongs to its owning plugin and is deliberately NOT copied.
    let spec = DuplicateSpec::new("contacts")
        .set("code", json!(code))
        .copy_suffix("name")
        .skip("record_state")
        .skip("active")
        .skip("updated_by");
    let new_id = match spec.execute(&db, id, Some(user.id)).await {
        Ok(new_id) => new_id,
        Err(e) => {
            error!(error = %e, "contact duplicate failed");
            return (
                vortex_plugin_sdk::axum::http::StatusCode::INTERNAL_SERVER_ERROR,
                "Duplicate failed",
            ).into_response();
        }
    };

    // Carry the source's tags over to the copy (best-effort: a tag
    // failure must not orphan the already-created contact).
    if let Err(e) = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO contact_tag_rel (contact_id, tag_id) \
         SELECT $1, tag_id FROM contact_tag_rel WHERE contact_id = $2",
    )
    .bind(new_id)
    .bind(id)
    .execute(&db)
    .await
    {
        error!(error = %e, "copying contact tags failed");
    }

    let audit_entry = vortex_plugin_sdk::security::AuditEntry::new(
        vortex_plugin_sdk::security::AuditAction::RecordCreated,
        vortex_plugin_sdk::security::AuditSeverity::Info,
    )
    .with_user(vortex_plugin_sdk::common::UserId(user.id))
    .with_username(&user.username)
    .with_database(&db_ctx.db_name)
    .with_resource("contact", new_id.to_string())
    .with_details(json!({ "duplicated_from": id, "code": code }));
    let _ = state.audit.log(audit_entry).await;

    info!(id = %new_id, source = %id, code = %code, "contact duplicated");
    vortex_plugin_sdk::axum::response::Redirect::to(&format!("/contacts/{new_id}")).into_response()
}

#[cfg(test)]
mod back_href_tests {
    use super::list_return_href;
    use vortex_plugin_sdk::axum::http::HeaderMap;

    fn with_referer(r: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert("referer", r.parse().unwrap());
        h
    }

    #[test]
    fn preserves_list_query_from_absolute_referer() {
        let h = with_referer("http://localhost:3003/contacts?search=23356&page=3");
        assert_eq!(
            list_return_href(&h, "/contacts"),
            "/contacts?search=23356&page=3"
        );
    }

    #[test]
    fn preserves_query_from_relative_referer() {
        let h = with_referer("/contacts?sort=name&dir=desc");
        assert_eq!(list_return_href(&h, "/contacts"), "/contacts?sort=name&dir=desc");
    }

    #[test]
    fn bare_list_path_when_no_referer() {
        assert_eq!(list_return_href(&HeaderMap::new(), "/contacts"), "/contacts");
    }

    #[test]
    fn ignores_referer_whose_path_is_not_the_list() {
        // A record page or another module must not become the back target
        // — the path doesn't match, so fall back to the list root.
        let h = with_referer("http://localhost:3003/contacts/abc-123");
        assert_eq!(list_return_href(&h, "/contacts"), "/contacts");
        let h = with_referer("http://localhost:3003/accounting/invoices");
        assert_eq!(list_return_href(&h, "/contacts"), "/contacts");
    }

    #[test]
    fn output_is_always_a_relative_path_never_cross_origin() {
        // The host is stripped by design: we only ever emit a path+query
        // relative to our own origin, so a crafted cross-origin referer
        // cannot become an open redirect — at worst it yields a harmless
        // relative link to our own list (the caller HTML-escapes it too).
        let h = with_referer("http://evil.example/contacts?x=1");
        let out = list_return_href(&h, "/contacts");
        assert_eq!(out, "/contacts?x=1");
        assert!(out.starts_with('/'), "must be relative, got: {out}");
    }
}
