//! SESB EAM HTTP handlers. Phase 1 covers reference/master data and the
//! location hierarchy. Later phases add their own sub-modules and merge
//! their routers in [`routes`].

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::uuid::Uuid;

pub mod analytics;
pub mod api;
pub mod checklist;
pub mod control_room;
pub mod dashboards;
pub mod diagrams;
pub mod equipment;
pub mod hierarchy;
pub mod jobs;
pub mod maintenance;
pub mod maps;
pub mod networks;
pub mod ops;
pub mod planning;
pub mod portal;
pub mod reference;
pub mod reports;
pub mod sld;
pub mod spec;
pub mod verification;
pub mod workforce;

/// Combined router for the whole plugin.
pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .merge(reference::routes())
        .merge(hierarchy::routes())
        .merge(equipment::routes())
        .merge(networks::routes())
        .merge(checklist::routes())
        .merge(maintenance::routes())
        .merge(ops::routes())
        .merge(planning::routes())
        .merge(workforce::routes())
        .merge(verification::routes())
        .merge(dashboards::routes())
        .merge(control_room::routes())
        .merge(sld::routes())
        .merge(maps::routes())
        .merge(reports::routes())
        .merge(api::routes())
        .merge(portal::routes())
        .merge(diagrams::routes())
}

// ─────────────────────────────────────────────────────────────────────────
// Shared UI scaffolding (mirrors the vortex-maintenance conventions)
// ─────────────────────────────────────────────────────────────────────────

pub(crate) fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=4" rel="stylesheet"/>
<script src="/static/vortex.js?v=4" defer></script>
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
        title = title, sidebar = sidebar, content = content,
    )
}

pub(crate) fn render_sidebar_active(
    state: &AppState,
    user: &AuthUser,
    db_ctx: &DatabaseContext,
    active: &str,
) -> String {
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
    )
}

pub(crate) async fn default_company(db: &vortex_plugin_sdk::sqlx::PgPool) -> Option<Uuid> {
    vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM companies LIMIT 1")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

pub(crate) fn esc(s: &str) -> String {
    vortex_plugin_sdk::framework::html_escape(s)
}

pub(crate) fn opt_uuid(form: &HashMap<String, String>, key: &str) -> Option<Uuid> {
    form.get(key).filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
}

pub(crate) fn opt_str<'a>(form: &'a HashMap<String, String>, key: &str) -> Option<&'a String> {
    form.get(key).filter(|s| !s.trim().is_empty())
}

pub(crate) fn opt_i32(form: &HashMap<String, String>, key: &str) -> Option<i32> {
    form.get(key).and_then(|s| s.trim().parse::<i32>().ok())
}

pub(crate) fn opt_date(
    form: &HashMap<String, String>,
    key: &str,
) -> Option<vortex_plugin_sdk::chrono::NaiveDate> {
    form.get(key).filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
}

pub(crate) fn opt_dec(
    form: &HashMap<String, String>,
    key: &str,
) -> Option<vortex_plugin_sdk::rust_decimal::Decimal> {
    form.get(key).and_then(|s| s.trim().parse().ok())
}

/// `<option>` builder from (id, label) rows of a simple query.
pub(crate) async fn options_query(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    sql: &str,
    placeholder: &str,
    selected: Option<Uuid>,
) -> String {
    use vortex_plugin_sdk::sqlx::Row;
    let rows = vortex_plugin_sdk::sqlx::query(sql).fetch_all(db).await.unwrap_or_default();
    let mut out = format!(r#"<option value="">{}</option>"#, esc(placeholder));
    for r in &rows {
        let id: Uuid = r.get("id");
        let label: String = r.get("label");
        let sel = if selected == Some(id) { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{label}</option>"#,
            id = id, sel = sel, label = esc(&label)
        ));
    }
    out
}

// Common select-option sources reused across forms.
pub(crate) async fn region_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_region WHERE active ORDER BY sequence, name", "-- Region --", sel).await
}
pub(crate) async fn zon_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_zon WHERE active ORDER BY sequence, name", "-- Zon --", sel).await
}
pub(crate) async fn kawasan_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_kawasan WHERE active ORDER BY sequence, name", "-- Kawasan --", sel).await
}
pub(crate) async fn site_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (code || ' · ' || name) AS label FROM eam_site WHERE active ORDER BY code", "-- Site --", sel).await
}
pub(crate) async fn voltage_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, name AS label FROM eam_voltage_level WHERE active ORDER BY voltage_kv DESC", "-- Voltage Level --", sel).await
}
pub(crate) async fn asset_type_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, (acronym || ' · ' || name) AS label FROM eam_asset_type WHERE active ORDER BY acronym", "-- Asset Type --", sel).await
}
pub(crate) async fn user_options(db: &vortex_plugin_sdk::sqlx::PgPool, sel: Option<Uuid>) -> String {
    options_query(db, "SELECT id, username AS label FROM users ORDER BY username", "-- Unassigned --", sel).await
}

/// `<option>`s from a fixed (value,label) enum list with selection.
pub(crate) fn enum_options(items: &[(&str, &str)], selected: &str) -> String {
    let mut out = String::new();
    for (val, label) in items {
        let sel = if *val == selected { " selected" } else { "" };
        out.push_str(&format!(r#"<option value="{val}"{sel}>{label}</option>"#, val = val, sel = sel, label = label));
    }
    out
}

/// Small helper: the back-link + title header used by every form page.
pub(crate) fn form_header(back_url: &str, back_label: &str, title: &str) -> String {
    format!(
        r#"<a href="{back}" class="btn btn-ghost btn-sm mb-4">← {back_label}</a>
<h1 class="text-2xl font-bold mb-6">{title}</h1>"#,
        back = back_url, back_label = esc(back_label), title = esc(title),
    )
}

// ── Form-field builders (shared by reference + hierarchy forms) ──

pub(crate) fn text_field(label: &str, name: &str, value: &str, required: bool) -> String {
    format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">{label}{star}</span></label>
<input name="{name}" class="input input-bordered input-sm" value="{value}" {req}/></div>"#,
        label = label, star = if required { " *" } else { "" }, name = name,
        value = esc(value), req = if required { "required" } else { "" },
    )
}

pub(crate) fn num_field(label: &str, name: &str, value: &str, step: &str) -> String {
    format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">{label}</span></label>
<input name="{name}" type="number" step="{step}" class="input input-bordered input-sm" value="{value}"/></div>"#,
        label = label, name = name, step = step, value = esc(value),
    )
}

pub(crate) fn date_field(label: &str, name: &str, value: &str) -> String {
    format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">{label}</span></label>
<input name="{name}" type="date" class="input input-bordered input-sm" value="{value}"/></div>"#,
        label = label, name = name, value = esc(value),
    )
}

pub(crate) fn textarea_field(label: &str, name: &str, value: &str) -> String {
    format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">{label}</span></label>
<textarea name="{name}" class="textarea textarea-bordered" rows="2">{value}</textarea></div>"#,
        label = label, name = name, value = esc(value),
    )
}

pub(crate) fn select_field(label: &str, name: &str, options: &str) -> String {
    format!(
        r#"<div class="form-control mb-3"><label class="label"><span class="label-text">{label}</span></label>
<select name="{name}" class="select select-bordered select-sm">{options}</select></div>"#,
        label = label, name = name, options = options,
    )
}

pub(crate) fn active_field(active: bool, is_new: bool) -> String {
    if is_new {
        String::new()
    } else {
        format!(
            r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="active" class="checkbox checkbox-sm" {c}/><span class="label-text">Active</span></label></div>"#,
            c = if active { "checked" } else { "" },
        )
    }
}

/// Wrap a form body in the standard single-column card page.
pub(crate) fn form_page(action: &str, header: &str, body: &str) -> String {
    format!(
        r#"<div class="max-w-2xl">{header}<form method="POST" action="{action}">
<div class="card bg-base-100 shadow"><div class="card-body">{body}
<div class="flex gap-2 mt-4"><button class="btn btn-primary btn-sm">Save</button></div>
</div></div></form></div>"#,
        header = header, action = action, body = body,
    )
}

/// Wrap a wide multi-column form body in a card page (for the big
/// substation / equipment forms).
pub(crate) fn wide_form_page(action: &str, header: &str, body: &str) -> String {
    format!(
        r#"<div class="max-w-4xl">{header}<form method="POST" action="{action}">
<div class="card bg-base-100 shadow"><div class="card-body">{body}
<div class="flex gap-2 mt-4"><button class="btn btn-primary btn-sm">Save</button></div>
</div></div></form></div>"#,
        header = header, action = action, body = body,
    )
}

/// Two-column responsive grid wrapper around a set of field strings.
pub(crate) fn grid2(fields: &str) -> String {
    format!(r#"<div class="grid grid-cols-1 md:grid-cols-2 gap-x-4">{}</div>"#, fields)
}

pub(crate) fn bad(msg: &str) -> Response {
    (vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}
