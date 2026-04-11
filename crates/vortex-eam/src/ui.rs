//! EAM HTML UI handlers — the 48 `/eam/*` routes plus their helpers.
//!
//! Moved here from `vortex-cli/src/commands/server.rs` in Phase 0.3b
//! as the final step of making EAM a real plugin. The core binary no
//! longer compiles any of these handlers when `vortex-eam` is not a
//! dependency, and even when it is, they live in this crate rather
//! than in the CLI.
//!
//! These handlers are `Router<Arc<AppState>>` — stateful routes that
//! share the host binary's `AppState`. The `EamPlugin::routes()`
//! method returns the router from [`eam_ui_routes`] and the host
//! merges it into the main router at startup.
//!
//! Internal organization is intentionally flat: 48 handler functions
//! in one file, roughly grouped by resource (dashboard, sites, assets,
//! work orders, inspections, transmission, etc.). A later phase may
//! split these into per-resource files if the file becomes unwieldy,
//! but for Phase 0.3b the priority is "get them out of the core."

use std::sync::Arc;

use axum::extract::{Form, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::routing::{get, post};
use axum::{Extension, Router};
use chrono::Datelike;
use serde::Deserialize;
use sqlx::Row;
use tracing::{error, info, warn};
use vortex_framework::{
    build_pagination_html, build_sidebar, error_response, format_number, forbidden_page,
    get_initials, html_escape, AppState, AuthUser, DatabaseContext, Db,
};

/// Build the complete EAM UI router — registered by
/// `EamPlugin::routes()` and merged into the host router at startup.
pub fn eam_ui_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/eam", get(eam_dashboard))
        .route("/eam/sites", get(eam_sites))
        .route("/eam/sites/new", get(eam_site_form))
        .route("/eam/sites", post(eam_site_create))
        .route("/eam/sites/{id}", get(eam_site_detail))
        .route("/eam/sites/{id}/edit", get(eam_site_edit))
        .route("/eam/sites/{id}", post(eam_site_update))
        .route("/eam/assets", get(eam_assets))
        .route("/eam/assets/new", get(eam_asset_form))
        .route("/eam/assets", post(eam_asset_create))
        .route("/eam/assets/{id}", get(eam_asset_detail))
        .route("/eam/assets/{id}/edit", get(eam_asset_edit))
        .route("/eam/assets/{id}", post(eam_asset_update))
        .route("/eam/configuration", get(eam_configuration))
        .route("/eam/work-orders", get(eam_work_orders))
        .route("/eam/work-orders/new", get(eam_work_order_new))
        .route("/eam/work-orders/new", post(eam_work_order_create))
        .route("/eam/work-orders/{id}", get(eam_work_order_detail))
        .route("/eam/work-orders/{id}/edit", get(eam_work_order_edit))
        .route("/eam/work-orders/{id}/edit", post(eam_work_order_save))
        .route("/api/eam/work-orders/{id}/transition", post(eam_work_order_transition))
        .route("/eam/functional-locations", get(eam_functional_locations))
        .route("/eam/functional-locations/new", get(eam_functional_location_new))
        .route("/eam/functional-locations/new", post(eam_functional_location_create))
        .route("/eam/functional-locations/{id}", get(eam_functional_location_detail))
        .route("/eam/functional-locations/{id}/edit", get(eam_functional_location_edit))
        .route("/eam/functional-locations/{id}/edit", post(eam_functional_location_save))
        .route("/eam/equipment", get(eam_equipment))
        .route("/eam/inspections", get(eam_inspections))
        .route("/eam/inspections/new", get(eam_inspection_new))
        .route("/eam/inspections/new", post(eam_inspection_create))
        .route("/eam/checklists", get(eam_checklists))
        .route("/eam/checklists/new", get(eam_checklist_new))
        .route("/eam/checklists/new", post(eam_checklist_create))
        .route("/eam/plans", get(eam_plans))
        .route("/eam/plans/new", get(eam_plan_new))
        .route("/eam/plans/new", post(eam_plan_create))
        .route("/eam/transmission", get(eam_transmission))
        .route("/eam/transmission/lines/new", get(eam_transmission_line_form))
        .route("/eam/transmission/lines/new", post(eam_transmission_line_create))
        .route("/eam/transmission/{id}", get(eam_transmission_line_detail))
        .route("/eam/transmission/towers/new", get(eam_transmission_tower_form))
        .route("/eam/transmission/towers/new", post(eam_transmission_tower_create))
        .route("/eam/sld", get(eam_sld))
        .route("/api/eam/sld/substations", get(eam_sld_substations_api))
        .route("/api/eam/sld/substations/{id}", get(eam_sld_data_api))
        .route("/eam/condition", get(eam_condition_monitoring))
        .route("/eam/manufacturers", get(eam_manufacturers))
}

// ============================================================================
// Handler bodies — moved verbatim from vortex-cli/src/commands/server.rs
// ============================================================================

async fn eam_dashboard(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Get user's company_id
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get stats
    let total_sites: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_sites WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let total_locations: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_functional_locations WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let total_assets: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_assets WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let in_service: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets a JOIN eam_asset_statuses s ON a.status_id = s.id WHERE a.company_id = $1 AND a.is_active = true AND s.code = 'ACTIVE'"
    ).bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let under_maint: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets a JOIN eam_asset_statuses s ON a.status_id = s.id WHERE a.company_id = $1 AND a.is_active = true AND s.code = 'MAINT'"
    ).bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let faulty: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM eam_assets a JOIN eam_asset_statuses s ON a.status_id = s.id WHERE a.company_id = $1 AND a.is_active = true AND s.code = 'FAULTY'"
    ).bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_dashboard", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Asset Management - Remicle</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><h1 class="text-2xl font-bold">Enterprise Asset Management</h1><p class="text-base-content/60">Distribution substation asset tracking</p></div>
<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Sites</div><div class="stat-value text-primary">{total_sites}</div><div class="stat-desc">Substations</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Functional Locations</div><div class="stat-value text-secondary">{total_locations}</div><div class="stat-desc">PPU, SSU, PP, PE</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">Total Assets</div><div class="stat-value text-accent">{total_assets}</div><div class="stat-desc">Equipment</div></div>
<div class="stat bg-base-100 rounded-lg shadow"><div class="stat-title">In Service</div><div class="stat-value text-success">{in_service}</div><div class="stat-desc">Operational</div></div>
</div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title">Asset Status</h2><div class="space-y-4 mt-4">
<div class="flex items-center justify-between"><div class="flex items-center gap-2"><span class="badge badge-success badge-sm"></span><span>In Service</span></div><span class="font-semibold">{in_service}</span></div>
<div class="flex items-center justify-between"><div class="flex items-center gap-2"><span class="badge badge-warning badge-sm"></span><span>Under Maintenance</span></div><span class="font-semibold">{under_maint}</span></div>
<div class="flex items-center justify-between"><div class="flex items-center gap-2"><span class="badge badge-error badge-sm"></span><span>Faulty</span></div><span class="font-semibold">{faulty}</span></div>
</div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><h2 class="card-title">Quick Actions</h2><div class="grid grid-cols-1 sm:grid-cols-2 gap-3 mt-4">
<a href="/eam/sites" class="btn btn-outline btn-primary">View Sites</a>
<a href="/eam/assets" class="btn btn-outline btn-secondary">View Assets</a>
<a href="/eam/sites/new" class="btn btn-outline btn-accent">New Site</a>
<a href="/eam/configuration" class="btn btn-outline">Configuration</a>
</div></div></div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_sites(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let type_filter = params.get("type").map(|s| s.as_str()).unwrap_or("");
    let status_filter = params.get("status").map(|s| s.as_str()).unwrap_or("");
    let view = params.get("view").map(|s| s.as_str()).unwrap_or("list");

    // Get user's company_id
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let sites = sqlx::query(
        r#"SELECT s.id, s.code, s.name, s.site_type, s.city, s.status, s.feeder_count,
           COALESCE((SELECT COUNT(*) FROM eam_assets a JOIN eam_functional_locations fl ON a.functional_location_id = fl.id WHERE fl.site_id = s.id), 0) as asset_count
           FROM eam_sites s WHERE s.company_id = $1 AND s.is_active = true
           AND ($2 = '' OR s.code ILIKE '%' || $2 || '%' OR s.name ILIKE '%' || $2 || '%' OR s.city ILIKE '%' || $2 || '%')
           AND ($3 = '' OR s.site_type = $3)
           AND ($4 = '' OR s.status = $4)
           ORDER BY s.code"#
    ).bind(company_id).bind(search).bind(type_filter).bind(status_filter)
    .fetch_all(&db).await.unwrap_or_default();

    // Build content based on view type
    let content = match view {
        "card" => {
            let mut cards = String::new();
            for site in &sites {
                let id: uuid::Uuid = site.get("id");
                let code: String = site.get("code");
                let name: String = site.get("name");
                let site_type: Option<String> = site.get("site_type");
                let city: Option<String> = site.get("city");
                let status: Option<String> = site.get("status");
                let asset_count: i64 = site.get("asset_count");
                let feeder_count: Option<i32> = site.get("feeder_count");
                cards.push_str(&format!(r#"<a href="/eam/sites/{}" class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                    <div class="card-body">
                        <div class="flex justify-between items-start">
                            <div class="badge badge-primary badge-outline">{}</div>
                            <span class="badge badge-sm">{}</span>
                        </div>
                        <h3 class="card-title text-lg mt-2">{}</h3>
                        <p class="text-base-content/60 text-sm">{}</p>
                        <div class="flex gap-4 mt-3 text-sm">
                            <div><span class="text-base-content/60">Assets:</span> <span class="font-semibold">{}</span></div>
                            <div><span class="text-base-content/60">Feeders:</span> <span class="font-semibold">{}</span></div>
                        </div>
                        <div class="card-actions justify-end mt-2">
                            <a href="/eam/sites/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                        </div>
                    </div>
                </a>"#, id, code, status.unwrap_or("Active".into()), name, city.unwrap_or("-".into()),
                    asset_count, feeder_count.unwrap_or(0), id));
            }
            if sites.is_empty() {
                cards = r#"<div class="col-span-full text-center py-12"><p class="text-lg">No sites found</p></div>"#.to_string();
            }
            format!(r#"<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">{}</div>"#, cards)
        },
        "pivot" => {
            // Group by site_type
            let mut by_type: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for site in &sites {
                let site_type: Option<String> = site.get("site_type");
                by_type.entry(site_type.unwrap_or("Unspecified".into())).or_default().push(site);
            }
            let mut pivot_html = String::new();
            for (stype, type_sites) in &by_type {
                let total_assets: i64 = type_sites.iter().map(|s| s.get::<i64, _>("asset_count")).sum();
                pivot_html.push_str(&format!(r#"<div class="collapse collapse-arrow bg-base-100 mb-2">
                    <input type="checkbox" checked/>
                    <div class="collapse-title font-medium flex justify-between items-center">
                        <span>{} ({} sites)</span>
                        <span class="badge">{} assets</span>
                    </div>
                    <div class="collapse-content"><div class="overflow-x-auto">
                    <table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>City</th><th>Assets</th><th></th></tr></thead><tbody>"#,
                    stype, type_sites.len(), total_assets));
                for site in type_sites {
                    let id: uuid::Uuid = site.get("id");
                    let code: String = site.get("code");
                    let name: String = site.get("name");
                    let city: Option<String> = site.get("city");
                    let asset_count: i64 = site.get("asset_count");
                    pivot_html.push_str(&format!(r#"<tr><td class="font-mono">{}</td><td>{}</td><td>{}</td><td>{}</td>
                        <td><a href="/eam/sites/{}" class="btn btn-ghost btn-xs">View</a></td></tr>"#,
                        code, name, city.unwrap_or("-".into()), asset_count, id));
                }
                pivot_html.push_str("</tbody></table></div></div></div>");
            }
            if sites.is_empty() {
                pivot_html = r#"<div class="text-center py-12"><p class="text-lg">No sites found</p></div>"#.to_string();
            }
            pivot_html
        },
        _ => {
            // List view (default)
            let mut rows = String::new();
            for site in &sites {
                let id: uuid::Uuid = site.get("id");
                let code: String = site.get("code");
                let name: String = site.get("name");
                let site_type: Option<String> = site.get("site_type");
                let city: Option<String> = site.get("city");
                let status: Option<String> = site.get("status");
                let asset_count: i64 = site.get("asset_count");
                rows.push_str(&format!(r#"<tr class="hover">
                    <td class="font-mono font-semibold">{}</td><td>{}</td><td>{}</td><td>{}</td>
                    <td><span class="badge badge-outline">{}</span></td><td>{}</td>
                    <td class="flex gap-1">
                        <a href="/eam/sites/{}" class="btn btn-ghost btn-xs">View</a>
                        <a href="/eam/sites/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                    </td>
                </tr>"#, code, name, site_type.unwrap_or("-".into()), city.unwrap_or("-".into()),
                    status.unwrap_or("Unknown".into()), asset_count, id, id));
            }
            let empty = if sites.is_empty() { r#"<tr><td colspan="7" class="text-center py-12">No sites found</td></tr>"# } else { "" };
            format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>City</th><th>Status</th><th>Assets</th><th>Actions</th></tr></thead><tbody>{}{}</tbody></table></div>"#, rows, empty)
        }
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_sites", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    let view_btns = format!(r#"<div class="btn-group">
        <a href="?view=list&search={search}&type={type_filter}&status={status_filter}" class="btn btn-sm {}" title="List View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>List</a>
        <a href="?view=card&search={search}&type={type_filter}&status={status_filter}" class="btn btn-sm {}" title="Card View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>Card</a>
        <a href="?view=pivot&search={search}&type={type_filter}&status={status_filter}" class="btn btn-sm {}" title="Pivot View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>Pivot</a>
    </div>"#,
        if view == "list" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "card" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "pivot" { "btn-active btn-primary" } else { "btn-ghost" },
    );

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Sites - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6">
<div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Sites</li></ul></div>
<h1 class="text-2xl font-bold">Sites</h1><p class="text-base-content/60">Substations and distribution locations</p></div>
<a href="/eam/sites/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Site</a></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex flex-wrap justify-between items-center gap-3 mb-4">
<form method="GET" class="flex flex-wrap gap-3">
<input type="hidden" name="view" value="{view}"/>
<input type="text" name="search" placeholder="Search code, name, city..." value="{search}" class="input input-bordered input-sm w-64"/>
<select name="type" class="select select-bordered select-sm">
<option value="">All Types</option>
<option value="Indoor GIS" {}>Indoor GIS</option>
<option value="Outdoor AIS" {}>Outdoor AIS</option>
<option value="Hybrid" {}>Hybrid</option>
</select>
<select name="status" class="select select-bordered select-sm">
<option value="">All Status</option>
<option value="Active" {}>Active</option>
<option value="Inactive" {}>Inactive</option>
<option value="Under Construction" {}>Under Construction</option>
</select>
<button type="submit" class="btn btn-sm btn-primary">Search</button>
<a href="/eam/sites?view={view}" class="btn btn-sm btn-ghost">Clear</a>
</form>
{view_btns}
</div>
{content}
</div></div>
</main></div></body></html>"#,
        if type_filter == "Indoor GIS" { "selected" } else { "" },
        if type_filter == "Outdoor AIS" { "selected" } else { "" },
        if type_filter == "Hybrid" { "selected" } else { "" },
        if status_filter == "Active" { "selected" } else { "" },
        if status_filter == "Inactive" { "selected" } else { "" },
        if status_filter == "Under Construction" { "selected" } else { "" },
    )).into_response()
}

async fn eam_assets(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let search = params.get("search").map(|s| s.as_str()).unwrap_or("");
    let category_filter = params.get("category").map(|s| s.as_str()).unwrap_or("");
    let status_filter = params.get("status").map(|s| s.as_str()).unwrap_or("");
    let site_filter = params.get("site").map(|s| s.as_str()).unwrap_or("");
    let view = params.get("view").map(|s| s.as_str()).unwrap_or("list");

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let categories: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_categories WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let statuses: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true ORDER BY display_order"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let sites_list: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_sites WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let assets = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, c.name as category_name, c.id as category_id,
           s.name as site_name, s.id as site_id, fl.name as location_name,
           st.name as status_name, st.id as status_id, st.color as status_color
           FROM eam_assets a
           LEFT JOIN eam_asset_categories c ON a.category_id = c.id
           LEFT JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_asset_statuses st ON a.status_id = st.id
           WHERE a.company_id = $1 AND a.is_active = true
           AND ($2 = '' OR a.asset_code ILIKE '%' || $2 || '%' OR a.name ILIKE '%' || $2 || '%')
           AND ($3 = '' OR c.id::text = $3)
           AND ($4 = '' OR st.id::text = $4)
           AND ($5 = '' OR s.id::text = $5)
           ORDER BY a.asset_code LIMIT 100"#
    ).bind(company_id).bind(search).bind(category_filter).bind(status_filter).bind(site_filter)
    .fetch_all(&db).await.unwrap_or_default();

    // Build content based on view type
    let content = match view {
        "card" => {
            let mut cards = String::new();
            for asset in &assets {
                let id: uuid::Uuid = asset.get("id");
                let code: String = asset.get("asset_code");
                let name: String = asset.get("name");
                let category: Option<String> = asset.get("category_name");
                let site: Option<String> = asset.get("site_name");
                let status: Option<String> = asset.get("status_name");
                let color: Option<String> = asset.get("status_color");
                let manufacturer: Option<String> = asset.get("manufacturer");
                let model: Option<String> = asset.get("model");
                cards.push_str(&format!(r#"<a href="/eam/assets/{}" class="card bg-base-100 shadow hover:shadow-lg transition-shadow">
                    <div class="card-body">
                        <div class="flex justify-between items-start">
                            <span class="badge badge-sm">{}</span>
                            <span class="badge badge-sm" style="background-color:{};color:white">{}</span>
                        </div>
                        <h3 class="card-title text-base mt-2">{}</h3>
                        <p class="font-mono text-sm text-base-content/60">{}</p>
                        <div class="text-sm mt-2">
                            <p><span class="text-base-content/60">Site:</span> {}</p>
                            <p><span class="text-base-content/60">Mfr:</span> {} {}</p>
                        </div>
                        <div class="card-actions justify-end mt-2">
                            <a href="/eam/assets/{}/edit" class="btn btn-ghost btn-xs">Edit</a>
                        </div>
                    </div>
                </a>"#, id, category.clone().unwrap_or("-".into()), color.unwrap_or("#6C757D".into()),
                    status.unwrap_or("-".into()), name, code, site.unwrap_or("-".into()),
                    manufacturer.unwrap_or("-".into()), model.unwrap_or("".into()), id));
            }
            if assets.is_empty() { cards = r#"<div class="col-span-full text-center py-12"><p class="text-lg">No assets found</p></div>"#.to_string(); }
            format!(r#"<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">{}</div>"#, cards)
        },
        "pivot" => {
            let mut by_cat: std::collections::HashMap<String, Vec<_>> = std::collections::HashMap::new();
            for asset in &assets {
                let cat: Option<String> = asset.get("category_name");
                by_cat.entry(cat.unwrap_or("Uncategorized".into())).or_default().push(asset);
            }
            let mut pivot_html = String::new();
            for (cat, cat_assets) in &by_cat {
                pivot_html.push_str(&format!(r#"<div class="collapse collapse-arrow bg-base-100 mb-2">
                    <input type="checkbox" checked/>
                    <div class="collapse-title font-medium"><span>{}</span> <span class="badge badge-sm">{}</span></div>
                    <div class="collapse-content"><div class="overflow-x-auto">
                    <table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Site</th><th>Status</th><th></th></tr></thead><tbody>"#,
                    cat, cat_assets.len()));
                for asset in cat_assets {
                    let id: uuid::Uuid = asset.get("id");
                    let code: String = asset.get("asset_code");
                    let name: String = asset.get("name");
                    let site: Option<String> = asset.get("site_name");
                    let status: Option<String> = asset.get("status_name");
                    let color: Option<String> = asset.get("status_color");
                    pivot_html.push_str(&format!(r#"<tr><td class="font-mono">{}</td><td>{}</td><td>{}</td>
                        <td><span class="badge badge-sm" style="background-color:{};color:white">{}</span></td>
                        <td><a href="/eam/assets/{}" class="btn btn-ghost btn-xs">View</a></td></tr>"#,
                        code, name, site.unwrap_or("-".into()), color.unwrap_or("#6C757D".into()), status.unwrap_or("-".into()), id));
                }
                pivot_html.push_str("</tbody></table></div></div></div>");
            }
            if assets.is_empty() { pivot_html = r#"<div class="text-center py-12"><p class="text-lg">No assets found</p></div>"#.to_string(); }
            pivot_html
        },
        _ => {
            let mut rows = String::new();
            for asset in &assets {
                let id: uuid::Uuid = asset.get("id");
                let code: String = asset.get("asset_code");
                let name: String = asset.get("name");
                let category: Option<String> = asset.get("category_name");
                let site: Option<String> = asset.get("site_name");
                let location: Option<String> = asset.get("location_name");
                let status: Option<String> = asset.get("status_name");
                let color: Option<String> = asset.get("status_color");
                rows.push_str(&format!(r#"<tr class="hover">
                    <td class="font-mono font-semibold">{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>
                    <td><span class="badge" style="background-color:{};color:white">{}</span></td>
                    <td class="flex gap-1"><a href="/eam/assets/{}" class="btn btn-ghost btn-xs">View</a><a href="/eam/assets/{}/edit" class="btn btn-ghost btn-xs">Edit</a></td>
                </tr>"#, code, name, category.unwrap_or("-".into()), site.unwrap_or("-".into()),
                    location.unwrap_or("-".into()), color.unwrap_or("#6C757D".into()), status.unwrap_or("Unknown".into()), id, id));
            }
            let empty = if assets.is_empty() { r#"<tr><td colspan="7" class="text-center py-12">No assets found</td></tr>"# } else { "" };
            format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Category</th><th>Site</th><th>Location</th><th>Status</th><th>Actions</th></tr></thead><tbody>{}{}</tbody></table></div>"#, rows, empty)
        }
    };

    let cat_options: String = categories.iter().map(|(id, name)| format!(r#"<option value="{}" {}>{}</option>"#, id, if category_filter == id { "selected" } else { "" }, name)).collect();
    let status_options: String = statuses.iter().map(|(id, name)| format!(r#"<option value="{}" {}>{}</option>"#, id, if status_filter == id { "selected" } else { "" }, name)).collect();
    let site_options: String = sites_list.iter().map(|(id, name)| format!(r#"<option value="{}" {}>{}</option>"#, id, if site_filter == id { "selected" } else { "" }, name)).collect();

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_assets", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    let view_btns = format!(r#"<div class="btn-group">
        <a href="?view=list&search={search}&category={category_filter}&status={status_filter}&site={site_filter}" class="btn btn-sm {}" title="List View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 10h16M4 14h16M4 18h16"/></svg>List</a>
        <a href="?view=card&search={search}&category={category_filter}&status={status_filter}&site={site_filter}" class="btn btn-sm {}" title="Card View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2V6zM14 6a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2V6zM4 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2H6a2 2 0 01-2-2v-2zM14 16a2 2 0 012-2h2a2 2 0 012 2v2a2 2 0 01-2 2h-2a2 2 0 01-2-2v-2z"/></svg>Card</a>
        <a href="?view=pivot&search={search}&category={category_filter}&status={status_filter}&site={site_filter}" class="btn btn-sm {}" title="Pivot View">
            <svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 17V7m0 10a2 2 0 01-2 2H5a2 2 0 01-2-2V7a2 2 0 012-2h2a2 2 0 012 2m0 10a2 2 0 002 2h2a2 2 0 002-2M9 7a2 2 0 012-2h2a2 2 0 012 2m0 10V7m0 10a2 2 0 002 2h2a2 2 0 002-2V7a2 2 0 00-2-2h-2a2 2 0 00-2 2"/></svg>Pivot</a>
    </div>"#,
        if view == "list" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "card" { "btn-active btn-primary" } else { "btn-ghost" },
        if view == "pivot" { "btn-active btn-primary" } else { "btn-ghost" });

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Assets - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6">
<div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Assets</li></ul></div>
<h1 class="text-2xl font-bold">Assets</h1><p class="text-base-content/60">Equipment and components</p></div>
<a href="/eam/assets/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Asset</a></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex flex-wrap justify-between items-center gap-3 mb-4">
<form method="GET" class="flex flex-wrap gap-3">
<input type="hidden" name="view" value="{view}"/>
<input type="text" name="search" placeholder="Search code or name..." value="{search}" class="input input-bordered input-sm w-48"/>
<select name="category" class="select select-bordered select-sm"><option value="">All Categories</option>{cat_options}</select>
<select name="status" class="select select-bordered select-sm"><option value="">All Status</option>{status_options}</select>
<select name="site" class="select select-bordered select-sm"><option value="">All Sites</option>{site_options}</select>
<button type="submit" class="btn btn-sm btn-primary">Search</button>
<a href="/eam/assets?view={view}" class="btn btn-sm btn-ghost">Clear</a>
</form>
{view_btns}
</div>
{content}
</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_configuration(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Get user's company_id
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let voltage_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let unit_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_unit_types WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let category_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_asset_categories WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let status_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_configuration", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Configuration - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Configuration</li></ul></div>
<h1 class="text-2xl font-bold">EAM Configuration</h1><p class="text-base-content/60">Manage voltage levels, unit types, categories, and statuses</p></div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-6">
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-warning/20 p-3 rounded-lg"><svg class="w-6 h-6 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg></div>
<div><h2 class="card-title text-lg">Voltage Levels</h2><p class="text-base-content/60 text-sm">275kV, 132kV, 33kV, 11kV, etc.</p></div></div>
<div class="badge badge-lg">{voltage_count}</div></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-info/20 p-3 rounded-lg"><svg class="w-6 h-6 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 3v2m6-2v2M9 19v2m6-2v2M5 9H3m2 6H3m18-6h-2m2 6h-2M7 19h10a2 2 0 002-2V7a2 2 0 00-2-2H7a2 2 0 00-2 2v10a2 2 0 002 2zM9 9h6v6H9V9z"/></svg></div>
<div><h2 class="card-title text-lg">Unit Types</h2><p class="text-base-content/60 text-sm">PPU, SSU, PP, PE classifications</p></div></div>
<div class="badge badge-lg">{unit_count}</div></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-secondary/20 p-3 rounded-lg"><svg class="w-6 h-6 text-secondary" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 7h.01M7 3h5c.512 0 1.024.195 1.414.586l7 7a2 2 0 010 2.828l-7 7a2 2 0 01-2.828 0l-7-7A2 2 0 013 12V7a4 4 0 014-4z"/></svg></div>
<div><h2 class="card-title text-lg">Asset Categories</h2><p class="text-base-content/60 text-sm">Transformer, Switchgear, RMU, etc.</p></div></div>
<div class="badge badge-lg">{category_count}</div></div></div></div>
<div class="card bg-base-100 shadow"><div class="card-body"><div class="flex items-center justify-between">
<div class="flex items-center gap-3"><div class="bg-success/20 p-3 rounded-lg"><svg class="w-6 h-6 text-success" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg></div>
<div><h2 class="card-title text-lg">Asset Statuses</h2><p class="text-base-content/60 text-sm">In Service, Maintenance, Faulty, etc.</p></div></div>
<div class="badge badge-lg">{status_count}</div></div></div></div>
</div>
<div class="alert mt-6"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>
<div><h3 class="font-bold">Default Configuration</h3><div class="text-sm">Standard Malaysian electrical utility voltage levels and equipment categories are pre-configured.</div></div></div>
</main></div></body></html>"#)).into_response()
}

// =============================================================================
// NEW SESB EAM FEATURES
// =============================================================================

async fn eam_work_orders(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get stats
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let draft: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'draft'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let scheduled: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'scheduled'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let in_progress: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'in_progress'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let on_hold: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'on_hold'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let completed: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_work_orders WHERE company_id = $1 AND state = 'completed'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);

    // Get work orders
    let rows = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start, a.name as asset_name, u.full_name as assigned_to
           FROM eam_work_orders wo
           LEFT JOIN eam_assets a ON wo.asset_id = a.id
           LEFT JOIN users u ON wo.assigned_to = u.id
           WHERE wo.company_id = $1
           ORDER BY CASE wo.state WHEN 'in_progress' THEN 1 WHEN 'scheduled' THEN 2 WHEN 'on_hold' THEN 3 WHEN 'draft' THEN 4 ELSE 5 END,
                    wo.scheduled_start NULLS LAST LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let wo_number: String = row.get("wo_number");
        let title: String = row.get("title");
        let maint_type: String = row.get::<Option<String>, _>("maintenance_type").unwrap_or_else(|| "-".to_string());
        let priority_int: i32 = row.get::<Option<i32>, _>("priority").unwrap_or(2);
        let priority = match priority_int { 0 => "critical", 1 => "high", 2 => "medium", 3 => "low", _ => "medium" }.to_string();
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let assigned: String = row.get::<Option<String>, _>("assigned_to").unwrap_or_else(|| "-".to_string());
        let sched_date: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_start")
            .map(|d| d.format("%d/%m/%Y").to_string()).unwrap_or_else(|| "-".to_string());

        let priority_color = match priority.as_str() {
            "critical" => "#DC2626", "high" => "#F97316", "medium" => "#EAB308", "low" => "#22C55E", _ => "#6B7280"
        };
        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "scheduled" => "#3B82F6", "in_progress" => "#F59E0B", "on_hold" => "#EF4444", "completed" => "#10B981", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{wo_number}</td><td>{title}</td><td>{asset_name}</td>
            <td><span class="badge badge-outline badge-sm">{maint_type}</span></td>
            <td><span class="badge badge-sm" style="background-color:{priority_color};color:white;">{priority}</span></td>
            <td><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></td>
            <td>{sched_date}</td><td>{assigned}</td>
            <td><a href="/eam/work-orders/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg><h3 class="text-lg font-semibold mb-2">No Work Orders Yet</h3><p class="text-base-content/60">Create a work order to schedule maintenance</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>WO Number</th><th>Title</th><th>Asset</th><th>Type</th><th>Priority</th><th>State</th><th>Scheduled</th><th>Assigned</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_work_orders", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Work Orders - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Work Orders</li></ul></div>
<h1 class="text-2xl font-bold">Work Orders</h1><p class="text-base-content/60">Maintenance work order management</p></div>
<a href="/eam/work-orders/new" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Work Order</a></div>
<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Total</div><div class="stat-value text-2xl">{total}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Draft</div><div class="stat-value text-2xl text-gray-500">{draft}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Scheduled</div><div class="stat-value text-2xl text-blue-500">{scheduled}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">In Progress</div><div class="stat-value text-2xl text-amber-500">{in_progress}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">On Hold</div><div class="stat-value text-2xl text-red-500">{on_hold}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Completed</div><div class="stat-value text-2xl text-green-500">{completed}</div></div>
</div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get assets for dropdown
    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    // Get users for assignment dropdown
    let users_rows = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    // Build asset options
    let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        asset_options.push_str(&format!(r#"<option value="{aid}">{acode} - {aname}</option>"#));
    }

    // Build user options
    let mut user_options = r#"<option value="">-- Unassigned --</option>"#.to_string();
    for u in &users_rows {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get::<Option<String>, _>("full_name")
            .unwrap_or_else(|| u.get::<String, _>("username"));
        user_options.push_str(&format!(r#"<option value="{uid}">{uname}</option>"#));
    }

    // Maintenance type options
    let mtype_html = r#"<option value="">-- Select Type --</option>
        <option value="pm">Preventive (PM)</option><option value="cm">Corrective (CM)</option>
        <option value="emergency">Emergency</option><option value="inspection">Inspection</option>
        <option value="testing">Testing</option><option value="overhaul">Overhaul</option>"#;

    let priority_html = r#"<option value="0">Critical</option><option value="1">High</option>
        <option value="2" selected>Medium</option><option value="3">Low</option>"#;

    let content = format!(r##"<form method="POST" action="/eam/work-orders/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">General Information</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Title *</span></label>
<input type="text" name="title" class="input input-bordered" placeholder="Enter work order title" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24" placeholder="Describe the work to be done"></textarea></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Maintenance Type</span></label>
<select name="maintenance_type" class="select select-bordered">{mtype_html}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered">{priority_html}</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assignment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered">{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered">{user_options}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Planned Duration (hours)</span></label>
<input type="number" name="planned_duration_hours" class="input input-bordered" step="0.5" min="0"/></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Schedule</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Scheduled Start</span></label>
<input type="datetime-local" name="scheduled_start" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Scheduled End</span></label>
<input type="datetime-local" name="scheduled_end" class="input input-bordered"/></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/work-orders" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Work Order</button>
</div>
</div></div></form>"##);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_work_orders", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Work Order - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/work-orders">Work Orders</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Work Order</h1></div>
<a href="/eam/work-orders" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let title = form.get("title").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let priority: i32 = form.get("priority").and_then(|p| p.parse().ok()).unwrap_or(2);
    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let assigned_to = form.get("assigned_to").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let scheduled_start = form.get("scheduled_start").cloned().unwrap_or_default();
    let scheduled_end = form.get("scheduled_end").cloned().unwrap_or_default();
    let duration: Option<f64> = form.get("planned_duration_hours").and_then(|d| d.parse().ok());

    let sched_start_ts = if scheduled_start.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_start, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };
    let sched_end_ts = if scheduled_end.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_end, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };

    // Generate WO number
    let next_num: i64 = sqlx::query_scalar("SELECT COUNT(*) + 1 FROM eam_work_orders WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(1);
    let wo_number = format!("WO-{}-{:05}", chrono::Utc::now().format("%Y"), next_num);

    let mtype_opt = if maintenance_type.is_empty() { None } else { Some(maintenance_type) };
    let desc_opt = if description.is_empty() { None } else { Some(description) };

    let new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_work_orders (company_id, wo_number, title, description, maintenance_type, priority, state,
            asset_id, assigned_to, scheduled_start, scheduled_end, planned_duration_hours, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, 'draft', $7, $8, $9, $10, $11, $12)
            RETURNING id"#
    )
    .bind(company_id).bind(&wo_number).bind(&title).bind(&desc_opt).bind(&mtype_opt).bind(priority)
    .bind(asset_id).bind(assigned_to).bind(sched_start_ts).bind(sched_end_ts)
    .bind(duration).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to(&format!("/eam/work-orders/{}", new_id)).into_response()
}

async fn eam_work_order_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Get work order details
    let wo = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.description, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start, wo.scheduled_end, wo.actual_start, wo.actual_end,
                  wo.findings, wo.actions_taken, wo.recommendations, wo.hold_reason, wo.cancel_reason,
                  wo.created_at, wo.materials_cost, wo.labor_cost, wo.total_cost,
                  a.name as asset_name, a.asset_code, a.id as asset_id,
                  u.full_name as assigned_to, cr.full_name as created_by_name
           FROM eam_work_orders wo
           LEFT JOIN eam_assets a ON wo.asset_id = a.id
           LEFT JOIN users u ON wo.assigned_to = u.id
           LEFT JOIN users cr ON wo.created_by = cr.id
           WHERE wo.id = $1"#
    ).bind(id).fetch_optional(&db).await.unwrap_or(None);

    // Get activity/state history
    let history_rows = sqlx::query(
        r#"SELECT h.from_state, h.to_state, h.action, h.reason, h.changed_at, u.full_name as changed_by
           FROM eam_work_order_state_history h
           LEFT JOIN users u ON h.changed_by = u.id
           WHERE h.work_order_id = $1 ORDER BY h.changed_at DESC"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let content = if let Some(row) = wo {
        let wo_number: String = row.get("wo_number");
        let title: String = row.get("title");
        let description: String = row.get::<Option<String>, _>("description").unwrap_or_default();
        let maint_type: String = row.get::<Option<String>, _>("maintenance_type").unwrap_or_else(|| "-".to_string());
        let priority_int: i32 = row.get::<Option<i32>, _>("priority").unwrap_or(2);
        let priority = match priority_int { 0 => "Critical", 1 => "High", 2 => "Medium", 3 => "Low", _ => "Medium" };
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let asset_code: String = row.get::<Option<String>, _>("asset_code").unwrap_or_else(|| "-".to_string());
        let assigned: String = row.get::<Option<String>, _>("assigned_to").unwrap_or_else(|| "Unassigned".to_string());
        let created_by: String = row.get::<Option<String>, _>("created_by_name").unwrap_or_else(|| "-".to_string());
        let created_at: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let sched_start: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_start")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let sched_end: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_end")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let actual_start: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("actual_start")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let actual_end: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("actual_end")
            .map(|d| d.format("%d/%m/%Y %H:%M").to_string()).unwrap_or_else(|| "-".to_string());
        let findings: String = row.get::<Option<String>, _>("findings").unwrap_or_default();
        let actions: String = row.get::<Option<String>, _>("actions_taken").unwrap_or_default();
        let recommendations: String = row.get::<Option<String>, _>("recommendations").unwrap_or_default();
        let hold_reason: String = row.get::<Option<String>, _>("hold_reason").unwrap_or_default();

        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "scheduled" => "#3B82F6", "in_progress" => "#F59E0B",
            "on_hold" => "#EF4444", "completed" => "#10B981", "cancelled" => "#9CA3AF", _ => "#6B7280"
        };
        let priority_color = match priority_int { 0 => "#DC2626", 1 => "#F97316", 2 => "#EAB308", 3 => "#22C55E", _ => "#6B7280" };

        // Status progress bar steps
        let steps = vec!["draft", "scheduled", "in_progress", "completed"];
        let current_idx = steps.iter().position(|s| *s == state_val.as_str()).unwrap_or(0);
        let is_cancelled = state_val == "cancelled";
        let is_on_hold = state_val == "on_hold";

        let mut steps_html = String::new();
        for (i, step) in steps.iter().enumerate() {
            let label = match *step { "draft" => "Draft", "scheduled" => "Scheduled", "in_progress" => "In Progress", "completed" => "Completed", _ => step };
            let class = if is_cancelled {
                "step"
            } else if i < current_idx {
                "step step-primary"
            } else if i == current_idx {
                "step step-primary"
            } else {
                "step"
            };
            steps_html.push_str(&format!(r#"<li class="{class}">{label}</li>"#));
        }

        let on_hold_badge = if is_on_hold {
            r#"<div class="alert alert-error mt-2"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z"/></svg><span>ON HOLD</span></div>"#
        } else { "" };

        let cancelled_badge = if is_cancelled {
            r#"<div class="alert alert-warning mt-2"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M18.364 18.364A9 9 0 005.636 5.636m12.728 12.728A9 9 0 015.636 5.636m12.728 12.728L5.636 5.636"/></svg><span>CANCELLED</span></div>"#
        } else { "" };

        // Action buttons based on state
        let action_buttons = match state_val.as_str() {
            "draft" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="schedule"/>
                <button type="submit" class="btn btn-primary btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg>Schedule</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="start"/>
                <button type="submit" class="btn btn-warning btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>Start Work</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="cancel"/>
                <button type="submit" class="btn btn-ghost btn-block text-error" onclick="return confirm('Cancel this work order?')">Cancel</button></form>"#),
            "scheduled" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="start"/>
                <button type="submit" class="btn btn-primary btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>Start Work</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="cancel"/>
                <button type="submit" class="btn btn-ghost btn-block text-error" onclick="return confirm('Cancel this work order?')">Cancel</button></form>"#),
            "in_progress" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="complete"/>
                <button type="submit" class="btn btn-success btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Complete</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="hold"/>
                <button type="submit" class="btn btn-outline btn-error btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 9v6m4-6v6m7-3a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>Put On Hold</button></form>"#),
            "on_hold" => format!(r#"
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="resume"/>
                <button type="submit" class="btn btn-primary btn-block mb-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/></svg>Resume Work</button></form>
                <form method="POST" action="/api/eam/work-orders/{id}/transition"><input type="hidden" name="action" value="cancel"/>
                <button type="submit" class="btn btn-ghost btn-block text-error" onclick="return confirm('Cancel this work order?')">Cancel</button></form>"#),
            "completed" => String::new(),
            "cancelled" => String::new(),
            _ => String::new(),
        };

        // Activity stream
        let mut activity_html = String::new();
        if history_rows.is_empty() {
            activity_html.push_str(&format!(
                r#"<li><div class="timeline-start timeline-box text-sm">Work order created</div>
                <div class="timeline-middle"><svg class="w-5 h-5 text-primary" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg></div>
                <div class="timeline-end text-xs text-base-content/60">{created_at}<br/>{created_by}</div><hr/></li>"#));
        }
        for (i, hrow) in history_rows.iter().enumerate() {
            let from: String = hrow.get("from_state");
            let to: String = hrow.get("to_state");
            let action: String = hrow.get("action");
            let reason: String = hrow.get::<Option<String>, _>("reason").unwrap_or_default();
            let changed_at: String = hrow.get::<chrono::DateTime<chrono::Utc>, _>("changed_at")
                .format("%d/%m/%Y %H:%M").to_string();
            let changed_by: String = hrow.get::<Option<String>, _>("changed_by").unwrap_or_else(|| "System".to_string());

            let icon_color = match to.as_str() {
                "scheduled" => "text-blue-500", "in_progress" => "text-amber-500",
                "completed" => "text-green-500", "on_hold" => "text-red-500",
                "cancelled" => "text-gray-400", _ => "text-primary"
            };
            let action_label = match action.as_str() {
                "schedule" => "Scheduled", "start" => "Started", "complete" => "Completed",
                "hold" => "Put on hold", "resume" => "Resumed", "cancel" => "Cancelled", _ => &action
            };
            let reason_line = if reason.is_empty() { String::new() } else { format!(r#"<div class="text-xs text-base-content/50 italic mt-1">{reason}</div>"#) };
            let hr = if i < history_rows.len() - 1 { "<hr/>" } else { "" };

            activity_html.push_str(&format!(
                r#"<li><hr/><div class="timeline-start timeline-box text-sm"><span class="font-semibold">{action_label}</span><br/><span class="text-xs text-base-content/60">{from} &rarr; {to}</span>{reason_line}</div>
                <div class="timeline-middle"><svg class="w-5 h-5 {icon_color}" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg></div>
                <div class="timeline-end text-xs text-base-content/60">{changed_at}<br/>{changed_by}</div>{hr}</li>"#));
        }
        // Add creation event at bottom
        activity_html.push_str(&format!(
            r#"<li><hr/><div class="timeline-start timeline-box text-sm"><span class="font-semibold">Created</span></div>
            <div class="timeline-middle"><svg class="w-5 h-5 text-primary" fill="currentColor" viewBox="0 0 20 20"><path fill-rule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zm3.857-9.809a.75.75 0 00-1.214-.882l-3.483 4.79-1.88-1.88a.75.75 0 10-1.06 1.061l2.5 2.5a.75.75 0 001.137-.089l4-5.5z" clip-rule="evenodd"/></svg></div>
            <div class="timeline-end text-xs text-base-content/60">{created_at}<br/>{created_by}</div></li>"#));

        let findings_section = if findings.is_empty() && actions.is_empty() && recommendations.is_empty() {
            r#"<p class="text-base-content/40 italic">No findings recorded yet</p>"#.to_string()
        } else {
            let f = if findings.is_empty() { String::new() } else { format!(r#"<h4 class="text-sm font-semibold text-base-content/60 mt-2">Findings</h4><p class="whitespace-pre-wrap">{findings}</p>"#) };
            let a = if actions.is_empty() { String::new() } else { format!(r#"<h4 class="text-sm font-semibold text-base-content/60 mt-2">Actions Taken</h4><p class="whitespace-pre-wrap">{actions}</p>"#) };
            let r = if recommendations.is_empty() { String::new() } else { format!(r#"<h4 class="text-sm font-semibold text-base-content/60 mt-2">Recommendations</h4><p class="whitespace-pre-wrap">{recommendations}</p>"#) };
            format!("{f}{a}{r}")
        };

        let hold_info = if !hold_reason.is_empty() {
            format!(r#"<div class="alert alert-error mt-4"><div><span class="font-semibold">Hold Reason:</span> {hold_reason}</div></div>"#)
        } else { String::new() };

        format!(r##"
<!-- Status Progress Bar -->
<div class="card bg-base-100 shadow mb-6"><div class="card-body py-4">
<ul class="steps steps-horizontal w-full">{steps_html}</ul>
{on_hold_badge}{cancelled_badge}
</div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
<!-- Left Column: Details -->
<div class="lg:col-span-2 space-y-6">

<!-- Header Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex justify-between items-start">
<div><h2 class="card-title text-xl">{title}</h2>
<p class="font-mono text-sm text-base-content/60 mt-1">{wo_number}</p></div>
<div class="flex gap-2">
<span class="badge" style="background-color:{priority_color};color:white;">{priority}</span>
<span class="badge" style="background-color:{state_color};color:white;">{state_val}</span>
<span class="badge badge-outline">{maint_type}</span>
</div></div>
<p class="text-base-content/70 mt-3">{description}</p>
{hold_info}
</div></div>

<!-- Details Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-3">Details</h3>
<div class="grid grid-cols-2 md:grid-cols-3 gap-4">
<div><span class="text-xs text-base-content/50 uppercase">Asset</span><p class="font-semibold">{asset_name}</p><p class="text-xs text-base-content/60">{asset_code}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Assigned To</span><p class="font-semibold">{assigned}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Created By</span><p class="font-semibold">{created_by}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Scheduled Start</span><p class="font-semibold">{sched_start}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Scheduled End</span><p class="font-semibold">{sched_end}</p></div>
<div><span class="text-xs text-base-content/50 uppercase">Actual Start</span><p class="font-semibold">{actual_start}</p></div>
</div></div></div>

<!-- Findings Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-3">Work Report</h3>
{findings_section}
</div></div>

<!-- Activity Stream -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Activity Stream</h3>
<ul class="timeline timeline-vertical timeline-compact">{activity_html}</ul>
</div></div>
</div>

<!-- Right Column: Actions & Info -->
<div class="space-y-6">

<!-- Actions Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold mb-4">Actions</h3>
{action_buttons}
<a href="/eam/work-orders/{id}/edit" class="btn btn-outline btn-block mt-2"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit Work Order</a>
</div></div>

<!-- Info Card -->
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold mb-4">Information</h3>
<div class="space-y-3 text-sm">
<div class="flex justify-between"><span class="text-base-content/60">WO Number</span><span class="font-mono font-semibold">{wo_number}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Status</span><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Priority</span><span class="badge badge-sm" style="background-color:{priority_color};color:white;">{priority}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Type</span><span class="badge badge-outline badge-sm">{maint_type}</span></div>
<div class="divider my-1"></div>
<div class="flex justify-between"><span class="text-base-content/60">Created</span><span>{created_at}</span></div>
<div class="flex justify-between"><span class="text-base-content/60">Actual End</span><span>{actual_end}</span></div>
</div></div></div>
</div></div>"##)
    } else {
        r#"<div class="text-center py-12"><h3 class="text-lg font-semibold">Work Order Not Found</h3><a href="/eam/work-orders" class="btn btn-primary mt-4">Back to Work Orders</a></div>"#.to_string()
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_work_orders", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Work Order Detail - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/work-orders">Work Orders</a></li><li>Detail</li></ul></div>
<h1 class="text-2xl font-bold">Work Order Detail</h1></div>
<a href="/eam/work-orders" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let wo = sqlx::query(
        r#"SELECT wo.id, wo.wo_number, wo.title, wo.description, wo.maintenance_type, wo.priority, wo.state,
                  wo.scheduled_start, wo.scheduled_end, wo.asset_id, wo.assigned_to,
                  wo.findings, wo.actions_taken, wo.recommendations, wo.planned_duration_hours
           FROM eam_work_orders wo WHERE wo.id = $1"#
    ).bind(id).fetch_optional(&db).await.unwrap_or(None);

    // Get assets for dropdown
    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    // Get users for assignment dropdown
    let users = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let content = if let Some(row) = wo {
        let wo_number: String = row.get("wo_number");
        let title: String = row.get("title");
        let description: String = row.get::<Option<String>, _>("description").unwrap_or_default();
        let maint_type: String = row.get::<Option<String>, _>("maintenance_type").unwrap_or_default();
        let priority_int: i32 = row.get::<Option<i32>, _>("priority").unwrap_or(2);
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_id: Option<uuid::Uuid> = row.get("asset_id");
        let assigned_to: Option<uuid::Uuid> = row.get("assigned_to");
        let sched_start: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_start")
            .map(|d| d.format("%Y-%m-%dT%H:%M").to_string()).unwrap_or_default();
        let sched_end: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("scheduled_end")
            .map(|d| d.format("%Y-%m-%dT%H:%M").to_string()).unwrap_or_default();
        let findings: String = row.get::<Option<String>, _>("findings").unwrap_or_default();
        let actions: String = row.get::<Option<String>, _>("actions_taken").unwrap_or_default();
        let recommendations: String = row.get::<Option<String>, _>("recommendations").unwrap_or_default();
        let duration: String = row.get::<Option<f64>, _>("planned_duration_hours")
            .map(|d| format!("{}", d)).unwrap_or_default();

        // Build asset options
        let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
        for a in &assets {
            let aid: uuid::Uuid = a.get("id");
            let acode: String = a.get("asset_code");
            let aname: String = a.get("name");
            let selected = if asset_id == Some(aid) { " selected" } else { "" };
            asset_options.push_str(&format!(r#"<option value="{aid}"{selected}>{acode} - {aname}</option>"#));
        }

        // Build user options
        let mut user_options = r#"<option value="">-- Unassigned --</option>"#.to_string();
        for u in &users {
            let uid: uuid::Uuid = u.get("id");
            let uname: String = u.get::<Option<String>, _>("full_name")
                .unwrap_or_else(|| u.get::<String, _>("username"));
            let selected = if assigned_to == Some(uid) { " selected" } else { "" };
            user_options.push_str(&format!(r#"<option value="{uid}"{selected}>{uname}</option>"#));
        }

        // Build maintenance type options
        let mtype_options = ["pm", "cm", "emergency", "inspection", "testing", "overhaul"];
        let mtype_labels = ["Preventive (PM)", "Corrective (CM)", "Emergency", "Inspection", "Testing", "Overhaul"];
        let mut mtype_html = r#"<option value="">-- Select Type --</option>"#.to_string();
        for (val, label) in mtype_options.iter().zip(mtype_labels.iter()) {
            let selected = if maint_type == *val { " selected" } else { "" };
            mtype_html.push_str(&format!(r#"<option value="{val}"{selected}>{label}</option>"#));
        }

        // Priority options
        let priority_opts = [(0, "Critical"), (1, "High"), (2, "Medium"), (3, "Low")];
        let mut priority_html = String::new();
        for (val, label) in &priority_opts {
            let selected = if priority_int == *val { " selected" } else { "" };
            priority_html.push_str(&format!(r#"<option value="{val}"{selected}>{label}</option>"#));
        }

        format!(r##"<form method="POST" action="/eam/work-orders/{id}/edit">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<!-- Left Column -->
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">General Information</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">WO Number</span></label>
<input type="text" class="input input-bordered" value="{wo_number}" disabled/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Title *</span></label>
<input type="text" name="title" class="input input-bordered" value="{title}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24">{description}</textarea></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Maintenance Type</span></label>
<select name="maintenance_type" class="select select-bordered">{mtype_html}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered">{priority_html}</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assignment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset</span></label>
<select name="asset_id" class="select select-bordered">{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered">{user_options}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Planned Duration (hours)</span></label>
<input type="number" name="planned_duration_hours" class="input input-bordered" value="{duration}" step="0.5" min="0"/></div>
</div></div>
</div>

<!-- Right Column -->
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Schedule</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Scheduled Start</span></label>
<input type="datetime-local" name="scheduled_start" class="input input-bordered" value="{sched_start}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Scheduled End</span></label>
<input type="datetime-local" name="scheduled_end" class="input input-bordered" value="{sched_end}"/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Work Report</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Findings</span></label>
<textarea name="findings" class="textarea textarea-bordered h-20">{findings}</textarea></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Actions Taken</span></label>
<textarea name="actions_taken" class="textarea textarea-bordered h-20">{actions}</textarea></div>
<div class="form-control"><label class="label"><span class="label-text">Recommendations</span></label>
<textarea name="recommendations" class="textarea textarea-bordered h-20">{recommendations}</textarea></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/work-orders/{id}" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Changes</button>
</div>
</div></div></form>"##)
    } else {
        r#"<div class="text-center py-12"><h3 class="text-lg font-semibold">Work Order Not Found</h3></div>"#.to_string()
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_work_orders", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Edit Work Order - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/work-orders">Work Orders</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Work Order</h1></div>
<a href="/eam/work-orders/{id}" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_work_order_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let title = form.get("title").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let priority: i32 = form.get("priority").and_then(|p| p.parse().ok()).unwrap_or(2);
    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let assigned_to = form.get("assigned_to").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let scheduled_start = form.get("scheduled_start").cloned().unwrap_or_default();
    let scheduled_end = form.get("scheduled_end").cloned().unwrap_or_default();
    let findings = form.get("findings").cloned().unwrap_or_default();
    let actions_taken = form.get("actions_taken").cloned().unwrap_or_default();
    let recommendations = form.get("recommendations").cloned().unwrap_or_default();
    let duration: Option<f64> = form.get("planned_duration_hours").and_then(|d| d.parse().ok());

    let sched_start_ts = if scheduled_start.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_start, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };
    let sched_end_ts = if scheduled_end.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&scheduled_end, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };

    let mtype_opt = if maintenance_type.is_empty() { None } else { Some(maintenance_type) };
    let findings_opt = if findings.is_empty() { None } else { Some(findings) };
    let actions_opt = if actions_taken.is_empty() { None } else { Some(actions_taken) };
    let recs_opt = if recommendations.is_empty() { None } else { Some(recommendations) };

    let _ = sqlx::query(
        r#"UPDATE eam_work_orders SET title = $2, description = $3, maintenance_type = $4, priority = $5,
            asset_id = $6, assigned_to = $7, scheduled_start = $8, scheduled_end = $9,
            findings = $10, actions_taken = $11, recommendations = $12, planned_duration_hours = $13,
            updated_at = now(), updated_by = $14
            WHERE id = $1"#
    )
    .bind(id).bind(&title).bind(&description).bind(&mtype_opt).bind(priority)
    .bind(asset_id).bind(assigned_to).bind(sched_start_ts).bind(sched_end_ts)
    .bind(&findings_opt).bind(&actions_opt).bind(&recs_opt).bind(duration)
    .bind(user.id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/work-orders/{}", id)).into_response()
}

async fn eam_work_order_transition(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let action = form.get("action").cloned().unwrap_or_default();

    // Get current state
    let current_state: Option<String> = sqlx::query_scalar(
        "SELECT state FROM eam_work_orders WHERE id = $1"
    ).bind(id).fetch_optional(&db).await.unwrap_or(None);

    if let Some(current) = current_state {
        let new_state = match (current.as_str(), action.as_str()) {
            ("draft", "schedule") => Some("scheduled"),
            ("draft", "start") => Some("in_progress"),
            ("draft", "cancel") => Some("cancelled"),
            ("scheduled", "start") => Some("in_progress"),
            ("scheduled", "cancel") => Some("cancelled"),
            ("in_progress", "complete") => Some("completed"),
            ("in_progress", "hold") => Some("on_hold"),
            ("on_hold", "resume") => Some("in_progress"),
            ("on_hold", "cancel") => Some("cancelled"),
            _ => None,
        };

        if let Some(to_state) = new_state {
            // Update work order state with parameterized binds
            let now = chrono::Utc::now();
            let needs_start = to_state == "in_progress" && current != "on_hold";
            let needs_end = to_state == "completed";

            let update_sql = if needs_start {
                "UPDATE eam_work_orders SET state = $4, actual_start = $5, updated_at = $2, updated_by = $3 WHERE id = $1"
            } else if needs_end {
                "UPDATE eam_work_orders SET state = $4, actual_end = $5, updated_at = $2, updated_by = $3 WHERE id = $1"
            } else {
                "UPDATE eam_work_orders SET state = $4, updated_at = $2, updated_by = $3 WHERE id = $1"
            };

            let _ = if needs_start || needs_end {
                sqlx::query(update_sql)
                    .bind(id).bind(now).bind(user.id).bind(to_state).bind(now)
                    .execute(&db).await
            } else {
                sqlx::query(update_sql)
                    .bind(id).bind(now).bind(user.id).bind(to_state)
                    .execute(&db).await
            };

            // Record state history
            let _ = sqlx::query(
                r#"INSERT INTO eam_work_order_state_history (work_order_id, from_state, to_state, action, changed_by)
                   VALUES ($1, $2, $3, $4, $5)"#
            ).bind(id).bind(&current).bind(to_state).bind(&action).bind(user.id)
             .execute(&db).await;
        }
    }

    // Redirect back to detail page
    axum::response::Redirect::to(&format!("/eam/work-orders/{}", id)).into_response()
}

async fn eam_equipment(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(params): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let filter = params.get("type").cloned().unwrap_or_else(|| "all".to_string());
    let eq_page: i64 = params.get("page").and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
    let eq_per_page: i64 = params.get("per_page").and_then(|s| s.parse().ok()).unwrap_or(80).max(10).min(500);
    let eq_offset = (eq_page - 1) * eq_per_page;

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get counts - equipment tables linked via asset_id to eam_assets
    let transformers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transformers t JOIN eam_assets a ON t.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let switchgear: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_switch_gears s JOIN eam_assets a ON s.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let rmu: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_ring_main_units r JOIN eam_assets a ON r.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let batteries: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_batteries b JOIN eam_assets a ON b.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let ct_vt: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_current_voltage_transformers c JOIN eam_assets a ON c.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let total = transformers + switchgear + rmu + batteries + ct_vt;

    // Determine the count for the current filter tab (used for pagination)
    let filtered_total = match filter.as_str() {
        "transformer" => transformers,
        "switchgear" => switchgear,
        "rmu" => rmu,
        "battery" => batteries,
        "ct_vt" => ct_vt,
        _ => total,
    };

    // Build equipment table based on filter — all use parameterized LIMIT/OFFSET ($2/$3)
    let equipment_query = match filter.as_str() {
        "transformer" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'Transformer' as eq_type, t.mva_rating as rating
            FROM eam_assets a JOIN eam_transformers t ON t.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT $2 OFFSET $3"#,
        "switchgear" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'Switchgear' as eq_type, s.rated_voltage as rating
            FROM eam_assets a JOIN eam_switch_gears s ON s.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT $2 OFFSET $3"#,
        "battery" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'Battery' as eq_type, b.nominal_voltage as rating
            FROM eam_assets a JOIN eam_batteries b ON b.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT $2 OFFSET $3"#,
        "ct_vt" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'CT/VT' as eq_type, c.rated_voltage_kv as rating
            FROM eam_assets a JOIN eam_current_voltage_transformers c ON c.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT $2 OFFSET $3"#,
        "rmu" => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, 'RMU' as eq_type, r.rated_voltage_kv as rating
            FROM eam_assets a JOIN eam_ring_main_units r ON r.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT $2 OFFSET $3"#,
        _ => r#"SELECT a.id, a.asset_code, a.name, a.manufacturer, a.model, a.operational_status, c.name as eq_type, NULL::float8 as rating
            FROM eam_assets a LEFT JOIN eam_asset_categories c ON a.category_id = c.id WHERE a.company_id = $1 AND a.is_active = true ORDER BY a.name LIMIT $2 OFFSET $3"#,
    };

    let eq_rows = sqlx::query(equipment_query).bind(company_id).bind(eq_per_page).bind(eq_offset).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &eq_rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("asset_code");
        let name: String = row.get("name");
        let mfr: String = row.get::<Option<String>, _>("manufacturer").unwrap_or_else(|| "-".to_string());
        let model: String = row.get::<Option<String>, _>("model").unwrap_or_else(|| "-".to_string());
        let status: String = row.get::<Option<String>, _>("operational_status").unwrap_or_else(|| "unknown".to_string());
        let eq_type: String = row.get::<Option<String>, _>("eq_type").unwrap_or_else(|| "-".to_string());
        let rating: String = row.get::<Option<f64>, _>("rating").map(|r| format!("{:.1}", r)).unwrap_or_else(|| "-".to_string());

        let status_color = match status.as_str() {
            "in_service" => "#10B981", "out_of_service" => "#EF4444", "standby" => "#F59E0B", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{name}</td><td><span class="badge badge-outline badge-sm">{eq_type}</span></td>
            <td>{mfr}</td><td>{model}</td><td>{rating}</td>
            <td><span class="badge badge-sm" style="background-color:{status_color};color:white;">{status}</span></td>
            <td><a href="/eam/assets/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if eq_rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z"/></svg><h3 class="text-lg font-semibold mb-2">No Equipment Found</h3><p class="text-base-content/60">Add equipment to track assets</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Type</th><th>Manufacturer</th><th>Model</th><th>Rating</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let filter_tabs = format!(r#"<div class="tabs tabs-boxed bg-base-100 p-1 mb-6">
<a href="/eam/equipment" class="tab {}">All ({total})</a>
<a href="/eam/equipment?type=transformer" class="tab {}">Transformers ({transformers})</a>
<a href="/eam/equipment?type=switchgear" class="tab {}">Switchgear ({switchgear})</a>
<a href="/eam/equipment?type=rmu" class="tab {}">RMU ({rmu})</a>
<a href="/eam/equipment?type=battery" class="tab {}">Batteries ({batteries})</a>
<a href="/eam/equipment?type=ct_vt" class="tab {}">CT/VT ({ct_vt})</a>
</div>"#,
        if filter == "all" { "tab-active" } else { "" },
        if filter == "transformer" { "tab-active" } else { "" },
        if filter == "switchgear" { "tab-active" } else { "" },
        if filter == "rmu" { "tab-active" } else { "" },
        if filter == "battery" { "tab-active" } else { "" },
        if filter == "ct_vt" { "tab-active" } else { "" },
    );

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_equipment", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Equipment - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Equipment</li></ul></div>
<h1 class="text-2xl font-bold">Equipment</h1><p class="text-base-content/60">All equipment types across the system</p></div>
<a href="/eam/equipment/new" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Equipment</a></div>
{filter_tabs}
<div class="card bg-base-100 shadow"><div class="card-body">{content}{eq_pagination}</div></div>
</main></div></body></html>"#,
        eq_pagination = {
            let mut base_url = String::from("/eam/equipment");
            let mut qp = Vec::new();
            if filter != "all" {
                qp.push(format!("type={}", filter));
            }
            if eq_per_page != 80 {
                qp.push(format!("per_page={}", eq_per_page));
            }
            if !qp.is_empty() {
                base_url.push('?');
                base_url.push_str(&qp.join("&"));
            }
            build_pagination_html(eq_page, eq_per_page, filtered_total, &base_url)
        }
    )).into_response()
}

async fn eam_inspections(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT i.id, i.inspection_code, i.inspection_type, i.state, i.overall_condition,
                  i.inspection_date, a.name as asset_name, u.full_name as inspector_name
           FROM eam_inspection_results i
           LEFT JOIN eam_assets a ON i.asset_id = a.id
           LEFT JOIN users u ON i.inspector_id = u.id
           WHERE i.company_id = $1
           ORDER BY i.inspection_date DESC NULLS LAST LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get::<Option<String>, _>("inspection_code").unwrap_or_default();
        let insp_type: String = row.get::<Option<String>, _>("inspection_type").unwrap_or_else(|| "-".to_string());
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let condition: String = row.get::<Option<String>, _>("overall_condition").unwrap_or_else(|| "-".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let inspector: String = row.get::<Option<String>, _>("inspector_name").unwrap_or_else(|| "-".to_string());
        let insp_date: String = row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("inspection_date")
            .map(|d| d.format("%d/%m/%Y").to_string()).unwrap_or_else(|| "-".to_string());

        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "submitted" => "#3B82F6", "approved" => "#10B981", "rejected" => "#EF4444", _ => "#6B7280"
        };
        let cond_color = match condition.as_str() {
            "good" => "#10B981", "fair" => "#EAB308", "poor" => "#F97316", "critical" => "#EF4444", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{asset_name}</td>
            <td><span class="badge badge-outline badge-sm">{insp_type}</span></td>
            <td>{insp_date}</td><td>{inspector}</td>
            <td><span class="badge badge-sm" style="background-color:{cond_color};color:white;">{condition}</span></td>
            <td><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></td>
            <td><a href="/eam/inspections/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4"/></svg><h3 class="text-lg font-semibold mb-2">No Inspections Yet</h3><p class="text-base-content/60">Inspection results will appear here once created.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Asset</th><th>Type</th><th>Date</th><th>Inspector</th><th>Condition</th><th>State</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_inspections", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Inspections - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Inspections</li></ul></div>
<h1 class="text-2xl font-bold">Inspections</h1><p class="text-base-content/60">Asset inspection results and approval workflow</p></div>
<a href="/eam/inspections/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Inspection</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_checklists(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT ct.id, ct.name, ct.equipment_category, ct.maintenance_type, ct.version, ct.is_active,
                  (SELECT COUNT(*) FROM eam_checklist_template_items cti WHERE cti.template_id = ct.id) as item_count
           FROM eam_checklist_templates ct
           WHERE ct.company_id = $1
           ORDER BY ct.name LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let name: String = row.get("name");
        let category: String = row.get("equipment_category");
        let maint_type: String = row.get("maintenance_type");
        let version: i32 = row.get::<Option<i32>, _>("version").unwrap_or(1);
        let is_active: bool = row.get::<Option<bool>, _>("is_active").unwrap_or(true);
        let item_count: i64 = row.get::<Option<i64>, _>("item_count").unwrap_or(0);
        let status_badge = if is_active {
            r#"<span class="badge badge-sm badge-success">Active</span>"#
        } else {
            r#"<span class="badge badge-sm badge-ghost">Inactive</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-semibold">{name}</td>
            <td><span class="badge badge-outline badge-sm">{category}</span></td>
            <td><span class="badge badge-outline badge-sm">{maint_type}</span></td>
            <td>v{version}</td><td>{item_count} items</td>
            <td>{status_badge}</td>
            <td><a href="/eam/checklists/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3 class="text-lg font-semibold mb-2">No Checklist Templates</h3><p class="text-base-content/60">Create templates to standardize maintenance and inspection procedures.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Name</th><th>Equipment Category</th><th>Maintenance Type</th><th>Version</th><th>Items</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_checklists", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Checklist Templates - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Checklist Templates</li></ul></div>
<h1 class="text-2xl font-bold">Checklist Templates</h1><p class="text-base-content/60">Reusable checklists for equipment maintenance and inspection</p></div>
<a href="/eam/checklists/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Checklist</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_plans(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT mp.id, mp.plan_code, mp.maintenance_type, mp.state,
                  mp.frequency_interval, mp.frequency_unit, mp.next_maintenance_date,
                  a.name as asset_name
           FROM eam_maintenance_plans mp
           LEFT JOIN eam_assets a ON mp.asset_id = a.id
           WHERE mp.company_id = $1
           ORDER BY mp.state, mp.next_maintenance_date NULLS LAST LIMIT 100"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let plan_code: String = row.get::<Option<String>, _>("plan_code").unwrap_or_else(|| "-".to_string());
        let maint_type: String = row.get("maintenance_type");
        let state_val: String = row.get::<Option<String>, _>("state").unwrap_or_else(|| "draft".to_string());
        let asset_name: String = row.get::<Option<String>, _>("asset_name").unwrap_or_else(|| "-".to_string());
        let freq_interval: Option<i32> = row.get("frequency_interval");
        let freq_unit: Option<String> = row.get("frequency_unit");
        let next_date: String = row.get::<Option<String>, _>("next_maintenance_date").unwrap_or_else(|| "-".to_string());

        let frequency = match (freq_interval, freq_unit.as_deref()) {
            (Some(n), Some(u)) => format!("Every {} {}s", n, u),
            _ => "-".to_string(),
        };

        let state_color = match state_val.as_str() {
            "draft" => "#6B7280", "active" => "#10B981", "done" => "#3B82F6", "cancelled" => "#EF4444", _ => "#6B7280"
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{plan_code}</td><td>{asset_name}</td>
            <td><span class="badge badge-outline badge-sm">{maint_type}</span></td>
            <td>{frequency}</td><td>{next_date}</td>
            <td><span class="badge badge-sm" style="background-color:{state_color};color:white;">{state_val}</span></td>
            <td><a href="/eam/plans/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 7V3m8 4V3m-9 8h10M5 21h14a2 2 0 002-2V7a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z"/></svg><h3 class="text-lg font-semibold mb-2">No Maintenance Plans</h3><p class="text-base-content/60">Create plans to schedule recurring maintenance and auto-generate work orders.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Plan Code</th><th>Asset</th><th>Type</th><th>Frequency</th><th>Next Due</th><th>State</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_plans", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Maintenance Plans - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Maintenance Plans</li></ul></div>
<h1 class="text-2xl font-bold">Maintenance Plans</h1><p class="text-base-content/60">Recurring maintenance schedules with automatic work order generation</p></div>
<a href="/eam/plans/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Plan</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_inspection_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let users_rows = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        asset_options.push_str(&format!(r#"<option value="{aid}">{acode} - {aname}</option>"#));
    }

    let mut user_options = r#"<option value="">-- Select Inspector --</option>"#.to_string();
    for u in &users_rows {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get::<Option<String>, _>("full_name")
            .unwrap_or_else(|| u.get::<String, _>("username"));
        user_options.push_str(&format!(r#"<option value="{uid}">{uname}</option>"#));
    }

    let content = format!(r##"<form method="POST" action="/eam/inspections/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Inspection Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset *</span></label>
<select name="asset_id" class="select select-bordered" required>{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Inspector *</span></label>
<select name="inspector_id" class="select select-bordered" required>{user_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Inspection Type</span></label>
<select name="inspection_type" class="select select-bordered">
<option value="">-- Select Type --</option>
<option value="routine">Routine</option><option value="detailed">Detailed</option>
<option value="commissioning">Commissioning</option><option value="post_fault">Post-Fault</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Inspection Date *</span></label>
<input type="datetime-local" name="inspection_date" class="input input-bordered" required/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assessment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Overall Condition</span></label>
<select name="overall_condition" class="select select-bordered">
<option value="">-- Select Condition --</option>
<option value="good">Good</option><option value="fair">Fair</option>
<option value="poor">Poor</option><option value="critical">Critical</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Defects Found</span></label>
<textarea name="defects_found" class="textarea textarea-bordered h-24" placeholder="Describe any defects observed"></textarea></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Recommendations</span></label>
<textarea name="observations" class="textarea textarea-bordered h-24" placeholder="Recommendations and observations"></textarea></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3">
<input type="checkbox" name="immediate_action_required" value="true" class="checkbox checkbox-warning"/>
<span class="label-text">Immediate action required</span></label></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Visual Checks</h3>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="visual_check" value="true" class="checkbox"/><span class="label-text">Visual inspection passed</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="cleanliness_check" value="true" class="checkbox"/><span class="label-text">Cleanliness OK</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="corrosion_check" value="true" class="checkbox"/><span class="label-text">No corrosion found</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="oil_leak_check" value="true" class="checkbox"/><span class="label-text">No oil leaks</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="connection_check" value="true" class="checkbox"/><span class="label-text">Connections secure</span></label></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3"><input type="checkbox" name="labeling_check" value="true" class="checkbox"/><span class="label-text">Labels intact</span></label></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/inspections" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Inspection</button>
</div>
</div></div></form>"##);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_inspections", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Inspection - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/inspections">Inspections</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Inspection</h1></div>
<a href="/eam/inspections" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_inspection_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let inspector_id = form.get("inspector_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let inspection_type = form.get("inspection_type").cloned().unwrap_or_default();
    let inspection_date_str = form.get("inspection_date").cloned().unwrap_or_default();
    let overall_condition = form.get("overall_condition").cloned().unwrap_or_default();
    let defects_found = form.get("defects_found").cloned().unwrap_or_default();
    let observations = form.get("observations").cloned().unwrap_or_default();
    let immediate_action = form.get("immediate_action_required").map(|v| v == "true").unwrap_or(false);
    let visual_check = form.get("visual_check").map(|v| v == "true").unwrap_or(false);
    let cleanliness_check = form.get("cleanliness_check").map(|v| v == "true").unwrap_or(false);
    let corrosion_check = form.get("corrosion_check").map(|v| v == "true").unwrap_or(false);
    let oil_leak_check = form.get("oil_leak_check").map(|v| v == "true").unwrap_or(false);
    let connection_check = form.get("connection_check").map(|v| v == "true").unwrap_or(false);
    let labeling_check = form.get("labeling_check").map(|v| v == "true").unwrap_or(false);

    let insp_date = if inspection_date_str.is_empty() { None } else {
        chrono::NaiveDateTime::parse_from_str(&inspection_date_str, "%Y-%m-%dT%H:%M").ok()
            .map(|dt| dt.and_local_timezone(chrono::FixedOffset::east_opt(8 * 3600).unwrap()).unwrap())
    };

    let next_num: i64 = sqlx::query_scalar("SELECT COUNT(*) + 1 FROM eam_inspection_results WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(1);
    let inspection_code = format!("INS-{}-{:05}", chrono::Utc::now().format("%Y"), next_num);

    let itype_opt = if inspection_type.is_empty() { None } else { Some(inspection_type) };
    let cond_opt = if overall_condition.is_empty() { None } else { Some(overall_condition) };
    let defects_opt = if defects_found.is_empty() { None } else { Some(defects_found) };
    let obs_opt = if observations.is_empty() { None } else { Some(observations) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_inspection_results (company_id, inspection_code, asset_id, inspector_id,
            inspection_type, inspection_date, overall_condition, defects_found, observations,
            immediate_action_required, visual_check, cleanliness_check, corrosion_check,
            oil_leak_check, connection_check, labeling_check, state, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'draft', $17)
            RETURNING id"#
    )
    .bind(company_id).bind(&inspection_code).bind(asset_id).bind(inspector_id)
    .bind(&itype_opt).bind(insp_date).bind(&cond_opt).bind(&defects_opt).bind(&obs_opt)
    .bind(immediate_action).bind(visual_check).bind(cleanliness_check).bind(corrosion_check)
    .bind(oil_leak_check).bind(connection_check).bind(labeling_check).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/inspections").into_response()
}

async fn eam_checklist_new(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let content = r##"<form method="POST" action="/eam/checklists/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Template Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input type="text" name="name" class="input input-bordered" placeholder="Enter checklist template name" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Equipment Category *</span></label>
<select name="equipment_category" class="select select-bordered" required>
<option value="">-- Select Category --</option>
<option value="transformer">Transformer</option><option value="switchgear">Switchgear</option>
<option value="circuit_breaker">Circuit Breaker</option><option value="relay">Relay</option>
<option value="cable">Cable</option><option value="battery">Battery</option>
<option value="general">General</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Maintenance Type *</span></label>
<select name="maintenance_type" class="select select-bordered" required>
<option value="">-- Select Type --</option>
<option value="pm">Preventive (PM)</option><option value="cm">Corrective (CM)</option>
<option value="inspection">Inspection</option><option value="testing">Testing</option>
<option value="overhaul">Overhaul</option>
</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Version</span></label>
<input type="number" name="version" class="input input-bordered" value="1" min="1"/></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Additional Info</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-32" placeholder="Describe the purpose and scope of this checklist"></textarea></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3">
<input type="checkbox" name="is_active" value="true" class="checkbox checkbox-success" checked/>
<span class="label-text">Active</span></label></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/checklists" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Checklist</button>
</div>
</div></div></form>"##;

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_checklists", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Checklist Template - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/checklists">Checklist Templates</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Checklist Template</h1></div>
<a href="/eam/checklists" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_checklist_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let name = form.get("name").cloned().unwrap_or_default();
    let equipment_category = form.get("equipment_category").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let version: i32 = form.get("version").and_then(|v| v.parse().ok()).unwrap_or(1);
    let description = form.get("description").cloned().unwrap_or_default();
    let is_active = form.get("is_active").map(|v| v == "true").unwrap_or(false);

    let desc_opt = if description.is_empty() { None } else { Some(description) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_checklist_templates (company_id, name, equipment_category, maintenance_type,
            version, description, is_active, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id"#
    )
    .bind(company_id).bind(&name).bind(&equipment_category).bind(&maintenance_type)
    .bind(version).bind(&desc_opt).bind(is_active).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/checklists").into_response()
}

async fn eam_plan_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let assets = sqlx::query(
        "SELECT id, asset_code, name FROM eam_assets WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let users_rows = sqlx::query(
        "SELECT id, full_name, username FROM users WHERE company_id = $1 ORDER BY full_name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let templates = sqlx::query(
        "SELECT id, name, equipment_category FROM eam_checklist_templates WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut asset_options = r#"<option value="">-- Select Asset --</option>"#.to_string();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        asset_options.push_str(&format!(r#"<option value="{aid}">{acode} - {aname}</option>"#));
    }

    let mut user_options = r#"<option value="">-- Unassigned --</option>"#.to_string();
    for u in &users_rows {
        let uid: uuid::Uuid = u.get("id");
        let uname: String = u.get::<Option<String>, _>("full_name")
            .unwrap_or_else(|| u.get::<String, _>("username"));
        user_options.push_str(&format!(r#"<option value="{uid}">{uname}</option>"#));
    }

    let mut template_options = r#"<option value="">-- No Checklist --</option>"#.to_string();
    for t in &templates {
        let tid: uuid::Uuid = t.get("id");
        let tname: String = t.get("name");
        let tcat: String = t.get("equipment_category");
        template_options.push_str(&format!(r#"<option value="{tid}">{tname} ({tcat})</option>"#));
    }

    let content = format!(r##"<form method="POST" action="/eam/plans/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Plan Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Asset *</span></label>
<select name="asset_id" class="select select-bordered" required>{asset_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24" placeholder="Describe the maintenance plan"></textarea></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Maintenance Type *</span></label>
<select name="maintenance_type" class="select select-bordered" required>
<option value="">-- Select Type --</option>
<option value="pm">Preventive (PM)</option><option value="cm">Corrective (CM)</option>
<option value="inspection">Inspection</option><option value="testing">Testing</option>
<option value="overhaul">Overhaul</option>
</select></div>
<div class="form-control"><label class="label"><span class="label-text">Priority</span></label>
<select name="priority" class="select select-bordered">
<option value="0">Critical</option><option value="1">High</option>
<option value="2" selected>Medium</option><option value="3">Low</option>
</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assignment</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Assigned To</span></label>
<select name="assigned_to" class="select select-bordered">{user_options}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Checklist Template</span></label>
<select name="checklist_template_id" class="select select-bordered">{template_options}</select></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Schedule</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Start Date</span></label>
<input type="date" name="start_date" class="input input-bordered"/></div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mb-3">
<div class="form-control"><label class="label"><span class="label-text">Frequency Interval</span></label>
<input type="number" name="frequency_interval" class="input input-bordered" min="1" placeholder="e.g. 3"/></div>
<div class="form-control"><label class="label"><span class="label-text">Frequency Unit</span></label>
<select name="frequency_unit" class="select select-bordered">
<option value="">-- Select --</option>
<option value="day">Day</option><option value="week">Week</option>
<option value="month" selected>Month</option><option value="year">Year</option>
</select></div>
</div>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Planning Horizon Interval</span></label>
<input type="number" name="planning_horizon_interval" class="input input-bordered" min="1" placeholder="e.g. 12"/></div>
<div class="form-control"><label class="label"><span class="label-text">Horizon Unit</span></label>
<select name="planning_horizon_unit" class="select select-bordered">
<option value="">-- Select --</option>
<option value="day">Day</option><option value="week">Week</option>
<option value="month" selected>Month</option><option value="year">Year</option>
</select></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Notes</h3>
<div class="form-control"><textarea name="notes" class="textarea textarea-bordered h-24" placeholder="Additional notes for this plan"></textarea></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/plans" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Plan</button>
</div>
</div></div></form>"##);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_plans", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Maintenance Plan - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/plans">Maintenance Plans</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Maintenance Plan</h1></div>
<a href="/eam/plans" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_plan_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset_id = form.get("asset_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let description = form.get("description").cloned().unwrap_or_default();
    let maintenance_type = form.get("maintenance_type").cloned().unwrap_or_default();
    let priority: i32 = form.get("priority").and_then(|p| p.parse().ok()).unwrap_or(2);
    let assigned_to = form.get("assigned_to").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let checklist_template_id = form.get("checklist_template_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let start_date = form.get("start_date").cloned().unwrap_or_default();
    let frequency_interval: Option<i32> = form.get("frequency_interval").and_then(|v| v.parse().ok());
    let frequency_unit = form.get("frequency_unit").cloned().unwrap_or_default();
    let planning_horizon_interval: Option<i32> = form.get("planning_horizon_interval").and_then(|v| v.parse().ok());
    let planning_horizon_unit = form.get("planning_horizon_unit").cloned().unwrap_or_default();
    let notes = form.get("notes").cloned().unwrap_or_default();

    let next_num: i64 = sqlx::query_scalar("SELECT COUNT(*) + 1 FROM eam_maintenance_plans WHERE company_id = $1")
        .bind(company_id).fetch_one(&db).await.unwrap_or(1);
    let plan_code = format!("MP-{}-{:05}", chrono::Utc::now().format("%Y"), next_num);

    let desc_opt = if description.is_empty() { None } else { Some(description) };
    let start_opt = if start_date.is_empty() { None } else { Some(start_date) };
    let freq_unit_opt = if frequency_unit.is_empty() { None } else { Some(frequency_unit) };
    let horizon_unit_opt = if planning_horizon_unit.is_empty() { None } else { Some(planning_horizon_unit) };
    let notes_opt = if notes.is_empty() { None } else { Some(notes) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_maintenance_plans (company_id, plan_code, description, asset_id,
            maintenance_type, priority, assigned_to, checklist_template_id,
            start_date, frequency_interval, frequency_unit,
            planning_horizon_interval, planning_horizon_unit,
            state, notes, is_active, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, 'draft', $14, true, $15)
            RETURNING id"#
    )
    .bind(company_id).bind(&plan_code).bind(&desc_opt).bind(asset_id)
    .bind(&maintenance_type).bind(priority).bind(assigned_to).bind(checklist_template_id)
    .bind(&start_opt).bind(frequency_interval).bind(&freq_unit_opt)
    .bind(planning_horizon_interval).bind(&horizon_unit_opt)
    .bind(&notes_opt).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/plans").into_response()
}

// =============================================================================
// FUNCTIONAL LOCATIONS
// =============================================================================

async fn eam_functional_locations(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, fl.status, fl.description,
                  ut.name as unit_type, ut.code as unit_type_code,
                  s.name as site_name,
                  vl.name as voltage_level,
                  p.name as parent_name, p.code as parent_code
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_voltage_levels vl ON fl.voltage_level_id = vl.id
           LEFT JOIN eam_functional_locations p ON fl.parent_id = p.id
           WHERE fl.company_id = $1 AND fl.is_active = true
           ORDER BY s.name, fl.display_order, fl.code
           LIMIT 200"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let status: String = row.get::<Option<String>, _>("status").unwrap_or_else(|| "active".to_string());
        let unit_type: String = row.get::<Option<String>, _>("unit_type").unwrap_or_else(|| "-".to_string());
        let unit_code: String = row.get::<Option<String>, _>("unit_type_code").unwrap_or_default();
        let site_name: String = row.get::<Option<String>, _>("site_name").unwrap_or_else(|| "-".to_string());
        let voltage: String = row.get::<Option<String>, _>("voltage_level").unwrap_or_else(|| "-".to_string());
        let parent: String = row.get::<Option<String>, _>("parent_code").unwrap_or_else(|| "-".to_string());

        let status_badge = if status == "active" {
            r#"<span class="badge badge-sm badge-success">Active</span>"#
        } else {
            r#"<span class="badge badge-sm badge-ghost">Inactive</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{name}</td>
            <td><span class="badge badge-outline badge-sm">{unit_code}</span> {unit_type}</td>
            <td>{site_name}</td><td>{voltage}</td><td>{parent}</td>
            <td>{status_badge}</td>
            <td><a href="/eam/functional-locations/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3.055 11H5a2 2 0 012 2v1a2 2 0 002 2 2 2 0 012 2v2.945M8 3.935V5.5A2.5 2.5 0 0010.5 8h.5a2 2 0 012 2 2 2 0 104 0 2 2 0 012-2h1.064M15 20.488V18a2 2 0 012-2h3.064M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg><h3 class="text-lg font-semibold mb-2">No Functional Locations</h3><p class="text-base-content/60">Create functional locations to organize your assets by site hierarchy.</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Unit Type</th><th>Site</th><th>Voltage</th><th>Parent</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Functional Locations - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Functional Locations</li></ul></div>
<h1 class="text-2xl font-bold">Functional Locations</h1><p class="text-base-content/60">Hierarchical organization of plant units (PPU, SSU, PP, PE)</p></div>
<a href="/eam/functional-locations/new" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Location</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_functional_location_new(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Sites dropdown
    let sites = sqlx::query(
        "SELECT id, code, name FROM eam_sites WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut site_options = r#"<option value="">-- Select Site --</option>"#.to_string();
    for s in &sites {
        let sid: uuid::Uuid = s.get("id");
        let scode: String = s.get("code");
        let sname: String = s.get("name");
        site_options.push_str(&format!(r#"<option value="{sid}">[{scode}] {sname}</option>"#));
    }

    // Unit types dropdown
    let unit_types = sqlx::query(
        "SELECT id, code, name FROM eam_unit_types WHERE company_id = $1 AND is_active = true ORDER BY display_order, name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut ut_options = r#"<option value="">-- Select Unit Type --</option>"#.to_string();
    for ut in &unit_types {
        let uid: uuid::Uuid = ut.get("id");
        let ucode: String = ut.get("code");
        let uname: String = ut.get("name");
        ut_options.push_str(&format!(r#"<option value="{uid}">{ucode} - {uname}</option>"#));
    }

    // Voltage levels dropdown
    let voltages = sqlx::query(
        "SELECT id, code, name, voltage_value FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut vl_options = r#"<option value="">-- None --</option>"#.to_string();
    for vl in &voltages {
        let vid: uuid::Uuid = vl.get("id");
        let vname: String = vl.get("name");
        vl_options.push_str(&format!(r#"<option value="{vid}">{vname}</option>"#));
    }

    // Parent functional locations dropdown
    let parents = sqlx::query(
        "SELECT id, code, name FROM eam_functional_locations WHERE company_id = $1 AND is_active = true ORDER BY code"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut parent_options = r#"<option value="">-- No Parent (Top Level) --</option>"#.to_string();
    for p in &parents {
        let pid: uuid::Uuid = p.get("id");
        let pcode: String = p.get("code");
        let pname: String = p.get("name");
        parent_options.push_str(&format!(r#"<option value="{pid}">[{pcode}] {pname}</option>"#));
    }

    let content = format!(r##"<form method="POST" action="/eam/functional-locations/new">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Location Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Code *</span></label>
<input type="text" name="code" class="input input-bordered font-mono" placeholder="e.g. PPU-AMP-001-SSU33" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input type="text" name="name" class="input input-bordered" placeholder="e.g. SSU 33kV - Ampang" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Short Name</span></label>
<input type="text" name="short_name" class="input input-bordered" placeholder="Short display name"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24" placeholder="Description of this functional location"></textarea></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Classification</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Site *</span></label>
<select name="site_id" class="select select-bordered" required>{site_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Unit Type *</span></label>
<select name="unit_type_id" class="select select-bordered" required>{ut_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered">{vl_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parent Location</span></label>
<select name="parent_id" class="select select-bordered">{parent_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Display Order</span></label>
<input type="number" name="display_order" class="input input-bordered" value="0" min="0"/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">References</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">SLD Reference</span></label>
<input type="text" name="sld_reference" class="input input-bordered" placeholder="Single line diagram reference"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">SCADA Point Group</span></label>
<input type="text" name="scada_point_group" class="input input-bordered" placeholder="SCADA telemetry group"/></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/functional-locations" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Create Location</button>
</div>
</div></div></form>"##);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Functional Location - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/functional-locations">Functional Locations</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">New Functional Location</h1></div>
<a href="/eam/functional-locations" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_functional_location_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    let short_name = form.get("short_name").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let site_id = form.get("site_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let unit_type_id = form.get("unit_type_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let voltage_level_id = form.get("voltage_level_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let parent_id = form.get("parent_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let display_order: i32 = form.get("display_order").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sld_reference = form.get("sld_reference").cloned().unwrap_or_default();
    let scada_point_group = form.get("scada_point_group").cloned().unwrap_or_default();

    let short_opt = if short_name.is_empty() { None } else { Some(short_name) };
    let desc_opt = if description.is_empty() { None } else { Some(description) };
    let sld_opt = if sld_reference.is_empty() { None } else { Some(sld_reference) };
    let scada_opt = if scada_point_group.is_empty() { None } else { Some(scada_point_group) };

    let _new_id: uuid::Uuid = sqlx::query_scalar(
        r#"INSERT INTO eam_functional_locations (company_id, site_id, unit_type_id, code, name,
            short_name, description, voltage_level_id, parent_id, display_order,
            sld_reference, scada_point_group, created_by)
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
            RETURNING id"#
    )
    .bind(company_id).bind(site_id).bind(unit_type_id).bind(&code).bind(&name)
    .bind(&short_opt).bind(&desc_opt).bind(voltage_level_id).bind(parent_id).bind(display_order)
    .bind(&sld_opt).bind(&scada_opt).bind(user.id)
    .fetch_one(&db).await
    .unwrap_or_default();

    axum::response::Redirect::to("/eam/functional-locations").into_response()
}

async fn eam_functional_location_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let row = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, fl.short_name, fl.description, fl.status,
                  fl.sld_reference, fl.scada_point_group, fl.display_order, fl.created_at,
                  ut.name as unit_type, ut.code as unit_type_code,
                  s.name as site_name, s.code as site_code,
                  vl.name as voltage_level,
                  p.name as parent_name, p.code as parent_code
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_voltage_levels vl ON fl.voltage_level_id = vl.id
           LEFT JOIN eam_functional_locations p ON fl.parent_id = p.id
           WHERE fl.id = $1 AND fl.company_id = $2"#
    ).bind(id).bind(company_id).fetch_optional(&db).await.unwrap_or(None);

    let row = match row {
        Some(r) => r,
        None => return axum::response::Redirect::to("/eam/functional-locations").into_response(),
    };

    let code: String = row.get("code");
    let name: String = row.get("name");
    let short_name: String = row.get::<Option<String>, _>("short_name").unwrap_or_else(|| "-".to_string());
    let description: String = row.get::<Option<String>, _>("description").unwrap_or_else(|| "-".to_string());
    let status: String = row.get::<Option<String>, _>("status").unwrap_or_else(|| "active".to_string());
    let unit_type: String = row.get::<Option<String>, _>("unit_type").unwrap_or_else(|| "-".to_string());
    let unit_code: String = row.get::<Option<String>, _>("unit_type_code").unwrap_or_default();
    let site_name: String = row.get::<Option<String>, _>("site_name").unwrap_or_else(|| "-".to_string());
    let voltage: String = row.get::<Option<String>, _>("voltage_level").unwrap_or_else(|| "-".to_string());
    let parent_name: String = row.get::<Option<String>, _>("parent_name").unwrap_or_else(|| "-".to_string());
    let parent_code: String = row.get::<Option<String>, _>("parent_code").unwrap_or_default();
    let sld_ref: String = row.get::<Option<String>, _>("sld_reference").unwrap_or_else(|| "-".to_string());
    let scada: String = row.get::<Option<String>, _>("scada_point_group").unwrap_or_else(|| "-".to_string());
    let created_at: chrono::DateTime<chrono::Utc> = row.get("created_at");

    let status_badge = if status == "active" {
        r#"<span class="badge badge-success">Active</span>"#
    } else {
        r#"<span class="badge badge-ghost">Inactive</span>"#
    };

    let parent_display = if parent_code.is_empty() {
        parent_name.clone()
    } else {
        format!("[{}] {}", parent_code, parent_name)
    };

    // Child locations
    let children = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, ut.code as unit_type_code
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           WHERE fl.parent_id = $1 AND fl.is_active = true
           ORDER BY fl.display_order, fl.code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut children_html = String::new();
    for c in &children {
        let cid: uuid::Uuid = c.get("id");
        let ccode: String = c.get("code");
        let cname: String = c.get("name");
        let cut: String = c.get::<Option<String>, _>("unit_type_code").unwrap_or_default();
        children_html.push_str(&format!(
            r#"<tr><td class="font-mono"><a href="/eam/functional-locations/{cid}" class="link link-primary">{ccode}</a></td><td>{cname}</td><td><span class="badge badge-outline badge-sm">{cut}</span></td></tr>"#
        ));
    }

    let children_section = if children.is_empty() {
        r#"<p class="text-base-content/50 text-sm py-4">No child locations</p>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Type</th></tr></thead><tbody>{children_html}</tbody></table></div>"#)
    };

    // Assets at this location
    let assets = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.operational_status
           FROM eam_assets a
           WHERE a.functional_location_id = $1 AND a.is_active = true
           ORDER BY a.asset_code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut assets_html = String::new();
    for a in &assets {
        let aid: uuid::Uuid = a.get("id");
        let acode: String = a.get("asset_code");
        let aname: String = a.get("name");
        let astatus: String = a.get::<Option<String>, _>("operational_status").unwrap_or_else(|| "in_service".to_string());
        let sc = match astatus.as_str() {
            "in_service" | "operational" => "badge-success",
            "standby" => "badge-warning",
            "out_of_service" => "badge-error",
            _ => "badge-ghost",
        };
        assets_html.push_str(&format!(
            r#"<tr><td class="font-mono"><a href="/eam/assets/{aid}" class="link link-primary">{acode}</a></td><td>{aname}</td><td><span class="badge badge-sm {sc}">{astatus}</span></td></tr>"#
        ));
    }

    let assets_section = if assets.is_empty() {
        r#"<p class="text-base-content/50 text-sm py-4">No assets at this location</p>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-sm"><thead><tr><th>Code</th><th>Name</th><th>Status</th></tr></thead><tbody>{assets_html}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{code} - Functional Location</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/functional-locations">Functional Locations</a></li><li>{code}</li></ul></div>
<h1 class="text-2xl font-bold">{name}</h1>
<p class="text-base-content/60 font-mono">{code}</p></div>
<div class="flex gap-2">
<a href="/eam/functional-locations/{id}/edit" class="btn btn-primary btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit</a>
<a href="/eam/functional-locations" class="btn btn-ghost btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a>
</div></div>

<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Details</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-y-3">
<div><span class="text-base-content/50 text-sm">Status</span><div class="mt-1">{status_badge}</div></div>
<div><span class="text-base-content/50 text-sm">Unit Type</span><div class="mt-1"><span class="badge badge-outline">{unit_code}</span> {unit_type}</div></div>
<div><span class="text-base-content/50 text-sm">Site</span><div class="mt-1 font-medium">{site_name}</div></div>
<div><span class="text-base-content/50 text-sm">Voltage Level</span><div class="mt-1">{voltage}</div></div>
<div><span class="text-base-content/50 text-sm">Parent Location</span><div class="mt-1">{parent_display}</div></div>
<div><span class="text-base-content/50 text-sm">Short Name</span><div class="mt-1">{short_name}</div></div>
<div class="col-span-2"><span class="text-base-content/50 text-sm">Description</span><div class="mt-1">{description}</div></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">References</h3>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-y-3">
<div><span class="text-base-content/50 text-sm">SLD Reference</span><div class="mt-1 font-mono">{sld_ref}</div></div>
<div><span class="text-base-content/50 text-sm">SCADA Point Group</span><div class="mt-1 font-mono">{scada}</div></div>
<div><span class="text-base-content/50 text-sm">Created</span><div class="mt-1">{}</div></div>
</div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Child Locations <span class="badge badge-sm">{}</span></h3>
{children_section}
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Assets <span class="badge badge-sm">{}</span></h3>
{assets_section}
</div></div>
</div>
</main></div></body></html>"#,
        created_at.format("%d/%m/%Y %H:%M"), children.len(), assets.len()
    )).into_response()
}

async fn eam_functional_location_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let row = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, fl.short_name, fl.description, fl.status,
                  fl.site_id, fl.unit_type_id, fl.voltage_level_id, fl.parent_id,
                  fl.display_order, fl.sld_reference, fl.scada_point_group
           FROM eam_functional_locations fl
           WHERE fl.id = $1 AND fl.company_id = $2"#
    ).bind(id).bind(company_id).fetch_optional(&db).await.unwrap_or(None);

    let row = match row {
        Some(r) => r,
        None => return axum::response::Redirect::to("/eam/functional-locations").into_response(),
    };

    let cur_code: String = row.get("code");
    let cur_name: String = row.get("name");
    let cur_short: String = row.get::<Option<String>, _>("short_name").unwrap_or_default();
    let cur_desc: String = row.get::<Option<String>, _>("description").unwrap_or_default();
    let cur_status: String = row.get::<Option<String>, _>("status").unwrap_or_else(|| "active".to_string());
    let cur_site_id: Option<uuid::Uuid> = row.get("site_id");
    let cur_ut_id: Option<uuid::Uuid> = row.get("unit_type_id");
    let cur_vl_id: Option<uuid::Uuid> = row.get("voltage_level_id");
    let cur_parent_id: Option<uuid::Uuid> = row.get("parent_id");
    let cur_order: i32 = row.get::<Option<i32>, _>("display_order").unwrap_or(0);
    let cur_sld: String = row.get::<Option<String>, _>("sld_reference").unwrap_or_default();
    let cur_scada: String = row.get::<Option<String>, _>("scada_point_group").unwrap_or_default();

    // Dropdowns
    let sites = sqlx::query("SELECT id, code, name FROM eam_sites WHERE company_id = $1 AND is_active = true ORDER BY name")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut site_options = r#"<option value="">-- Select Site --</option>"#.to_string();
    for s in &sites {
        let sid: uuid::Uuid = s.get("id");
        let scode: String = s.get("code");
        let sname: String = s.get("name");
        let sel = if Some(sid) == cur_site_id { " selected" } else { "" };
        site_options.push_str(&format!(r#"<option value="{sid}"{sel}>[{scode}] {sname}</option>"#));
    }

    let unit_types = sqlx::query("SELECT id, code, name FROM eam_unit_types WHERE company_id = $1 AND is_active = true ORDER BY display_order, name")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut ut_options = r#"<option value="">-- Select Unit Type --</option>"#.to_string();
    for ut in &unit_types {
        let uid: uuid::Uuid = ut.get("id");
        let ucode: String = ut.get("code");
        let uname: String = ut.get("name");
        let sel = if Some(uid) == cur_ut_id { " selected" } else { "" };
        ut_options.push_str(&format!(r#"<option value="{uid}"{sel}>{ucode} - {uname}</option>"#));
    }

    let voltages = sqlx::query("SELECT id, code, name, voltage_value FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut vl_options = r#"<option value="">-- None --</option>"#.to_string();
    for vl in &voltages {
        let vid: uuid::Uuid = vl.get("id");
        let vname: String = vl.get("name");
        let sel = if Some(vid) == cur_vl_id { " selected" } else { "" };
        vl_options.push_str(&format!(r#"<option value="{vid}"{sel}>{vname}</option>"#));
    }

    let parents = sqlx::query("SELECT id, code, name FROM eam_functional_locations WHERE company_id = $1 AND is_active = true AND id != $2 ORDER BY code")
        .bind(company_id).bind(id).fetch_all(&db).await.unwrap_or_default();
    let mut parent_options = r#"<option value="">-- No Parent (Top Level) --</option>"#.to_string();
    for p in &parents {
        let pid: uuid::Uuid = p.get("id");
        let pcode: String = p.get("code");
        let pname: String = p.get("name");
        let sel = if Some(pid) == cur_parent_id { " selected" } else { "" };
        parent_options.push_str(&format!(r#"<option value="{pid}"{sel}>[{pcode}] {pname}</option>"#));
    }

    let active_checked = if cur_status == "active" { " checked" } else { "" };

    let content = format!(r##"<form method="POST" action="/eam/functional-locations/{id}/edit">
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Location Details</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Code *</span></label>
<input type="text" name="code" class="input input-bordered font-mono" value="{cur_code}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Name *</span></label>
<input type="text" name="name" class="input input-bordered" value="{cur_name}" required/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Short Name</span></label>
<input type="text" name="short_name" class="input input-bordered" value="{cur_short}"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Description</span></label>
<textarea name="description" class="textarea textarea-bordered h-24">{cur_desc}</textarea></div>
<div class="form-control"><label class="label cursor-pointer justify-start gap-3">
<input type="checkbox" name="is_active" value="true" class="checkbox checkbox-success"{active_checked}/>
<span class="label-text">Active</span></label></div>
</div></div>
</div>

<div class="space-y-6">
<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">Classification</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">Site *</span></label>
<select name="site_id" class="select select-bordered" required>{site_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Unit Type *</span></label>
<select name="unit_type_id" class="select select-bordered" required>{ut_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered">{vl_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Parent Location</span></label>
<select name="parent_id" class="select select-bordered">{parent_options}</select></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">Display Order</span></label>
<input type="number" name="display_order" class="input input-bordered" value="{cur_order}" min="0"/></div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h3 class="font-semibold text-lg mb-4">References</h3>
<div class="form-control mb-3"><label class="label"><span class="label-text">SLD Reference</span></label>
<input type="text" name="sld_reference" class="input input-bordered" value="{cur_sld}"/></div>
<div class="form-control mb-3"><label class="label"><span class="label-text">SCADA Point Group</span></label>
<input type="text" name="scada_point_group" class="input input-bordered" value="{cur_scada}"/></div>
</div></div>

<div class="flex gap-3 justify-end">
<a href="/eam/functional-locations/{id}" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M5 13l4 4L19 7"/></svg>Save Changes</button>
</div>
</div></div></form>"##);

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_functional_locations", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Edit {cur_code} - Functional Location</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/functional-locations">Functional Locations</a></li><li><a href="/eam/functional-locations/{id}">{cur_code}</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Functional Location</h1></div>
<a href="/eam/functional-locations/{id}" class="btn btn-ghost"><svg class="w-5 h-5 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10 19l-7-7m0 0l7-7m-7 7h18"/></svg>Back</a></div>
{content}
</main></div></body></html>"#)).into_response()
}

async fn eam_functional_location_save(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(id): axum::extract::Path<uuid::Uuid>,
    Form(form): Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").cloned().unwrap_or_default();
    let name = form.get("name").cloned().unwrap_or_default();
    let short_name = form.get("short_name").cloned().unwrap_or_default();
    let description = form.get("description").cloned().unwrap_or_default();
    let is_active = form.get("is_active").map(|v| v == "true").unwrap_or(false);
    let site_id = form.get("site_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let unit_type_id = form.get("unit_type_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let voltage_level_id = form.get("voltage_level_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let parent_id = form.get("parent_id").and_then(|a| uuid::Uuid::parse_str(a).ok());
    let display_order: i32 = form.get("display_order").and_then(|v| v.parse().ok()).unwrap_or(0);
    let sld_reference = form.get("sld_reference").cloned().unwrap_or_default();
    let scada_point_group = form.get("scada_point_group").cloned().unwrap_or_default();

    let status = if is_active { "active" } else { "inactive" };
    let short_opt = if short_name.is_empty() { None } else { Some(short_name) };
    let desc_opt = if description.is_empty() { None } else { Some(description) };
    let sld_opt = if sld_reference.is_empty() { None } else { Some(sld_reference) };
    let scada_opt = if scada_point_group.is_empty() { None } else { Some(scada_point_group) };

    let _ = sqlx::query(
        r#"UPDATE eam_functional_locations
           SET code = $1, name = $2, short_name = $3, description = $4,
               site_id = $5, unit_type_id = $6, voltage_level_id = $7, parent_id = $8,
               display_order = $9, sld_reference = $10, scada_point_group = $11,
               status = $12, is_active = $13, updated_by = $14, updated_at = now()
           WHERE id = $15 AND company_id = $16"#
    )
    .bind(&code).bind(&name).bind(&short_opt).bind(&desc_opt)
    .bind(site_id).bind(unit_type_id).bind(voltage_level_id).bind(parent_id)
    .bind(display_order).bind(&sld_opt).bind(&scada_opt)
    .bind(status).bind(is_active).bind(user.id)
    .bind(id).bind(company_id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/functional-locations/{}", id)).into_response()
}

// =============================================================================
// SINGLE LINE DIAGRAM (SLD)
// =============================================================================

async fn eam_sld(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_sld", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    let header = format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Single Line Diagram - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex h-screen">{sidebar}
<main class="flex-1 flex flex-col overflow-hidden min-w-0">
<div class="p-4 pb-0"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Single Line Diagram</li></ul></div></div>
<div id="sld-root" class="flex-1 m-4 mt-2 card bg-base-100 shadow overflow-hidden"></div>
</main></div>"#);

    let css = r##"<style>
.sld-view{display:flex;flex-direction:column;height:100%;background:oklch(var(--b2))}
.sld-toolbar{background:oklch(var(--b1));border-bottom:1px solid oklch(var(--b3));padding:10px 16px;display:flex;align-items:center;gap:12px;flex-shrink:0;flex-wrap:wrap}
.sld-toolbar h4{margin:0;font-size:16px;font-weight:600;white-space:nowrap;color:oklch(var(--bc))}
.sld-toolbar select{min-width:240px;max-width:400px}
.sld-toolbar-spacer{flex:1}
.sld-legend{display:flex;align-items:center;gap:10px;flex-wrap:wrap}
.sld-legend-item{display:flex;align-items:center;gap:4px;font-size:11px;color:oklch(var(--bc)/0.6);white-space:nowrap}
.sld-legend-dot{width:10px;height:10px;border-radius:2px;flex-shrink:0}
.sld-status-legend{display:flex;align-items:center;gap:8px;margin-left:12px;padding-left:12px;border-left:1px solid oklch(var(--b3));flex-wrap:wrap}
.sld-status-legend-item{display:flex;align-items:center;gap:3px;font-size:10px;color:oklch(var(--bc)/0.6)}
.sld-status-dot{width:8px;height:8px;border-radius:50%;flex-shrink:0}
.sld-info-bar{background:oklch(var(--b1));border-bottom:1px solid oklch(var(--b3));padding:8px 16px;display:flex;align-items:center;gap:16px;font-size:12px;flex-shrink:0}
.sld-info-label{color:oklch(var(--bc)/0.5)}
.sld-info-value{font-weight:600;color:oklch(var(--bc))}
.sld-substation-link{color:oklch(var(--p));cursor:pointer;font-weight:600}
.sld-substation-link:hover{text-decoration:underline}
.sld-canvas-wrapper{flex:1;overflow:auto;padding:20px}
.sld-canvas{position:relative;min-height:400px;margin:0 auto}
.sld-busbar{position:absolute;left:0;right:0;height:6px;border-radius:3px;z-index:1}
.sld-busbar-label{position:absolute;left:0;top:-10px;transform:translateY(-100%);padding:2px 10px;border-radius:10px;color:#fff;font-size:11px;font-weight:600;white-space:nowrap;z-index:2}
.sld-bay-column{position:absolute;width:140px;z-index:3}
.sld-bay-header{background:oklch(var(--b1));border:1px solid oklch(var(--b3));border-radius:6px;padding:6px 8px;cursor:pointer;transition:box-shadow .15s,border-color .15s;margin-bottom:4px}
.sld-bay-header:hover{border-color:oklch(var(--p));box-shadow:0 2px 8px oklch(var(--p)/0.15)}
.sld-bay-name{font-size:11px;font-weight:600;color:oklch(var(--bc));margin-bottom:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sld-bay-type{font-size:9px;text-transform:uppercase;color:oklch(var(--bc)/0.5);letter-spacing:.5px}
.sld-bay-feeder{font-size:9px;color:oklch(var(--bc)/0.7);margin-top:2px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sld-bay-stem{width:2px;margin:0 auto;position:relative}
.sld-equipment-stack{display:flex;flex-direction:column;align-items:center;gap:0;padding:0 10px}
.sld-equipment-item{width:44px;height:44px;background:oklch(var(--b2));border:2px solid oklch(var(--b3));border-radius:6px;display:flex;align-items:center;justify-content:center;cursor:pointer;transition:transform .15s,box-shadow .15s,border-color .15s;position:relative;z-index:4}
.sld-equipment-item:hover{transform:scale(1.15);box-shadow:0 3px 10px rgba(0,0,0,.25);z-index:10}
.sld-equipment-item svg{width:30px;height:30px}
.sld-equipment-connector{width:2px;height:8px;background:oklch(var(--bc)/0.3);margin:0 auto}
.sld-status-operational{border-color:#198754}
.sld-status-in_service{border-color:#198754}
.sld-status-standby{border-color:#ffc107}
.sld-status-out_of_service{border-color:#dc3545}
.sld-status-under_repair{border-color:#fd7e14}
.sld-status-decommissioned{border-color:#6c757d}
.sld-equipment-item .sld-tooltip{display:none;position:absolute;bottom:calc(100% + 8px);left:50%;transform:translateX(-50%);background:#1d232a;color:#a6adbb;padding:8px 10px;border-radius:6px;font-size:10px;white-space:nowrap;z-index:100;pointer-events:none;box-shadow:0 4px 12px rgba(0,0,0,.4);border:1px solid oklch(var(--b3))}
.sld-equipment-item .sld-tooltip::after{content:'';position:absolute;top:100%;left:50%;transform:translateX(-50%);border:5px solid transparent;border-top-color:#1d232a}
.sld-equipment-item:hover .sld-tooltip{display:block}
.sld-tooltip-name{font-weight:600;margin-bottom:2px;font-size:11px;color:oklch(var(--bc))}
.sld-tooltip-code{color:oklch(var(--bc)/0.5);margin-bottom:4px}
.sld-tooltip-row{display:flex;justify-content:space-between;gap:12px;line-height:1.5}
.sld-tooltip-label{color:oklch(var(--bc)/0.5)}
.sld-tooltip-value{font-weight:500;text-transform:capitalize;color:oklch(var(--bc))}
.sld-transformer-bridge{width:2px;border-left:2px dashed oklch(var(--bc)/0.3);margin:0 auto;position:relative}
.sld-empty-state{text-align:center;padding:60px 20px;color:oklch(var(--bc)/0.5)}
.sld-empty-state svg{width:48px;height:48px;margin:0 auto 16px;stroke:oklch(var(--bc)/0.3)}
.sld-loading{text-align:center;padding:60px 20px;color:oklch(var(--bc)/0.5)}
@media(max-width:768px){.sld-toolbar select{min-width:180px}.sld-legend,.sld-status-legend{display:none}}
</style>"##;

    let js = r##"<script>
// ─── VComponent: Lightweight Reactive Component Framework ───────────────────
// A minimal OWL-equivalent with reactive state, event delegation, and templates.
class VComponent {
    constructor(el, props = {}) {
        this.$el = el;
        this.props = props;
        this._state = {};
        this._eventsBound = false;
    }
    get state() { return this._state; }
    setState(patch) {
        Object.assign(this._state, typeof patch === 'function' ? patch(this._state) : patch);
        this._render();
    }
    _mount() {
        this.setup();
        this._render();
        if (!this._eventsBound) {
            this._eventsBound = true;
            this.$el.addEventListener('click', e => {
                const t = e.target.closest('[data-action]');
                if (t && typeof this[t.dataset.action] === 'function') {
                    e.preventDefault();
                    this[t.dataset.action](t.dataset.param, e);
                }
            });
            this.$el.addEventListener('change', e => {
                const t = e.target.closest('[data-on-change]');
                if (t && typeof this[t.dataset.onChange] === 'function') {
                    this[t.dataset.onChange](e);
                }
            });
        }
        this.mounted();
    }
    _render() { this.$el.innerHTML = this.render(); this.afterRender(); }
    setup() {}
    mounted() {}
    render() { return ''; }
    afterRender() {}
    static mount(Cls, el, props) { const c = new Cls(el, props); c._mount(); return c; }
}

// ─── Constants ──────────────────────────────────────────────────────────────
const STATUS_COLORS = {
    operational:'#198754', in_service:'#198754', standby:'#ffc107',
    out_of_service:'#dc3545', under_repair:'#fd7e14', decommissioned:'#6c757d'
};
const VOLTAGE_PALETTE = ['#dc3545','#0d6efd','#198754','#fd7e14','#6f42c1','#0dcaf0'];
const EQUIP_ORDER = {
    switchgear:0, isolator:1, ct:2, vt:3, cvt:4, transformer:5,
    surge_arrester:6, cable:7, busbar:8, other:9
};
const L = {
    COL_W:160, COL_CW:140, LEFT:80, BB_Y:50, LABEL_H:28, BB_H:6,
    GAP_BB_HDR:14, HDR_H:90, GAP_HDR_EQ:6, EQ_H:44, EQ_GAP:8, GAP_BOT:40, STEM_W:2
};

// ─── IEC SVG Symbols ────────────────────────────────────────────────────────
const SVG = {
    switchgear: c => `<svg viewBox="0 0 30 30"><rect x="3" y="3" width="24" height="24" rx="2" fill="none" stroke="${c}" stroke-width="2"/><line x1="5" y1="5" x2="25" y2="25" stroke="${c}" stroke-width="2"/><line x1="25" y1="5" x2="5" y2="25" stroke="${c}" stroke-width="2"/></svg>`,
    transformer: c => `<svg viewBox="0 0 30 30"><circle cx="12" cy="15" r="8" fill="none" stroke="${c}" stroke-width="2"/><circle cx="18" cy="15" r="8" fill="none" stroke="${c}" stroke-width="2"/></svg>`,
    isolator: c => `<svg viewBox="0 0 30 30"><line x1="3" y1="15" x2="10" y2="15" stroke="${c}" stroke-width="2"/><line x1="10" y1="15" x2="20" y2="5" stroke="${c}" stroke-width="2"/><line x1="20" y1="15" x2="27" y2="15" stroke="${c}" stroke-width="2"/></svg>`,
    ct: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><circle cx="15" cy="15" r="2" fill="${c}"/></svg>`,
    vt: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><line x1="15" y1="5" x2="15" y2="25" stroke="${c}" stroke-width="1.5"/></svg>`,
    cvt: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><circle cx="15" cy="15" r="2" fill="${c}"/><line x1="15" y1="5" x2="15" y2="25" stroke="${c}" stroke-width="1"/></svg>`,
    surge_arrester: c => `<svg viewBox="0 0 30 30"><line x1="15" y1="2" x2="15" y2="7" stroke="${c}" stroke-width="2"/><polyline points="10,7 15,14 12,14 17,21 14,21 19,28" fill="none" stroke="${c}" stroke-width="2"/><line x1="8" y1="28" x2="22" y2="28" stroke="${c}" stroke-width="2"/></svg>`,
    cable: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><text x="15" y="19" text-anchor="middle" fill="${c}" font-size="10" font-weight="bold">C</text></svg>`,
    busbar: c => `<svg viewBox="0 0 30 30"><rect x="2" y="10" width="26" height="10" rx="2" fill="none" stroke="${c}" stroke-width="2"/><line x1="5" y1="15" x2="25" y2="15" stroke="${c}" stroke-width="2"/></svg>`,
    other: c => `<svg viewBox="0 0 30 30"><circle cx="15" cy="15" r="10" fill="none" stroke="${c}" stroke-width="2"/><text x="15" y="19" text-anchor="middle" fill="${c}" font-size="10" font-weight="bold">?</text></svg>`
};

// ─── SLD View Component ─────────────────────────────────────────────────────
class SldView extends VComponent {
    setup() {
        this._state = {
            loaded:false, loading:false, substations:[], selectedId:null,
            substation:null, voltageLevels:[], bays:[], bayEquipment:{}
        };
    }
    async mounted() { await this.loadSubstations(); }

    // ── Data ─────────────────────────────────────────────────
    async loadSubstations() {
        try {
            const r = await fetch('/api/eam/sld/substations');
            const data = await r.json();
            this.setState({ substations: data, loaded: true });
        } catch(e) { this.setState({ loaded: true }); }
    }
    async loadSldData(id) {
        if (!id) { this.setState({ substation:null, voltageLevels:[], bays:[], bayEquipment:{} }); return; }
        this.setState({ loading: true });
        try {
            const r = await fetch(`/api/eam/sld/substations/${id}`);
            const d = await r.json();
            const grouped = {};
            for (const eq of (d.equipment || [])) {
                if (!grouped[eq.bay_id]) grouped[eq.bay_id] = [];
                grouped[eq.bay_id].push(eq);
            }
            for (const bid in grouped) {
                grouped[bid].sort((a,b) => (EQUIP_ORDER[a.equipment_type]??9) - (EQUIP_ORDER[b.equipment_type]??9));
            }
            this.setState({
                substation: d.substation, voltageLevels: d.voltage_levels || [],
                bays: d.bays || [], bayEquipment: grouped, loading: false
            });
        } catch(e) { this.setState({ loading: false }); }
    }

    // ── Layout Algorithm ─────────────────────────────────────
    computeLayout() {
        const { substation: sub, voltageLevels: vls, bays, bayEquipment } = this._state;
        if (!sub || !vls.length) return null;

        const vlMap = {}; for (const vl of vls) vlMap[vl.id] = vl;
        const vlBays = {}; const xformBays = []; const couplerBays = [];

        for (const bay of bays) {
            const vlId = bay.voltage_level_id;
            if (bay.bay_type === 'transformer') { xformBays.push(bay); }
            else if (bay.bay_type === 'bus_coupler' || bay.bay_type === 'bus_section') { couplerBays.push(bay); }
            else {
                if (!vlBays[vlId]) vlBays[vlId] = [];
                vlBays[vlId].push(bay);
            }
        }

        const cols = []; let ci = 0;
        for (const vl of vls) {
            for (const bay of (vlBays[vl.id] || [])) { cols.push({ bay, ci: ci++, type: bay.bay_type, vlId: vl.id }); }
        }
        for (const bay of xformBays) {
            const vlId = bay.voltage_level_id || (vls[0] && vls[0].id);
            cols.push({ bay, ci: ci++, type: 'transformer', vlId });
        }
        for (const bay of couplerBays) {
            const vlId = bay.voltage_level_id || (vls[0] && vls[0].id);
            cols.push({ bay, ci: ci++, type: bay.bay_type, vlId });
        }
        const totalCols = ci || 1;

        const eqCount = bid => (bayEquipment[bid] || []).length;
        const stackH = n => n <= 0 ? 0 : n * L.EQ_H + (n-1) * L.EQ_GAP;

        const vlPos = {}; let curY = L.BB_Y;
        for (const vl of vls) {
            vlPos[vl.id] = { y: curY };
            let maxEq = 0;
            for (const c of cols) { if (c.vlId === vl.id) { const n = eqCount(c.bay.id); if (n > maxEq) maxEq = n; } }
            const secH = L.BB_H + L.GAP_BB_HDR + L.HDR_H + L.GAP_HDR_EQ + stackH(maxEq) + L.GAP_BOT;
            vlPos[vl.id].bottom = curY + secH;
            curY += secH;
        }

        return { sub, vls, vlMap, vlPos, cols, totalCols, height: curY + 40 };
    }

    // ── Helpers ──────────────────────────────────────────────
    fmtLabel(s) { return (s || '').replace(/_/g, ' '); }
    fmtStatus(s) { return ({ operational:'Operational', in_service:'In Service', standby:'Standby', out_of_service:'Out of Service', under_repair:'Under Repair', decommissioned:'Decommissioned' })[s] || this.fmtLabel(s); }
    statusColor(s) { return STATUS_COLORS[s] || '#6c757d'; }
    equipSvg(type, status) { return (SVG[type] || SVG.other)(this.statusColor(status)); }

    // ── Event Handlers ───────────────────────────────────────
    async onSelectSubstation(e) {
        const val = e.target.value;
        this._state.selectedId = val || null;
        this._render();
        await this.loadSldData(val);
    }
    onClickEquipment(id) { window.location.href = '/eam/assets/' + id; }
    onClickBay(id) { /* future bay detail page */ }

    // ── Render ───────────────────────────────────────────────
    render() {
        const { loaded, loading, substations, selectedId, substation: sub, voltageLevels: vls } = this._state;
        const layout = this.computeLayout();

        let toolbar = `<div class="sld-toolbar">
            <svg class="w-5 h-5" style="color:oklch(var(--bc)/0.5)" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/><circle cx="17" cy="18" r="3" stroke-width="2" fill="none"/></svg>
            <h4>Single Line Diagram</h4>
            <select class="select select-bordered select-sm" data-on-change="onSelectSubstation">
                <option value="">-- Select Substation --</option>
                ${substations.map(s => `<option value="${s.id}" ${selectedId===s.id?'selected':''}>[${this.esc(s.code)}] ${this.esc(s.name)}</option>`).join('')}
            </select>`;

        if (sub) toolbar += `<span class="badge badge-ghost badge-sm" style="text-transform:capitalize">${this.fmtLabel(sub.busbar_configuration)}</span>`;
        toolbar += `<div class="sld-toolbar-spacer"></div>`;

        if (vls.length) {
            toolbar += `<div class="sld-legend">
                <span style="font-size:11px;color:oklch(var(--bc)/0.5);font-weight:600">Voltage:</span>
                ${vls.map((vl,i) => { const c = VOLTAGE_PALETTE[i % VOLTAGE_PALETTE.length]; return `<span class="sld-legend-item"><span class="sld-legend-dot" style="background:${c}"></span>${this.esc(vl.name)} (${vl.voltage_kv}kV)</span>`; }).join('')}
            </div>
            <div class="sld-status-legend">
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#198754"></span>Oper.</span>
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#ffc107"></span>Standby</span>
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#dc3545"></span>OOS</span>
                <span class="sld-status-legend-item"><span class="sld-status-dot" style="background:#fd7e14"></span>Repair</span>
            </div>`;
        }
        toolbar += `</div>`;

        let infoBar = '';
        if (sub) {
            const bayCount = this._state.bays.length;
            let eqTotal = 0; for (const b in this._state.bayEquipment) eqTotal += this._state.bayEquipment[b].length;
            infoBar = `<div class="sld-info-bar">
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Substation:</span><span class="sld-substation-link">${this.esc(sub.name)}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Code:</span><span class="sld-info-value">${this.esc(sub.code)}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Type:</span><span class="sld-info-value" style="text-transform:capitalize">${this.fmtLabel(sub.substation_type)}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Bays:</span><span class="sld-info-value">${bayCount}</span></div>
                <div style="display:flex;align-items:center;gap:4px"><span class="sld-info-label">Equipment:</span><span class="sld-info-value">${eqTotal}</span></div>
            </div>`;
        }

        let canvas = '';
        if (loading) {
            canvas = `<div class="sld-loading"><div class="loading loading-spinner loading-lg"></div><p style="margin-top:12px">Loading diagram...</p></div>`;
        } else if (!selectedId) {
            canvas = `<div class="sld-empty-state"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h7"/><circle cx="17" cy="18" r="3" stroke-width="2" fill="none"/></svg><p>Select a substation to view its Single Line Diagram</p></div>`;
        } else if (layout) {
            canvas = this.renderCanvas(layout);
        }

        return `<div class="sld-view">${toolbar}${infoBar}<div class="sld-canvas-wrapper">${canvas}</div></div>`;
    }

    renderCanvas(ly) {
        const { vls, vlMap, vlPos, cols, totalCols, height } = ly;
        const w = totalCols * L.COL_W + L.LEFT + 40;
        let html = `<div class="sld-canvas" style="min-width:${w}px;min-height:${height}px">`;

        // Busbars
        for (let i = 0; i < vls.length; i++) {
            const vl = vls[i]; const c = VOLTAGE_PALETTE[i % VOLTAGE_PALETTE.length];
            const y = vlPos[vl.id].y;
            html += `<div class="sld-busbar" style="top:${y}px;background:${c}">
                <div class="sld-busbar-label" style="background:${c}">${this.esc(vl.name)} (${vl.voltage_kv}kV)</div></div>`;
        }

        // Bay columns
        for (const col of cols) {
            const left = col.ci * L.COL_W + L.LEFT;
            const bbY = vlPos[col.vlId] ? vlPos[col.vlId].y : L.BB_Y;
            const stemTop = bbY + L.BB_H;
            const hdrTop = stemTop + L.GAP_BB_HDR;
            const eqTop = hdrTop + L.HDR_H + L.GAP_HDR_EQ;
            const vlColor = VOLTAGE_PALETTE[vls.findIndex(v => v.id === col.vlId) % VOLTAGE_PALETTE.length] || '#6c757d';
            const bay = col.bay;
            const eqs = this._state.bayEquipment[bay.id] || [];
            const statusBadge = bay.status === 'active' ? 'badge-success' : 'badge-ghost';

            html += `<div class="sld-bay-column" style="left:${left}px">`;
            // Stem
            html += `<div class="sld-bay-stem" style="position:absolute;left:69px;top:${stemTop}px;height:${L.GAP_BB_HDR}px;background:${vlColor}"></div>`;
            // Header
            html += `<div class="sld-bay-header" style="position:absolute;width:${L.COL_CW}px;top:${hdrTop}px" data-action="onClickBay" data-param="${bay.id}">
                <div class="sld-bay-name">${this.esc(bay.name)}</div>
                <div class="sld-bay-type">${this.fmtLabel(bay.bay_type)}</div>
                ${bay.feeder_name ? `<div class="sld-bay-feeder">${this.esc(bay.feeder_name)}</div>` : ''}
                <span class="badge ${statusBadge}" style="font-size:8px;margin-top:3px">${this.fmtLabel(bay.status)}</span>
            </div>`;
            // Equipment stack
            html += `<div class="sld-equipment-stack" style="position:absolute;width:${L.COL_CW}px;top:${eqTop}px">`;
            for (let ei = 0; ei < eqs.length; ei++) {
                const eq = eqs[ei];
                if (ei > 0) html += `<div class="sld-equipment-connector"></div>`;
                const sc = `sld-status-${eq.operational_status || 'in_service'}`;
                html += `<div class="sld-equipment-item ${sc}" data-action="onClickEquipment" data-param="${eq.id}">
                    ${this.equipSvg(eq.equipment_type, eq.operational_status)}
                    <div class="sld-tooltip">
                        <div class="sld-tooltip-name">${this.esc(eq.name)}</div>
                        <div class="sld-tooltip-code">${this.esc(eq.code)}</div>
                        <div class="sld-tooltip-row"><span class="sld-tooltip-label">Category:</span><span class="sld-tooltip-value">${this.fmtLabel(eq.equipment_type)}</span></div>
                        <div class="sld-tooltip-row"><span class="sld-tooltip-label">Status:</span><span class="sld-tooltip-value">${this.fmtStatus(eq.operational_status)}</span></div>
                        <div class="sld-tooltip-row"><span class="sld-tooltip-label">Condition:</span><span class="sld-tooltip-value">${Math.round(eq.condition_score || 0)}%</span></div>
                        ${eq.rated_voltage_kv ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Voltage:</span><span class="sld-tooltip-value">${eq.rated_voltage_kv}kV</span></div>` : ''}
                        ${eq.rated_current_a ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Current:</span><span class="sld-tooltip-value">${eq.rated_current_a}A</span></div>` : ''}
                        ${eq.rated_power_kva ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Power:</span><span class="sld-tooltip-value">${eq.rated_power_kva}kVA</span></div>` : ''}
                        ${eq.manufacturer_name ? `<div class="sld-tooltip-row"><span class="sld-tooltip-label">Mfg:</span><span class="sld-tooltip-value">${this.esc(eq.manufacturer_name)}</span></div>` : ''}
                    </div>
                </div>`;
            }
            html += `</div>`;

            // Transformer bridge
            if (col.type === 'transformer' && vls.length >= 2) {
                const vi = vls.findIndex(v => v.id === col.vlId);
                if (vi >= 0 && vi < vls.length - 1) {
                    const nextVl = vls[vi + 1];
                    const nextBBY = vlPos[nextVl.id].y;
                    const eqStackH = eqs.length <= 0 ? 0 : eqs.length * L.EQ_H + (eqs.length-1) * L.EQ_GAP;
                    const bridgeStart = eqTop + eqStackH + 4;
                    const bridgeH = nextBBY - bridgeStart;
                    if (bridgeH > 0) {
                        html += `<div class="sld-transformer-bridge" style="position:absolute;left:69px;top:${bridgeStart}px;height:${bridgeH}px"></div>`;
                    }
                }
            }
            html += `</div>`;
        }

        if (cols.length === 0) {
            html += `<div class="sld-empty-state" style="margin-top:80px"><svg fill="none" stroke="currentColor" viewBox="0 0 24 24" style="width:48px;height:48px;margin:0 auto 16px;display:block"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg><p>No bays found for this substation</p></div>`;
        }

        html += `</div>`;
        return html;
    }

    esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
}

// Mount on load
document.addEventListener('DOMContentLoaded', () => {
    VComponent.mount(SldView, document.getElementById('sld-root'));
});
</script>"##;

    let mut html = String::with_capacity(header.len() + css.len() + js.len() + 30);
    html.push_str(&header);
    html.push_str(css);
    html.push_str(js);
    html.push_str("</body></html>");
    Html(html).into_response()
}

async fn eam_sld_substations_api(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT s.id, s.code, s.name, s.substation_type, s.busbar_configuration,
                  st.name as site_name
           FROM eam_substations s
           LEFT JOIN eam_sites st ON st.id = s.site_id
           WHERE s.company_id = $1 AND s.is_active = true
           ORDER BY s.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let arr: Vec<serde_json::Value> = rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "substation_type": r.get::<Option<String>, _>("substation_type"),
            "busbar_configuration": r.get::<Option<String>, _>("busbar_configuration"),
            "site_name": r.get::<Option<String>, _>("site_name")
        })
    }).collect();

    axum::Json(serde_json::Value::Array(arr)).into_response()
}

async fn eam_sld_data_api(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Path(substation_id): axum::extract::Path<uuid::Uuid>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Substation details
    let sub_row = sqlx::query(
        r#"SELECT id, code, name, substation_type, busbar_configuration
           FROM eam_substations WHERE id = $1 AND company_id = $2"#
    ).bind(substation_id).bind(company_id).fetch_optional(&db).await.unwrap_or(None);

    let sub_json = match sub_row {
        Some(r) => serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "substation_type": r.get::<Option<String>, _>("substation_type"),
            "busbar_configuration": r.get::<Option<String>, _>("busbar_configuration")
        }),
        None => return axum::Json(serde_json::json!({"error":"Not found"})).into_response(),
    };

    // Voltage levels (derived from bays)
    let vl_rows = sqlx::query(
        r#"SELECT DISTINCT vl.id, vl.code, vl.name, vl.voltage_value, vl.voltage_type
           FROM eam_voltage_levels vl
           INNER JOIN eam_bays b ON b.voltage_level_id = vl.id
           WHERE b.substation_id = $1 AND b.is_active = true AND vl.is_active = true
           ORDER BY vl.voltage_value DESC"#
    ).bind(substation_id).fetch_all(&db).await.unwrap_or_default();

    let vl_json: Vec<serde_json::Value> = vl_rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "voltage_kv": r.get::<f64, _>("voltage_value"),
            "voltage_type": r.get::<Option<String>, _>("voltage_type")
        })
    }).collect();

    // Bays
    let bay_rows = sqlx::query(
        r#"SELECT b.id, b.code, b.name, b.bay_type, b.voltage_level_id,
                  b.feeder_name, b.sld_reference, b.status, b.display_order
           FROM eam_bays b
           WHERE b.substation_id = $1 AND b.is_active = true
           ORDER BY b.display_order, b.code"#
    ).bind(substation_id).fetch_all(&db).await.unwrap_or_default();

    let bay_json: Vec<serde_json::Value> = bay_rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("code"),
            "name": r.get::<String, _>("name"),
            "bay_type": r.get::<Option<String>, _>("bay_type"),
            "voltage_level_id": r.get::<Option<uuid::Uuid>, _>("voltage_level_id").map(|u| u.to_string()),
            "feeder_name": r.get::<Option<String>, _>("feeder_name"),
            "sld_reference": r.get::<Option<String>, _>("sld_reference"),
            "status": r.get::<Option<String>, _>("status")
        })
    }).collect();

    // Equipment (all assets in bays of this substation, with type detection)
    let eq_rows = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.operational_status, a.condition_score,
                  a.bay_id, a.serial_number,
                  CASE
                      WHEN t.id IS NOT NULL THEN 'transformer'
                      WHEN sg.id IS NOT NULL THEN 'switchgear'
                      WHEN cvt.id IS NOT NULL THEN cvt.device_type
                      WHEN sa.id IS NOT NULL THEN 'surge_arrester'
                      WHEN iso.id IS NOT NULL THEN 'isolator'
                      WHEN bb.id IS NOT NULL THEN 'busbar'
                      WHEN cb.id IS NOT NULL THEN 'cable'
                      ELSE 'other'
                  END as equipment_type,
                  COALESCE(t.primary_voltage, sg.rated_voltage, cvt.rated_voltage_kv,
                           sa.rated_voltage_kv, iso.rated_voltage_kv, bb.rated_voltage_kv,
                           cb.voltage_rating_kv) as rated_voltage_kv,
                  COALESCE(sg.rated_current, iso.rated_current_a, bb.rated_current_a,
                           cb.rated_current_a) as rated_current_a,
                  t.mva_rating * 1000 as rated_power_kva,
                  m.name as manufacturer_name
           FROM eam_assets a
           LEFT JOIN eam_transformers t ON t.asset_id = a.id
           LEFT JOIN eam_switch_gears sg ON sg.asset_id = a.id
           LEFT JOIN eam_current_voltage_transformers cvt ON cvt.asset_id = a.id
           LEFT JOIN eam_surge_arresters sa ON sa.asset_id = a.id
           LEFT JOIN eam_isolators iso ON iso.asset_id = a.id
           LEFT JOIN eam_busbars bb ON bb.asset_id = a.id
           LEFT JOIN eam_cables cb ON cb.asset_id = a.id
           LEFT JOIN eam_manufacturers m ON m.id = a.manufacturer_id
           WHERE a.bay_id IN (SELECT id FROM eam_bays WHERE substation_id = $1 AND is_active = true)
             AND a.is_active = true
           ORDER BY a.display_order, a.name"#
    ).bind(substation_id).fetch_all(&db).await.unwrap_or_default();

    let eq_json: Vec<serde_json::Value> = eq_rows.iter().map(|r| {
        serde_json::json!({
            "id": r.get::<uuid::Uuid, _>("id").to_string(),
            "code": r.get::<String, _>("asset_code"),
            "name": r.get::<String, _>("name"),
            "operational_status": r.get::<Option<String>, _>("operational_status"),
            "condition_score": r.get::<Option<f64>, _>("condition_score"),
            "bay_id": r.get::<Option<uuid::Uuid>, _>("bay_id").map(|u| u.to_string()),
            "serial_number": r.get::<Option<String>, _>("serial_number"),
            "equipment_type": r.get::<Option<String>, _>("equipment_type"),
            "rated_voltage_kv": r.get::<Option<f64>, _>("rated_voltage_kv"),
            "rated_current_a": r.get::<Option<f64>, _>("rated_current_a"),
            "rated_power_kva": r.get::<Option<f64>, _>("rated_power_kva"),
            "manufacturer_name": r.get::<Option<String>, _>("manufacturer_name")
        })
    }).collect();

    axum::Json(serde_json::json!({
        "substation": sub_json,
        "voltage_levels": vl_json,
        "bays": bay_json,
        "equipment": eq_json
    })).into_response()
}

async fn eam_transmission(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Counts
    let total_lines: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transmission_lines WHERE company_id = $1 AND (is_deleted IS NULL OR is_deleted = FALSE)")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let total_towers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transmission_towers WHERE company_id = $1 AND (is_deleted IS NULL OR is_deleted = FALSE)")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let operational_lines: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transmission_lines WHERE company_id = $1 AND (is_deleted IS NULL OR is_deleted = FALSE) AND state = 'operational'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let critical_towers: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_transmission_towers WHERE company_id = $1 AND (is_deleted IS NULL OR is_deleted = FALSE) AND condition_status = 'critical'")
        .bind(company_id).fetch_one(&db).await.unwrap_or(0);

    // Fetch lines with tower counts
    let line_rows = sqlx::query(
        r#"SELECT l.id, l.code, l.name, l.line_length_km, l.voltage_level_id, l.conductor_type, l.state, l.ownership,
                  COALESCE(fs.name, '') as from_sub_name, COALESCE(ts.name, '') as to_sub_name,
                  (SELECT COUNT(*) FROM eam_transmission_towers t WHERE t.transmission_line_id = l.id AND (t.is_deleted IS NULL OR t.is_deleted = FALSE)) as tower_count
           FROM eam_transmission_lines l
           LEFT JOIN eam_substations fs ON l.from_substation_id = fs.id
           LEFT JOIN eam_substations ts ON l.to_substation_id = ts.id
           WHERE l.company_id = $1 AND (l.is_deleted IS NULL OR l.is_deleted = FALSE)
           ORDER BY l.code"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut line_table = String::new();
    for row in &line_rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let length: Option<f64> = row.get("line_length_km");
        let conductor: Option<String> = row.get("conductor_type");
        let state_val: Option<String> = row.get("state");
        let from_sub: String = row.get("from_sub_name");
        let to_sub: String = row.get("to_sub_name");
        let tower_count: i64 = row.get("tower_count");

        let length_str = length.map(|l| format!("{:.1} km", l)).unwrap_or_else(|| "-".into());
        let conductor_str = conductor.unwrap_or_else(|| "-".into());
        let state_badge = match state_val.as_deref() {
            Some("operational") => r#"<span class="badge badge-success badge-sm">Operational</span>"#,
            Some("construction") => r#"<span class="badge badge-warning badge-sm">Construction</span>"#,
            Some("planning") => r#"<span class="badge badge-info badge-sm">Planning</span>"#,
            Some("maintenance") => r#"<span class="badge badge-warning badge-sm">Maintenance</span>"#,
            Some("decommissioned") => r#"<span class="badge badge-ghost badge-sm">Decommissioned</span>"#,
            _ => r#"<span class="badge badge-ghost badge-sm">-</span>"#,
        };
        let route_str = if !from_sub.is_empty() && !to_sub.is_empty() {
            format!("{} → {}", html_escape(&from_sub), html_escape(&to_sub))
        } else if !from_sub.is_empty() {
            html_escape(&from_sub)
        } else {
            "-".into()
        };

        line_table.push_str(&format!(
            r#"<tr class="hover"><td class="font-mono font-semibold">{}</td><td>{}</td><td class="text-sm">{}</td><td>{}</td><td class="uppercase text-xs">{}</td><td class="text-center">{}</td><td>{}</td>
            <td><a href="/eam/transmission/{}" class="btn btn-ghost btn-xs">View</a></td></tr>"#,
            html_escape(&code), html_escape(&name), route_str, length_str, conductor_str, tower_count, state_badge, id
        ));
    }

    let lines_content = if line_rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 10V3L4 14h7v7l9-11h-7z"/></svg><h3 class="text-lg font-semibold mb-2">No Transmission Lines Yet</h3><p class="text-base-content/60">Create transmission lines and towers to manage overhead line assets</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Route</th><th>Length</th><th>Conductor</th><th>Towers</th><th>Status</th><th>Actions</th></tr></thead><tbody>{line_table}</tbody></table></div>"#)
    };

    let critical_class = if critical_towers > 0 { "bg-error/10" } else { "" };
    let critical_text = if critical_towers > 0 { "text-error" } else { "" };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_transmission", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Transmission - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Transmission</li></ul></div>
<h1 class="text-2xl font-bold">Transmission Network</h1><p class="text-base-content/60">Overhead transmission lines and towers</p></div>
<div class="dropdown dropdown-end"><label tabindex="0" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New</label>
<ul tabindex="0" class="dropdown-content z-[1] menu p-2 shadow bg-base-100 rounded-box w-52">
<li><a href="/eam/transmission/lines/new">Transmission Line</a></li>
<li><a href="/eam/transmission/towers/new">Transmission Tower</a></li>
</ul></div></div>
<div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Lines</div><div class="stat-value text-2xl">{total_lines}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Towers</div><div class="stat-value text-2xl">{total_towers}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Operational</div><div class="stat-value text-2xl">{operational_lines}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4 {critical_class}"><div class="stat-title text-xs">Critical Towers</div><div class="stat-value text-2xl {critical_text}">{critical_towers}</div></div>
</div>
<div class="card bg-base-100 shadow"><div class="card-header p-4 border-b border-base-300"><h2 class="card-title text-lg">Transmission Lines</h2><p class="text-sm text-base-content/60">Overhead power lines with associated towers</p></div><div class="card-body">{lines_content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_transmission_line_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get regions for dropdown
    let regions = sqlx::query("SELECT id, name FROM eam_regions WHERE company_id = $1 AND is_active = true ORDER BY name")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut region_opts = String::new();
    for r in &regions {
        let rid: uuid::Uuid = r.get("id");
        let rname: String = r.get("name");
        region_opts.push_str(&format!(r#"<option value="{rid}">{}</option>"#, html_escape(&rname)));
    }

    // Get substations for from/to dropdowns
    let subs = sqlx::query("SELECT id, name FROM eam_substations WHERE company_id = $1 AND is_active = true ORDER BY name")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut sub_opts = String::new();
    for s in &subs {
        let sid: uuid::Uuid = s.get("id");
        let sname: String = s.get("name");
        sub_opts.push_str(&format!(r#"<option value="{sid}">{}</option>"#, html_escape(&sname)));
    }

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_transmission", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Transmission Line - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/transmission">Transmission</a></li><li>New Line</li></ul></div>
<h1 class="text-2xl font-bold">Create Transmission Line</h1></div>
<form method="POST" action="/eam/transmission/lines/new" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Code *</span></label><input type="text" name="code" required class="input input-bordered" placeholder="TL-132-001"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" placeholder="132kV Ampang - Gombak Line"/></div>
<div class="form-control"><label class="label"><span class="label-text">Region *</span></label><select name="region_id" required class="select select-bordered"><option value="">Select Region</option>{region_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">State</span></label><select name="state" class="select select-bordered"><option value="">Select</option><option value="planning">Planning</option><option value="construction">Construction</option><option value="operational" selected>Operational</option><option value="maintenance">Maintenance</option><option value="decommissioned">Decommissioned</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">From Substation</span></label><select name="from_substation_id" class="select select-bordered"><option value="">Select</option>{sub_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">To Substation</span></label><select name="to_substation_id" class="select select-bordered"><option value="">Select</option>{sub_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Line Length (km)</span></label><input type="number" step="0.01" name="line_length_km" class="input input-bordered" placeholder="12.5"/></div>
<div class="form-control"><label class="label"><span class="label-text">Conductor Type</span></label><select name="conductor_type" class="select select-bordered"><option value="">Select</option><option value="acsr">ACSR</option><option value="acar">ACAR</option><option value="aaac">AAAC</option><option value="aac">AAC</option><option value="accc">ACCC</option><option value="htls">HTLS</option><option value="opgw">OPGW</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Conductor Size (mm²)</span></label><input type="number" step="0.01" name="conductor_size_mm2" class="input input-bordered" placeholder="300"/></div>
<div class="form-control"><label class="label"><span class="label-text">Number of Circuits</span></label><input type="number" name="number_of_circuits" class="input input-bordered" placeholder="2"/></div>
<div class="form-control"><label class="label"><span class="label-text">Rated Current (A)</span></label><input type="number" step="0.01" name="rated_current_a" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Earth Wire Type</span></label><input type="text" name="earth_wire_type" class="input input-bordered" placeholder="OPGW / Galvanized Steel"/></div>
<div class="form-control"><label class="label"><span class="label-text">Ownership</span></label><select name="ownership" class="select select-bordered"><option value="">Select</option><option value="sesb">SESB</option><option value="ipp">IPP</option><option value="shared">Shared</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Commissioning Date</span></label><input type="date" name="commissioning_date" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Design Life (years)</span></label><input type="number" name="design_life_years" class="input input-bordered" placeholder="40"/></div>
<div class="form-control"><label class="label"><span class="label-text">Max Sag (m)</span></label><input type="number" step="0.01" name="max_sag_m" class="input input-bordered"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Notes</span></label><textarea name="notes" class="textarea textarea-bordered" rows="3"></textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/transmission" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create Transmission Line</button></div>
</div></form>
</main></div></body></html>"#)).into_response()
}

async fn eam_transmission_line_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let region_id: Option<uuid::Uuid> = form.get("region_id").and_then(|s| s.parse().ok());
    let state_val = form.get("state").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let from_sub: Option<uuid::Uuid> = form.get("from_substation_id").and_then(|s| s.parse().ok());
    let to_sub: Option<uuid::Uuid> = form.get("to_substation_id").and_then(|s| s.parse().ok());
    let length: Option<f64> = form.get("line_length_km").and_then(|s| s.parse().ok());
    let conductor = form.get("conductor_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let conductor_size: Option<f64> = form.get("conductor_size_mm2").and_then(|s| s.parse().ok());
    let circuits: Option<i32> = form.get("number_of_circuits").and_then(|s| s.parse().ok());
    let rated_current: Option<f64> = form.get("rated_current_a").and_then(|s| s.parse().ok());
    let earth_wire = form.get("earth_wire_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let ownership = form.get("ownership").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let commissioning = form.get("commissioning_date").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let design_life: Option<i32> = form.get("design_life_years").and_then(|s| s.parse().ok());
    let max_sag: Option<f64> = form.get("max_sag_m").and_then(|s| s.parse().ok());
    let notes = form.get("notes").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"INSERT INTO eam_transmission_lines (company_id, code, name, region_id, state,
           from_substation_id, to_substation_id, line_length_km, conductor_type, conductor_size_mm2,
           number_of_circuits, rated_current_a, earth_wire_type, ownership, commissioning_date,
           design_life_years, max_sag_m, notes, is_active, created_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,true,$19)
           RETURNING id"#
    )
    .bind(company_id).bind(code).bind(name).bind(region_id).bind(state_val)
    .bind(from_sub).bind(to_sub).bind(length).bind(conductor).bind(conductor_size)
    .bind(circuits).bind(rated_current).bind(earth_wire).bind(ownership).bind(commissioning)
    .bind(design_life).bind(max_sag).bind(notes).bind(user.id)
    .fetch_one(&db).await;

    match result {
        Ok(id) => axum::response::Redirect::to(&format!("/eam/transmission/{}", id)).into_response(),
        Err(e) => {
            let msg = format!("{}", e);
            let user_msg = if msg.contains("duplicate key") {
                "A transmission line with this code already exists.".to_string()
            } else {
                format!("Error creating transmission line: {}", html_escape(&msg))
            };
            (axum::http::StatusCode::BAD_REQUEST, Html(format!(
                r#"<!DOCTYPE html><html><head><title>Error</title><link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen bg-base-200 flex items-center justify-center"><div class="card bg-base-100 shadow-xl p-8 max-w-md"><div class="text-error text-lg font-bold mb-2">Error</div><p>{user_msg}</p><a href="/eam/transmission/lines/new" class="btn btn-primary mt-4">Go Back</a></div></body></html>"#
            ))).into_response()
        }
    }
}

async fn eam_transmission_line_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let line = sqlx::query(
        r#"SELECT l.*, COALESCE(r.name, '') as region_name,
                  COALESCE(fs.name, '') as from_sub_name, COALESCE(ts.name, '') as to_sub_name
           FROM eam_transmission_lines l
           LEFT JOIN eam_regions r ON l.region_id = r.id
           LEFT JOIN eam_substations fs ON l.from_substation_id = fs.id
           LEFT JOIN eam_substations ts ON l.to_substation_id = ts.id
           WHERE l.id = $1 AND l.company_id = $2 AND (l.is_deleted IS NULL OR l.is_deleted = FALSE)"#
    ).bind(id).bind(company_id).fetch_optional(&db).await.ok().flatten();

    let Some(line) = line else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Transmission line not found")).into_response();
    };

    let code: String = line.get("code");
    let name: String = line.get("name");
    let region_name: String = line.get("region_name");
    let from_sub: String = line.get("from_sub_name");
    let to_sub: String = line.get("to_sub_name");
    let length: Option<f64> = line.get("line_length_km");
    let conductor: Option<String> = line.get("conductor_type");
    let conductor_size: Option<f64> = line.get("conductor_size_mm2");
    let circuits: Option<i32> = line.get("number_of_circuits");
    let rated_current: Option<f64> = line.get("rated_current_a");
    let earth_wire: Option<String> = line.get("earth_wire_type");
    let state_val: Option<String> = line.get("state");
    let ownership: Option<String> = line.get("ownership");
    let commissioning: Option<String> = line.get("commissioning_date");
    let design_life: Option<i32> = line.get("design_life_years");
    let max_sag: Option<f64> = line.get("max_sag_m");
    let notes: Option<String> = line.get("notes");

    let state_badge = match state_val.as_deref() {
        Some("operational") => r#"<span class="badge badge-success">Operational</span>"#,
        Some("construction") => r#"<span class="badge badge-warning">Construction</span>"#,
        Some("planning") => r#"<span class="badge badge-info">Planning</span>"#,
        Some("maintenance") => r#"<span class="badge badge-warning">Maintenance</span>"#,
        Some("decommissioned") => r#"<span class="badge badge-ghost">Decommissioned</span>"#,
        _ => r#"<span class="badge badge-ghost">-</span>"#,
    };

    let length_str = length.map(|l| format!("{:.1} km", l)).unwrap_or_else(|| "-".into());
    let conductor_str = conductor.as_deref().map(|c| c.to_uppercase()).unwrap_or_else(|| "-".into());
    let conductor_size_str = conductor_size.map(|s| format!("{:.0} mm²", s)).unwrap_or_else(|| "-".into());
    let circuits_str = circuits.map(|c| c.to_string()).unwrap_or_else(|| "-".into());
    let rated_current_str = rated_current.map(|c| format!("{:.0} A", c)).unwrap_or_else(|| "-".into());
    let earth_wire_str = earth_wire.unwrap_or_else(|| "-".into());
    let ownership_str = ownership.as_deref().map(|o| o.to_uppercase()).unwrap_or_else(|| "-".into());
    let commissioning_str = commissioning.unwrap_or_else(|| "-".into());
    let design_life_str = design_life.map(|y| format!("{} years", y)).unwrap_or_else(|| "-".into());
    let max_sag_str = max_sag.map(|s| format!("{:.1} m", s)).unwrap_or_else(|| "-".into());
    let notes_str = notes.map(|n| html_escape(&n)).unwrap_or_else(|| "-".into());
    let route_str = if !from_sub.is_empty() && !to_sub.is_empty() {
        format!("{} → {}", html_escape(&from_sub), html_escape(&to_sub))
    } else { "-".into() };

    // Fetch towers for this line
    let towers = sqlx::query(
        r#"SELECT id, code, name, tower_number, tower_type, tower_function, height_m,
                  gps_latitude, gps_longitude, operational_status, condition_status, health_index
           FROM eam_transmission_towers
           WHERE transmission_line_id = $1 AND (is_deleted IS NULL OR is_deleted = FALSE)
           ORDER BY tower_number, code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut tower_rows = String::new();
    for t in &towers {
        let tid: uuid::Uuid = t.get("id");
        let tcode: String = t.get("code");
        let tname: String = t.get("name");
        let tnum: Option<i32> = t.get("tower_number");
        let ttype: Option<String> = t.get("tower_type");
        let tfunc: Option<String> = t.get("tower_function");
        let theight: Option<f64> = t.get("height_m");
        let tlat: Option<f64> = t.get("gps_latitude");
        let tlon: Option<f64> = t.get("gps_longitude");
        let tstatus: Option<String> = t.get("operational_status");
        let tcond: Option<String> = t.get("condition_status");
        let thi: Option<f64> = t.get("health_index");

        let num_str = tnum.map(|n| n.to_string()).unwrap_or_else(|| "-".into());
        let type_str = ttype.unwrap_or_else(|| "-".into());
        let height_str = theight.map(|h| format!("{:.1}m", h)).unwrap_or_else(|| "-".into());
        let gps_str = match (tlat, tlon) {
            (Some(lat), Some(lon)) => format!("{:.4}, {:.4}", lat, lon),
            _ => "-".into(),
        };
        let status_badge = match tstatus.as_deref() {
            Some("operational") => r#"<span class="badge badge-success badge-sm">Operational</span>"#,
            Some("out_of_service") => r#"<span class="badge badge-error badge-sm">Out of Service</span>"#,
            Some("under_repair") => r#"<span class="badge badge-warning badge-sm">Under Repair</span>"#,
            _ => r#"<span class="badge badge-ghost badge-sm">-</span>"#,
        };
        let cond_badge = match tcond.as_deref() {
            Some("excellent") => r#"<span class="badge badge-success badge-sm">Excellent</span>"#,
            Some("good") => r#"<span class="badge badge-success badge-sm">Good</span>"#,
            Some("fair") => r#"<span class="badge badge-warning badge-sm">Fair</span>"#,
            Some("poor") => r#"<span class="badge badge-error badge-sm">Poor</span>"#,
            Some("critical") => r#"<span class="badge badge-error badge-sm">Critical</span>"#,
            _ => r#"<span class="badge badge-ghost badge-sm">-</span>"#,
        };

        tower_rows.push_str(&format!(
            r#"<tr class="hover"><td>{num_str}</td><td class="font-mono">{}</td><td>{}</td><td class="capitalize">{type_str}</td><td>{height_str}</td><td class="text-xs">{gps_str}</td><td>{status_badge}</td><td>{cond_badge}</td></tr>"#,
            html_escape(&tcode), html_escape(&tname)
        ));
    }

    let tower_content = if towers.is_empty() {
        r#"<div class="text-center py-8"><p class="text-base-content/60">No towers registered for this line</p><a href="/eam/transmission/towers/new" class="btn btn-sm btn-primary mt-2">Add Tower</a></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra table-sm"><thead><tr><th>#</th><th>Code</th><th>Name</th><th>Type</th><th>Height</th><th>GPS</th><th>Status</th><th>Condition</th></tr></thead><tbody>{tower_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_transmission", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{} - Transmission Line</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/transmission">Transmission</a></li><li>{}</li></ul></div>
<h1 class="text-2xl font-bold">{}</h1><p class="text-base-content/60">{}</p></div>
<div>{state_badge}</div></div>
<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
<div class="card bg-base-100 shadow"><div class="card-header p-4 border-b border-base-300"><h2 class="card-title text-lg">Line Details</h2></div><div class="card-body">
<table class="table table-sm"><tbody>
<tr><td class="font-semibold w-40">Code</td><td class="font-mono">{}</td></tr>
<tr><td class="font-semibold">Region</td><td>{}</td></tr>
<tr><td class="font-semibold">Route</td><td>{route_str}</td></tr>
<tr><td class="font-semibold">Length</td><td>{length_str}</td></tr>
<tr><td class="font-semibold">Ownership</td><td>{ownership_str}</td></tr>
<tr><td class="font-semibold">Commissioning</td><td>{commissioning_str}</td></tr>
<tr><td class="font-semibold">Design Life</td><td>{design_life_str}</td></tr>
</tbody></table></div></div>
<div class="card bg-base-100 shadow"><div class="card-header p-4 border-b border-base-300"><h2 class="card-title text-lg">Conductor Specifications</h2></div><div class="card-body">
<table class="table table-sm"><tbody>
<tr><td class="font-semibold w-40">Type</td><td>{conductor_str}</td></tr>
<tr><td class="font-semibold">Size</td><td>{conductor_size_str}</td></tr>
<tr><td class="font-semibold">Circuits</td><td>{circuits_str}</td></tr>
<tr><td class="font-semibold">Rated Current</td><td>{rated_current_str}</td></tr>
<tr><td class="font-semibold">Earth Wire</td><td>{earth_wire_str}</td></tr>
<tr><td class="font-semibold">Max Sag</td><td>{max_sag_str}</td></tr>
</tbody></table></div></div>
</div>
<div class="card bg-base-100 shadow mb-6"><div class="card-header p-4 border-b border-base-300 flex justify-between items-center"><div><h2 class="card-title text-lg">Towers ({tower_count})</h2></div><a href="/eam/transmission/towers/new" class="btn btn-sm btn-primary">Add Tower</a></div><div class="card-body">{tower_content}</div></div>
<div class="card bg-base-100 shadow"><div class="card-header p-4 border-b border-base-300"><h2 class="card-title text-lg">Notes</h2></div><div class="card-body"><p>{notes_str}</p></div></div>
</main></div></body></html>"#,
        html_escape(&name), html_escape(&code), html_escape(&name), html_escape(&code),
        html_escape(&code), html_escape(&region_name), tower_count = towers.len()
    )).into_response()
}

async fn eam_transmission_tower_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Get transmission lines for dropdown
    let lines = sqlx::query("SELECT id, code, name FROM eam_transmission_lines WHERE company_id = $1 AND (is_deleted IS NULL OR is_deleted = FALSE) ORDER BY code")
        .bind(company_id).fetch_all(&db).await.unwrap_or_default();
    let mut line_opts = String::new();
    for l in &lines {
        let lid: uuid::Uuid = l.get("id");
        let lcode: String = l.get("code");
        let lname: String = l.get("name");
        line_opts.push_str(&format!(r#"<option value="{lid}">{} - {}</option>"#, html_escape(&lcode), html_escape(&lname)));
    }

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_transmission", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Tower - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/transmission">Transmission</a></li><li>New Tower</li></ul></div>
<h1 class="text-2xl font-bold">Create Transmission Tower</h1></div>
<form method="POST" action="/eam/transmission/towers/new" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Code *</span></label><input type="text" name="code" required class="input input-bordered" placeholder="TWR-001"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" placeholder="Tower 1 - Ampang Line"/></div>
<div class="form-control"><label class="label"><span class="label-text">Transmission Line *</span></label><select name="transmission_line_id" required class="select select-bordered"><option value="">Select Line</option>{line_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Tower Number</span></label><input type="number" name="tower_number" class="input input-bordered" placeholder="1"/></div>
<div class="form-control"><label class="label"><span class="label-text">Tower Type</span></label><select name="tower_type" class="select select-bordered"><option value="">Select</option><option value="lattice_steel">Lattice Steel</option><option value="tubular_steel">Tubular Steel</option><option value="wood_pole">Wood Pole</option><option value="concrete_pole">Concrete Pole</option><option value="monopole">Monopole</option><option value="h_frame">H-Frame</option><option value="guyed_v">Guyed V</option><option value="self_supporting">Self Supporting</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Tower Function</span></label><select name="tower_function" class="select select-bordered"><option value="">Select</option><option value="suspension">Suspension</option><option value="tension">Tension</option><option value="angle">Angle</option><option value="dead_end">Dead End</option><option value="transposition">Transposition</option><option value="junction">Junction</option></select></div>
</div>
<div class="divider">Physical Dimensions</div>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Height (m)</span></label><input type="number" step="0.1" name="height_m" class="input input-bordered" placeholder="35"/></div>
<div class="form-control"><label class="label"><span class="label-text">Base Width (m)</span></label><input type="number" step="0.1" name="base_width_m" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Weight (kg)</span></label><input type="number" step="0.1" name="weight_kg" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Foundation Type</span></label><input type="text" name="foundation_type" class="input input-bordered" placeholder="Pad / Pile / Grillage"/></div>
<div class="form-control"><label class="label"><span class="label-text">Span to Next (m)</span></label><input type="number" step="0.1" name="span_to_next_m" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Span to Previous (m)</span></label><input type="number" step="0.1" name="span_to_previous_m" class="input input-bordered"/></div>
</div>
<div class="divider">GPS Location</div>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Latitude</span></label><input type="number" step="0.000001" name="gps_latitude" class="input input-bordered" placeholder="5.9788"/></div>
<div class="form-control"><label class="label"><span class="label-text">Longitude</span></label><input type="number" step="0.000001" name="gps_longitude" class="input input-bordered" placeholder="116.0735"/></div>
<div class="form-control"><label class="label"><span class="label-text">Elevation (m)</span></label><input type="number" step="0.1" name="elevation_m" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Ground Clearance (m)</span></label><input type="number" step="0.1" name="ground_clearance_m" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Right of Way (m)</span></label><input type="number" step="0.1" name="right_of_way_m" class="input input-bordered"/></div>
</div>
<div class="divider">Electrical</div>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Phase Configuration</span></label><input type="text" name="phase_configuration" class="input input-bordered" placeholder="Vertical / Horizontal / Delta"/></div>
<div class="form-control"><label class="label"><span class="label-text">Insulator Type</span></label><select name="insulator_type" class="select select-bordered"><option value="">Select</option><option value="glass">Glass</option><option value="porcelain">Porcelain</option><option value="composite">Composite</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Insulator Count</span></label><input type="number" name="insulator_count" class="input input-bordered"/></div>
<div class="form-control"><label class="label flex cursor-pointer gap-2"><span class="label-text">Earth Wire Attached</span><input type="checkbox" name="earth_wire_attached" value="true" class="checkbox checkbox-sm"/></label></div>
<div class="form-control"><label class="label flex cursor-pointer gap-2"><span class="label-text">Aviation Marking</span><input type="checkbox" name="aviation_marking" value="true" class="checkbox checkbox-sm"/></label></div>
</div>
<div class="divider">Status</div>
<div class="grid grid-cols-1 md:grid-cols-3 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Operational Status</span></label><select name="operational_status" class="select select-bordered"><option value="operational">Operational</option><option value="standby">Standby</option><option value="out_of_service">Out of Service</option><option value="under_repair">Under Repair</option><option value="decommissioned">Decommissioned</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Condition</span></label><select name="condition_status" class="select select-bordered"><option value="">Select</option><option value="excellent">Excellent</option><option value="good">Good</option><option value="fair">Fair</option><option value="poor">Poor</option><option value="critical">Critical</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Health Index (0-100)</span></label><input type="number" step="0.1" min="0" max="100" name="health_index" class="input input-bordered"/></div>
</div>
<div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
<div class="form-control"><label class="label"><span class="label-text">Last Inspection Date</span></label><input type="date" name="last_inspection_date" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Next Inspection Date</span></label><input type="date" name="next_inspection_date" class="input input-bordered"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Notes</span></label><textarea name="notes" class="textarea textarea-bordered" rows="3"></textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/transmission" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create Tower</button></div>
</div></form>
</main></div></body></html>"#)).into_response()
}

async fn eam_transmission_tower_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let line_id: Option<uuid::Uuid> = form.get("transmission_line_id").and_then(|s| s.parse().ok());
    let tower_number: Option<i32> = form.get("tower_number").and_then(|s| s.parse().ok());
    let tower_type = form.get("tower_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let tower_function = form.get("tower_function").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let height: Option<f64> = form.get("height_m").and_then(|s| s.parse().ok());
    let base_width: Option<f64> = form.get("base_width_m").and_then(|s| s.parse().ok());
    let weight: Option<f64> = form.get("weight_kg").and_then(|s| s.parse().ok());
    let foundation = form.get("foundation_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let span_next: Option<f64> = form.get("span_to_next_m").and_then(|s| s.parse().ok());
    let span_prev: Option<f64> = form.get("span_to_previous_m").and_then(|s| s.parse().ok());
    let lat: Option<f64> = form.get("gps_latitude").and_then(|s| s.parse().ok());
    let lon: Option<f64> = form.get("gps_longitude").and_then(|s| s.parse().ok());
    let elevation: Option<f64> = form.get("elevation_m").and_then(|s| s.parse().ok());
    let clearance: Option<f64> = form.get("ground_clearance_m").and_then(|s| s.parse().ok());
    let row_m: Option<f64> = form.get("right_of_way_m").and_then(|s| s.parse().ok());
    let phase_config = form.get("phase_configuration").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let insulator_type = form.get("insulator_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let insulator_count: Option<i32> = form.get("insulator_count").and_then(|s| s.parse().ok());
    let earth_wire = form.contains_key("earth_wire_attached");
    let aviation = form.contains_key("aviation_marking");
    let op_status = form.get("operational_status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let cond_status = form.get("condition_status").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let health: Option<f64> = form.get("health_index").and_then(|s| s.parse().ok());
    let last_insp = form.get("last_inspection_date").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let next_insp = form.get("next_inspection_date").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let notes = form.get("notes").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"INSERT INTO eam_transmission_towers (company_id, code, name, transmission_line_id, tower_number,
           tower_type, tower_function, height_m, base_width_m, weight_kg, foundation_type,
           span_to_next_m, span_to_previous_m, gps_latitude, gps_longitude, elevation_m,
           ground_clearance_m, right_of_way_m, phase_configuration, insulator_type, insulator_count,
           earth_wire_attached, aviation_marking, operational_status, condition_status, health_index,
           last_inspection_date, next_inspection_date, notes, is_active, created_by)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,true,$30)
           RETURNING id"#
    )
    .bind(company_id).bind(code).bind(name).bind(line_id).bind(tower_number)
    .bind(tower_type).bind(tower_function).bind(height).bind(base_width).bind(weight).bind(foundation)
    .bind(span_next).bind(span_prev).bind(lat).bind(lon).bind(elevation)
    .bind(clearance).bind(row_m).bind(phase_config).bind(insulator_type).bind(insulator_count)
    .bind(earth_wire).bind(aviation).bind(op_status).bind(cond_status).bind(health)
    .bind(last_insp).bind(next_insp).bind(notes).bind(user.id)
    .fetch_one(&db).await;

    match result {
        Ok(_id) => {
            // Redirect to the parent line's detail page if we have the line_id
            let redirect_url = if let Some(lid) = line_id {
                format!("/eam/transmission/{}", lid)
            } else {
                "/eam/transmission".to_string()
            };
            axum::response::Redirect::to(&redirect_url).into_response()
        }
        Err(e) => {
            let msg = format!("{}", e);
            let user_msg = if msg.contains("duplicate key") {
                "A tower with this code already exists.".to_string()
            } else {
                format!("Error creating tower: {}", html_escape(&msg))
            };
            (axum::http::StatusCode::BAD_REQUEST, Html(format!(
                r#"<!DOCTYPE html><html><head><title>Error</title><link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head><body class="min-h-screen bg-base-200 flex items-center justify-center"><div class="card bg-base-100 shadow-xl p-8 max-w-md"><div class="text-error text-lg font-bold mb-2">Error</div><p>{user_msg}</p><a href="/eam/transmission/towers/new" class="btn btn-primary mt-4">Go Back</a></div></body></html>"#
            ))).into_response()
        }
    }
}

async fn eam_condition_monitoring(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    // Condition monitoring tables linked via asset_id to eam_assets
    let dga_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_dga_analyses d JOIN eam_assets a ON d.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let oil_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_oil_quality_tests o JOIN eam_assets a ON o.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let thermal: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_thermal_imaging t JOIN eam_assets a ON t.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let pd_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_partial_discharge_tests p JOIN eam_assets a ON p.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let ir_tests: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_insulation_resistance_tests i JOIN eam_assets a ON i.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true").bind(company_id).fetch_one(&db).await.unwrap_or(0);
    let critical: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM eam_dga_analyses d JOIN eam_assets a ON d.asset_id = a.id WHERE a.company_id = $1 AND a.is_active = true AND d.status = 'critical'").bind(company_id).fetch_one(&db).await.unwrap_or(0);

    let content = r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z"/></svg><h3 class="text-lg font-semibold mb-2">No DGA Results Yet</h3><p class="text-base-content/60">Record dissolved gas analysis results to monitor transformer health</p></div>"#;

    let critical_class = if critical > 0 { "bg-error/10" } else { "" };
    let critical_text = if critical > 0 { "text-error" } else { "" };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_condition", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Condition Monitoring - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Condition Monitoring</li></ul></div>
<h1 class="text-2xl font-bold">Condition Monitoring</h1><p class="text-base-content/60">Equipment health and diagnostic tests</p></div>
<div class="dropdown dropdown-end"><label tabindex="0" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Test</label>
<ul tabindex="0" class="dropdown-content z-[1] menu p-2 shadow bg-base-100 rounded-box w-52">
<li><a href="/eam/condition/dga/new">DGA Analysis</a></li>
<li><a href="/eam/condition/oil-quality/new">Oil Quality Test</a></li>
<li><a href="/eam/condition/thermal/new">Thermal Imaging</a></li>
<li><a href="/eam/condition/pd/new">Partial Discharge</a></li>
<li><a href="/eam/condition/ir/new">Insulation Resistance</a></li>
</ul></div></div>
<div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">DGA Tests</div><div class="stat-value text-2xl">{dga_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Oil Quality</div><div class="stat-value text-2xl">{oil_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">Thermal Scans</div><div class="stat-value text-2xl">{thermal}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">PD Tests</div><div class="stat-value text-2xl">{pd_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4"><div class="stat-title text-xs">IR Tests</div><div class="stat-value text-2xl">{ir_tests}</div></div>
<div class="stat bg-base-100 rounded-lg shadow p-4 {critical_class}"><div class="stat-title text-xs">Critical Alerts</div><div class="stat-value text-2xl {critical_text}">{critical}</div></div>
</div>
<div class="card bg-base-100 shadow"><div class="card-header p-4 border-b border-base-300"><h2 class="card-title text-lg">Dissolved Gas Analysis (DGA) Results</h2><p class="text-sm text-base-content/60">IEEE C57.104 compliant transformer oil analysis</p></div><div class="card-body">{content}</div></div>
<div class="mt-4 p-3 bg-base-100 rounded-lg"><h4 class="font-semibold text-sm mb-2">IEEE C57.104 Status Legend</h4><div class="flex flex-wrap gap-4 text-sm">
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#10B981;color:white;">Normal</span><span>Gas levels within normal limits</span></div>
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#EAB308;color:white;">Caution</span><span>Elevated levels, monitor closely</span></div>
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#F97316;color:white;">Warning</span><span>High levels, plan maintenance</span></div>
<div class="flex items-center gap-2"><span class="badge badge-sm" style="background-color:#EF4444;color:white;">Critical</span><span>Immediate action required</span></div>
</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_manufacturers(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let rows = sqlx::query(
        r#"SELECT m.id, m.code, m.name, m.country_code, m.website, m.is_approved_vendor
           FROM eam_manufacturers m
           WHERE m.company_id = $1 AND m.is_active = true ORDER BY m.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let mut table_rows = String::new();
    for row in &rows {
        let id: uuid::Uuid = row.get("id");
        let code: String = row.get("code");
        let name: String = row.get("name");
        let country: String = row.get::<Option<String>, _>("country_code").unwrap_or_else(|| "-".to_string());
        let website: Option<String> = row.get("website");
        let is_approved: bool = row.get::<Option<bool>, _>("is_approved_vendor").unwrap_or(false);

        let website_cell = website.map(|w| format!(r#"<a href="{w}" target="_blank" class="link link-primary text-sm">{w}</a>"#))
            .unwrap_or_else(|| "-".to_string());
        let status_badge = if is_approved {
            r#"<span class="badge badge-success badge-sm">Approved</span>"#
        } else {
            r#"<span class="badge badge-warning badge-sm">Pending</span>"#
        };

        table_rows.push_str(&format!(
            r#"<tr><td class="font-mono font-semibold">{code}</td><td>{name}</td><td>{country}</td><td>{website_cell}</td><td>{status_badge}</td>
            <td><a href="/eam/manufacturers/{id}" class="btn btn-ghost btn-xs">View</a></td></tr>"#
        ));
    }

    let content = if rows.is_empty() {
        r#"<div class="text-center py-12"><svg class="w-16 h-16 mx-auto text-base-content/30 mb-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4"/></svg><h3 class="text-lg font-semibold mb-2">No Manufacturers Yet</h3><p class="text-base-content/60">Add manufacturers to track equipment suppliers</p></div>"#.to_string()
    } else {
        format!(r#"<div class="overflow-x-auto"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Country</th><th>Website</th><th>Status</th><th>Actions</th></tr></thead><tbody>{table_rows}</tbody></table></div>"#)
    };

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_manufacturers", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Manufacturers - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/><script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="flex justify-between items-center mb-6"><div><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li>Manufacturers</li></ul></div>
<h1 class="text-2xl font-bold">Manufacturers</h1><p class="text-base-content/60">Equipment manufacturers and suppliers</p></div>
<a href="/eam/manufacturers/new" class="btn btn-primary"><svg class="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>New Manufacturer</a></div>
<div class="card bg-base-100 shadow"><div class="card-body">{content}</div></div>
</main></div></body></html>"#)).into_response()
}

async fn eam_site_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Fetch site details
    let site = sqlx::query(
        r#"SELECT id, code, name, short_name, description, address, city, state, postal_code,
                  gps_latitude, gps_longitude, site_type, commissioning_date, ownership, operator,
                  busbar_configuration, feeder_count, status
           FROM eam_sites WHERE id = $1 AND is_active = true"#
    ).bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(site) = site else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Site not found")).into_response();
    };

    let code: String = site.get("code");
    let name: String = site.get("name");
    let description: Option<String> = site.get("description");
    let address: Option<String> = site.get("address");
    let city: Option<String> = site.get("city");
    let state_name: Option<String> = site.get("state");
    let site_type: Option<String> = site.get("site_type");
    let ownership: Option<String> = site.get("ownership");
    let operator: Option<String> = site.get("operator");
    let busbar_config: Option<String> = site.get("busbar_configuration");
    let feeder_count: Option<i32> = site.get("feeder_count");
    let status: Option<String> = site.get("status");
    let gps_lat: Option<f64> = site.get("gps_latitude");
    let gps_lon: Option<f64> = site.get("gps_longitude");

    // Fetch functional locations for this site
    let locations = sqlx::query(
        r#"SELECT fl.id, fl.code, fl.name, ut.name as unit_type, vl.name as voltage_level
           FROM eam_functional_locations fl
           LEFT JOIN eam_unit_types ut ON fl.unit_type_id = ut.id
           LEFT JOIN eam_voltage_levels vl ON fl.voltage_level_id = vl.id
           WHERE fl.site_id = $1 AND fl.is_active = true
           ORDER BY fl.display_order, fl.code"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut location_rows = String::new();
    for loc in &locations {
        let loc_code: String = loc.get("code");
        let loc_name: String = loc.get("name");
        let unit_type: Option<String> = loc.get("unit_type");
        let voltage: Option<String> = loc.get("voltage_level");
        location_rows.push_str(&format!(r#"<tr>
            <td class="font-mono">{}</td><td>{}</td><td>{}</td><td>{}</td>
        </tr>"#, loc_code, loc_name, unit_type.unwrap_or("-".into()), voltage.unwrap_or("-".into())));
    }

    // Fetch assets count for this site
    let asset_count: i64 = sqlx::query_scalar(
        r#"SELECT COUNT(*) FROM eam_assets a
           JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           WHERE fl.site_id = $1 AND a.is_active = true"#
    ).bind(id).fetch_one(&db).await.unwrap_or(0);

    // Fetch activity stream (chatter messages)
    let activities = sqlx::query(
        r#"SELECT m.id, m.body, m.message_type, m.created_at, u.username as author_name
           FROM chatter_messages m
           LEFT JOIN users u ON m.author_id = u.id
           WHERE m.res_model = 'eam_sites' AND m.res_id = $1 AND m.active = true
           ORDER BY m.created_at DESC LIMIT 20"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut activity_html = String::new();
    if activities.is_empty() {
        activity_html = r#"<div class="text-center py-8 text-base-content/60"><p>No activities yet</p><p class="text-sm">Add a note to start the activity stream</p></div>"#.to_string();
    } else {
        for activity in &activities {
            let body: String = activity.get("body");
            let msg_type: String = activity.get("message_type");
            let author: Option<String> = activity.get("author_name");
            let created: chrono::DateTime<chrono::Utc> = activity.get("created_at");
            let icon = match msg_type.as_str() {
                "system" => r#"<svg class="w-5 h-5 text-info" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>"#,
                "notification" => r#"<svg class="w-5 h-5 text-warning" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9"/></svg>"#,
                _ => r#"<svg class="w-5 h-5 text-base-content/60" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z"/></svg>"#,
            };
            activity_html.push_str(&format!(r#"<div class="flex gap-3 p-3 rounded-lg bg-base-200">
                <div class="flex-shrink-0 mt-1">{}</div>
                <div class="flex-1">
                    <div class="flex justify-between items-start">
                        <span class="font-semibold text-sm">{}</span>
                        <span class="text-xs text-base-content/60">{}</span>
                    </div>
                    <div class="mt-1 text-sm">{}</div>
                </div>
            </div>"#, icon, author.unwrap_or("System".into()), created.format("%d/%m/%Y %H:%M"), body));
        }
    }

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_sites", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    let location = format!("{}, {}", city.as_deref().unwrap_or("-"), state_name.as_deref().unwrap_or("-"));
    let gps = if let (Some(lat), Some(lon)) = (gps_lat, gps_lon) {
        format!("{:.4}, {:.4}", lat, lon)
    } else { "-".to_string() };

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{name} - Site Details</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/sites">Sites</a></li><li>{code}</li></ul></div>
<div class="flex justify-between items-start">
<div><h1 class="text-2xl font-bold">{name}</h1><p class="text-base-content/60">{}</p></div>
<div class="flex items-center gap-2">
<span class="badge badge-lg badge-outline">{}</span>
<a href="/eam/sites/{id}/edit" class="btn btn-primary btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit</a>
</div></div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
<div class="card bg-base-100 shadow lg:col-span-2"><div class="card-body">
<h2 class="card-title">Site Information</h2>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
<div><span class="text-base-content/60 text-sm">Code</span><p class="font-mono font-semibold">{code}</p></div>
<div><span class="text-base-content/60 text-sm">Type</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Location</span><p>{location}</p></div>
<div><span class="text-base-content/60 text-sm">GPS Coordinates</span><p class="font-mono">{gps}</p></div>
<div><span class="text-base-content/60 text-sm">Ownership</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Operator</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Busbar Configuration</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Feeder Count</span><p>{}</p></div>
</div>
{}</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Statistics</h2>
<div class="stats stats-vertical shadow mt-4">
<div class="stat"><div class="stat-title">Functional Locations</div><div class="stat-value text-primary">{}</div></div>
<div class="stat"><div class="stat-title">Total Assets</div><div class="stat-value text-secondary">{asset_count}</div></div>
</div></div></div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Functional Locations</h2>
<div class="overflow-x-auto mt-4"><table class="table table-zebra"><thead><tr><th>Code</th><th>Name</th><th>Unit Type</th><th>Voltage Level</th></tr></thead>
<tbody>{location_rows}</tbody></table></div></div></div>

<div class="card bg-base-100 shadow mt-6"><div class="card-body">
<div class="flex justify-between items-center">
<h2 class="card-title">Activity Stream</h2>
<div class="flex gap-2">
<button onclick="document.getElementById('activity_form').classList.toggle('hidden')" class="btn btn-sm btn-ghost">
<svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Add Note</button>
</div></div>
<form id="activity_form" class="hidden mt-4 p-4 bg-base-200 rounded-lg" hx-post="/api/chatter/eam_sites/{id}/messages" hx-swap="none" hx-on::after-request="this.reset(); location.reload();">
<textarea name="body" class="textarea textarea-bordered w-full" rows="3" placeholder="Add a note or comment..."></textarea>
<div class="flex justify-end gap-2 mt-2">
<button type="button" onclick="document.getElementById('activity_form').classList.add('hidden')" class="btn btn-sm btn-ghost">Cancel</button>
<button type="submit" class="btn btn-sm btn-primary">Post</button>
</div></form>
<div class="mt-4 space-y-4" id="activity_stream">{activity_html}</div>
</div></div>
</main></div></body></html>"#,
        description.as_deref().unwrap_or("Distribution Substation"),
        status.as_deref().unwrap_or("Active"),
        site_type.as_deref().unwrap_or("-"),
        ownership.as_deref().unwrap_or("-"),
        operator.as_deref().unwrap_or("-"),
        busbar_config.as_deref().unwrap_or("-"),
        feeder_count.map(|f| f.to_string()).unwrap_or("-".into()),
        if let Some(addr) = address { format!(r#"<div class="col-span-2 mt-2"><span class="text-base-content/60 text-sm">Address</span><p>{}</p></div>"#, addr) } else { String::new() },
        locations.len(),
    )).into_response()
}

async fn eam_asset_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    // Fetch asset details
    let asset = sqlx::query(
        r#"SELECT a.id, a.asset_code, a.name, a.tag_number, a.description, a.manufacturer, a.model,
                  a.serial_number, a.year_manufactured, a.commissioning_date, a.criticality_rating,
                  a.operational_status, a.condition_score, a.last_maintenance_date, a.next_maintenance_date,
                  c.name as category_name, st.name as status_name, st.color as status_color,
                  fl.name as location_name, fl.code as location_code,
                  s.name as site_name, s.code as site_code, s.id as site_id,
                  vl.name as voltage_level
           FROM eam_assets a
           LEFT JOIN eam_asset_categories c ON a.category_id = c.id
           LEFT JOIN eam_asset_statuses st ON a.status_id = st.id
           LEFT JOIN eam_functional_locations fl ON a.functional_location_id = fl.id
           LEFT JOIN eam_sites s ON fl.site_id = s.id
           LEFT JOIN eam_voltage_levels vl ON a.voltage_level_id = vl.id
           WHERE a.id = $1 AND a.is_active = true"#
    ).bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(asset) = asset else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Asset not found")).into_response();
    };

    // Fetch activity stream (chatter messages)
    let activities = sqlx::query(
        r#"SELECT m.id, m.body, m.message_type, m.created_at, u.username as author_name
           FROM chatter_messages m
           LEFT JOIN users u ON m.author_id = u.id
           WHERE m.res_model = 'eam_assets' AND m.res_id = $1 AND m.active = true
           ORDER BY m.created_at DESC LIMIT 20"#
    ).bind(id).fetch_all(&db).await.unwrap_or_default();

    let mut activity_html = String::new();
    for act in &activities {
        let body: String = act.get("body");
        let msg_type: String = act.get("message_type");
        let author: Option<String> = act.get("author_name");
        let created: chrono::DateTime<chrono::Utc> = act.get("created_at");
        let icon = match msg_type.as_str() {
            "note" => r#"<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z"/></svg>"#,
            "system" => r#"<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/></svg>"#,
            _ => r#"<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M8 10h.01M12 10h.01M16 10h.01M9 16H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-5l-5 5v-5z"/></svg>"#,
        };
        activity_html.push_str(&format!(
            r#"<div class="flex gap-3 p-3 bg-base-200 rounded-lg"><div class="text-primary">{}</div><div class="flex-1"><div class="flex justify-between text-sm"><span class="font-semibold">{}</span><span class="text-base-content/60">{}</span></div><p class="mt-1">{}</p></div></div>"#,
            icon, author.as_deref().unwrap_or("System"), created.format("%d/%m/%Y %H:%M"), body
        ));
    }
    if activity_html.is_empty() {
        activity_html = r#"<p class="text-base-content/60 text-center py-4">No activity yet</p>"#.to_string();
    }

    let asset_code: String = asset.get("asset_code");
    let name: String = asset.get("name");
    let tag_number: Option<String> = asset.get("tag_number");
    let description: Option<String> = asset.get("description");
    let manufacturer: Option<String> = asset.get("manufacturer");
    let model: Option<String> = asset.get("model");
    let serial_number: Option<String> = asset.get("serial_number");
    let year_manufactured: Option<i32> = asset.get("year_manufactured");
    let criticality: Option<i32> = asset.get("criticality_rating");
    let category: Option<String> = asset.get("category_name");
    let status: Option<String> = asset.get("status_name");
    let status_color: Option<String> = asset.get("status_color");
    let location_name: Option<String> = asset.get("location_name");
    let site_name: Option<String> = asset.get("site_name");
    let site_id: Option<uuid::Uuid> = asset.get("site_id");
    let voltage: Option<String> = asset.get("voltage_level");

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_assets", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);
    let criticality_badge = match criticality {
        Some(5) => r#"<span class="badge badge-error">Critical (5)</span>"#,
        Some(4) => r#"<span class="badge badge-warning">High (4)</span>"#,
        Some(3) => r#"<span class="badge badge-info">Medium (3)</span>"#,
        Some(2) => r#"<span class="badge badge-success">Low (2)</span>"#,
        Some(1) => r#"<span class="badge badge-ghost">Minimal (1)</span>"#,
        _ => "-",
    };

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>{name} - Asset Details</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://unpkg.com/htmx.org@1.9.10"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/assets">Assets</a></li><li>{asset_code}</li></ul></div>
<div class="flex justify-between items-start">
<div><h1 class="text-2xl font-bold">{name}</h1><p class="text-base-content/60">{} - {}</p></div>
<div class="flex items-center gap-2">
<span class="badge badge-lg" style="background-color:{};color:white">{}</span>
<a href="/eam/assets/{id}/edit" class="btn btn-primary btn-sm"><svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z"/></svg>Edit</a>
</div></div></div>

<div class="grid grid-cols-1 lg:grid-cols-3 gap-6 mb-6">
<div class="card bg-base-100 shadow lg:col-span-2"><div class="card-body">
<h2 class="card-title">Asset Information</h2>
<div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-4">
<div><span class="text-base-content/60 text-sm">Asset Code</span><p class="font-mono font-semibold">{asset_code}</p></div>
<div><span class="text-base-content/60 text-sm">Tag Number</span><p class="font-mono">{}</p></div>
<div><span class="text-base-content/60 text-sm">Category</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Voltage Level</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Criticality</span><p>{criticality_badge}</p></div>
<div><span class="text-base-content/60 text-sm">Year Manufactured</span><p>{}</p></div>
</div>
{}</div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<h2 class="card-title">Location</h2>
<div class="mt-4 space-y-4">
<div><span class="text-base-content/60 text-sm">Site</span><p><a href="/eam/sites/{}" class="link link-primary">{}</a></p></div>
<div><span class="text-base-content/60 text-sm">Functional Location</span><p>{}</p></div>
</div></div></div></div>

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
<h2 class="card-title">Manufacturer Details</h2>
<div class="grid grid-cols-1 sm:grid-cols-3 gap-4 mt-4">
<div><span class="text-base-content/60 text-sm">Manufacturer</span><p class="font-semibold">{}</p></div>
<div><span class="text-base-content/60 text-sm">Model</span><p>{}</p></div>
<div><span class="text-base-content/60 text-sm">Serial Number</span><p class="font-mono">{}</p></div>
</div></div></div>

<div class="card bg-base-100 shadow"><div class="card-body">
<div class="flex justify-between items-center">
<h2 class="card-title">Activity Stream</h2>
<button onclick="document.getElementById('asset_activity_form').classList.toggle('hidden')" class="btn btn-sm btn-ghost">
<svg class="w-4 h-4 mr-1" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/></svg>Add Note</button>
</div>
<form id="asset_activity_form" class="hidden mt-4 p-4 bg-base-200 rounded-lg" hx-post="/api/chatter/eam_assets/{id}/messages" hx-target="[id=asset_activity_stream]" hx-swap="afterbegin">
<textarea name="body" rows="3" class="textarea textarea-bordered w-full" placeholder="Add a note..."></textarea>
<input type="hidden" name="message_type" value="note"/>
<div class="mt-2 flex justify-end gap-2">
<button type="button" onclick="this.closest('form').classList.add('hidden')" class="btn btn-sm btn-ghost">Cancel</button>
<button type="submit" class="btn btn-sm btn-primary">Post Note</button>
</div></form>
<div class="mt-4 space-y-4" id="asset_activity_stream">{}</div>
</div></div>
</main></div></body></html>"#,
        category.as_deref().unwrap_or("-"),
        location_name.as_deref().unwrap_or("-"),
        status_color.as_deref().unwrap_or("#6C757D"),
        status.as_deref().unwrap_or("Unknown"),
        tag_number.as_deref().unwrap_or("-"),
        category.as_deref().unwrap_or("-"),
        voltage.as_deref().unwrap_or("-"),
        year_manufactured.map(|y| y.to_string()).unwrap_or("-".into()),
        if let Some(desc) = description { format!(r#"<div class="col-span-2 mt-2"><span class="text-base-content/60 text-sm">Description</span><p>{}</p></div>"#, desc) } else { String::new() },
        site_id.map(|s| s.to_string()).unwrap_or_default(),
        site_name.as_deref().unwrap_or("-"),
        location_name.as_deref().unwrap_or("-"),
        manufacturer.as_deref().unwrap_or("-"),
        model.as_deref().unwrap_or("-"),
        serial_number.as_deref().unwrap_or("-"),
        activity_html,
    )).into_response()
}

// Site Create/Edit Forms
async fn eam_site_form(
    State(state): State<Arc<AppState>>,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);
    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_sites", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Site - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/sites">Sites</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">Create New Site</h1></div>
<form method="POST" action="/eam/sites" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Code *</span></label><input type="text" name="code" required class="input input-bordered" placeholder="PPU-XXX-001"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" placeholder="PPU Ampang"/></div>
<div class="form-control"><label class="label"><span class="label-text">Short Name</span></label><input type="text" name="short_name" class="input input-bordered" placeholder="Ampang"/></div>
<div class="form-control"><label class="label"><span class="label-text">Site Type</span></label>
<select name="site_type" class="select select-bordered"><option value="">Select Type</option><option value="Indoor GIS">Indoor GIS</option><option value="Outdoor AIS">Outdoor AIS</option><option value="Hybrid">Hybrid</option></select></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Address</span></label><input type="text" name="address" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">City</span></label><input type="text" name="city" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">State</span></label><input type="text" name="state" class="input input-bordered" value="Selangor"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Latitude</span></label><input type="text" name="gps_latitude" class="input input-bordered" placeholder="3.1234"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Longitude</span></label><input type="text" name="gps_longitude" class="input input-bordered" placeholder="101.5678"/></div>
<div class="form-control"><label class="label"><span class="label-text">Ownership</span></label><input type="text" name="ownership" class="input input-bordered" value="TNB Distribution"/></div>
<div class="form-control"><label class="label"><span class="label-text">Operator</span></label><input type="text" name="operator" class="input input-bordered" value="TNB Distribution Sdn Bhd"/></div>
<div class="form-control"><label class="label"><span class="label-text">Busbar Configuration</span></label>
<select name="busbar_configuration" class="select select-bordered"><option value="">Select</option><option>Single Bus</option><option>Double Bus</option><option>Ring Bus</option><option>Breaker and a Half</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Feeder Count</span></label><input type="number" name="feeder_count" class="input input-bordered"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3"></textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/sites" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create Site</button></div>
</div></form>
</main></div></body></html>"#)).into_response()
}

async fn eam_site_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let short_name = form.get("short_name").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let site_type = form.get("site_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let address = form.get("address").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let city = form.get("city").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let state_val = form.get("state").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let gps_lat: Option<f64> = form.get("gps_latitude").and_then(|s| s.parse().ok());
    let gps_lon: Option<f64> = form.get("gps_longitude").and_then(|s| s.parse().ok());
    let ownership = form.get("ownership").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let operator = form.get("operator").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let busbar = form.get("busbar_configuration").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let feeder_count: Option<i32> = form.get("feeder_count").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"INSERT INTO eam_sites (company_id, code, name, short_name, site_type, address, city, state,
           gps_latitude, gps_longitude, ownership, operator, busbar_configuration, feeder_count, description,
           status, is_active, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, 'Active', true, $16)
           RETURNING id"#
    )
    .bind(company_id).bind(code).bind(name).bind(short_name).bind(site_type)
    .bind(address).bind(city).bind(state_val).bind(gps_lat).bind(gps_lon)
    .bind(ownership).bind(operator).bind(busbar).bind(feeder_count).bind(description)
    .bind(user.id)
    .fetch_one(&db).await;

    match result {
        Ok(id) => axum::response::Redirect::to(&format!("/eam/sites/{}", id)).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Html(format!("Error: {}", e))).into_response(),
    }
}

async fn eam_site_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let site = sqlx::query(
        "SELECT * FROM eam_sites WHERE id = $1 AND is_active = true"
    ).bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(site) = site else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Site not found")).into_response();
    };

    let code: String = site.get("code");
    let name: String = site.get("name");
    let short_name: Option<String> = site.get("short_name");
    let site_type: Option<String> = site.get("site_type");
    let address: Option<String> = site.get("address");
    let city: Option<String> = site.get("city");
    let state_val: Option<String> = site.get("state");
    let gps_lat: Option<f64> = site.get("gps_latitude");
    let gps_lon: Option<f64> = site.get("gps_longitude");
    let ownership: Option<String> = site.get("ownership");
    let operator: Option<String> = site.get("operator");
    let busbar: Option<String> = site.get("busbar_configuration");
    let feeder_count: Option<i32> = site.get("feeder_count");
    let description: Option<String> = site.get("description");

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_sites", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Edit {name} - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/sites">Sites</a></li><li><a href="/eam/sites/{id}">{code}</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Site</h1></div>
<form method="POST" action="/eam/sites/{id}" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Code *</span></label><input type="text" name="code" required class="input input-bordered" value="{code}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" value="{name}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Short Name</span></label><input type="text" name="short_name" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Site Type</span></label>
<select name="site_type" class="select select-bordered"><option value="">Select Type</option>
<option value="Indoor GIS" {}>Indoor GIS</option><option value="Outdoor AIS" {}>Outdoor AIS</option><option value="Hybrid" {}>Hybrid</option></select></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Address</span></label><input type="text" name="address" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">City</span></label><input type="text" name="city" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">State</span></label><input type="text" name="state" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Latitude</span></label><input type="text" name="gps_latitude" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">GPS Longitude</span></label><input type="text" name="gps_longitude" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Ownership</span></label><input type="text" name="ownership" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Operator</span></label><input type="text" name="operator" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Busbar Configuration</span></label>
<select name="busbar_configuration" class="select select-bordered"><option value="">Select</option>
<option {}>Single Bus</option><option {}>Double Bus</option><option {}>Ring Bus</option><option {}>Breaker and a Half</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Feeder Count</span></label><input type="number" name="feeder_count" class="input input-bordered" value="{}"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3">{}</textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/sites/{id}" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Save Changes</button></div>
</div></form>
</main></div></body></html>"#,
        short_name.as_deref().unwrap_or(""),
        if site_type.as_deref() == Some("Indoor GIS") { "selected" } else { "" },
        if site_type.as_deref() == Some("Outdoor AIS") { "selected" } else { "" },
        if site_type.as_deref() == Some("Hybrid") { "selected" } else { "" },
        address.as_deref().unwrap_or(""),
        city.as_deref().unwrap_or(""),
        state_val.as_deref().unwrap_or(""),
        gps_lat.map(|v| v.to_string()).unwrap_or_default(),
        gps_lon.map(|v| v.to_string()).unwrap_or_default(),
        ownership.as_deref().unwrap_or(""),
        operator.as_deref().unwrap_or(""),
        if busbar.as_deref() == Some("Single Bus") { "selected" } else { "" },
        if busbar.as_deref() == Some("Double Bus") { "selected" } else { "" },
        if busbar.as_deref() == Some("Ring Bus") { "selected" } else { "" },
        if busbar.as_deref() == Some("Breaker and a Half") { "selected" } else { "" },
        feeder_count.map(|v| v.to_string()).unwrap_or_default(),
        description.as_deref().unwrap_or(""),
    )).into_response()
}

async fn eam_site_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let code = form.get("code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let short_name = form.get("short_name").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let site_type = form.get("site_type").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let address = form.get("address").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let city = form.get("city").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let state_val = form.get("state").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let gps_lat: Option<f64> = form.get("gps_latitude").and_then(|s| s.parse().ok());
    let gps_lon: Option<f64> = form.get("gps_longitude").and_then(|s| s.parse().ok());
    let ownership = form.get("ownership").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let operator = form.get("operator").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let busbar = form.get("busbar_configuration").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let feeder_count: Option<i32> = form.get("feeder_count").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let _ = sqlx::query(
        r#"UPDATE eam_sites SET code=$1, name=$2, short_name=$3, site_type=$4, address=$5, city=$6, state=$7,
           gps_latitude=$8, gps_longitude=$9, ownership=$10, operator=$11, busbar_configuration=$12,
           feeder_count=$13, description=$14, updated_by=$15, updated_at=NOW()
           WHERE id=$16"#
    )
    .bind(code).bind(name).bind(short_name).bind(site_type)
    .bind(address).bind(city).bind(state_val).bind(gps_lat).bind(gps_lon)
    .bind(ownership).bind(operator).bind(busbar).bind(feeder_count).bind(description)
    .bind(user.id).bind(id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/sites/{}", id)).into_response()
}

// Asset Create/Edit Forms
async fn eam_asset_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let categories: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_categories WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let statuses: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true ORDER BY display_order"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let locations: Vec<(String, String, String)> = sqlx::query_as(
        r#"SELECT fl.id::text, fl.name, s.name as site_name FROM eam_functional_locations fl
           JOIN eam_sites s ON fl.site_id = s.id
           WHERE fl.company_id = $1 AND fl.is_active = true ORDER BY s.name, fl.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let voltages: Vec<(String, String)> = sqlx::query_as(
        "SELECT id::text, name FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let cat_opts: String = categories.iter().map(|(id, name)| format!(r#"<option value="{}">{}</option>"#, id, name)).collect();
    let status_opts: String = statuses.iter().map(|(id, name)| format!(r#"<option value="{}">{}</option>"#, id, name)).collect();
    let loc_opts: String = locations.iter().map(|(id, name, site)| format!(r#"<option value="{}">{} - {}</option>"#, id, site, name)).collect();
    let volt_opts: String = voltages.iter().map(|(id, name)| format!(r#"<option value="{}">{}</option>"#, id, name)).collect();

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_assets", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>New Asset - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/assets">Assets</a></li><li>New</li></ul></div>
<h1 class="text-2xl font-bold">Create New Asset</h1></div>
<form method="POST" action="/eam/assets" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Asset Code *</span></label><input type="text" name="asset_code" required class="input input-bordered" placeholder="TX-XXX-001"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Functional Location *</span></label>
<select name="functional_location_id" required class="select select-bordered"><option value="">Select Location</option>{loc_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Category *</span></label>
<select name="category_id" required class="select select-bordered"><option value="">Select Category</option>{cat_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Status *</span></label>
<select name="status_id" required class="select select-bordered"><option value="">Select Status</option>{status_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered"><option value="">Select Voltage</option>{volt_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Tag Number</span></label><input type="text" name="tag_number" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Criticality (1-5)</span></label>
<select name="criticality_rating" class="select select-bordered"><option value="">Select</option>
<option value="1">1 - Minimal</option><option value="2">2 - Low</option><option value="3">3 - Medium</option><option value="4">4 - High</option><option value="5">5 - Critical</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Manufacturer</span></label><input type="text" name="manufacturer" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Model</span></label><input type="text" name="model" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Serial Number</span></label><input type="text" name="serial_number" class="input input-bordered"/></div>
<div class="form-control"><label class="label"><span class="label-text">Year Manufactured</span></label><input type="number" name="year_manufactured" class="input input-bordered" min="1950" max="2030"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3"></textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/assets" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Create Asset</button></div>
</div></form>
</main></div></body></html>"#)).into_response()
}

async fn eam_asset_create(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset_code = form.get("asset_code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let fl_id: Option<uuid::Uuid> = form.get("functional_location_id").and_then(|s| s.parse().ok());
    let cat_id: Option<uuid::Uuid> = form.get("category_id").and_then(|s| s.parse().ok());
    let status_id: Option<uuid::Uuid> = form.get("status_id").and_then(|s| s.parse().ok());
    let voltage_id: Option<uuid::Uuid> = form.get("voltage_level_id").and_then(|s| s.parse().ok());
    let tag_number = form.get("tag_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let criticality: Option<i32> = form.get("criticality_rating").and_then(|s| s.parse().ok());
    let manufacturer = form.get("manufacturer").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let model = form.get("model").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let serial = form.get("serial_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let year: Option<i32> = form.get("year_manufactured").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let result = sqlx::query_scalar::<_, uuid::Uuid>(
        r#"INSERT INTO eam_assets (company_id, asset_code, name, functional_location_id, category_id, status_id,
           voltage_level_id, tag_number, criticality_rating, manufacturer, model, serial_number, year_manufactured,
           description, is_active, created_by)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true, $15)
           RETURNING id"#
    )
    .bind(company_id).bind(asset_code).bind(name).bind(fl_id).bind(cat_id).bind(status_id)
    .bind(voltage_id).bind(tag_number).bind(criticality).bind(manufacturer).bind(model)
    .bind(serial).bind(year).bind(description).bind(user.id)
    .fetch_one(&db).await;

    match result {
        Ok(id) => axum::response::Redirect::to(&format!("/eam/assets/{}", id)).into_response(),
        Err(e) => (axum::http::StatusCode::BAD_REQUEST, Html(format!("Error: {}", e))).into_response(),
    }
}

async fn eam_asset_edit(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<uuid::Uuid>,
) -> Response {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = get_initials(display_name);

    let company_id: uuid::Uuid = sqlx::query_scalar("SELECT company_id FROM users WHERE id = $1")
        .bind(user.id).fetch_one(&db).await.unwrap_or_default();

    let asset = sqlx::query("SELECT * FROM eam_assets WHERE id = $1 AND is_active = true")
        .bind(id).fetch_optional(&db).await.ok().flatten();

    let Some(asset) = asset else {
        return (axum::http::StatusCode::NOT_FOUND, Html("Asset not found")).into_response();
    };

    let asset_code: String = asset.get("asset_code");
    let name: String = asset.get("name");
    let fl_id: Option<uuid::Uuid> = asset.get("functional_location_id");
    let cat_id: Option<uuid::Uuid> = asset.get("category_id");
    let status_id: Option<uuid::Uuid> = asset.get("status_id");
    let voltage_id: Option<uuid::Uuid> = asset.get("voltage_level_id");
    let tag_number: Option<String> = asset.get("tag_number");
    let criticality: Option<i32> = asset.get("criticality_rating");
    let manufacturer: Option<String> = asset.get("manufacturer");
    let model: Option<String> = asset.get("model");
    let serial: Option<String> = asset.get("serial_number");
    let year: Option<i32> = asset.get("year_manufactured");
    let description: Option<String> = asset.get("description");

    let categories: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM eam_asset_categories WHERE company_id = $1 AND is_active = true ORDER BY name"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let statuses: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM eam_asset_statuses WHERE company_id = $1 AND is_active = true ORDER BY display_order"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let locations: Vec<(uuid::Uuid, String, String)> = sqlx::query_as(
        r#"SELECT fl.id, fl.name, s.name as site_name FROM eam_functional_locations fl
           JOIN eam_sites s ON fl.site_id = s.id
           WHERE fl.company_id = $1 AND fl.is_active = true ORDER BY s.name, fl.name"#
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let voltages: Vec<(uuid::Uuid, String)> = sqlx::query_as(
        "SELECT id, name FROM eam_voltage_levels WHERE company_id = $1 AND is_active = true ORDER BY voltage_value DESC"
    ).bind(company_id).fetch_all(&db).await.unwrap_or_default();

    let cat_opts: String = categories.iter().map(|(cid, cname)|
        format!(r#"<option value="{}" {}>{}</option>"#, cid, if cat_id == Some(*cid) { "selected" } else { "" }, cname)).collect();
    let status_opts: String = statuses.iter().map(|(sid, sname)|
        format!(r#"<option value="{}" {}>{}</option>"#, sid, if status_id == Some(*sid) { "selected" } else { "" }, sname)).collect();
    let loc_opts: String = locations.iter().map(|(lid, lname, site)|
        format!(r#"<option value="{}" {}>{} - {}</option>"#, lid, if fl_id == Some(*lid) { "selected" } else { "" }, site, lname)).collect();
    let volt_opts: String = voltages.iter().map(|(vid, vname)|
        format!(r#"<option value="{}" {}>{}</option>"#, vid, if voltage_id == Some(*vid) { "selected" } else { "" }, vname)).collect();

    let installed = db_ctx.installed_modules.clone();
    let sidebar = build_sidebar("eam_assets", display_name, &initials, &installed, user.is_admin(), &state.plugin_registry, &user.roles);

    Html(format!(r#"<!DOCTYPE html><html data-theme="dark"><head><script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script><style>[data-theme="corporate"] .theme-icon-sun{{display:none !important}}[data-theme="corporate"] .theme-icon-moon{{display:inline-block !important}}</style><title>Edit {name} - Asset Management</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="https://cdn.jsdelivr.net/npm/daisyui@4.7.2/dist/full.min.css" rel="stylesheet"/>
<script src="https://cdn.tailwindcss.com"></script></head>
<body class="min-h-screen bg-base-200">
<div class="sticky top-0 z-30 flex items-center bg-base-100 px-4 py-2 shadow lg:hidden"><button onclick="document.getElementById('sidebar').classList.toggle('-translate-x-full');document.getElementById('sidebar-overlay').classList.toggle('hidden')" class="btn btn-ghost btn-sm btn-square"><svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M4 6h16M4 12h16M4 18h16"/></svg></button><a href="/home" class="ml-2 text-lg font-bold"><span class="text-success">re</span><span class="opacity-60">micle</span></a><button onclick="(function(){{var h=document.documentElement,c=h.getAttribute('data-theme')==='dark'?'corporate':'dark';h.setAttribute('data-theme',c);localStorage.setItem('theme',c);document.querySelectorAll('.theme-icon-sun,.theme-icon-moon').forEach(function(e){{e.classList.toggle('hidden')}})}})();" class="btn btn-ghost btn-sm btn-square ml-auto"><svg class="theme-icon-sun w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24"><circle cx="12" cy="12" r="5" stroke-width="2"/><path stroke-linecap="round" stroke-width="2" d="M12 1v2m0 18v2M4.22 4.22l1.42 1.42m12.72 12.72l1.42 1.42M1 12h2m18 0h2M4.22 19.78l1.42-1.42M18.36 5.64l1.42-1.42"/></svg><svg class="theme-icon-moon w-5 h-5 hidden" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/></svg></button></div>
<div id="sidebar-overlay" class="fixed inset-0 z-30 bg-black/50 hidden lg:hidden" onclick="document.getElementById('sidebar').classList.add('-translate-x-full');this.classList.add('hidden')"></div>
<div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">
<div class="mb-6"><div class="breadcrumbs text-sm"><ul><li><a href="/eam">Asset Management</a></li><li><a href="/eam/assets">Assets</a></li><li><a href="/eam/assets/{id}">{asset_code}</a></li><li>Edit</li></ul></div>
<h1 class="text-2xl font-bold">Edit Asset</h1></div>
<form method="POST" action="/eam/assets/{id}" class="card bg-base-100 shadow"><div class="card-body">
<div class="grid grid-cols-1 md:grid-cols-2 gap-4">
<div class="form-control"><label class="label"><span class="label-text">Asset Code *</span></label><input type="text" name="asset_code" required class="input input-bordered" value="{asset_code}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Name *</span></label><input type="text" name="name" required class="input input-bordered" value="{name}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Functional Location *</span></label>
<select name="functional_location_id" required class="select select-bordered"><option value="">Select Location</option>{loc_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Category *</span></label>
<select name="category_id" required class="select select-bordered"><option value="">Select Category</option>{cat_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Status *</span></label>
<select name="status_id" required class="select select-bordered"><option value="">Select Status</option>{status_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Voltage Level</span></label>
<select name="voltage_level_id" class="select select-bordered"><option value="">Select Voltage</option>{volt_opts}</select></div>
<div class="form-control"><label class="label"><span class="label-text">Tag Number</span></label><input type="text" name="tag_number" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Criticality (1-5)</span></label>
<select name="criticality_rating" class="select select-bordered"><option value="">Select</option>
<option value="1" {}>1 - Minimal</option><option value="2" {}>2 - Low</option><option value="3" {}>3 - Medium</option><option value="4" {}>4 - High</option><option value="5" {}>5 - Critical</option></select></div>
<div class="form-control"><label class="label"><span class="label-text">Manufacturer</span></label><input type="text" name="manufacturer" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Model</span></label><input type="text" name="model" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Serial Number</span></label><input type="text" name="serial_number" class="input input-bordered" value="{}"/></div>
<div class="form-control"><label class="label"><span class="label-text">Year Manufactured</span></label><input type="number" name="year_manufactured" class="input input-bordered" value="{}" min="1950" max="2030"/></div>
<div class="form-control md:col-span-2"><label class="label"><span class="label-text">Description</span></label><textarea name="description" class="textarea textarea-bordered" rows="3">{}</textarea></div>
</div>
<div class="card-actions justify-end mt-6"><a href="/eam/assets/{id}" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">Save Changes</button></div>
</div></form>
</main></div></body></html>"#,
        tag_number.as_deref().unwrap_or(""),
        if criticality == Some(1) { "selected" } else { "" },
        if criticality == Some(2) { "selected" } else { "" },
        if criticality == Some(3) { "selected" } else { "" },
        if criticality == Some(4) { "selected" } else { "" },
        if criticality == Some(5) { "selected" } else { "" },
        manufacturer.as_deref().unwrap_or(""),
        model.as_deref().unwrap_or(""),
        serial.as_deref().unwrap_or(""),
        year.map(|y| y.to_string()).unwrap_or_default(),
        description.as_deref().unwrap_or(""),
    )).into_response()
}

async fn eam_asset_update(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(id): Path<uuid::Uuid>,
    axum::extract::Form(form): axum::extract::Form<std::collections::HashMap<String, String>>,
) -> Response {
    let asset_code = form.get("asset_code").map(|s| s.as_str()).unwrap_or("");
    let name = form.get("name").map(|s| s.as_str()).unwrap_or("");
    let fl_id: Option<uuid::Uuid> = form.get("functional_location_id").and_then(|s| s.parse().ok());
    let cat_id: Option<uuid::Uuid> = form.get("category_id").and_then(|s| s.parse().ok());
    let status_id: Option<uuid::Uuid> = form.get("status_id").and_then(|s| s.parse().ok());
    let voltage_id: Option<uuid::Uuid> = form.get("voltage_level_id").and_then(|s| s.parse().ok());
    let tag_number = form.get("tag_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let criticality: Option<i32> = form.get("criticality_rating").and_then(|s| s.parse().ok());
    let manufacturer = form.get("manufacturer").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let model = form.get("model").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let serial = form.get("serial_number").map(|s| s.as_str()).filter(|s| !s.is_empty());
    let year: Option<i32> = form.get("year_manufactured").and_then(|s| s.parse().ok());
    let description = form.get("description").map(|s| s.as_str()).filter(|s| !s.is_empty());

    let _ = sqlx::query(
        r#"UPDATE eam_assets SET asset_code=$1, name=$2, functional_location_id=$3, category_id=$4, status_id=$5,
           voltage_level_id=$6, tag_number=$7, criticality_rating=$8, manufacturer=$9, model=$10, serial_number=$11,
           year_manufactured=$12, description=$13, updated_by=$14, updated_at=NOW()
           WHERE id=$15"#
    )
    .bind(asset_code).bind(name).bind(fl_id).bind(cat_id).bind(status_id)
    .bind(voltage_id).bind(tag_number).bind(criticality).bind(manufacturer).bind(model)
    .bind(serial).bind(year).bind(description).bind(user.id).bind(id)
    .execute(&db).await;

    axum::response::Redirect::to(&format!("/eam/assets/{}", id)).into_response()
}

