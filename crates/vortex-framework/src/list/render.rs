//! HTML rendering for list views — DaisyUI table with search bar,
//! filter dropdowns, sortable headers, and pagination.

use sqlx::Row;
use uuid::Uuid;

use crate::ui::html_escape;

use super::config::{CellRenderer, ListConfig};
use super::params::{ListParams, SortDir};
use super::query::ListResult;

/// Render the complete list view HTML (content area only — the
/// caller wraps it in the page shell with sidebar).
pub fn render_list(
    config: &ListConfig,
    result: &ListResult,
    params: &ListParams,
    base_url: &str,
) -> String {
    let mut html = String::with_capacity(8192);

    // Title bar with create button + column toggle
    html.push_str(&format!(
        r#"<div class="flex items-center justify-between mb-4">
<h1 class="text-2xl font-bold">{title}</h1>
<div class="flex gap-2">"#,
        title = html_escape(config.title),
    ));

    // Column visibility toggle dropdown
    html.push_str(&render_column_toggle(config, base_url));

    if let Some(url) = config.pivot_url {
        html.push_str(&format!(
            r#"<a href="{url}" class="btn btn-ghost btn-sm" title="Pivot View"><svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M3 10h18M3 14h18m-9-4v8m-7 0h14a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z"/></svg></a>"#,
            url = html_escape(url),
        ));
    }

    if let (Some(label), Some(url)) = (config.create_label, config.create_url) {
        html.push_str(&format!(
            r#"<a href="{url}" class="btn btn-primary btn-sm">{label}</a>"#,
            url = html_escape(url),
            label = html_escape(label),
        ));
    }
    html.push_str("</div></div>");

    // Search + filters bar
    html.push_str(&render_search_bar(config, params, base_url));

    // Table
    html.push_str(r#"<div class="card bg-base-100 shadow"><div class="card-body p-0"><div class="overflow-x-auto"><table class="table table-sm">"#);

    // Header — each <th> gets a data-col attribute for column toggle
    html.push_str("<thead><tr>");
    for col in &config.columns {
        let data_col = format!(r#" data-col="{}""#, col.field);
        if col.sortable {
            let is_active = params.sort_field.as_deref() == Some(col.field);
            let next_dir = if is_active {
                params.sort_dir.opposite()
            } else {
                SortDir::Asc
            };
            let indicator = if is_active {
                format!(" {}", params.sort_dir.icon())
            } else {
                String::new()
            };
            let qs = params.to_query_with(&[("sort", col.field), ("dir", next_dir.as_sql().to_lowercase().as_str()), ("page", "1")]);
            html.push_str(&format!(
                r#"<th{data_col}><a href="{base_url}?{qs}" class="link link-hover">{label}{indicator}</a></th>"#,
                data_col = data_col,
                base_url = base_url,
                qs = qs,
                label = html_escape(col.label),
                indicator = indicator,
            ));
        } else {
            html.push_str(&format!(r#"<th{data_col}>{}</th>"#, html_escape(col.label), data_col = data_col));
        }
    }
    html.push_str("</tr></thead>");

    // Body
    html.push_str("<tbody>");
    if result.is_empty() {
        let colspan = config.columns.len();
        html.push_str(&format!(
            r#"<tr><td colspan="{colspan}" class="text-center py-8 text-base-content/50">No records found</td></tr>"#
        ));
    } else {
        // If group_by is active, track the current group value and
        // insert a colored section-header row when it changes.
        let group_field = params.group_by.as_deref().and_then(|g| {
            if config.columns.iter().any(|c| c.field == g) { Some(g) } else { None }
        });
        let group_col = group_field.and_then(|gf|
            config.columns.iter().find(|c| c.field == gf)
        );
        let mut current_group: Option<String> = None;
        let colspan = config.columns.len();

        for row in &result.rows {
            // Group header
            if let (Some(gf), Some(gc)) = (group_field, group_col) {
                let group_val: String = row.try_get(gf).unwrap_or_default();
                let should_show = match &current_group {
                    Some(prev) => prev != &group_val,
                    None => true,
                };
                if should_show {
                    let display = render_cell_value(&group_val, gc);
                    html.push_str(&format!(
                        r#"<tr><td colspan="{colspan}" class="bg-base-200 font-semibold text-sm py-2 px-4">{label}: {display}</td></tr>"#,
                        colspan = colspan,
                        label = html_escape(gc.label),
                        display = display,
                    ));
                    current_group = Some(group_val);
                }
            }

            let row_id: Uuid = row.try_get("id").unwrap_or_default();
            let onclick = config.detail_url.map(|url| {
                let detail = url.replace("{id}", &row_id.to_string());
                format!(r#" onclick="window.location='{}'" class="hover cursor-pointer""#, detail)
            }).unwrap_or_default();

            html.push_str(&format!("<tr{onclick}>"));
            for col in &config.columns {
                let cell = render_cell(row, col);
                html.push_str(&format!(r#"<td data-col="{field}">{cell}</td>"#, field = col.field));
            }
            html.push_str("</tr>");
        }
    }
    html.push_str("</tbody></table></div>");

    // Empty state or pagination
    if !result.is_empty() {
        html.push_str(&render_pagination(result, params, base_url));
    }
    html.push_str("</div></div>");

    html
}

/// Render the column visibility toggle dropdown + JS.
fn render_column_toggle(config: &ListConfig, base_url: &str) -> String {
    let mut html = String::new();

    // Dropdown button with checkboxes
    html.push_str(r#"<div class="dropdown dropdown-end">
<label tabindex="0" class="btn btn-ghost btn-sm">
<svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z"/><path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z"/></svg>
Columns
</label>
<div tabindex="0" class="dropdown-content z-[1] menu p-3 shadow-lg bg-base-100 rounded-box w-56">"#);

    html.push_str(r#"<p class="text-xs font-semibold text-base-content/50 mb-2">Show / Hide Columns</p>"#);

    for col in &config.columns {
        html.push_str(&format!(
            r#"<label class="flex items-center gap-2 py-1 cursor-pointer">
<input type="checkbox" class="checkbox checkbox-xs col-toggle-cb" data-field="{field}" checked onchange="toggleColumn('{field}', this.checked)"/>
<span class="text-sm">{label}</span>
</label>"#,
            field = col.field,
            label = html_escape(col.label),
        ));
    }

    html.push_str("</div></div>");

    // JavaScript for column toggle + localStorage persistence
    let storage_key = format!("vortex_cols_{}", base_url.replace('/', "_"));
    html.push_str(&format!(
        r#"<script>
(function() {{
    var KEY = '{key}';

    window.toggleColumn = function(field, visible) {{
        var cells = document.querySelectorAll('[data-col="' + field + '"]');
        for (var i = 0; i < cells.length; i++) {{
            cells[i].style.display = visible ? '' : 'none';
        }}
        saveState();
    }};

    function saveState() {{
        var cbs = document.querySelectorAll('.col-toggle-cb');
        var state = {{}};
        for (var i = 0; i < cbs.length; i++) {{
            state[cbs[i].getAttribute('data-field')] = cbs[i].checked;
        }}
        try {{ localStorage.setItem(KEY, JSON.stringify(state)); }} catch(e) {{}}
    }}

    function restoreState() {{
        try {{
            var raw = localStorage.getItem(KEY);
            if (!raw) return;
            var state = JSON.parse(raw);
            for (var field in state) {{
                if (!state[field]) {{
                    toggleColumn(field, false);
                    var cb = document.querySelector('.col-toggle-cb[data-field="' + field + '"]');
                    if (cb) cb.checked = false;
                }}
            }}
        }} catch(e) {{}}
    }}

    restoreState();
}})();
</script>"#,
        key = storage_key,
    ));

    html
}

/// Render the search bar and filter dropdowns.
fn render_search_bar(config: &ListConfig, params: &ListParams, base_url: &str) -> String {
    let mut html = String::new();

    let has_search = !config.searchable_exprs().is_empty();
    let has_filters = config.columns.iter().any(|c| !c.filter_options.is_empty());
    let has_groups = !config.group_options.is_empty();

    if !has_search && !has_filters && !has_groups {
        return html;
    }

    html.push_str(&format!(
        r#"<form method="GET" action="{base_url}" class="flex flex-wrap gap-2 mb-4 items-end">"#
    ));

    // Preserve current sort/dir
    if let Some(sort) = &params.sort_field {
        html.push_str(&format!(r#"<input type="hidden" name="sort" value="{}">"#, html_escape(sort)));
    }
    html.push_str(&format!(r#"<input type="hidden" name="dir" value="{}">"#, params.sort_dir.as_sql().to_lowercase()));
    html.push_str(r#"<input type="hidden" name="page" value="1">"#);

    // Search input
    if has_search {
        let val = params.search.as_deref().unwrap_or("");
        html.push_str(&format!(
            r#"<div class="form-control flex-1 min-w-[200px]">
<input type="text" name="search" placeholder="Search..." class="input input-bordered input-sm" value="{val}"/>
</div>"#,
            val = html_escape(val),
        ));
    }

    // Filter dropdowns
    for col in &config.columns {
        if col.filter_options.is_empty() {
            continue;
        }
        let current = params.filters.get(col.field).map(|s| s.as_str()).unwrap_or("");
        let field_name = format!("filter_{}", col.field);
        html.push_str(&format!(
            r#"<select name="{name}" class="select select-bordered select-sm">
<option value="">{label}: All</option>"#,
            name = html_escape(&field_name),
            label = html_escape(col.label),
        ));
        for (val, label) in &col.filter_options {
            let selected = if current == *val { " selected" } else { "" };
            html.push_str(&format!(
                r#"<option value="{val}"{selected}>{label}</option>"#,
                val = html_escape(val),
                label = html_escape(label),
            ));
        }
        html.push_str("</select>");
    }

    // Group-by dropdown
    if has_groups {
        let current_group = params.group_by.as_deref().unwrap_or("");
        html.push_str(r#"<select name="group" class="select select-bordered select-sm"><option value="">Group: None</option>"#);
        for (field, label) in &config.group_options {
            let selected = if current_group == *field { " selected" } else { "" };
            html.push_str(&format!(
                r#"<option value="{field}"{selected}>{label}</option>"#,
                field = html_escape(field),
                label = html_escape(label),
            ));
        }
        html.push_str("</select>");
    }

    html.push_str(r#"<button type="submit" class="btn btn-sm btn-ghost">Apply</button>"#);

    // Clear filters link
    if params.search.is_some() || !params.filters.is_empty() || params.group_by.is_some() {
        html.push_str(&format!(
            r#"<a href="{base_url}" class="btn btn-sm btn-ghost text-error">Clear</a>"#,
        ));
    }

    html.push_str("</form>");
    html
}

/// Render a raw string value using the column's renderer — used for
/// group headers where we have the value as a string, not a row.
fn render_cell_value(val: &str, col: &super::config::ListColumn) -> String {
    match &col.renderer {
        CellRenderer::Text | CellRenderer::Code => html_escape(val),
        CellRenderer::Badge(mappings) => {
            for (db_val, label, css) in mappings {
                if val == *db_val {
                    return format!(r#"<span class="badge {css} badge-sm">{label}</span>"#);
                }
            }
            html_escape(val)
        }
        CellRenderer::BoolBadge {
            true_label, true_css, false_label, false_css,
        } => {
            if val == "true" || val == "t" {
                format!(r#"<span class="badge {true_css} badge-sm">{true_label}</span>"#)
            } else {
                format!(r#"<span class="badge {false_css} badge-sm">{false_label}</span>"#)
            }
        }
    }
}

/// Render a single cell value based on the column's renderer.
fn render_cell(row: &sqlx::postgres::PgRow, col: &super::config::ListColumn) -> String {
    match &col.renderer {
        CellRenderer::Text => {
            let val: Option<String> = row.try_get(col.field).ok();
            html_escape(val.as_deref().unwrap_or(""))
        }
        CellRenderer::Code => {
            let val: Option<String> = row.try_get(col.field).ok();
            format!(
                r#"<span class="font-mono text-sm">{}</span>"#,
                html_escape(val.as_deref().unwrap_or(""))
            )
        }
        CellRenderer::Badge(mappings) => {
            let val: String = row.try_get(col.field).unwrap_or_default();
            for (db_val, label, css) in mappings {
                if val == *db_val {
                    return format!(r#"<span class="badge {css} badge-sm">{label}</span>"#);
                }
            }
            html_escape(&val)
        }
        CellRenderer::BoolBadge {
            true_label,
            true_css,
            false_label,
            false_css,
        } => {
            let val: bool = row.try_get(col.field).unwrap_or(false);
            if val {
                format!(r#"<span class="badge {true_css} badge-sm">{true_label}</span>"#)
            } else {
                format!(r#"<span class="badge {false_css} badge-sm">{false_label}</span>"#)
            }
        }
    }
}

/// Render pagination controls.
fn render_pagination(result: &ListResult, params: &ListParams, base_url: &str) -> String {
    // Keyset lists navigate by cursor (Prev / Next) — no total, no page numbers.
    if result.is_keyset() {
        return render_keyset_pagination(result, params, base_url);
    }

    let start = params.offset() + 1;
    let end = (params.offset() + params.page_size).min(result.total as u64);
    // An estimated total is shown as approximate; the end of the current window
    // can exceed a stale estimate, so clamp the label to at least `end`.
    let total_label = if result.estimated {
        format!("~{}", result.total.max(end as i64))
    } else {
        result.total.to_string()
    };

    let mut html = String::new();
    html.push_str(&format!(
        r#"<div class="flex items-center justify-between p-4 text-sm text-base-content/60">
<span>Showing {start}–{end} of {total}</span>
<div class="join">"#,
        start = start,
        end = end,
        total = total_label,
    ));

    // Previous
    if params.page > 1 {
        let qs = params.to_query_with(&[("page", &(params.page - 1).to_string())]);
        html.push_str(&format!(
            r#"<a href="{base_url}?{qs}" class="join-item btn btn-sm">«</a>"#
        ));
    } else {
        html.push_str(r#"<button class="join-item btn btn-sm btn-disabled">«</button>"#);
    }

    // Page numbers (show max 7)
    let total_pages = result.total_pages;
    let current = params.page;
    let (start_page, end_page) = if total_pages <= 7 {
        (1, total_pages)
    } else if current <= 4 {
        (1, 7)
    } else if current >= total_pages - 3 {
        (total_pages - 6, total_pages)
    } else {
        (current - 3, current + 3)
    };

    for p in start_page..=end_page {
        let qs = params.to_query_with(&[("page", &p.to_string())]);
        let active = if p == current { " btn-active" } else { "" };
        html.push_str(&format!(
            r#"<a href="{base_url}?{qs}" class="join-item btn btn-sm{active}">{p}</a>"#
        ));
    }

    // Next
    if params.page < total_pages {
        let qs = params.to_query_with(&[("page", &(params.page + 1).to_string())]);
        html.push_str(&format!(
            r#"<a href="{base_url}?{qs}" class="join-item btn btn-sm">»</a>"#
        ));
    } else {
        html.push_str(r#"<button class="join-item btn btn-sm btn-disabled">»</button>"#);
    }

    html.push_str("</div></div>");
    html
}

/// Cursor-based Prev/Next controls for keyset lists. `«` / `»` seek to the
/// adjacent page via `?before=` / `?after=`; each is disabled when its cursor
/// is absent (no adjacent page in that direction).
fn render_keyset_pagination(result: &ListResult, params: &ListParams, base_url: &str) -> String {
    let mut html = String::from(
        r#"<div class="flex items-center justify-end p-4 text-sm text-base-content/60"><div class="join">"#,
    );

    match &result.prev_cursor {
        Some(c) => {
            let qs = params.to_query_with(&[("before", c.as_str())]);
            html.push_str(&format!(
                r#"<a href="{base_url}?{qs}" class="join-item btn btn-sm">«&nbsp;Prev</a>"#
            ));
        }
        None => html.push_str(
            r#"<button class="join-item btn btn-sm btn-disabled">«&nbsp;Prev</button>"#,
        ),
    }

    match &result.next_cursor {
        Some(c) => {
            let qs = params.to_query_with(&[("after", c.as_str())]);
            html.push_str(&format!(
                r#"<a href="{base_url}?{qs}" class="join-item btn btn-sm">Next&nbsp;»</a>"#
            ));
        }
        None => html.push_str(
            r#"<button class="join-item btn btn-sm btn-disabled">Next&nbsp;»</button>"#,
        ),
    }

    html.push_str("</div></div>");
    html
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::config::ListColumn;

    fn empty_result(total: i64, page: u64, page_size: u64, total_pages: u64) -> ListResult {
        ListResult {
            rows: Vec::new(),
            total,
            page,
            page_size,
            total_pages,
            next_cursor: None,
            prev_cursor: None,
            estimated: false,
        }
    }

    #[test]
    fn cell_value_text_is_html_escaped() {
        let col = ListColumn::new("name", "Name");
        let out = render_cell_value("<script>alert(1)</script>", &col);
        assert!(!out.contains("<script>"), "raw markup leaked: {out}");
        assert!(out.contains("&lt;script&gt;"));
    }

    #[test]
    fn cell_value_badge_maps_known_value_else_escapes() {
        let col = ListColumn::new("contact_type", "Type")
            .badge(&[("customer", "Customer", "badge-info")]);
        // Known value renders the mapped, static label + css.
        let mapped = render_cell_value("customer", &col);
        assert!(mapped.contains(r#"class="badge badge-info badge-sm""#));
        assert!(mapped.contains(">Customer<"));
        // Unknown value falls back to escaped raw text, not a badge.
        let unknown = render_cell_value("<evil>", &col);
        assert!(!unknown.contains("badge-info"));
        assert!(unknown.contains("&lt;evil&gt;"));
    }

    #[test]
    fn cell_value_bool_badge_picks_branch() {
        let col = ListColumn::new("active", "Status")
            .bool_badge("Active", "badge-success", "Archived", "badge-warning");
        assert!(render_cell_value("true", &col).contains("Active"));
        assert!(render_cell_value("t", &col).contains("Active"));
        assert!(render_cell_value("false", &col).contains("Archived"));
    }

    #[test]
    fn empty_list_renders_no_records_and_escapes_title() {
        let config = ListConfig::new("Tom & Jerry", "t")
            .column(ListColumn::new("name", "Name"));
        let result = empty_result(0, 1, 25, 0);
        let html = render_list(&config, &result, &ListParams::default(), "/things");
        assert!(html.contains("No records found"));
        // The title is escaped — the raw ampersand must not survive.
        assert!(html.contains("Tom &amp; Jerry"));
        assert!(!html.contains("Tom & Jerry"));
    }

    #[test]
    fn pagination_reports_correct_window() {
        // 100 rows, 25 per page, on page 2 → showing 26–50 of 100.
        let result = empty_result(100, 2, 25, 4);
        let params = ListParams { page: 2, page_size: 25, ..Default::default() };
        let html = render_pagination(&result, &params, "/things");
        assert!(html.contains("Showing 26–50 of 100"), "got: {html}");
    }

    #[test]
    fn pagination_last_page_clamps_end_to_total() {
        // 90 rows, 25 per page, page 4 → rows 76–90 (not 76–100).
        let result = empty_result(90, 4, 25, 4);
        let params = ListParams { page: 4, page_size: 25, ..Default::default() };
        let html = render_pagination(&result, &params, "/things");
        assert!(html.contains("Showing 76–90 of 90"), "got: {html}");
    }
}
