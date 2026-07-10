//! Saveable dashboards (Initiative #4).
//!
//! A dashboard is a named board of widgets an operator assembles in the UI — no
//! code, no deploy. Each widget runs **one** aggregate query over a registered
//! model and renders either a KPI number or a grouped "bars" breakdown.
//!
//! The query builder is the same shape as the report engine: the model's table
//! and every field a widget names are resolved from the code-derived registry
//! (`ir_model` / `ir_model_field`), every identifier is allow-listed against it,
//! and every value is bound. A widget can therefore only ever read a real,
//! registered column of its own model.

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::html_escape;

/// Aggregate functions offered to widget authors, as `(code, label)`.
pub const AGGREGATES: &[(&str, &str)] = &[
    ("count", "Count of records"),
    ("sum", "Sum of"),
    ("avg", "Average of"),
    ("min", "Minimum of"),
    ("max", "Maximum of"),
];

/// Widget shapes, as `(code, label)`.
pub const WIDGET_TYPES: &[(&str, &str)] = &[
    ("kpi", "KPI — a single number"),
    ("bars", "Bars — a breakdown by a field"),
];

/// Filter operators, as `(code, label)`.
pub const FILTER_OPS: &[(&str, &str)] = &[
    ("=", "is"),
    ("!=", "is not"),
    ("ilike", "contains"),
    (">", "greater than"),
    ("<", "less than"),
    (">=", "at least"),
    ("<=", "at most"),
];

const NUMERIC_TYPES: &[&str] = &["integer", "float", "decimal", "monetary", "number"];

#[derive(Debug, Clone)]
pub struct Dashboard {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: Option<Uuid>,
    pub is_shared: bool,
}

impl Dashboard {
    /// May a user see this dashboard? Owner, or shared, or admin.
    pub fn can_view(&self, user_id: Uuid, is_admin: bool) -> bool {
        self.is_shared || is_admin || self.owner_id == Some(user_id)
    }
    /// May a user edit/delete it? Owner or admin.
    pub fn can_edit(&self, user_id: Uuid, is_admin: bool) -> bool {
        is_admin || self.owner_id == Some(user_id)
    }
}

#[derive(Debug, Clone)]
pub struct Widget {
    pub id: Uuid,
    pub dashboard_id: Uuid,
    pub title: String,
    pub widget_type: String,
    pub model_name: String,
    pub measure_field: Option<String>,
    pub aggregate: String,
    pub group_field: Option<String>,
    pub filter_field: Option<String>,
    pub filter_op: Option<String>,
    pub filter_value: Option<String>,
    pub row_limit: i32,
    pub col_span: i32,
}

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn valid_agg(a: &str) -> bool {
    AGGREGATES.iter().any(|(c, _)| *c == a)
}
fn valid_op(op: &str) -> bool {
    FILTER_OPS.iter().any(|(c, _)| *c == op)
}
fn valid_type(t: &str) -> bool {
    WIDGET_TYPES.iter().any(|(c, _)| *c == t)
}

async fn model_table(db: &PgPool, model: &str) -> Option<String> {
    let t: Option<String> =
        sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
            .bind(model)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    t.filter(|t| ident(t))
}

/// name -> (field_type, related_model) for a model, from the registry.
async fn model_fields(db: &PgPool, model: &str) -> std::collections::HashMap<String, (String, Option<String>)> {
    let rows = sqlx::query(
        "SELECT f.name, f.field_type, f.related_model FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id WHERE m.name = $1 AND f.is_custom = false",
    )
    .bind(model)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.into_iter()
        .map(|r| {
            (
                r.get::<String, _>("name"),
                (r.get::<String, _>("field_type"), r.try_get::<Option<String>, _>("related_model").ok().flatten()),
            )
        })
        .collect()
}

// ── CRUD ────────────────────────────────────────────────────────────────────

fn row_to_dashboard(r: sqlx::postgres::PgRow) -> Dashboard {
    Dashboard {
        id: r.get("id"),
        name: r.get("name"),
        description: r.try_get("description").ok().flatten(),
        owner_id: r.try_get("owner_id").ok().flatten(),
        is_shared: r.get("is_shared"),
    }
}

/// Dashboards a user may see: their own plus every shared one (admins see all).
pub async fn list_visible(db: &PgPool, user_id: Uuid, is_admin: bool) -> Vec<Dashboard> {
    let rows = if is_admin {
        sqlx::query("SELECT id, name, description, owner_id, is_shared FROM dashboard ORDER BY sequence, name")
            .fetch_all(db).await
    } else {
        sqlx::query("SELECT id, name, description, owner_id, is_shared FROM dashboard \
                     WHERE is_shared = true OR owner_id = $1 ORDER BY sequence, name")
            .bind(user_id).fetch_all(db).await
    };
    rows.unwrap_or_default().into_iter().map(row_to_dashboard).collect()
}

pub async fn load(db: &PgPool, id: Uuid) -> Option<Dashboard> {
    sqlx::query("SELECT id, name, description, owner_id, is_shared FROM dashboard WHERE id = $1")
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(row_to_dashboard)
}

pub async fn create(
    db: &PgPool,
    name: &str,
    description: Option<&str>,
    owner_id: Uuid,
    is_shared: bool,
) -> Result<Uuid, String> {
    if name.trim().is_empty() {
        return Err("A dashboard needs a name.".into());
    }
    sqlx::query_scalar(
        "INSERT INTO dashboard (name, description, owner_id, is_shared) VALUES ($1, $2, $3, $4) RETURNING id",
    )
    .bind(name.trim())
    .bind(description.map(str::trim).filter(|s| !s.is_empty()))
    .bind(owner_id)
    .bind(is_shared)
    .fetch_one(db)
    .await
    .map_err(|e| format!("save failed: {e}"))
}

pub async fn delete(db: &PgPool, id: Uuid) -> Result<(), String> {
    sqlx::query("DELETE FROM dashboard WHERE id = $1")
        .bind(id)
        .execute(db)
        .await
        .map_err(|e| format!("delete failed: {e}"))?;
    Ok(())
}

pub async fn widgets_for(db: &PgPool, dashboard_id: Uuid) -> Vec<Widget> {
    let rows = sqlx::query(
        "SELECT id, dashboard_id, title, widget_type, model_name, measure_field, aggregate, \
                group_field, filter_field, filter_op, filter_value, row_limit, col_span \
         FROM dashboard_widget WHERE dashboard_id = $1 ORDER BY sequence, created_at",
    )
    .bind(dashboard_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.into_iter()
        .map(|r| Widget {
            id: r.get("id"),
            dashboard_id: r.get("dashboard_id"),
            title: r.get("title"),
            widget_type: r.get("widget_type"),
            model_name: r.get("model_name"),
            measure_field: r.try_get("measure_field").ok().flatten(),
            aggregate: r.get("aggregate"),
            group_field: r.try_get("group_field").ok().flatten(),
            filter_field: r.try_get("filter_field").ok().flatten(),
            filter_op: r.try_get("filter_op").ok().flatten(),
            filter_value: r.try_get("filter_value").ok().flatten(),
            row_limit: r.get("row_limit"),
            col_span: r.get("col_span"),
        })
        .collect()
}

/// Validate and add a widget. Every field named is checked against the registry.
#[allow(clippy::too_many_arguments)]
pub async fn add_widget(
    db: &PgPool,
    dashboard_id: Uuid,
    title: &str,
    widget_type: &str,
    model: &str,
    measure_field: Option<&str>,
    aggregate: &str,
    group_field: Option<&str>,
    filter_field: Option<&str>,
    filter_op: Option<&str>,
    filter_value: Option<&str>,
    col_span: i32,
) -> Result<(), String> {
    if title.trim().is_empty() {
        return Err("A widget needs a title.".into());
    }
    if !valid_type(widget_type) {
        return Err("Invalid widget type.".into());
    }
    if !valid_agg(aggregate) {
        return Err("Invalid aggregate.".into());
    }
    let fields = model_fields(db, model).await;
    if fields.is_empty() {
        return Err(format!("Unknown or empty model {model:?}."));
    }

    // A non-count aggregate needs a numeric measure field.
    let measure_field = measure_field.map(str::trim).filter(|s| !s.is_empty());
    if aggregate != "count" {
        let Some(m) = measure_field else {
            return Err("Choose a number field to aggregate.".into());
        };
        match fields.get(m) {
            Some((ft, _)) if NUMERIC_TYPES.contains(&ft.as_str()) => {}
            Some(_) => return Err(format!("{m:?} is not a number field.")),
            None => return Err(format!("{m:?} is not a field of {model}.")),
        }
    }

    // A bars widget needs a group field.
    let group_field = group_field.map(str::trim).filter(|s| !s.is_empty());
    if widget_type == "bars" {
        match group_field {
            Some(g) if fields.contains_key(g) => {}
            Some(g) => return Err(format!("{g:?} is not a field of {model}.")),
            None => return Err("A bars widget needs a field to break down by.".into()),
        }
    }

    // Optional filter.
    let filter_field = filter_field.map(str::trim).filter(|s| !s.is_empty());
    let filter_op = filter_op.map(str::trim).filter(|s| !s.is_empty());
    if let Some(ff) = filter_field {
        if !fields.contains_key(ff) {
            return Err(format!("Filter field {ff:?} is not a field of {model}."));
        }
        match filter_op {
            Some(op) if valid_op(op) => {}
            _ => return Err("Choose a valid filter operator.".into()),
        }
    }

    sqlx::query(
        "INSERT INTO dashboard_widget \
            (dashboard_id, title, widget_type, model_name, measure_field, aggregate, \
             group_field, filter_field, filter_op, filter_value, col_span, sequence) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, \
                 COALESCE((SELECT MAX(sequence) + 1 FROM dashboard_widget WHERE dashboard_id = $1), 0))",
    )
    .bind(dashboard_id)
    .bind(title.trim())
    .bind(widget_type)
    .bind(model)
    .bind(measure_field)
    .bind(aggregate)
    .bind(group_field)
    .bind(filter_field)
    .bind(filter_op.filter(|_| filter_field.is_some()))
    .bind(filter_value.map(str::trim).filter(|s| !s.is_empty()).filter(|_| filter_field.is_some()))
    .bind(col_span.clamp(1, 3))
    .execute(db)
    .await
    .map_err(|e| format!("save failed: {e}"))?;
    Ok(())
}

pub async fn delete_widget(db: &PgPool, id: Uuid) -> Result<Option<Uuid>, String> {
    let dash: Option<Uuid> = sqlx::query_scalar(
        "DELETE FROM dashboard_widget WHERE id = $1 RETURNING dashboard_id",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .map_err(|e| format!("delete failed: {e}"))?;
    Ok(dash)
}

// ── Computation ─────────────────────────────────────────────────────────────

/// The SQL aggregate expression for a widget over alias `t`. `count` ignores
/// the measure; the others require a numeric measure (already validated).
fn agg_expr(aggregate: &str, measure: Option<&str>) -> String {
    match aggregate {
        "count" => "COUNT(*)".to_string(),
        other => {
            let m = measure.unwrap_or("id");
            let f = match other {
                "sum" => "SUM",
                "avg" => "AVG",
                "min" => "MIN",
                "max" => "MAX",
                _ => "COUNT",
            };
            format!("{f}(t.{m}::numeric)")
        }
    }
}

/// A widget's WHERE clause (bound parameter `$1` when a filter is present).
fn where_clause(w: &Widget) -> (String, Option<String>) {
    match (&w.filter_field, &w.filter_op) {
        (Some(f), Some(op)) if ident(f) && valid_op(op) => {
            let raw = w.filter_value.clone().unwrap_or_default();
            let bind = if op == "ilike" { format!("%{raw}%") } else { raw };
            (format!(" WHERE t.{f}::text {op} $1"), Some(bind))
        }
        _ => (String::new(), None),
    }
}

/// Rendered result of one widget.
pub enum WidgetData {
    Kpi(String),
    Bars { rows: Vec<(String, f64)>, max: f64 },
    Error(String),
}

fn fmt_num(n: f64) -> String {
    if n.fract().abs() < 1e-9 {
        format!("{}", n as i64)
    } else {
        format!("{n:.2}")
    }
}

/// Run a widget's query and return its rendered data. Never panics; a malformed
/// widget yields `WidgetData::Error`.
pub async fn compute(db: &PgPool, w: &Widget) -> WidgetData {
    let Some(table) = model_table(db, &w.model_name).await else {
        return WidgetData::Error(format!("unknown model '{}'", w.model_name));
    };
    let fields = model_fields(db, &w.model_name).await;

    if w.aggregate != "count" {
        match w.measure_field.as_deref() {
            Some(m) if ident(m) && fields.contains_key(m) => {}
            _ => return WidgetData::Error("invalid measure field".into()),
        }
    }
    let (where_sql, bind) = where_clause(w);
    let agg = agg_expr(&w.aggregate, w.measure_field.as_deref());

    if w.widget_type == "kpi" {
        let sql = format!("SELECT ({agg})::text FROM {table} t{where_sql}");
        let mut q = sqlx::query_scalar::<_, Option<String>>(&sql);
        if let Some(b) = bind {
            q = q.bind(b);
        }
        return match q.fetch_one(db).await {
            Ok(v) => {
                let raw = v.unwrap_or_default();
                let shown = raw.trim().parse::<f64>().map(fmt_num).unwrap_or(raw);
                WidgetData::Kpi(shown)
            }
            Err(e) => WidgetData::Error(format!("query failed: {e}")),
        };
    }

    // bars: group by group_field, aggregate, order desc, limit.
    let Some(group) = w.group_field.as_deref().filter(|g| ident(g) && fields.contains_key(*g)) else {
        return WidgetData::Error("invalid group field".into());
    };
    // Resolve a many2one group to the related record's name for readability.
    let group_sql = match fields.get(group) {
        Some((ft, Some(rel))) if ft == "many2one" => match model_table(db, rel).await {
            Some(rtable) => format!("(SELECT r.name FROM {rtable} r WHERE r.id = t.{group})::text"),
            None => format!("t.{group}::text"),
        },
        _ => format!("t.{group}::text"),
    };
    let limit = w.row_limit.clamp(1, 50);
    let sql = format!(
        "SELECT COALESCE({group_sql}, '(none)') AS k, ({agg})::text AS v \
         FROM {table} t{where_sql} GROUP BY 1 ORDER BY 2 DESC NULLS LAST LIMIT {limit}"
    );
    let mut q = sqlx::query(&sql);
    if let Some(b) = bind {
        q = q.bind(b);
    }
    match q.fetch_all(db).await {
        Ok(rows) => {
            let mut out = Vec::new();
            let mut max = 0.0_f64;
            for r in &rows {
                let k: String = r.try_get::<Option<String>, _>("k").ok().flatten().unwrap_or_else(|| "(none)".into());
                let v: f64 = r.try_get::<Option<String>, _>("v").ok().flatten()
                    .and_then(|s| s.trim().parse().ok()).unwrap_or(0.0);
                max = max.max(v);
                out.push((k, v));
            }
            WidgetData::Bars { rows: out, max }
        }
        Err(e) => WidgetData::Error(format!("query failed: {e}")),
    }
}

/// Render one widget card (chrome + computed content).
pub async fn render_widget(db: &PgPool, w: &Widget, can_edit: bool) -> String {
    let span = match w.col_span.clamp(1, 3) {
        3 => "lg:col-span-3",
        2 => "lg:col-span-2",
        _ => "",
    };
    let delete_btn = if can_edit {
        format!(
            r#"<form method="post" action="/dashboards/widget/{id}/delete" onsubmit="return confirm('Remove this widget?');" class="inline">
<button class="btn btn-ghost btn-xs text-error" title="Remove">✕</button></form>"#,
            id = w.id
        )
    } else {
        String::new()
    };

    let body = match compute(db, w).await {
        WidgetData::Kpi(v) => format!(
            r#"<div class="text-4xl font-bold tabular-nums mt-2">{}</div>"#,
            html_escape(&v)
        ),
        WidgetData::Bars { rows, max } => {
            if rows.is_empty() {
                r#"<p class="opacity-60 text-sm mt-4">No data.</p>"#.to_string()
            } else {
                let mut b = String::from(r#"<div class="mt-3 space-y-2">"#);
                for (k, v) in &rows {
                    let pct = if max > 0.0 { (v / max * 100.0).clamp(2.0, 100.0) } else { 0.0 };
                    b.push_str(&format!(
                        r#"<div><div class="flex justify-between text-sm mb-0.5"><span class="truncate pr-2">{k}</span><span class="tabular-nums font-medium">{v}</span></div>
<div class="h-2 rounded bg-base-200 overflow-hidden"><div class="h-full bg-primary" style="width:{pct:.1}%"></div></div></div>"#,
                        k = html_escape(k),
                        v = html_escape(&fmt_num(*v)),
                        pct = pct,
                    ));
                }
                b.push_str("</div>");
                b
            }
        }
        WidgetData::Error(e) => format!(
            r#"<p class="text-error text-sm mt-4">⚠ {}</p>"#,
            html_escape(&e)
        ),
    };

    format!(
        r#"<div class="card bg-base-100 shadow {span}"><div class="card-body p-4">
<div class="flex items-start justify-between"><h3 class="card-title text-sm opacity-70 uppercase tracking-wide">{title}</h3>{delete_btn}</div>
{body}</div></div>"#,
        span = span,
        title = html_escape(&w.title),
        delete_btn = delete_btn,
        body = body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agg_expression() {
        assert_eq!(agg_expr("count", None), "COUNT(*)");
        assert_eq!(agg_expr("sum", Some("amount")), "SUM(t.amount::numeric)");
        assert_eq!(agg_expr("avg", Some("qty")), "AVG(t.qty::numeric)");
    }

    #[test]
    fn allowlists() {
        assert!(valid_agg("sum"));
        assert!(!valid_agg("median"));
        assert!(valid_op("ilike"));
        assert!(!valid_op("; DROP"));
        assert!(valid_type("bars"));
        assert!(!valid_type("pie"));
        assert!(ident("credit_limit"));
        assert!(!ident("a; DROP"));
    }

    #[test]
    fn number_formatting() {
        assert_eq!(fmt_num(100.0), "100");
        assert_eq!(fmt_num(15.5), "15.50");
    }

    #[test]
    fn permissions() {
        let owner = Uuid::new_v4();
        let other = Uuid::new_v4();
        let d = Dashboard { id: Uuid::new_v4(), name: "D".into(), description: None,
            owner_id: Some(owner), is_shared: false };
        assert!(d.can_view(owner, false));
        assert!(!d.can_view(other, false), "private, not owner");
        assert!(d.can_view(other, true), "admin sees all");
        assert!(!d.can_edit(other, false));
        assert!(d.can_edit(owner, false));

        let shared = Dashboard { is_shared: true, owner_id: Some(owner), ..d.clone() };
        assert!(shared.can_view(other, false), "shared is visible");
        assert!(!shared.can_edit(other, false), "but not editable by non-owner");
    }

    /// Full loop against a real DB. Runs only when `VORTEX_TEST_DB` points at a
    /// migrated throwaway DB; otherwise skips.
    #[tokio::test]
    async fn widget_compute_against_db() {
        let Ok(url) = std::env::var("VORTEX_TEST_DB") else {
            eprintln!("skip widget_compute_against_db: VORTEX_TEST_DB unset");
            return;
        };
        let db = PgPool::connect(&url).await.expect("connect");
        let owner = Uuid::new_v4();

        // Seed a couple of contacts to count.
        let c1 = Uuid::new_v4();
        let c2 = Uuid::new_v4();
        for (id, t) in [(c1, "customer"), (c2, "supplier")] {
            sqlx::query("INSERT INTO contacts (id, name, contact_type, active, company_id) \
                         VALUES ($1, 'X', $2, true, (SELECT id FROM companies LIMIT 1))")
                .bind(id).bind(t).execute(&db).await.expect("insert");
        }

        let dash = create(&db, "Ops", Some("test"), owner, true).await.expect("create dash");
        add_widget(&db, dash, "Total contacts", "kpi", "contacts",
            None, "count", None, None, None, None, 1).await.expect("add kpi");
        add_widget(&db, dash, "By type", "bars", "contacts",
            None, "count", Some("contact_type"), None, None, None, 2).await.expect("add bars");

        let widgets = widgets_for(&db, dash).await;
        assert_eq!(widgets.len(), 2);

        let kpi = widgets.iter().find(|w| w.widget_type == "kpi").unwrap();
        match compute(&db, kpi).await {
            WidgetData::Kpi(v) => {
                let n: i64 = v.parse().unwrap_or(0);
                assert!(n >= 2, "at least the two seeded contacts, got {n}");
            }
            other => panic!("expected KPI, got {:?}", matches!(other, WidgetData::Error(_))),
        }

        let bars = widgets.iter().find(|w| w.widget_type == "bars").unwrap();
        match compute(&db, bars).await {
            WidgetData::Bars { rows, .. } => assert!(!rows.is_empty(), "bars has groups"),
            _ => panic!("expected bars"),
        }

        // Cleanup (cascade drops widgets).
        delete(&db, dash).await.expect("delete dash");
        sqlx::query("DELETE FROM contacts WHERE id = ANY($1)")
            .bind(vec![c1, c2]).execute(&db).await.ok();
    }
}
