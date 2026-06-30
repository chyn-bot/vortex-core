//! User-authored report engine (QWeb-like), DB-stored so no code change is
//! needed to add a report. Two shapes share one definition:
//!
//! * **tabular** — pick a model, columns, filters, sort, group-by and
//!   aggregates; [`run_tabular`] builds parameterized SQL (every identifier is
//!   allow-listed, every value is bound) and groups/aggregates in Rust.
//! * **template** — an authored HTML document rendered by [`render_template`],
//!   a sandboxed mini-engine (`{{ field }}`, `{% for r in records %}`,
//!   `{% if %}`) that interpolates **escaped** record data into trusted markup.
//!
//! Output: HTML (print → PDF), CSV, JSON. The model registry (`ir_model` /
//! `ir_model_field`) supplies field introspection and many2one labels.

use std::collections::BTreeMap;

use sqlx::{PgPool, Row};
use uuid::Uuid;

use crate::ui::html_escape;

/// Self-hosted report stylesheet (no CDN, no build step). Inline this into a
/// report/print page so PDF output is fully offline and deterministic.
pub const REPORT_CSS: &str = include_str!("report.css");

fn ident(s: &str) -> bool {
    !s.is_empty() && s.len() <= 63 && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Allowed filter operators (everything else is rejected before SQL).
fn valid_operator(op: &str) -> bool {
    matches!(op, "=" | "!=" | "ilike" | ">" | "<" | ">=" | "<=")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Aggregate {
    None,
    Sum,
    Avg,
    Count,
    Min,
    Max,
}

impl Aggregate {
    pub fn parse(s: &str) -> Self {
        match s {
            "sum" => Aggregate::Sum,
            "avg" => Aggregate::Avg,
            "count" => Aggregate::Count,
            "min" => Aggregate::Min,
            "max" => Aggregate::Max,
            _ => Aggregate::None,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Aggregate::None => "none",
            Aggregate::Sum => "sum",
            Aggregate::Avg => "avg",
            Aggregate::Count => "count",
            Aggregate::Min => "min",
            Aggregate::Max => "max",
        }
    }
    fn is_measure(&self) -> bool {
        !matches!(self, Aggregate::None)
    }
}

#[derive(Debug, Clone)]
pub struct ReportColumn {
    pub field: String,
    pub label: String,
    pub aggregate: Aggregate,
}

#[derive(Debug, Clone)]
pub struct ReportFilter {
    pub field: String,
    pub operator: String,
    pub value: Option<String>,
}

/// A loaded report definition with its columns and filters.
#[derive(Debug, Clone)]
pub struct ReportDef {
    pub id: Uuid,
    pub code: String,
    pub name: String,
    pub description: Option<String>,
    pub model_name: String,
    pub report_type: String, // tabular | template
    pub sort_field: Option<String>,
    pub sort_dir: String,
    pub group_field: Option<String>,
    pub template: Option<String>,
    pub paper_size: String,
    pub orientation: String,
    pub required_role: Option<String>,
    pub row_limit: i32,
    pub columns: Vec<ReportColumn>,
    pub filters: Vec<ReportFilter>,
}

impl ReportDef {
    /// May a user with `roles` run this report? (`required_role` None = anyone.)
    pub fn can_run(&self, roles: &[String], is_admin: bool) -> bool {
        match &self.required_role {
            None => true,
            Some(r) => is_admin || roles.iter().any(|x| x == r),
        }
    }
}

/// Load a report (with columns + filters) by id, or `None`.
pub async fn load(db: &PgPool, id: Uuid) -> Option<ReportDef> {
    let r = sqlx::query(
        "SELECT id, code, name, description, model_name, report_type, sort_field, sort_dir, \
                group_field, template, paper_size, orientation, required_role, row_limit \
         FROM ir_report WHERE id = $1 AND active = true",
    )
    .bind(id)
    .fetch_optional(db)
    .await
    .ok()
    .flatten()?;

    let columns = sqlx::query(
        "SELECT field, label, aggregate FROM ir_report_column WHERE report_id = $1 ORDER BY sequence, field",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|c| ReportColumn {
        field: c.get("field"),
        label: c.try_get::<Option<String>, _>("label").ok().flatten().unwrap_or_else(|| c.get("field")),
        aggregate: Aggregate::parse(&c.get::<String, _>("aggregate")),
    })
    .collect();

    let filters = sqlx::query(
        "SELECT field, operator, value FROM ir_report_filter WHERE report_id = $1 ORDER BY sequence",
    )
    .bind(id)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|f| ReportFilter {
        field: f.get("field"),
        operator: f.get("operator"),
        value: f.try_get("value").ok().flatten(),
    })
    .collect();

    Some(ReportDef {
        id: r.get("id"),
        code: r.get("code"),
        name: r.get("name"),
        description: r.try_get("description").ok().flatten(),
        model_name: r.get("model_name"),
        report_type: r.get("report_type"),
        sort_field: r.try_get("sort_field").ok().flatten(),
        sort_dir: r.get("sort_dir"),
        group_field: r.try_get("group_field").ok().flatten(),
        template: r.try_get("template").ok().flatten(),
        paper_size: r.get("paper_size"),
        orientation: r.get("orientation"),
        required_role: r.try_get("required_role").ok().flatten(),
        row_limit: r.get("row_limit"),
        columns,
        filters,
    })
}

async fn model_table(db: &PgPool, model_name: &str) -> Option<String> {
    sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND is_active = true")
        .bind(model_name)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
}

/// field name -> (field_type, related_model) for one model.
async fn model_fields(db: &PgPool, model_name: &str) -> BTreeMap<String, (String, Option<String>)> {
    let rows = sqlx::query(
        "SELECT f.name, f.field_type, f.related_model FROM ir_model_field f \
         JOIN ir_model m ON m.id = f.model_id WHERE m.name = $1",
    )
    .bind(model_name)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    rows.iter()
        .map(|r| {
            (
                r.get::<String, _>("name"),
                (r.get::<String, _>("field_type"), r.try_get::<Option<String>, _>("related_model").ok().flatten()),
            )
        })
        .collect()
}

/// Result of a tabular run, ready to render.
pub struct TabularResult {
    pub headers: Vec<String>,
    pub group_label: Option<String>,
    pub groups: Vec<GroupBlock>,
    /// Per-column grand total (None where the column has no aggregate).
    pub grand_totals: Vec<Option<String>>,
    pub total_rows: usize,
}

pub struct GroupBlock {
    pub key: String,
    pub rows: Vec<Vec<String>>,
    /// Per-column subtotal within the group (None where no aggregate).
    pub subtotals: Vec<Option<String>>,
}

/// Run a tabular report: safe SQL + in-Rust grouping/aggregation.
pub async fn run_tabular(db: &PgPool, def: &ReportDef) -> Result<TabularResult, String> {
    let table = model_table(db, &def.model_name)
        .await
        .ok_or_else(|| format!("unknown model '{}'", def.model_name))?;
    if !ident(&table) {
        return Err("invalid model table".into());
    }
    let fields = model_fields(db, &def.model_name).await;

    if def.columns.is_empty() {
        return Err("report has no columns".into());
    }
    // Validate every column field exists and is a safe identifier.
    for c in &def.columns {
        if !ident(&c.field) || !fields.contains_key(&c.field) {
            return Err(format!("invalid column '{}'", c.field));
        }
    }
    let group = def.group_field.as_deref().filter(|g| !g.is_empty());
    if let Some(g) = group {
        if !ident(g) || !fields.contains_key(g) {
            return Err(format!("invalid group field '{g}'"));
        }
    }

    // Build the SELECT list: group field (if any) first, then columns. Each
    // expression is cast to text so any column type reads back as a string;
    // many2one fields are resolved to the related record's name.
    let relation_expr = |field: &str| -> String {
        if let Some((ftype, Some(rel))) = fields.get(field) {
            if ftype == "many2one" {
                // resolved at render via a correlated subquery when safe
                return format!("{field}|m2o|{rel}");
            }
        }
        field.to_string()
    };

    let mut select_fields: Vec<String> = Vec::new();
    if let Some(g) = group {
        select_fields.push(relation_expr(g));
    }
    for c in &def.columns {
        select_fields.push(relation_expr(&c.field));
    }

    // Turn each marker into a real SQL expression.
    let mut select_sql: Vec<String> = Vec::new();
    for f in &select_fields {
        if let Some((field, rel)) = f.split_once("|m2o|") {
            // related table from ir_model; guard the name column existence cheaply
            if let Some(rtable) = model_table(db, rel).await {
                if ident(rtable.as_str()) && ident(field) {
                    select_sql.push(format!(
                        "(SELECT r.name FROM {rtable} r WHERE r.id = t.{field})::text"
                    ));
                    continue;
                }
            }
            select_sql.push(format!("t.{field}::text"));
        } else {
            select_sql.push(format!("t.{f}::text"));
        }
    }

    // WHERE from filters (values bound as parameters).
    let mut where_parts: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for fl in &def.filters {
        if !ident(&fl.field) || !fields.contains_key(&fl.field) || !valid_operator(&fl.operator) {
            return Err(format!("invalid filter on '{}'", fl.field));
        }
        let n = binds.len() + 1;
        where_parts.push(format!("t.{}::text {} ${}", fl.field, fl.operator, n));
        let raw = fl.value.clone().unwrap_or_default();
        binds.push(if fl.operator == "ilike" { format!("%{raw}%") } else { raw });
    }
    let where_sql = if where_parts.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", where_parts.join(" AND "))
    };

    // ORDER BY: group first (keeps groups contiguous), then sort field.
    let dir = if def.sort_dir.eq_ignore_ascii_case("desc") { "DESC" } else { "ASC" };
    let mut order: Vec<String> = Vec::new();
    if let Some(g) = group {
        order.push(format!("t.{g} ASC"));
    }
    if let Some(s) = def.sort_field.as_deref().filter(|s| !s.is_empty()) {
        if ident(s) && fields.contains_key(s) {
            order.push(format!("t.{s} {dir}"));
        }
    }
    let order_sql = if order.is_empty() { String::new() } else { format!(" ORDER BY {}", order.join(", ")) };

    let limit = def.row_limit.clamp(1, 100_000);
    let sql = format!(
        "SELECT {} FROM {} t{}{} LIMIT {}",
        select_sql.join(", "),
        table,
        where_sql,
        order_sql,
        limit
    );

    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.fetch_all(db).await.map_err(|e| format!("query failed: {e}"))?;

    // Read every selected expression as Option<String>.
    let group_offset = if group.is_some() { 1 } else { 0 };
    let mut data: Vec<(String, Vec<String>)> = Vec::new(); // (group key, column cells)
    for row in &rows {
        let gkey = if group.is_some() {
            row.try_get::<Option<String>, _>(0).ok().flatten().unwrap_or_default()
        } else {
            String::new()
        };
        let mut cells = Vec::with_capacity(def.columns.len());
        for i in 0..def.columns.len() {
            let v: Option<String> = row.try_get(i + group_offset).ok().flatten();
            cells.push(v.unwrap_or_default());
        }
        data.push((gkey, cells));
    }

    let headers: Vec<String> = def.columns.iter().map(|c| c.label.clone()).collect();
    let total_rows = data.len();

    // Group rows (single group when not grouping; rows are pre-sorted by key).
    let mut groups: Vec<GroupBlock> = Vec::new();
    for (gkey, cells) in data.iter() {
        let start_new = match groups.last() {
            None => true,
            Some(g) => group.is_some() && &g.key != gkey,
        };
        if start_new {
            groups.push(GroupBlock { key: gkey.clone(), rows: Vec::new(), subtotals: Vec::new() });
        }
        groups.last_mut().unwrap().rows.push(cells.clone());
    }

    // Compute subtotals per group and grand totals.
    for g in &mut groups {
        g.subtotals = aggregate_columns(&def.columns, &g.rows);
    }
    let all_rows: Vec<Vec<String>> = data.into_iter().map(|(_, c)| c).collect();
    let grand_totals = aggregate_columns(&def.columns, &all_rows);
    let group_label = group.map(|g| {
        def.columns
            .iter()
            .find(|c| c.field == g)
            .map(|c| c.label.clone())
            .unwrap_or_else(|| g.to_string())
    });

    Ok(TabularResult { headers, group_label, groups, grand_totals, total_rows })
}

/// Compute each column's aggregate over a set of rows.
fn aggregate_columns(cols: &[ReportColumn], rows: &[Vec<String>]) -> Vec<Option<String>> {
    cols.iter()
        .enumerate()
        .map(|(i, c)| {
            if !c.aggregate.is_measure() {
                return None;
            }
            if c.aggregate == Aggregate::Count {
                return Some(rows.len().to_string());
            }
            let nums: Vec<f64> = rows
                .iter()
                .filter_map(|r| r.get(i))
                .filter_map(|v| v.trim().parse::<f64>().ok())
                .collect();
            if nums.is_empty() {
                return Some(String::new());
            }
            let val = match c.aggregate {
                Aggregate::Sum => nums.iter().sum(),
                Aggregate::Avg => nums.iter().sum::<f64>() / nums.len() as f64,
                Aggregate::Min => nums.iter().cloned().fold(f64::INFINITY, f64::min),
                Aggregate::Max => nums.iter().cloned().fold(f64::NEG_INFINITY, f64::max),
                _ => 0.0,
            };
            Some(format!("{val:.2}"))
        })
        .collect()
}

/// Render a tabular result as an HTML table fragment (no page chrome).
pub fn render_tabular_html(def: &ReportDef, res: &TabularResult) -> String {
    let has_totals = res.grand_totals.iter().any(|t| t.is_some());
    let ncol = res.headers.len();

    let mut thead = String::from("<tr>");
    for h in &res.headers {
        thead.push_str(&format!(r#"<th class="text-left">{}</th>"#, html_escape(h)));
    }
    thead.push_str("</tr>");

    let mut body = String::new();
    let grouped = res.group_label.is_some();
    for g in &res.groups {
        if grouped {
            let key = if g.key.is_empty() { "(none)".to_string() } else { g.key.clone() };
            body.push_str(&format!(
                r#"<tr class="bg-base-200 font-semibold"><td colspan="{ncol}">{label}: {key} <span class="opacity-60">({n})</span></td></tr>"#,
                ncol = ncol,
                label = html_escape(res.group_label.as_deref().unwrap_or("")),
                key = html_escape(&key),
                n = g.rows.len(),
            ));
        }
        for row in &g.rows {
            body.push_str("<tr>");
            for cell in row {
                body.push_str(&format!("<td>{}</td>", html_escape(cell)));
            }
            body.push_str("</tr>");
        }
        if grouped && g.subtotals.iter().any(|s| s.is_some()) {
            body.push_str(r#"<tr class="border-t font-medium text-base-content/80">"#);
            for (i, sub) in g.subtotals.iter().enumerate() {
                let label = if i == 0 { "Subtotal" } else { "" };
                let val = sub.clone().unwrap_or_default();
                body.push_str(&format!("<td>{} {}</td>", label, html_escape(&val)));
            }
            body.push_str("</tr>");
        }
    }

    let mut tfoot = String::new();
    if has_totals {
        tfoot.push_str(r#"<tr class="border-t-2 font-bold">"#);
        for (i, t) in res.grand_totals.iter().enumerate() {
            let label = if i == 0 { "Total" } else { "" };
            tfoot.push_str(&format!("<td>{} {}</td>", label, html_escape(&t.clone().unwrap_or_default())));
        }
        tfoot.push_str("</tr>");
    }

    format!(
        r#"<table class="table table-sm w-full"><thead>{thead}</thead><tbody>{body}</tbody><tfoot>{tfoot}</tfoot></table>
<p class="text-sm opacity-60 mt-2">{n} rows · report "{name}"</p>"#,
        thead = thead,
        body = body,
        tfoot = tfoot,
        n = res.total_rows,
        name = html_escape(&def.name),
    )
}

/// Render a tabular result as CSV bytes (RFC 4180 quoting; group as first col).
pub fn render_tabular_csv(res: &TabularResult) -> Vec<u8> {
    let q = |s: &str| format!("\"{}\"", s.replace('"', "\"\""));
    let mut out = String::new();
    let grouped = res.group_label.is_some();
    if grouped {
        out.push_str(&q(res.group_label.as_deref().unwrap_or("Group")));
        out.push(',');
    }
    out.push_str(&res.headers.iter().map(|h| q(h)).collect::<Vec<_>>().join(","));
    out.push('\n');
    for g in &res.groups {
        for row in &g.rows {
            if grouped {
                out.push_str(&q(&g.key));
                out.push(',');
            }
            out.push_str(&row.iter().map(|c| q(c)).collect::<Vec<_>>().join(","));
            out.push('\n');
        }
    }
    out.into_bytes()
}

/// Render a tabular result as JSON (array of row objects).
pub fn render_tabular_json(res: &TabularResult) -> String {
    let mut arr: Vec<serde_json::Value> = Vec::new();
    for g in &res.groups {
        for row in &g.rows {
            let mut obj = serde_json::Map::new();
            if res.group_label.is_some() {
                obj.insert("_group".into(), serde_json::Value::String(g.key.clone()));
            }
            for (h, cell) in res.headers.iter().zip(row.iter()) {
                obj.insert(h.clone(), serde_json::Value::String(cell.clone()));
            }
            arr.push(serde_json::Value::Object(obj));
        }
    }
    serde_json::to_string_pretty(&serde_json::Value::Array(arr)).unwrap_or_else(|_| "[]".into())
}

// ─── Template shape ──────────────────────────────────────────────────────

/// Fetch the raw records for a template report as field->value maps (escaped
/// at render time). Reuses the same safe column logic as tabular but selects
/// every visible field of the model.
pub async fn fetch_template_records(
    db: &PgPool,
    def: &ReportDef,
) -> Result<Vec<BTreeMap<String, String>>, String> {
    let table = model_table(db, &def.model_name)
        .await
        .ok_or_else(|| format!("unknown model '{}'", def.model_name))?;
    if !ident(&table) {
        return Err("invalid model table".into());
    }
    let fields = model_fields(db, &def.model_name).await;
    let names: Vec<String> = fields.keys().filter(|n| ident(n)).cloned().collect();
    if names.is_empty() {
        return Err("model has no registered fields".into());
    }
    let select = names.iter().map(|n| format!("t.{n}::text AS {n}")).collect::<Vec<_>>().join(", ");

    let mut where_parts: Vec<String> = Vec::new();
    let mut binds: Vec<String> = Vec::new();
    for fl in &def.filters {
        if !ident(&fl.field) || !fields.contains_key(&fl.field) || !valid_operator(&fl.operator) {
            return Err(format!("invalid filter on '{}'", fl.field));
        }
        let n = binds.len() + 1;
        where_parts.push(format!("t.{}::text {} ${}", fl.field, fl.operator, n));
        let raw = fl.value.clone().unwrap_or_default();
        binds.push(if fl.operator == "ilike" { format!("%{raw}%") } else { raw });
    }
    let where_sql = if where_parts.is_empty() { String::new() } else { format!(" WHERE {}", where_parts.join(" AND ")) };
    let limit = def.row_limit.clamp(1, 100_000);
    let sql = format!("SELECT {select} FROM {table} t{where_sql} LIMIT {limit}");

    let mut q = sqlx::query(&sql);
    for b in &binds {
        q = q.bind(b);
    }
    let rows = q.fetch_all(db).await.map_err(|e| format!("query failed: {e}"))?;
    let mut out = Vec::new();
    for row in &rows {
        let mut map = BTreeMap::new();
        for n in &names {
            let v: Option<String> = row.try_get(n.as_str()).ok().flatten();
            map.insert(n.clone(), v.unwrap_or_default());
        }
        out.push(map);
    }
    Ok(out)
}

// ─── Sandboxed template engine ───────────────────────────────────────────

#[derive(Debug)]
enum Node {
    Text(String),
    Var(String),
    For { var: String, body: Vec<Node> },
    If { cond: String, body: Vec<Node>, els: Vec<Node> },
}

/// Render a sandboxed template. Supported syntax (data is HTML-escaped; the
/// surrounding markup is trusted authored HTML):
/// * `{{ path }}` — dotted lookup against the current record then globals
/// * `{% for x in records %}…{% endfor %}` — iterate the report's records
/// * `{% if path %}…{% else %}…{% endif %}` — truthy test (non-empty, not 0/false)
pub fn render_template(
    template: &str,
    records: &[BTreeMap<String, String>],
    globals: &BTreeMap<String, String>,
) -> String {
    let tokens = tokenize(template);
    let mut pos = 0;
    let nodes = parse_nodes(&tokens, &mut pos, &[]);
    let mut out = String::new();
    let scope: Vec<&BTreeMap<String, String>> = Vec::new();
    render_nodes(&nodes, records, globals, &scope, &mut out);
    out
}

#[derive(Debug, Clone)]
enum Token {
    Text(String),
    Var(String),
    Tag(String),
}

fn tokenize(s: &str) -> Vec<Token> {
    let mut tokens = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    let mut text_start = 0;
    while i < bytes.len() {
        if bytes[i] == b'{' && i + 1 < bytes.len() && (bytes[i + 1] == b'{' || bytes[i + 1] == b'%') {
            if i > text_start {
                tokens.push(Token::Text(s[text_start..i].to_string()));
            }
            let open = bytes[i + 1];
            let (close_a, close_b) = if open == b'{' { (b'}', b'}') } else { (b'%', b'}') };
            // find closing
            let mut j = i + 2;
            while j + 1 < bytes.len() && !(bytes[j] == close_a && bytes[j + 1] == close_b) {
                j += 1;
            }
            let inner = s[i + 2..j].trim().to_string();
            if open == b'{' {
                tokens.push(Token::Var(inner));
            } else {
                tokens.push(Token::Tag(inner));
            }
            i = j + 2;
            text_start = i;
        } else {
            i += 1;
        }
    }
    if text_start < bytes.len() {
        tokens.push(Token::Text(s[text_start..].to_string()));
    }
    tokens
}

/// Parse a node list until a terminator tag in `stop` is hit (consumed by caller).
fn parse_nodes(tokens: &[Token], pos: &mut usize, stop: &[&str]) -> Vec<Node> {
    let mut nodes = Vec::new();
    while *pos < tokens.len() {
        match &tokens[*pos] {
            Token::Text(t) => {
                nodes.push(Node::Text(t.clone()));
                *pos += 1;
            }
            Token::Var(v) => {
                nodes.push(Node::Var(v.clone()));
                *pos += 1;
            }
            Token::Tag(tag) => {
                let head = tag.split_whitespace().next().unwrap_or("");
                if stop.contains(&head) {
                    return nodes; // leave terminator for caller to consume
                }
                match head {
                    "for" => {
                        // for <var> in records
                        let parts: Vec<&str> = tag.split_whitespace().collect();
                        let var = parts.get(1).cloned().unwrap_or("item").to_string();
                        *pos += 1;
                        let body = parse_nodes(tokens, pos, &["endfor"]);
                        consume_tag(tokens, pos, "endfor");
                        nodes.push(Node::For { var, body });
                    }
                    "if" => {
                        let cond = tag[2..].trim().to_string();
                        *pos += 1;
                        let body = parse_nodes(tokens, pos, &["else", "endif"]);
                        let mut els = Vec::new();
                        if matches!(tokens.get(*pos), Some(Token::Tag(t)) if t.trim_start().starts_with("else")) {
                            *pos += 1; // consume else
                            els = parse_nodes(tokens, pos, &["endif"]);
                        }
                        consume_tag(tokens, pos, "endif");
                        nodes.push(Node::If { cond, body, els });
                    }
                    _ => {
                        // unknown tag — emit nothing, skip
                        *pos += 1;
                    }
                }
            }
        }
    }
    nodes
}

fn consume_tag(tokens: &[Token], pos: &mut usize, name: &str) {
    if let Some(Token::Tag(t)) = tokens.get(*pos) {
        if t.split_whitespace().next() == Some(name) {
            *pos += 1;
        }
    }
}

fn lookup(
    path: &str,
    record: Option<&BTreeMap<String, String>>,
    globals: &BTreeMap<String, String>,
) -> String {
    // Strip a leading "<loopvar>." so `c.name` and `name` both work.
    let key = match path.split_once('.') {
        Some((_, rest)) => rest,
        None => path,
    };
    if let Some(rec) = record {
        if let Some(v) = rec.get(key).or_else(|| rec.get(path)) {
            return v.clone();
        }
    }
    globals.get(path).or_else(|| globals.get(key)).cloned().unwrap_or_default()
}

fn truthy(v: &str) -> bool {
    let t = v.trim();
    !(t.is_empty() || t == "0" || t.eq_ignore_ascii_case("false"))
}

fn render_nodes(
    nodes: &[Node],
    records: &[BTreeMap<String, String>],
    globals: &BTreeMap<String, String>,
    scope: &[&BTreeMap<String, String>],
    out: &mut String,
) {
    let current = scope.last().copied();
    for node in nodes {
        match node {
            Node::Text(t) => out.push_str(t),
            Node::Var(v) => out.push_str(&html_escape(&lookup(v, current, globals))),
            Node::For { var: _, body } => {
                for rec in records {
                    let mut inner = scope.to_vec();
                    inner.push(rec);
                    render_nodes(body, records, globals, &inner, out);
                }
            }
            Node::If { cond, body, els } => {
                if truthy(&lookup(cond, current, globals)) {
                    render_nodes(body, records, globals, scope, out);
                } else {
                    render_nodes(els, records, globals, scope, out);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn template_loop_and_escape() {
        let recs = vec![rec(&[("name", "Lee"), ("city", "KL")]), rec(&[("name", "<b>X</b>"), ("city", "JB")])];
        let g = BTreeMap::new();
        let out = render_template("{% for c in records %}<li>{{ c.name }} - {{ city }}</li>{% endfor %}", &recs, &g);
        assert_eq!(out, "<li>Lee - KL</li><li>&lt;b&gt;X&lt;/b&gt; - JB</li>");
    }

    #[test]
    fn template_if_else() {
        let recs = vec![rec(&[("active", "true"), ("name", "A")]), rec(&[("active", ""), ("name", "B")])];
        let g = BTreeMap::new();
        let out = render_template(
            "{% for c in records %}{% if active %}ON:{{name}}{% else %}OFF:{{name}}{% endif %};{% endfor %}",
            &recs,
            &g,
        );
        assert_eq!(out, "ON:A;OFF:B;");
    }

    #[test]
    fn template_globals() {
        let g: BTreeMap<String, String> = [("report_name".to_string(), "Q1".to_string())].into_iter().collect();
        let out = render_template("Report: {{ report_name }}", &[], &g);
        assert_eq!(out, "Report: Q1");
    }

    #[test]
    fn aggregate_sum_and_count() {
        let cols = vec![
            ReportColumn { field: "name".into(), label: "Name".into(), aggregate: Aggregate::Count },
            ReportColumn { field: "amt".into(), label: "Amt".into(), aggregate: Aggregate::Sum },
        ];
        let rows = vec![
            vec!["a".to_string(), "10".to_string()],
            vec!["b".to_string(), "5.5".to_string()],
        ];
        let totals = aggregate_columns(&cols, &rows);
        assert_eq!(totals[0], Some("2".to_string()));
        assert_eq!(totals[1], Some("15.50".to_string()));
    }

    #[test]
    fn operators_allowlist() {
        assert!(valid_operator("ilike"));
        assert!(!valid_operator("; DROP TABLE"));
        assert!(!ident("a; DROP"));
        assert!(ident("credit_limit"));
    }
}
