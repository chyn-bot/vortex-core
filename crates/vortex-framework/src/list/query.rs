//! SQL generation for list views — SELECT + COUNT with dynamic
//! filters, search, sort, group, and pagination.
//!
//! Two pagination strategies share this builder:
//!
//! - **OFFSET** (default) — `LIMIT n OFFSET (page-1)*n` plus a `COUNT(*)` for
//!   the total. Simple, gives numbered pages and an exact total, but the
//!   `OFFSET` scans-and-discards and the `COUNT(*)` is O(rows) — both degrade
//!   on large tables at depth.
//! - **Keyset** (opt-in via [`ListConfig::keyset`]) — seeks by a `(sort, id)`
//!   cursor and drops the `COUNT(*)`, so navigation stays O(log n) at any depth.
//!   Engaged only when the sort is a plain base-table column (no `custom_from`
//!   JOIN); otherwise this falls back to OFFSET automatically.

use sqlx::{PgPool, Row, postgres::PgRow};
use vortex_common::{VortexError, VortexResult};

use super::config::ListConfig;
use super::params::{ListParams, SortDir};

/// Result of executing a list query — rows + pagination metadata.
#[derive(Debug)]
pub struct ListResult {
    pub rows: Vec<PgRow>,
    /// Total matching rows. `-1` when the list ran in keyset mode, where the
    /// `COUNT(*)` is deliberately skipped (navigation is by cursor, not page).
    pub total: i64,
    pub page: u64,
    pub page_size: u64,
    pub total_pages: u64,
    /// Keyset cursor for the *next* page (`Some` only in keyset mode when a
    /// next page exists). Feed back as `?after=`.
    pub next_cursor: Option<String>,
    /// Keyset cursor for the *previous* page. Feed back as `?before=`.
    pub prev_cursor: Option<String>,
    /// `total` is a `reltuples` estimate, not an exact count (unfiltered browse
    /// on an estimate-enabled list). The UI shows it as approximate (`~N`).
    pub estimated: bool,
}

impl ListResult {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Whether this result was produced by the keyset (cursor) path.
    pub fn is_keyset(&self) -> bool {
        self.total < 0
    }
}

/// A fully-rendered pair of SQL strings plus the positional bind
/// values they share. Produced by [`build_list_sql`] without touching
/// the database, so the generation logic is unit-testable in isolation
/// from execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListSql {
    /// `SELECT COUNT(*) FROM ... WHERE ...`. Empty in keyset mode (no count).
    pub count_sql: String,
    /// `SELECT ... FROM ... WHERE ... ORDER BY ... LIMIT ... [OFFSET ...]`
    pub data_sql: String,
    /// Positional bind values, in `$1, $2, ...` order, shared by both
    /// queries. All user-supplied *values* live here as bound params;
    /// never interpolated into the SQL.
    pub binds: Vec<String>,
    /// True when the keyset path was used (no count; `data_sql` fetches
    /// `page_size + 1` rows to detect a following page).
    pub keyset: bool,
    /// True when this is a *backward* (`before`) keyset query: the rows come
    /// back in reversed order and must be flipped to display order.
    pub reversed: bool,
    /// True when the total should come from a `reltuples` estimate rather than
    /// running `count_sql` (unfiltered browse on an estimate-enabled list).
    pub estimate_count: bool,
}

/// Resolve the effective sort expression and direction from params, falling
/// back to the configured default when the requested field is unknown.
fn resolve_sort<'a>(config: &'a ListConfig, params: &ListParams) -> (&'a str, SortDir) {
    let sort_field_name = params.sort_field.as_deref().unwrap_or(config.default_sort);
    let sort_expr = config.sql_expr_for(sort_field_name).unwrap_or_else(|| {
        config.sql_expr_for(config.default_sort).unwrap_or(config.default_sort)
    });
    (sort_expr, params.sort_dir)
}

/// Is keyset pagination usable for this request? Requires the opt-in, a plain
/// `FROM table` (so the cursor subquery can re-derive the boundary row), and a
/// base-table sort column (no JOIN-qualified expression).
fn keyset_applicable(config: &ListConfig, sort_expr: &str) -> bool {
    config.keyset && config.custom_from.is_none() && !sort_expr.contains('.')
}

/// Build the count + data SQL and bind values for a list query.
///
/// Security invariants (unchanged across both pagination modes):
/// - **Identifiers** (table, column, sort expression, direction) come only from
///   `ListConfig` (`&'static str`) or the [`SortDir`] enum — never request input.
///   Request sort/filter *keys* resolve through `config.sql_expr_for()`, which
///   returns a value only for configured columns; unknown keys are dropped.
/// - **Values** (search, filters, the keyset cursor) are always positional
///   binds (`$N`), never interpolated.
/// - `LIMIT`/`OFFSET` are `u64` from clamped [`ListParams`], so interpolating
///   them is safe.
pub(crate) fn build_list_sql(config: &ListConfig, params: &ListParams) -> ListSql {
    let (sort_expr, sort_dir) = resolve_sort(config, params);
    let from_clause = config.custom_from.unwrap_or(config.table);
    let select_fields = config
        .custom_select
        .map(String::from)
        .unwrap_or_else(|| config.select_fields());

    let (mut conditions, mut binds) = build_where(config, params);

    if keyset_applicable(config, sort_expr) {
        // A cursor is honoured only if it's a well-formed id (uuid) — a
        // malformed or tampered cursor falls back to the first page instead of
        // erroring, and can never reach the SQL.
        let cursor = params
            .before
            .as_ref()
            .or(params.after.as_ref())
            .filter(|c| uuid::Uuid::parse_str(c).is_ok());

        if let Some(cursor) = cursor {
            // Keyset seek. `reversed` (backward nav) flips the comparison, the
            // ORDER BY, and — at execution — the row order.
            let reversed = params.before.is_some();
            // Forward (after): ASC → rows greater than the cursor; DESC → less
            // than. Backward (before) inverts that.
            let forward_gt = matches!(sort_dir, SortDir::Asc);
            let cmp = if forward_gt ^ reversed { ">" } else { "<" };

            let idx = binds.len() + 1;
            // The boundary row is re-derived by primary key inside the subquery,
            // so the row comparison uses native column types on both sides — no
            // type-encoded cursor. Casting the *parameter* (`$n::uuid`), not the
            // column, keeps the pk-index seek that finds the boundary row (a
            // `id::text = $n` predicate would force a full scan).
            let seek = if sort_expr == "id" {
                format!(
                    "id {cmp} (SELECT id FROM {from} WHERE id = ${idx}::uuid)",
                    cmp = cmp, from = from_clause, idx = idx,
                )
            } else {
                format!(
                    "({s}, id) {cmp} (SELECT {s}, id FROM {from} WHERE id = ${idx}::uuid)",
                    s = sort_expr, cmp = cmp, from = from_clause, idx = idx,
                )
            };
            conditions.push(seek);
            binds.push(cursor.clone());

            let where_clause = assemble_where(&conditions);
            let order_clause = build_order_clause(config, params, reversed);
            // Fetch one extra row to detect whether a further page exists.
            let data_sql = format!(
                "SELECT {} FROM {} {} ORDER BY {} LIMIT {}",
                select_fields, from_clause, where_clause, order_clause, params.page_size + 1,
            );
            return ListSql {
                count_sql: String::new(), data_sql, binds,
                keyset: true, reversed, estimate_count: false,
            };
        }

        // Keyset first page: no cursor, no offset, no count — just the head.
        let where_clause = assemble_where(&conditions);
        let order_clause = build_order_clause(config, params, false);
        let data_sql = format!(
            "SELECT {} FROM {} {} ORDER BY {} LIMIT {}",
            select_fields, from_clause, where_clause, order_clause, params.page_size + 1,
        );
        return ListSql {
            count_sql: String::new(), data_sql, binds,
            keyset: true, reversed: false, estimate_count: false,
        };
    }

    // ── OFFSET path (default) ────────────────────────────────────────────
    // A reltuples estimate is only valid for the whole table, so it applies
    // only when nothing narrows the result (no base filter / search / filter).
    let estimate_count = config.estimate_count && conditions.is_empty();
    let where_clause = assemble_where(&conditions);
    let count_sql = format!("SELECT COUNT(*) FROM {} {}", from_clause, where_clause);
    let order_clause = build_order_clause(config, params, false);
    let data_sql = format!(
        "SELECT {} FROM {} {} ORDER BY {} LIMIT {} OFFSET {}",
        select_fields, from_clause, where_clause, order_clause, params.page_size, params.offset(),
    );
    ListSql { count_sql, data_sql, binds, keyset: false, reversed: false, estimate_count }
}

/// Build the `ORDER BY` body (without the `ORDER BY` keyword).
///
/// Always ends with an `id` tiebreaker so the ordering is a strict *total*
/// order — required for keyset correctness, and it also stabilises OFFSET
/// paging when the sort column has duplicate values. When `reverse` is set
/// (backward keyset nav) every direction is flipped. A group-by expression is
/// prepended (ascending) so grouped rows stay contiguous.
fn build_order_clause(config: &ListConfig, params: &ListParams, reverse: bool) -> String {
    let (sort_expr, sort_dir) = resolve_sort(config, params);
    let dir = if reverse { sort_dir.opposite() } else { sort_dir };

    let group_expr = params.group_by.as_deref().and_then(|g| config.sql_expr_for(g));
    let group_dir = if reverse { "DESC" } else { "ASC" };

    // The id tiebreaker is redundant when already sorting by id.
    let tiebreak = if sort_expr == "id" {
        String::new()
    } else {
        format!(", id {}", dir.as_sql())
    };

    match group_expr {
        Some(ge) if ge != sort_expr => {
            format!("{} {}, {} {}{}", ge, group_dir, sort_expr, dir.as_sql(), tiebreak)
        }
        _ => format!("{} {}{}", sort_expr, dir.as_sql(), tiebreak),
    }
}

/// Assemble a `WHERE ...` clause (or empty string) from condition fragments.
fn assemble_where(conditions: &[String]) -> String {
    if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    }
}

/// Extract a row's `id` as a cursor string. Keyset uses the platform's uuid
/// primary key; a list over a non-uuid pk simply shouldn't opt into keyset.
fn row_id_text(row: &PgRow) -> Option<String> {
    row.try_get::<uuid::Uuid, _>("id").ok().map(|u| u.to_string())
}

/// Execute the list query. OFFSET mode runs COUNT + data; keyset mode runs data
/// only (fetching one extra row to detect a following page) and returns cursors.
pub async fn execute_list(
    pool: &PgPool,
    config: &ListConfig,
    params: &ListParams,
) -> VortexResult<ListResult> {
    let sql = build_list_sql(config, params);

    if sql.keyset {
        return execute_keyset(pool, params, sql).await;
    }

    let ListSql { count_sql, data_sql, binds, estimate_count, .. } = sql;

    // Unfiltered browse on an estimate-enabled list: use the planner's
    // reltuples estimate (O(1)) instead of an exact COUNT(*) (O(rows)). A
    // never-analysed table reports reltuples < 0 → fall back to the exact count.
    let (total, estimated) = if estimate_count {
        let est: Option<i64> = sqlx::query_scalar(
            "SELECT reltuples::bigint FROM pg_class WHERE oid = to_regclass($1)",
        )
        .bind(config.table)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
        match est {
            Some(n) if n >= 0 => (n, true),
            _ => (run_exact_count(pool, &count_sql, &binds).await?, false),
        }
    } else {
        (run_exact_count(pool, &count_sql, &binds).await?, false)
    };

    let mut data_q = sqlx::query(&data_sql);
    for val in &binds {
        data_q = data_q.bind(val);
    }
    let rows = data_q
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("list data: {e}")))?;

    let total_pages = if total > 0 {
        ((total as u64) + params.page_size - 1) / params.page_size
    } else {
        0
    };

    Ok(ListResult {
        rows,
        total,
        page: params.page,
        page_size: params.page_size,
        total_pages,
        next_cursor: None,
        prev_cursor: None,
        estimated,
    })
}

/// Run the exact `COUNT(*)` for the list's WHERE clause.
async fn run_exact_count(pool: &PgPool, count_sql: &str, binds: &[String]) -> VortexResult<i64> {
    let mut count_q = sqlx::query_scalar::<_, i64>(count_sql);
    for val in binds {
        count_q = count_q.bind(val);
    }
    count_q
        .fetch_one(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("list count: {e}")))
}

/// Keyset execution: run only the data query, trim the sentinel extra row,
/// restore display order for backward nav, and compute Prev/Next cursors.
async fn execute_keyset(pool: &PgPool, params: &ListParams, sql: ListSql) -> VortexResult<ListResult> {
    let ListSql { data_sql, binds, reversed, .. } = sql;

    let mut data_q = sqlx::query(&data_sql);
    for val in &binds {
        data_q = data_q.bind(val);
    }
    let mut rows = data_q
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("list keyset: {e}")))?;

    // One row beyond `page_size` means another page exists in the direction we
    // fetched. Drop the sentinel before display.
    let has_more = rows.len() as u64 > params.page_size;
    if has_more {
        rows.truncate(params.page_size as usize);
    }
    // Backward nav fetched in reversed order; flip back to display order.
    if reversed {
        rows.reverse();
    }

    let first_id = rows.first().and_then(row_id_text);
    let last_id = rows.last().and_then(row_id_text);

    // Cursor logic:
    // - forward/first page: a Next exists iff we saw the sentinel; a Prev exists
    //   iff we arrived via a cursor.
    // - backward page: a Prev exists iff we saw the sentinel; a Next always
    //   exists (the page we came from).
    let (next_cursor, prev_cursor) = if reversed {
        let prev = if has_more { first_id.clone() } else { None };
        let next = last_id.clone();
        (next, prev)
    } else {
        let next = if has_more { last_id.clone() } else { None };
        let prev = if params.after.is_some() { first_id.clone() } else { None };
        (next, prev)
    };

    Ok(ListResult {
        rows,
        total: -1,
        page: params.page,
        page_size: params.page_size,
        total_pages: 0,
        estimated: false,
        next_cursor,
        prev_cursor,
    })
}

/// Build the WHERE condition fragments and their positional bind values.
/// Returns the fragments (not yet joined) so callers can append a keyset seek
/// with the correct next parameter index.
fn build_where(config: &ListConfig, params: &ListParams) -> (Vec<String>, Vec<String>) {
    let mut conditions: Vec<String> = Vec::new();
    let mut bind_values: Vec<String> = Vec::new();
    let mut param_idx = 0usize;

    // Base filter (e.g. "active = true")
    if let Some(base) = config.base_filter {
        conditions.push(base.to_string());
    }

    // Free-text search — ILIKE across all searchable columns (uses sql_expr for JOINed columns)
    let searchable = config.searchable_exprs();
    if let Some(search) = &params.search {
        if !searchable.is_empty() && !search.trim().is_empty() {
            param_idx += 1;
            let ilike_parts: Vec<String> = searchable
                .iter()
                .map(|expr| format!("COALESCE({}::text, '') ILIKE ${}", expr, param_idx))
                .collect();
            conditions.push(format!("({})", ilike_parts.join(" OR ")));
            bind_values.push(format!("%{}%",
                search.replace('%', "\\%").replace('_', "\\_")
            ));
        }
    }

    // Column-level filters (uses sql_expr for JOINed columns)
    for (field, value) in &params.filters {
        if let Some(sql_expr) = config.sql_expr_for(field) {
            param_idx += 1;
            conditions.push(format!("{} = ${}", sql_expr, param_idx));
            bind_values.push(value.clone());
        }
    }

    (conditions, bind_values)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::list::config::{ListColumn, ListConfig};
    use crate::list::params::{ListParams, SortDir};
    use std::collections::HashMap;

    /// A small representative config: a base table with a plain code,
    /// a searchable name, a filterable type, and a JOINed country name
    /// that sorts/searches on its real expression `co.name`.
    fn contacts_config() -> ListConfig {
        ListConfig::new("Contacts", "contacts")
            .column(ListColumn::new("code", "Code").sortable().code())
            .column(ListColumn::new("name", "Name").sortable().searchable())
            .column(ListColumn::new("email", "Email").searchable())
            .column(
                ListColumn::new("contact_type", "Type")
                    .filterable(&[("customer", "Customer"), ("supplier", "Supplier")]),
            )
            .column(
                ListColumn::new("country_name", "Country")
                    .sortable()
                    .searchable()
                    .sql_expr("co.name"),
            )
            .default_sort("name")
    }

    fn params_with(f: impl FnOnce(&mut ListParams)) -> ListParams {
        let mut p = ListParams::default();
        f(&mut p);
        p
    }

    #[test]
    fn minimal_query_no_filters() {
        let sql = build_list_sql(&contacts_config(), &ListParams::default());
        assert_eq!(sql.count_sql, "SELECT COUNT(*) FROM contacts ");
        assert!(sql.binds.is_empty());
        assert!(!sql.keyset);
        assert!(sql.data_sql.starts_with(
            "SELECT id, code, name, email, contact_type, country_name FROM contacts"
        ));
        // Default sort, ascending, with an id tiebreaker and clamped pagination.
        assert!(sql.data_sql.contains("ORDER BY name ASC, id ASC LIMIT 25 OFFSET 0"), "got: {}", sql.data_sql);
    }

    #[test]
    fn search_builds_ilike_across_searchable_and_escapes_wildcards() {
        let params = params_with(|p| p.search = Some("a%b_c".into()));
        let sql = build_list_sql(&contacts_config(), &params);
        let expected = "(COALESCE(name::text, '') ILIKE $1 OR \
             COALESCE(email::text, '') ILIKE $1 OR \
             COALESCE(co.name::text, '') ILIKE $1)";
        assert!(sql.data_sql.contains(expected), "got: {}", sql.data_sql);
        assert!(sql.count_sql.contains(expected));
        assert_eq!(sql.binds, vec![r"%a\%b\_c%".to_string()]);
    }

    #[test]
    fn blank_search_is_ignored() {
        let params = params_with(|p| p.search = Some("   ".into()));
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(!sql.data_sql.contains("ILIKE"));
        assert!(sql.binds.is_empty());
    }

    #[test]
    fn filters_only_apply_to_configured_columns() {
        let mut filters = HashMap::new();
        filters.insert("contact_type".to_string(), "customer".to_string());
        filters.insert("totally_made_up".to_string(), "x".to_string());
        let params = params_with(|p| p.filters = filters);
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("contact_type = $1"));
        assert_eq!(sql.binds, vec!["customer".to_string()]);
        assert!(!sql.data_sql.contains("totally_made_up"));
    }

    #[test]
    fn filter_key_cannot_inject_sql_identifier() {
        let mut filters = HashMap::new();
        filters.insert("id; DROP TABLE contacts; --".to_string(), "1".to_string());
        let params = params_with(|p| p.filters = filters);
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(!sql.data_sql.to_uppercase().contains("DROP"));
        assert!(sql.binds.is_empty());
    }

    #[test]
    fn filter_value_is_bound_never_interpolated() {
        let mut filters = HashMap::new();
        filters.insert(
            "contact_type".to_string(),
            "'; DROP TABLE contacts; --".to_string(),
        );
        let params = params_with(|p| p.filters = filters);
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("contact_type = $1"));
        assert!(!sql.data_sql.to_uppercase().contains("DROP"));
        assert_eq!(sql.binds, vec!["'; DROP TABLE contacts; --".to_string()]);
    }

    #[test]
    fn base_filter_and_search_combine_with_and() {
        let config = contacts_config().base_filter("active = true");
        let params = params_with(|p| p.search = Some("x".into()));
        let sql = build_list_sql(&config, &params);
        assert!(sql.data_sql.contains("WHERE active = true AND ("));
        assert_eq!(sql.binds, vec!["%x%".to_string()]);
    }

    #[test]
    fn unknown_sort_field_falls_back_to_default() {
        let params = params_with(|p| p.sort_field = Some("nope".into()));
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("ORDER BY name ASC, id ASC"));
    }

    #[test]
    fn sort_resolves_joined_column_through_sql_expr() {
        let params = params_with(|p| {
            p.sort_field = Some("country_name".into());
            p.sort_dir = SortDir::Desc;
        });
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("ORDER BY co.name DESC, id DESC"));
    }

    #[test]
    fn group_by_prepends_group_expression() {
        let params = params_with(|p| {
            p.group_by = Some("contact_type".into());
            p.sort_field = Some("name".into());
        });
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("ORDER BY contact_type ASC, name ASC, id ASC"));
    }

    #[test]
    fn sort_by_id_has_no_duplicate_tiebreaker() {
        let config = contacts_config().default_sort("id");
        let sql = build_list_sql(&config, &ListParams::default());
        assert!(sql.data_sql.contains("ORDER BY id ASC LIMIT"), "got: {}", sql.data_sql);
        assert!(!sql.data_sql.contains("id ASC, id ASC"));
    }

    #[test]
    fn custom_from_and_select_override_defaults() {
        let config = contacts_config()
            .custom_from("contacts c LEFT JOIN countries co ON co.id = c.country_id")
            .custom_select("c.id, c.name, co.name AS country_name");
        let sql = build_list_sql(&config, &ListParams::default());
        assert!(sql.data_sql.contains(
            "SELECT c.id, c.name, co.name AS country_name \
             FROM contacts c LEFT JOIN countries co ON co.id = c.country_id"
        ));
    }

    #[test]
    fn pagination_translates_to_limit_and_offset() {
        let params = params_with(|p| {
            p.page = 3;
            p.page_size = 50;
        });
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("LIMIT 50 OFFSET 100"));
    }

    // ── Keyset ────────────────────────────────────────────────────────────

    fn keyset_config() -> ListConfig {
        // Plain table (no custom_from) so keyset engages.
        ListConfig::new("Contacts", "contacts")
            .column(ListColumn::new("name", "Name").sortable().searchable())
            .default_sort("name")
            .keyset()
    }

    #[test]
    fn keyset_first_page_has_no_offset_and_no_count() {
        let sql = build_list_sql(&keyset_config(), &ListParams::default());
        assert!(sql.keyset);
        assert!(sql.count_sql.is_empty(), "keyset must not run COUNT(*)");
        assert!(!sql.data_sql.contains("OFFSET"));
        // page_size + 1 to detect a following page.
        assert!(sql.data_sql.contains("ORDER BY name ASC, id ASC LIMIT 26"), "got: {}", sql.data_sql);
    }

    // A well-formed cursor id (uuid) for the seek tests.
    const CUR: &str = "11111111-1111-1111-1111-111111111111";

    #[test]
    fn keyset_after_cursor_seeks_forward_asc() {
        let params = params_with(|p| p.after = Some(CUR.into()));
        let sql = build_list_sql(&keyset_config(), &params);
        assert!(sql.keyset && !sql.reversed);
        // Forward + ASC → greater-than; boundary re-derived by a pk-index seek
        // (parameter cast to uuid, not the column).
        assert!(sql.data_sql.contains(
            "(name, id) > (SELECT name, id FROM contacts WHERE id = $1::uuid)"
        ), "got: {}", sql.data_sql);
        assert!(sql.data_sql.contains("ORDER BY name ASC, id ASC LIMIT 26"));
        assert_eq!(sql.binds, vec![CUR.to_string()]);
    }

    #[test]
    fn keyset_before_cursor_reverses_comparison_and_order() {
        let params = params_with(|p| p.before = Some(CUR.into()));
        let sql = build_list_sql(&keyset_config(), &params);
        assert!(sql.keyset && sql.reversed);
        // Backward + ASC → less-than, and the ORDER flips to DESC (rows are
        // reversed back to display order at execution).
        assert!(sql.data_sql.contains(
            "(name, id) < (SELECT name, id FROM contacts WHERE id = $1::uuid)"
        ), "got: {}", sql.data_sql);
        assert!(sql.data_sql.contains("ORDER BY name DESC, id DESC LIMIT 26"));
    }

    #[test]
    fn keyset_desc_after_seeks_less_than() {
        let params = params_with(|p| {
            p.after = Some(CUR.into());
            p.sort_dir = SortDir::Desc;
        });
        let sql = build_list_sql(&keyset_config(), &params);
        assert!(sql.data_sql.contains(
            "(name, id) < (SELECT name, id FROM contacts WHERE id = $1::uuid)"
        ), "got: {}", sql.data_sql);
        assert!(sql.data_sql.contains("ORDER BY name DESC, id DESC LIMIT 26"));
    }

    #[test]
    fn keyset_falls_back_to_offset_with_custom_from() {
        // A JOINed list can't keyset (cursor subquery needs a plain table).
        let config = keyset_config()
            .custom_from("contacts c LEFT JOIN countries co ON co.id = c.country_id")
            .custom_select("c.id, c.name");
        let params = params_with(|p| p.after = Some(CUR.into()));
        let sql = build_list_sql(&config, &params);
        assert!(!sql.keyset, "keyset must not engage with custom_from");
        assert!(sql.data_sql.contains("OFFSET"));
        assert!(!sql.data_sql.contains("::uuid"));
    }

    #[test]
    fn keyset_tampered_cursor_is_dropped_not_interpolated() {
        // A non-uuid (e.g. injection) cursor is not a valid id, so it is
        // ignored entirely — no seek, no bind — falling back to the first page.
        let params = params_with(|p| p.after = Some("'; DROP TABLE contacts; --".into()));
        let sql = build_list_sql(&keyset_config(), &params);
        assert!(sql.keyset);
        assert!(!sql.data_sql.to_uppercase().contains("DROP"));
        assert!(!sql.data_sql.contains("::uuid"), "no seek for an invalid cursor");
        assert!(sql.binds.is_empty());
    }

    #[test]
    fn keyset_seek_shares_param_index_after_filters() {
        // A search ($1) then a cursor must land on $2.
        let params = params_with(|p| {
            p.search = Some("ac".into());
            p.after = Some(CUR.into());
        });
        let sql = build_list_sql(&keyset_config(), &params);
        assert!(sql.data_sql.contains("ILIKE $1"));
        assert!(sql.data_sql.contains("id = $2::uuid"), "got: {}", sql.data_sql);
        assert_eq!(sql.binds, vec![r"%ac%".to_string(), CUR.to_string()]);
    }

    // ── Count estimate ────────────────────────────────────────────────────

    #[test]
    fn estimate_count_engages_only_when_unfiltered() {
        let cfg = contacts_config().estimate_count();
        // Unfiltered browse → estimate.
        assert!(build_list_sql(&cfg, &ListParams::default()).estimate_count);
        // A search narrows the set → exact count.
        let searched = params_with(|p| p.search = Some("x".into()));
        assert!(!build_list_sql(&cfg, &searched).estimate_count);
        // A column filter → exact count.
        let mut f = HashMap::new();
        f.insert("contact_type".to_string(), "customer".to_string());
        let filtered = params_with(|p| p.filters = f);
        assert!(!build_list_sql(&cfg, &filtered).estimate_count);
        // A base filter → exact count (the whole-table estimate wouldn't match).
        let based = contacts_config().estimate_count().base_filter("active = true");
        assert!(!build_list_sql(&based, &ListParams::default()).estimate_count);
    }

    #[test]
    fn estimate_count_off_without_optin() {
        assert!(!build_list_sql(&contacts_config(), &ListParams::default()).estimate_count);
    }

    #[test]
    fn count_and_data_share_the_same_where_and_binds() {
        let params = params_with(|p| {
            p.search = Some("acme".into());
            let mut f = HashMap::new();
            f.insert("contact_type".to_string(), "customer".to_string());
            p.filters = f;
        });
        let sql = build_list_sql(&contacts_config(), &params);
        let where_in_count = sql.count_sql.split_once("WHERE").map(|(_, w)| w.trim());
        let where_in_data = sql
            .data_sql
            .split_once("WHERE")
            .and_then(|(_, w)| w.split_once("ORDER BY"))
            .map(|(w, _)| w.trim());
        assert_eq!(where_in_count, where_in_data);
        assert_eq!(sql.binds.len(), 2);
    }
}
