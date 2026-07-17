//! SQL generation for list views — SELECT + COUNT with dynamic
//! filters, search, sort, group, and pagination.

use sqlx::{PgPool, postgres::PgRow};
use vortex_common::{VortexError, VortexResult};

use super::config::ListConfig;
use super::params::ListParams;

/// Row-count threshold above which an unfiltered single-table list uses
/// the planner's `pg_class.reltuples` estimate instead of an exact
/// `COUNT(*)`. Below this, an exact count is cheap and worth its accuracy;
/// above it, a full-table `COUNT(*)` on every page load is the dominant
/// cost of browsing (≈1.3s on a 12M-row table) for a number nobody reads
/// precisely past the first few significant digits.
const ESTIMATE_THRESHOLD: i64 = 50_000;

/// Result of executing a list query — rows + total count.
#[derive(Debug)]
pub struct ListResult {
    pub rows: Vec<PgRow>,
    pub total: i64,
    /// True when `total` is a planner estimate (`reltuples`) rather than
    /// an exact `COUNT(*)`. The UI renders it with a `~` prefix. Only set
    /// for large, unfiltered, single-table lists; any filter/search makes
    /// the count exact again.
    pub total_is_estimate: bool,
    pub page: u64,
    pub page_size: u64,
    pub total_pages: u64,
}

impl ListResult {
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }
}

/// A fully-rendered pair of SQL strings plus the positional bind
/// values they share. Produced by [`build_list_sql`] without touching
/// the database, so the generation logic is unit-testable in isolation
/// from execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ListSql {
    /// `SELECT COUNT(*) FROM ... WHERE ...`
    pub count_sql: String,
    /// `SELECT ... FROM ... WHERE ... ORDER BY ... LIMIT ... OFFSET ...`
    pub data_sql: String,
    /// Positional bind values, in `$1, $2, ...` order, shared by both
    /// queries. All user-supplied *values* live here as bound params;
    /// never interpolated into the SQL string.
    pub binds: Vec<String>,
}

/// Build the count + data SQL and bind values for a list query.
///
/// This is the security-critical core of the list framework, so its
/// invariants are worth stating explicitly:
///
/// - **Identifiers** (table, column, sort expression, FROM/SELECT
///   clauses, sort direction) are only ever sourced from `ListConfig`
///   (`&'static str`) or the two-variant [`SortDir`] enum — never from
///   request input. Request-supplied sort/filter/group *keys* are
///   resolved through `config.sql_expr_for()`, which returns a value
///   only for configured columns; unknown keys are silently dropped.
/// - **Values** (search text, filter values) are always emitted as
///   positional binds (`$N`) and collected into `binds`, never
///   interpolated into the SQL.
/// - `LIMIT`/`OFFSET` are `u64` derived from clamped [`ListParams`]
///   (page ≥ 1, page_size ∈ [5, 200]), so interpolating them is safe.
pub(crate) fn build_list_sql(config: &ListConfig, params: &ListParams) -> ListSql {
    let parts = build_conditions(config, params);

    let from_clause = config.custom_from.unwrap_or(config.table);
    let select_fields = config
        .custom_select
        .map(String::from)
        .unwrap_or_else(|| config.select_fields());

    let (cte_prefix, where_clause) = assemble_where(config, &parts);

    let count_sql = format!("{}SELECT COUNT(*) FROM {} {}", cte_prefix, from_clause, where_clause);

    let order_clause = build_order_clause(config, params);

    let data_sql = format!(
        "{}SELECT {} FROM {} {} ORDER BY {} LIMIT {} OFFSET {}",
        cte_prefix,
        select_fields,
        from_clause,
        where_clause,
        order_clause,
        params.page_size,
        params.offset(),
    );

    ListSql { count_sql, data_sql, binds: parts.binds }
}

/// Assemble the query's leading CTE (if any) and its final `WHERE` clause
/// from the decomposed [`Conditions`]. Returns `(cte_prefix, where_clause)`;
/// `cte_prefix` is either empty or a `WITH … ` string the caller prepends to
/// **both** the count and data statements.
///
/// Two shapes, depending on `search_prefilter`:
/// - **Default:** base filter, search, and column filters are AND-ed inline
///   (`WHERE base AND (…ILIKE $1…) AND col = $2`) — the historical shape.
/// - **Prefiltered:** when a search is active *and* `search_prefilter` is
///   set, the search moves into a `MATERIALIZED` CTE so a trigram index can
///   drive it and — crucially — the planner sorts the *materialized match
///   set* for `ORDER BY … LIMIT`, rather than walking the sort-column index
///   across the whole table hunting for a page of matches:
///   `WITH _list_match AS MATERIALIZED (SELECT id FROM <base> WHERE …ILIKE $1…)
///    … WHERE base AND col = $2 AND <alias>.id IN (SELECT id FROM _list_match)`.
///   `MATERIALIZED` is load-bearing: without the fence, a search whose matches
///   sort *late* (e.g. `PreCustomer…` names in a table dominated by
///   `Customer…`) makes the planner scan millions of index rows and time out.
///   The parameter numbering is unchanged (search is still `$1`), so `binds`
///   order is identical either way.
fn assemble_where(config: &ListConfig, parts: &Conditions) -> (String, String) {
    let mut conds: Vec<String> = Vec::new();
    let mut cte_prefix = String::new();
    if let Some(base) = &parts.base_filter {
        conds.push(base.clone());
    }

    match (&parts.search, config.search_prefilter, config.prefilter_alias()) {
        // Prefiltered search: base + column filters inline, search via a
        // materialized CTE referenced by `id IN (SELECT id FROM _list_match)`.
        (Some(search), Some(prefilter_from), Some(alias)) => {
            conds.extend(parts.filters.iter().cloned());
            cte_prefix = format!(
                "WITH _list_match AS MATERIALIZED (SELECT {alias}.id FROM {from} WHERE {search}) ",
                alias = alias,
                from = prefilter_from,
                search = search,
            );
            conds.push(format!("{alias}.id IN (SELECT id FROM _list_match)", alias = alias));
        }
        // Default: inline search then column filters (historical order).
        _ => {
            if let Some(search) = &parts.search {
                conds.push(search.clone());
            }
            conds.extend(parts.filters.iter().cloned());
        }
    }

    let where_clause = if conds.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conds.join(" AND "))
    };
    (cte_prefix, where_clause)
}

/// Build the `ORDER BY` body (without the `ORDER BY` keyword).
///
/// Resolves the requested sort field through `sql_expr` so JOINed
/// columns sort on their real expression, falling back to the
/// configured default when the requested field is unknown. When a
/// group-by is active and differs from the sort expression, the group
/// expression is prepended (ascending) so grouped rows stay contiguous.
///
/// A stable `id` tiebreaker is appended for simple single-table lists so
/// that rows with equal sort values (e.g. millions of contacts sharing a
/// `created_at`) get a **total** order. Without it, the sort is
/// only partial and Postgres may return tied rows in a different physical
/// order per page — making `LIMIT/OFFSET` pagination silently skip or
/// repeat records across page boundaries. It also lets a composite index
/// `(sort_col, id)` satisfy the ordering by an index scan rather than a
/// full sort. The tiebreaker is skipped when a `custom_from` join is in
/// play (bare `id` could be ambiguous) or when `id` is already the sort
/// key.
fn build_order_clause(config: &ListConfig, params: &ListParams) -> String {
    let sort_field_name = params.sort_field.as_deref().unwrap_or(config.default_sort);
    let sort_expr = config.sql_expr_for(sort_field_name).unwrap_or_else(|| {
        // Fall back to default sort if the requested field is unknown
        config.sql_expr_for(config.default_sort).unwrap_or(config.default_sort)
    });

    let group_expr = params.group_by.as_deref().and_then(|g| config.sql_expr_for(g));

    let mut order = match group_expr {
        Some(ge) if ge != sort_expr => {
            format!("{} ASC, {} {}", ge, sort_expr, params.sort_dir.as_sql())
        }
        _ => format!("{} {}", sort_expr, params.sort_dir.as_sql()),
    };

    // Deterministic tiebreaker — see the doc comment above. An explicit
    // `config.tiebreak` (e.g. `"c.id"`) wins; otherwise a simple
    // single-table list gets bare `id`. Ascending to match the natural
    // `(sort_col <dir>, id)` composite index layout; any fixed direction
    // gives a stable total order.
    let tiebreak = config
        .tiebreak
        .or_else(|| config.custom_from.is_none().then_some("id"));
    if let Some(tb) = tiebreak {
        if tb != sort_expr && group_expr != Some(tb) {
            order.push_str(", ");
            order.push_str(tb);
        }
    }

    order
}

/// Execute the list query against the database. Runs two queries:
/// 1. COUNT(*) for the total matching rows (ignoring pagination)
/// 2. SELECT with LIMIT/OFFSET for the current page
///
/// Both share the same WHERE clause so the count is consistent
/// with the displayed rows.
pub async fn execute_list(
    pool: &PgPool,
    config: &ListConfig,
    params: &ListParams,
) -> VortexResult<ListResult> {
    let ListSql { count_sql, data_sql, binds } = build_list_sql(config, params);

    // Count strategy: an unfiltered list only needs an *exact* count when
    // the table is small. On large tables the exact `COUNT(*)` is a full
    // scan run on every page load, so we substitute the planner's
    // `reltuples` estimate. The estimable relation is the plain table for a
    // single-table list, or `count_estimate_from` when the author has
    // asserted a joined list is cardinality-preserving. Any WHERE
    // condition — base filter, search, or column filter — forces an exact
    // count so the number always matches what the user actually filtered.
    let estimate_table = config
        .count_estimate_from
        .or_else(|| config.custom_from.is_none().then_some(config.table));
    let unfiltered = config.base_filter.is_none() && binds.is_empty();

    let (total, total_is_estimate) = match estimate_table {
        Some(table) if unfiltered => match estimate_row_count(pool, table).await {
            Some(est) if est >= ESTIMATE_THRESHOLD => (est, true),
            _ => (exact_count(pool, &count_sql, &binds).await?, false),
        },
        _ => (exact_count(pool, &count_sql, &binds).await?, false),
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
        total_is_estimate,
        page: params.page,
        page_size: params.page_size,
        total_pages,
    })
}

/// Run the exact `SELECT COUNT(*)` with its bound values.
async fn exact_count(pool: &PgPool, count_sql: &str, binds: &[String]) -> VortexResult<i64> {
    let mut count_q = sqlx::query_scalar::<_, i64>(count_sql);
    for val in binds {
        count_q = count_q.bind(val);
    }
    count_q
        .fetch_one(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("list count: {e}")))
}

/// Fast approximate row count from planner statistics. `reltuples` is
/// maintained by `ANALYZE`/autovacuum and is accurate to a few percent on
/// an actively-vacuumed table — good enough to size a browse view.
///
/// Returns `None` (so the caller falls back to an exact count) when the
/// relation is unknown, has never been analyzed (`reltuples = -1`), or the
/// lookup errors. `table` originates from `ListConfig` (`&'static str`),
/// never request input, and is bound as a value cast to `regclass`.
async fn estimate_row_count(pool: &PgPool, table: &str) -> Option<i64> {
    let est: Option<f32> = sqlx::query_scalar("SELECT reltuples FROM pg_class WHERE oid = $1::regclass")
        .bind(table)
        .fetch_optional(pool)
        .await
        .ok()
        .flatten();
    match est {
        Some(r) if r >= 0.0 => Some(r as i64),
        _ => None,
    }
}

/// Decomposed WHERE conditions plus their positional bind values.
///
/// Kept as parts (rather than a single joined string) so
/// [`assemble_where`] can place the search either inline or inside an
/// `id IN (…)` prefilter subquery without changing bind numbering.
struct Conditions {
    /// Static base filter (`config.base_filter`), no bind.
    base_filter: Option<String>,
    /// Free-text search predicate `(… ILIKE $1 …)`, present only when a
    /// non-blank search was supplied. Always uses `$1`.
    search: Option<String>,
    /// Column-equality filters, each `expr = $N` (N ≥ 2 when a search is
    /// present, else N ≥ 1).
    filters: Vec<String>,
    /// Bind values in `$1, $2, …` order: search value first (if any),
    /// then one per column filter.
    binds: Vec<String>,
}

/// Build the decomposed WHERE conditions and positional bind values from
/// ListConfig + ListParams. Parameter numbering matches the order the
/// binds are returned in: search is `$1`, column filters follow.
fn build_conditions(config: &ListConfig, params: &ListParams) -> Conditions {
    let mut binds: Vec<String> = Vec::new();
    let mut param_idx = 0usize;

    let base_filter = config.base_filter.map(str::to_string);

    // Free-text search — ILIKE across all searchable columns (uses sql_expr for JOINed columns)
    let searchable = config.searchable_exprs();
    let mut search = None;
    if let Some(s) = &params.search {
        if !searchable.is_empty() && !s.trim().is_empty() {
            param_idx += 1;
            let ilike_parts: Vec<String> = searchable
                .iter()
                .map(|expr| format!("COALESCE({}::text, '') ILIKE ${}", expr, param_idx))
                .collect();
            search = Some(format!("({})", ilike_parts.join(" OR ")));
            binds.push(format!("%{}%", s.replace('%', "\\%").replace('_', "\\_")));
        }
    }

    // Column-level filters (uses sql_expr for JOINed columns)
    let mut filters: Vec<String> = Vec::new();
    for (field, value) in &params.filters {
        if let Some(sql_expr) = config.sql_expr_for(field) {
            param_idx += 1;
            filters.push(format!("{} = ${}", sql_expr, param_idx));
            binds.push(value.clone());
        }
    }

    Conditions { base_filter, search, filters, binds }
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
        // No WHERE clause, count and data agree on the (empty) filter.
        assert_eq!(sql.count_sql, "SELECT COUNT(*) FROM contacts ");
        assert!(sql.binds.is_empty());
        // id is always selected first, then the configured columns.
        assert!(sql.data_sql.starts_with(
            "SELECT id, code, name, email, contact_type, country_name FROM contacts"
        ));
        // Default sort, ascending, with a stable `id` tiebreaker and
        // clamped pagination.
        assert!(sql.data_sql.contains("ORDER BY name ASC, id LIMIT 25 OFFSET 0"));
    }

    #[test]
    fn order_by_appends_id_tiebreaker_for_single_table() {
        // Without a total order, tied sort values make LIMIT/OFFSET
        // pages skip or repeat rows. The `id` tiebreaker prevents that.
        let sql = build_list_sql(&contacts_config(), &ListParams::default());
        assert!(sql.data_sql.contains("ORDER BY name ASC, id "), "got: {}", sql.data_sql);
    }

    #[test]
    fn tiebreaker_skipped_for_custom_from_joins() {
        // A bare `id` would be ambiguous across joined tables, so the
        // tiebreaker is omitted; the join's own ordering stands.
        let config = contacts_config()
            .custom_from("contacts c LEFT JOIN countries co ON co.id = c.country_id")
            .custom_select("c.id, c.name");
        let sql = build_list_sql(&config, &ListParams::default());
        assert!(sql.data_sql.contains("ORDER BY name ASC LIMIT"), "got: {}", sql.data_sql);
        assert!(!sql.data_sql.contains(", id LIMIT"));
    }

    #[test]
    fn explicit_tiebreak_applies_to_joined_lists() {
        // A joined list opts back into a stable order by naming the
        // qualified PK, which the framework appends verbatim.
        let config = contacts_config()
            .custom_from("contacts c LEFT JOIN countries co ON co.id = c.country_id")
            .custom_select("c.id, c.name")
            .tiebreak("c.id");
        let sql = build_list_sql(&config, &ListParams::default());
        assert!(sql.data_sql.contains("ORDER BY name ASC, c.id LIMIT"), "got: {}", sql.data_sql);
    }

    #[test]
    fn tiebreaker_not_duplicated_when_sorting_by_id() {
        let config = ListConfig::new("X", "t")
            .column(ListColumn::new("id", "ID").sortable())
            .default_sort("id");
        let sql = build_list_sql(&config, &ListParams::default());
        assert!(sql.data_sql.contains("ORDER BY id ASC LIMIT"), "got: {}", sql.data_sql);
        assert!(!sql.data_sql.contains("id ASC, id"));
    }

    #[test]
    fn search_builds_ilike_across_searchable_and_escapes_wildcards() {
        // `%` and `_` are LIKE metacharacters and must be escaped so a
        // search for "50%" doesn't match everything.
        let params = params_with(|p| p.search = Some("a%b_c".into()));
        let sql = build_list_sql(&contacts_config(), &params);

        // Searchable columns are `name`, `email`, and `country_name`
        // (which searches on its sql_expr `co.name`), all against $1.
        let expected = "(COALESCE(name::text, '') ILIKE $1 OR \
             COALESCE(email::text, '') ILIKE $1 OR \
             COALESCE(co.name::text, '') ILIKE $1)";
        assert!(sql.data_sql.contains(expected), "got: {}", sql.data_sql);
        assert!(sql.count_sql.contains(expected));
        // The value is bound, with wildcards backslash-escaped.
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
        // One configured filter and one bogus key the client made up.
        let mut filters = HashMap::new();
        filters.insert("contact_type".to_string(), "customer".to_string());
        filters.insert("totally_made_up".to_string(), "x".to_string());
        let params = params_with(|p| p.filters = filters);

        let sql = build_list_sql(&contacts_config(), &params);
        // The configured filter is applied as a bound parameter.
        assert!(sql.data_sql.contains("contact_type = $1"));
        assert_eq!(sql.binds, vec!["customer".to_string()]);
        // The unconfigured key never reaches the SQL in any form.
        assert!(!sql.data_sql.contains("totally_made_up"));
    }

    #[test]
    fn filter_key_cannot_inject_sql_identifier() {
        // A malicious filter *key* is not a configured column, so it is
        // dropped wholesale — it can never become an identifier.
        let mut filters = HashMap::new();
        filters.insert("id; DROP TABLE contacts; --".to_string(), "1".to_string());
        let params = params_with(|p| p.filters = filters);

        let sql = build_list_sql(&contacts_config(), &params);
        assert!(!sql.data_sql.to_uppercase().contains("DROP"));
        assert!(sql.binds.is_empty());
    }

    #[test]
    fn filter_value_is_bound_never_interpolated() {
        // A malicious filter *value* on a real column is passed as a
        // bind, so the SQL text stays clean.
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
        assert!(sql.data_sql.contains("ORDER BY name ASC"));
    }

    #[test]
    fn sort_resolves_joined_column_through_sql_expr() {
        let params = params_with(|p| {
            p.sort_field = Some("country_name".into());
            p.sort_dir = SortDir::Desc;
        });
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("ORDER BY co.name DESC"));
    }

    #[test]
    fn group_by_prepends_group_expression() {
        let params = params_with(|p| {
            p.group_by = Some("contact_type".into());
            p.sort_field = Some("name".into());
        });
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("ORDER BY contact_type ASC, name ASC"));
    }

    #[test]
    fn group_by_equal_to_sort_is_not_duplicated() {
        let params = params_with(|p| {
            p.group_by = Some("name".into());
            p.sort_field = Some("name".into());
        });
        let sql = build_list_sql(&contacts_config(), &params);
        assert!(sql.data_sql.contains("ORDER BY name ASC"));
        assert!(!sql.data_sql.contains("name ASC, name ASC"));
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
        assert!(sql.count_sql.contains(
            "FROM contacts c LEFT JOIN countries co ON co.id = c.country_id"
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

    #[test]
    fn search_prefilter_wraps_search_in_materialized_cte() {
        // With search_prefilter set, a search moves into a MATERIALIZED CTE
        // (so a trigram index drives it AND the planner sorts the small match
        // set for ORDER BY … LIMIT instead of walking the sort-column index),
        // referenced by `id IN (SELECT id FROM _list_match)`. Base/column
        // filters stay inline. Search is still $1.
        let config = contacts_config()
            .custom_from("contacts c LEFT JOIN countries co ON co.id = c.country_id")
            .custom_select("c.id, c.name")
            .search_prefilter("contacts c")
            .base_filter("c.active = true");
        let mut filters = HashMap::new();
        filters.insert("contact_type".to_string(), "customer".to_string());
        let params = params_with(|p| {
            p.search = Some("acme".into());
            p.filters = filters;
        });
        let sql = build_list_sql(&config, &params);

        // The search lives in a leading MATERIALIZED CTE on the base alias,
        // using $1; both statements start with it.
        assert!(
            sql.data_sql.starts_with(
                "WITH _list_match AS MATERIALIZED (SELECT c.id FROM contacts c WHERE (COALESCE(name::text, '') ILIKE $1"
            ),
            "got: {}",
            sql.data_sql
        );
        assert!(sql.count_sql.starts_with("WITH _list_match AS MATERIALIZED (SELECT c.id FROM contacts c WHERE"));
        // Base filter and the column filter stay inline; the search is a
        // cheap membership test against the materialized set.
        assert!(sql.data_sql.contains(
            "WHERE c.active = true AND contact_type = $2 AND c.id IN (SELECT id FROM _list_match)"
        ), "got: {}", sql.data_sql);
        assert!(sql.count_sql.contains("c.id IN (SELECT id FROM _list_match)"));
        // Binds: search first ($1), then the column filter ($2).
        assert_eq!(sql.binds, vec!["%acme%".to_string(), "customer".to_string()]);
    }

    #[test]
    fn search_prefilter_inactive_without_search_is_plain() {
        // No search → no subquery, even with prefilter configured.
        let config = contacts_config().search_prefilter("contacts c");
        let mut filters = HashMap::new();
        filters.insert("contact_type".to_string(), "customer".to_string());
        let params = params_with(|p| p.filters = filters);
        let sql = build_list_sql(&config, &params);
        assert!(!sql.data_sql.contains(" IN ("));
        assert!(sql.data_sql.contains("contact_type = $1"));
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
        // Both queries must filter identically or the count is a lie.
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
