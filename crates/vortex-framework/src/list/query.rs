//! SQL generation for list views — SELECT + COUNT with dynamic
//! filters, search, sort, group, and pagination.

use sqlx::{PgPool, postgres::PgRow};
use vortex_common::{VortexError, VortexResult};

use super::config::ListConfig;
use super::params::ListParams;

/// Result of executing a list query — rows + total count.
#[derive(Debug)]
pub struct ListResult {
    pub rows: Vec<PgRow>,
    pub total: i64,
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
    let (where_clause, binds) = build_where(config, params);

    let from_clause = config.custom_from.unwrap_or(config.table);
    let select_fields = config
        .custom_select
        .map(String::from)
        .unwrap_or_else(|| config.select_fields());

    let count_sql = format!("SELECT COUNT(*) FROM {} {}", from_clause, where_clause);

    let order_clause = build_order_clause(config, params);

    let data_sql = format!(
        "SELECT {} FROM {} {} ORDER BY {} LIMIT {} OFFSET {}",
        select_fields,
        from_clause,
        where_clause,
        order_clause,
        params.page_size,
        params.offset(),
    );

    ListSql { count_sql, data_sql, binds }
}

/// Build the `ORDER BY` body (without the `ORDER BY` keyword).
///
/// Resolves the requested sort field through `sql_expr` so JOINed
/// columns sort on their real expression, falling back to the
/// configured default when the requested field is unknown. When a
/// group-by is active and differs from the sort expression, the group
/// expression is prepended (ascending) so grouped rows stay contiguous.
fn build_order_clause(config: &ListConfig, params: &ListParams) -> String {
    let sort_field_name = params.sort_field.as_deref().unwrap_or(config.default_sort);
    let sort_expr = config.sql_expr_for(sort_field_name).unwrap_or_else(|| {
        // Fall back to default sort if the requested field is unknown
        config.sql_expr_for(config.default_sort).unwrap_or(config.default_sort)
    });

    let group_expr = params.group_by.as_deref().and_then(|g| config.sql_expr_for(g));

    match group_expr {
        Some(ge) if ge != sort_expr => {
            format!("{} ASC, {} {}", ge, sort_expr, params.sort_dir.as_sql())
        }
        _ => format!("{} {}", sort_expr, params.sort_dir.as_sql()),
    }
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

    let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql);
    for val in &binds {
        count_q = count_q.bind(val);
    }
    let total = count_q
        .fetch_one(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("list count: {e}")))?;

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
    })
}

/// Build the WHERE clause and positional bind values from
/// ListConfig + ListParams.
fn build_where(config: &ListConfig, params: &ListParams) -> (String, Vec<String>) {
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

    let where_clause = if conditions.is_empty() {
        String::new()
    } else {
        format!("WHERE {}", conditions.join(" AND "))
    };

    (where_clause, bind_values)
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
        // Default sort, ascending, with clamped pagination.
        assert!(sql.data_sql.contains("ORDER BY name ASC LIMIT 25 OFFSET 0"));
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
