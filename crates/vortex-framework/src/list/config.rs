//! [`ListConfig`] and [`ListColumn`] — declarative list definition.

/// How a column renders its cell values.
#[derive(Debug, Clone)]
pub enum CellRenderer {
    /// Plain text (default).
    Text,
    /// DaisyUI badge — maps values to CSS classes.
    Badge(Vec<(&'static str, &'static str, &'static str)>), // (value, label, css)
    /// Boolean badge (active/inactive).
    BoolBadge {
        true_label: &'static str,
        true_css: &'static str,
        false_label: &'static str,
        false_css: &'static str,
    },
    /// Monospace font (for codes, IDs).
    Code,
}

/// A column in the list view.
#[derive(Debug, Clone)]
pub struct ListColumn {
    /// Database column name.
    pub field: &'static str,
    /// Display label in the header.
    pub label: &'static str,
    /// Whether the header is clickable to sort.
    pub sortable: bool,
    /// Whether this column is included in free-text search (ILIKE).
    pub searchable: bool,
    /// Filter options — if non-empty, a dropdown filter appears.
    pub filter_options: Vec<(&'static str, &'static str)>, // (value, label)
    /// How to render cell values.
    pub renderer: CellRenderer,
    /// SQL expression for WHERE/ORDER clauses when the column is a
    /// JOINed alias. e.g. for `country_name` (aliased from `co.name`),
    /// set this to `"co.name"` so search and filter use the real
    /// expression. If None, uses `field` directly.
    pub sql_expr: Option<&'static str>,
}

impl ListColumn {
    pub fn new(field: &'static str, label: &'static str) -> Self {
        Self {
            field,
            label,
            sortable: false,
            searchable: false,
            filter_options: Vec::new(),
            renderer: CellRenderer::Text,
            sql_expr: None,
        }
    }

    pub fn sortable(mut self) -> Self {
        self.sortable = true;
        self
    }

    pub fn searchable(mut self) -> Self {
        self.searchable = true;
        self
    }

    /// Add a dropdown filter with fixed options.
    pub fn filterable(mut self, options: &[(&'static str, &'static str)]) -> Self {
        self.filter_options = options.to_vec();
        self
    }

    /// Render as a DaisyUI badge. Each tuple is (db_value, display_label, css_class).
    pub fn badge(mut self, mappings: &[(&'static str, &'static str, &'static str)]) -> Self {
        self.renderer = CellRenderer::Badge(mappings.to_vec());
        self
    }

    /// Render boolean values as a badge.
    pub fn bool_badge(
        mut self,
        true_label: &'static str,
        true_css: &'static str,
        false_label: &'static str,
        false_css: &'static str,
    ) -> Self {
        self.renderer = CellRenderer::BoolBadge {
            true_label,
            true_css,
            false_label,
            false_css,
        };
        self
    }

    /// Render in monospace (for codes, IDs).
    pub fn code(mut self) -> Self {
        self.renderer = CellRenderer::Code;
        self
    }

    /// Set the SQL expression used in WHERE/ORDER for JOINed columns.
    /// e.g. `.sql_expr("co.name")` for a column aliased as `country_name`.
    pub fn sql_expr(mut self, expr: &'static str) -> Self {
        self.sql_expr = Some(expr);
        self
    }
}

/// Full configuration for a list view.
#[derive(Debug, Clone)]
pub struct ListConfig {
    /// Page title.
    pub title: &'static str,
    /// SQL table name to query.
    pub table: &'static str,
    /// Columns to display.
    pub columns: Vec<ListColumn>,
    /// URL template for row clicks, with `{id}` placeholder.
    /// e.g. `/contacts/{id}`
    pub detail_url: Option<&'static str>,
    /// Label for the create button. None = no button.
    pub create_label: Option<&'static str>,
    /// URL for the create action.
    pub create_url: Option<&'static str>,
    /// Default sort column.
    pub default_sort: &'static str,
    /// Extra WHERE clause appended to every query (e.g. "active = true").
    pub base_filter: Option<&'static str>,
    /// Available group-by columns.
    pub group_options: Vec<(&'static str, &'static str)>, // (field, label)
    /// Custom FROM clause with JOINs. When set, overrides the simple
    /// `FROM <table>` with the full expression. The columns in
    /// `select_fields()` must match the aliases used here.
    ///
    /// Example: `"contacts c LEFT JOIN countries co ON co.id = c.country_id"`
    pub custom_from: Option<&'static str>,
    /// Custom SELECT field list. When set, overrides `select_fields()`.
    /// Use this when JOINs bring in columns that need aliases.
    pub custom_select: Option<&'static str>,
    /// URL for the pivot view button. When set, a "Pivot" button appears
    /// next to the create button. Typically `/pivot/<model>?rows=<field>`.
    /// Requires the model to be registered in `ir_model` / `ir_model_field`.
    pub pivot_url: Option<&'static str>,
    /// Opt into keyset (cursor) pagination for large tables. When enabled and
    /// the sort is a plain base-table column (no `custom_from` JOIN), the list
    /// seeks by a `(sort, id)` cursor instead of `LIMIT/OFFSET` and drops the
    /// `COUNT(*)` — so navigation stays O(log n) at any depth on millions of
    /// rows, at the cost of Prev/Next navigation instead of numbered pages.
    /// Falls back to OFFSET when not applicable.
    pub keyset: bool,
}

impl ListConfig {
    pub fn new(title: &'static str, table: &'static str) -> Self {
        Self {
            title,
            table,
            columns: Vec::new(),
            detail_url: None,
            create_label: None,
            create_url: None,
            default_sort: "id",
            base_filter: None,
            group_options: Vec::new(),
            custom_from: None,
            custom_select: None,
            pivot_url: None,
            keyset: false,
        }
    }

    pub fn column(mut self, col: ListColumn) -> Self {
        self.columns.push(col);
        self
    }

    pub fn detail_url(mut self, url: &'static str) -> Self {
        self.detail_url = Some(url);
        self
    }

    pub fn create(mut self, label: &'static str, url: &'static str) -> Self {
        self.create_label = Some(label);
        self.create_url = Some(url);
        self
    }

    pub fn default_sort(mut self, field: &'static str) -> Self {
        self.default_sort = field;
        self
    }

    pub fn base_filter(mut self, clause: &'static str) -> Self {
        self.base_filter = Some(clause);
        self
    }

    pub fn group_by_options(mut self, options: &[(&'static str, &'static str)]) -> Self {
        self.group_options = options.to_vec();
        self
    }

    /// Set a custom FROM clause with JOINs. Use table aliases and
    /// match them in `custom_select`.
    pub fn custom_from(mut self, from: &'static str) -> Self {
        self.custom_from = Some(from);
        self
    }

    /// Set a custom SELECT field list (with aliases for JOINed columns).
    pub fn custom_select(mut self, select: &'static str) -> Self {
        self.custom_select = Some(select);
        self
    }

    /// Enable the pivot-view button in the list header.
    pub fn pivot_url(mut self, url: &'static str) -> Self {
        self.pivot_url = Some(url);
        self
    }

    /// Opt into keyset (cursor) pagination — see [`ListConfig::keyset`]. Enable
    /// for large tables where deep OFFSET paging would scan-and-discard.
    pub fn keyset(mut self) -> Self {
        self.keyset = true;
        self
    }

    /// Get searchable SQL expressions (uses `sql_expr` when set).
    pub fn searchable_exprs(&self) -> Vec<&str> {
        self.columns
            .iter()
            .filter(|c| c.searchable)
            .map(|c| c.sql_expr.unwrap_or(c.field))
            .collect()
    }

    /// Find the SQL expression for a given field name.
    pub fn sql_expr_for(&self, field: &str) -> Option<&str> {
        self.columns
            .iter()
            .find(|c| c.field == field)
            .map(|c| c.sql_expr.unwrap_or(c.field))
    }

    /// Get the SQL column list for SELECT.
    pub fn select_fields(&self) -> String {
        let mut fields: Vec<&str> = vec!["id"];
        for col in &self.columns {
            if col.field != "id" {
                fields.push(col.field);
            }
        }
        fields.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> ListConfig {
        ListConfig::new("Contacts", "contacts")
            .column(ListColumn::new("code", "Code").searchable())
            .column(ListColumn::new("name", "Name").searchable())
            .column(ListColumn::new("country_name", "Country").searchable().sql_expr("co.name"))
            .column(ListColumn::new("note", "Note"))
    }

    #[test]
    fn sql_expr_for_returns_only_configured_columns() {
        let c = config();
        // Plain column maps to itself.
        assert_eq!(c.sql_expr_for("name"), Some("name"));
        // JOINed column maps to its real expression.
        assert_eq!(c.sql_expr_for("country_name"), Some("co.name"));
        // Anything not configured is rejected — this is the allowlist
        // that keeps request input out of the identifier position.
        assert_eq!(c.sql_expr_for("nope"), None);
        assert_eq!(c.sql_expr_for("name; DROP TABLE x"), None);
    }

    #[test]
    fn searchable_exprs_uses_sql_expr_when_present() {
        let c = config();
        let exprs = c.searchable_exprs();
        // `note` is not searchable and is excluded; country uses co.name.
        assert_eq!(exprs, vec!["code", "name", "co.name"]);
    }

    #[test]
    fn select_fields_lists_id_first_without_duplication() {
        // Even if a column is explicitly named "id", it isn't repeated.
        let c = ListConfig::new("X", "t")
            .column(ListColumn::new("id", "ID"))
            .column(ListColumn::new("name", "Name"));
        assert_eq!(c.select_fields(), "id, name");
    }
}
