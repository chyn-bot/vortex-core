//! Microsoft SQL Server dialect implementation

use super::{DatabaseBackend, NullsPosition, SqlDialect};
use crate::field::FieldType;

/// Microsoft SQL Server dialect
#[derive(Debug, Clone, Copy, Default)]
pub struct MssqlDialect;

impl SqlDialect for MssqlDialect {
    fn backend(&self) -> DatabaseBackend {
        DatabaseBackend::MsSql
    }

    fn param_placeholder(&self, index: i32) -> String {
        format!("@p{}", index)
    }

    fn field_type_to_sql(&self, field_type: &FieldType) -> String {
        match field_type {
            FieldType::Serial => "INT IDENTITY(1,1)".to_string(),
            FieldType::Uuid => "UNIQUEIDENTIFIER".to_string(),
            FieldType::Boolean => "BIT".to_string(),
            FieldType::Integer => "INT".to_string(),
            FieldType::BigInt => "BIGINT".to_string(),
            FieldType::Float => "REAL".to_string(),
            FieldType::Double => "FLOAT".to_string(),
            FieldType::Decimal { precision, scale } => {
                format!("DECIMAL({}, {})", precision, scale)
            }
            FieldType::String { max_length } => match max_length {
                Some(len) if *len <= 4000 => format!("NVARCHAR({})", len),
                Some(_) | None => "NVARCHAR(MAX)".to_string(),
            },
            FieldType::Text => "NVARCHAR(MAX)".to_string(),
            FieldType::Date => "DATE".to_string(),
            FieldType::Time => "TIME".to_string(),
            FieldType::Timestamp => "DATETIMEOFFSET".to_string(),
            // SQL Server stores JSON as NVARCHAR(MAX) - no native JSON type
            FieldType::Json => "NVARCHAR(MAX)".to_string(),
            FieldType::Binary => "VARBINARY(MAX)".to_string(),
            // SQL Server doesn't have native arrays - store as JSON
            FieldType::Array(_) => "NVARCHAR(MAX)".to_string(),
            FieldType::Reference { .. } => "UNIQUEIDENTIFIER".to_string(),
            FieldType::Enum { .. } => "NVARCHAR(100)".to_string(),
            FieldType::Computed => unreachable!("Computed fields have no SQL type"),
        }
    }

    fn now_function(&self) -> &'static str {
        "GETUTCDATE()"
    }

    fn uuid_generate(&self) -> &'static str {
        "NEWID()"
    }

    fn ilike_expression(&self, column: &str, param: &str) -> String {
        // SQL Server doesn't have ILIKE, use LOWER() on both sides
        format!("LOWER({}) LIKE LOWER({})", column, param)
    }

    fn nulls_order(&self, field: &str, direction: &str, nulls: NullsPosition) -> String {
        // SQL Server doesn't support NULLS FIRST/LAST directly
        // Use CASE WHEN workaround
        match nulls {
            NullsPosition::Default => format!("{} {}", field, direction),
            NullsPosition::First => {
                format!("CASE WHEN {} IS NULL THEN 0 ELSE 1 END, {} {}", field, field, direction)
            }
            NullsPosition::Last => {
                format!("CASE WHEN {} IS NULL THEN 1 ELSE 0 END, {} {}", field, field, direction)
            }
        }
    }

    fn pagination_sql(&self, limit: u64, offset: u64) -> String {
        // SQL Server 2012+ syntax
        format!("OFFSET {} ROWS FETCH NEXT {} ROWS ONLY", offset, limit)
    }

    fn bool_literal(&self, value: bool) -> &'static str {
        if value { "1" } else { "0" }
    }

    fn quote_identifier(&self, name: &str) -> String {
        format!("[{}]", name.replace(']', "]]"))
    }

    fn for_update_sql(&self) -> &'static str {
        "WITH (UPDLOCK, ROWLOCK)"
    }

    fn date_subtract_hours(&self, hours: u32) -> String {
        format!("DATEADD(hour, -{}, GETUTCDATE())", hours)
    }

    fn supports_index_method(&self, method: &str) -> bool {
        // SQL Server only supports btree-style indexes by default
        // Doesn't support GIN, GIST, BRIN
        matches!(method.to_lowercase().as_str(), "btree" | "nonclustered" | "clustered")
    }

    fn array_agg(&self, column: &str) -> String {
        // SQL Server uses STRING_AGG for string concatenation
        // For proper array handling, we return as JSON
        format!("STRING_AGG({}, ',')", column)
    }

    fn empty_array_literal(&self, _element_type: &str) -> String {
        // Return empty string that can be split
        "''".to_string()
    }

    fn coalesce_array(&self, expr: &str, _element_type: &str) -> String {
        format!("COALESCE({}, '')", expr)
    }

    fn upsert_syntax(
        &self,
        table: &str,
        columns: &[&str],
        conflict_columns: &[&str],
        update_columns: &[&str],
    ) -> String {
        // SQL Server uses MERGE syntax
        let cols = columns.join(", ");
        let placeholders: Vec<String> = (1..=columns.len())
            .map(|i| self.param_placeholder(i as i32))
            .collect();
        let values = placeholders.join(", ");

        let match_conditions: Vec<String> = conflict_columns
            .iter()
            .map(|c| format!("target.{} = source.{}", c, c))
            .collect();
        let match_clause = match_conditions.join(" AND ");

        let updates: Vec<String> = update_columns
            .iter()
            .map(|c| format!("target.{} = source.{}", c, c))
            .collect();
        let update_clause = updates.join(", ");

        let insert_cols: Vec<String> = columns.iter().map(|c| format!("source.{}", c)).collect();
        let insert_values = insert_cols.join(", ");

        format!(
            "MERGE INTO {} AS target \
             USING (SELECT {} AS {}) AS source \
             ON {} \
             WHEN MATCHED THEN UPDATE SET {} \
             WHEN NOT MATCHED THEN INSERT ({}) VALUES ({});",
            table,
            values,
            cols.replace(", ", " AS dummy, ").replace(" AS dummy,", ","), // Hack for column aliases
            match_clause,
            update_clause,
            cols,
            insert_values
        )
    }

    fn serial_type(&self) -> &'static str {
        "INT IDENTITY(1,1)"
    }

    fn bigserial_type(&self) -> &'static str {
        "BIGINT IDENTITY(1,1)"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_placeholders() {
        let dialect = MssqlDialect;
        assert_eq!(dialect.param_placeholder(1), "@p1");
        assert_eq!(dialect.param_placeholder(2), "@p2");
        assert_eq!(dialect.param_placeholder(100), "@p100");
    }

    #[test]
    fn test_field_types() {
        let dialect = MssqlDialect;
        assert_eq!(dialect.field_type_to_sql(&FieldType::Boolean), "BIT");
        assert_eq!(dialect.field_type_to_sql(&FieldType::Uuid), "UNIQUEIDENTIFIER");
        assert_eq!(dialect.field_type_to_sql(&FieldType::Json), "NVARCHAR(MAX)");
        assert_eq!(dialect.field_type_to_sql(&FieldType::Timestamp), "DATETIMEOFFSET");
    }

    #[test]
    fn test_pagination() {
        let dialect = MssqlDialect;
        assert_eq!(
            dialect.pagination_sql(10, 20),
            "OFFSET 20 ROWS FETCH NEXT 10 ROWS ONLY"
        );
    }

    #[test]
    fn test_ilike() {
        let dialect = MssqlDialect;
        assert_eq!(
            dialect.ilike_expression("name", "@p1"),
            "LOWER(name) LIKE LOWER(@p1)"
        );
    }

    #[test]
    fn test_nulls_order() {
        let dialect = MssqlDialect;
        assert_eq!(
            dialect.nulls_order("name", "ASC", NullsPosition::First),
            "CASE WHEN name IS NULL THEN 0 ELSE 1 END, name ASC"
        );
    }

    #[test]
    fn test_bool_literal() {
        let dialect = MssqlDialect;
        assert_eq!(dialect.bool_literal(true), "1");
        assert_eq!(dialect.bool_literal(false), "0");
    }

    #[test]
    fn test_index_support() {
        let dialect = MssqlDialect;
        assert!(dialect.supports_index_method("btree"));
        assert!(!dialect.supports_index_method("gin"));
        assert!(!dialect.supports_index_method("gist"));
    }
}
