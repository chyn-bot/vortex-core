//! PostgreSQL dialect implementation

use super::{DatabaseBackend, NullsPosition, SqlDialect};
use crate::field::FieldType;

/// PostgreSQL SQL dialect
#[derive(Debug, Clone, Copy, Default)]
pub struct PostgresDialect;

impl SqlDialect for PostgresDialect {
    fn backend(&self) -> DatabaseBackend {
        DatabaseBackend::Postgres
    }

    fn param_placeholder(&self, index: i32) -> String {
        format!("${}", index)
    }

    fn field_type_to_sql(&self, field_type: &FieldType) -> String {
        match field_type {
            FieldType::Serial => "BIGSERIAL".to_string(),
            FieldType::Uuid => "UUID".to_string(),
            FieldType::Boolean => "BOOLEAN".to_string(),
            FieldType::Integer => "INTEGER".to_string(),
            FieldType::BigInt => "BIGINT".to_string(),
            FieldType::Float => "REAL".to_string(),
            FieldType::Double => "DOUBLE PRECISION".to_string(),
            FieldType::Decimal { precision, scale } => {
                format!("NUMERIC({}, {})", precision, scale)
            }
            FieldType::String { max_length } => match max_length {
                Some(len) => format!("VARCHAR({})", len),
                None => "TEXT".to_string(),
            },
            FieldType::Text => "TEXT".to_string(),
            FieldType::Date => "DATE".to_string(),
            FieldType::Time => "TIME".to_string(),
            FieldType::Timestamp => "TIMESTAMPTZ".to_string(),
            FieldType::Json => "JSONB".to_string(),
            FieldType::Binary => "BYTEA".to_string(),
            FieldType::Array(inner) => {
                format!("{}[]", self.field_type_to_sql(inner))
            }
            FieldType::Reference { .. } => "UUID".to_string(),
            FieldType::Enum { name, .. } => name.clone(),
            FieldType::Computed => unreachable!("Computed fields have no SQL type"),
        }
    }

    fn now_function(&self) -> &'static str {
        "NOW()"
    }

    fn uuid_generate(&self) -> &'static str {
        "gen_random_uuid()"
    }

    fn ilike_expression(&self, column: &str, param: &str) -> String {
        format!("{} ILIKE {}", column, param)
    }

    fn nulls_order(&self, field: &str, direction: &str, nulls: NullsPosition) -> String {
        let nulls_clause = match nulls {
            NullsPosition::Default => "",
            NullsPosition::First => " NULLS FIRST",
            NullsPosition::Last => " NULLS LAST",
        };
        format!("{} {}{}", field, direction, nulls_clause)
    }

    fn pagination_sql(&self, limit: u64, offset: u64) -> String {
        format!("LIMIT {} OFFSET {}", limit, offset)
    }

    fn bool_literal(&self, value: bool) -> &'static str {
        if value { "TRUE" } else { "FALSE" }
    }

    fn quote_identifier(&self, name: &str) -> String {
        format!("\"{}\"", name.replace('"', "\"\""))
    }

    fn for_update_sql(&self) -> &'static str {
        "FOR UPDATE"
    }

    fn date_subtract_hours(&self, hours: u32) -> String {
        format!("NOW() - INTERVAL '{} hours'", hours)
    }

    fn supports_index_method(&self, method: &str) -> bool {
        matches!(method.to_lowercase().as_str(), "btree" | "hash" | "gin" | "gist" | "brin")
    }

    fn array_agg(&self, column: &str) -> String {
        format!("array_agg({})", column)
    }

    fn empty_array_literal(&self, element_type: &str) -> String {
        format!("ARRAY[]::{}[]", element_type)
    }

    fn coalesce_array(&self, expr: &str, element_type: &str) -> String {
        format!("COALESCE({}, ARRAY[]::{}[])", expr, element_type)
    }

    fn upsert_syntax(
        &self,
        table: &str,
        columns: &[&str],
        conflict_columns: &[&str],
        update_columns: &[&str],
    ) -> String {
        let cols = columns.join(", ");
        let placeholders: Vec<String> = (1..=columns.len())
            .map(|i| self.param_placeholder(i as i32))
            .collect();
        let values = placeholders.join(", ");
        let conflict = conflict_columns.join(", ");
        let updates: Vec<String> = update_columns
            .iter()
            .map(|c| format!("{} = EXCLUDED.{}", c, c))
            .collect();
        let update_clause = updates.join(", ");

        format!(
            "INSERT INTO {} ({}) VALUES ({}) ON CONFLICT ({}) DO UPDATE SET {}",
            table, cols, values, conflict, update_clause
        )
    }

    fn serial_type(&self) -> &'static str {
        "SERIAL"
    }

    fn bigserial_type(&self) -> &'static str {
        "BIGSERIAL"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_param_placeholders() {
        let dialect = PostgresDialect;
        assert_eq!(dialect.param_placeholder(1), "$1");
        assert_eq!(dialect.param_placeholder(2), "$2");
        assert_eq!(dialect.param_placeholder(100), "$100");
    }

    #[test]
    fn test_field_types() {
        let dialect = PostgresDialect;
        assert_eq!(dialect.field_type_to_sql(&FieldType::Boolean), "BOOLEAN");
        assert_eq!(dialect.field_type_to_sql(&FieldType::Uuid), "UUID");
        assert_eq!(dialect.field_type_to_sql(&FieldType::Json), "JSONB");
        assert_eq!(dialect.field_type_to_sql(&FieldType::Timestamp), "TIMESTAMPTZ");
    }

    #[test]
    fn test_pagination() {
        let dialect = PostgresDialect;
        assert_eq!(dialect.pagination_sql(10, 20), "LIMIT 10 OFFSET 20");
    }

    #[test]
    fn test_ilike() {
        let dialect = PostgresDialect;
        assert_eq!(dialect.ilike_expression("name", "$1"), "name ILIKE $1");
    }

    #[test]
    fn test_nulls_order() {
        let dialect = PostgresDialect;
        assert_eq!(
            dialect.nulls_order("name", "ASC", NullsPosition::First),
            "name ASC NULLS FIRST"
        );
        assert_eq!(
            dialect.nulls_order("name", "DESC", NullsPosition::Last),
            "name DESC NULLS LAST"
        );
    }
}
