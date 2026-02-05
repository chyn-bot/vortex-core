//! Comprehensive tests for SQL dialect abstraction layer

use super::*;
use crate::field::FieldType;

mod postgres_dialect_tests {
    use super::*;

    fn dialect() -> PostgresDialect {
        PostgresDialect
    }

    #[test]
    fn test_backend_type() {
        assert_eq!(dialect().backend(), DatabaseBackend::Postgres);
    }

    #[test]
    fn test_param_placeholders() {
        let d = dialect();
        assert_eq!(d.param_placeholder(1), "$1");
        assert_eq!(d.param_placeholder(2), "$2");
        assert_eq!(d.param_placeholder(10), "$10");
        assert_eq!(d.param_placeholder(100), "$100");
    }

    #[test]
    fn test_field_type_mappings() {
        let d = dialect();

        // Basic types
        assert_eq!(d.field_type_to_sql(&FieldType::Serial), "BIGSERIAL");
        assert_eq!(d.field_type_to_sql(&FieldType::Uuid), "UUID");
        assert_eq!(d.field_type_to_sql(&FieldType::Boolean), "BOOLEAN");
        assert_eq!(d.field_type_to_sql(&FieldType::Integer), "INTEGER");
        assert_eq!(d.field_type_to_sql(&FieldType::BigInt), "BIGINT");
        assert_eq!(d.field_type_to_sql(&FieldType::Float), "REAL");
        assert_eq!(d.field_type_to_sql(&FieldType::Double), "DOUBLE PRECISION");

        // Decimal with precision
        assert_eq!(
            d.field_type_to_sql(&FieldType::Decimal { precision: 10, scale: 2 }),
            "NUMERIC(10, 2)"
        );

        // String types
        assert_eq!(
            d.field_type_to_sql(&FieldType::String { max_length: Some(100) }),
            "VARCHAR(100)"
        );
        assert_eq!(
            d.field_type_to_sql(&FieldType::String { max_length: None }),
            "TEXT"
        );
        assert_eq!(d.field_type_to_sql(&FieldType::Text), "TEXT");

        // Date/time types
        assert_eq!(d.field_type_to_sql(&FieldType::Date), "DATE");
        assert_eq!(d.field_type_to_sql(&FieldType::Time), "TIME");
        assert_eq!(d.field_type_to_sql(&FieldType::Timestamp), "TIMESTAMPTZ");

        // Complex types
        assert_eq!(d.field_type_to_sql(&FieldType::Json), "JSONB");
        assert_eq!(d.field_type_to_sql(&FieldType::Binary), "BYTEA");

        // Array type
        assert_eq!(
            d.field_type_to_sql(&FieldType::Array(Box::new(FieldType::Integer))),
            "INTEGER[]"
        );
        assert_eq!(
            d.field_type_to_sql(&FieldType::Array(Box::new(FieldType::Text))),
            "TEXT[]"
        );
    }

    #[test]
    fn test_now_function() {
        assert_eq!(dialect().now_function(), "NOW()");
    }

    #[test]
    fn test_uuid_generate() {
        assert_eq!(dialect().uuid_generate(), "gen_random_uuid()");
    }

    #[test]
    fn test_ilike_expression() {
        let d = dialect();
        assert_eq!(d.ilike_expression("name", "$1"), "name ILIKE $1");
        assert_eq!(d.ilike_expression("email", "$2"), "email ILIKE $2");
    }

    #[test]
    fn test_nulls_order() {
        let d = dialect();

        // Default - no nulls clause
        assert_eq!(d.nulls_order("name", "ASC", NullsPosition::Default), "name ASC");

        // Nulls first
        assert_eq!(
            d.nulls_order("name", "ASC", NullsPosition::First),
            "name ASC NULLS FIRST"
        );
        assert_eq!(
            d.nulls_order("created_at", "DESC", NullsPosition::First),
            "created_at DESC NULLS FIRST"
        );

        // Nulls last
        assert_eq!(
            d.nulls_order("name", "ASC", NullsPosition::Last),
            "name ASC NULLS LAST"
        );
        assert_eq!(
            d.nulls_order("updated_at", "DESC", NullsPosition::Last),
            "updated_at DESC NULLS LAST"
        );
    }

    #[test]
    fn test_pagination() {
        let d = dialect();
        assert_eq!(d.pagination_sql(10, 0), "LIMIT 10 OFFSET 0");
        assert_eq!(d.pagination_sql(25, 50), "LIMIT 25 OFFSET 50");
        assert_eq!(d.pagination_sql(100, 1000), "LIMIT 100 OFFSET 1000");
    }

    #[test]
    fn test_bool_literals() {
        let d = dialect();
        assert_eq!(d.bool_literal(true), "TRUE");
        assert_eq!(d.bool_literal(false), "FALSE");
    }

    #[test]
    fn test_quote_identifier() {
        let d = dialect();
        assert_eq!(d.quote_identifier("users"), "\"users\"");
        assert_eq!(d.quote_identifier("user_roles"), "\"user_roles\"");
        // Test escaping double quotes
        assert_eq!(d.quote_identifier("table\"name"), "\"table\"\"name\"");
    }

    #[test]
    fn test_for_update() {
        assert_eq!(dialect().for_update_sql(), "FOR UPDATE");
    }

    #[test]
    fn test_date_subtract_hours() {
        let d = dialect();
        assert_eq!(d.date_subtract_hours(24), "NOW() - INTERVAL '24 hours'");
        assert_eq!(d.date_subtract_hours(1), "NOW() - INTERVAL '1 hours'");
        assert_eq!(d.date_subtract_hours(168), "NOW() - INTERVAL '168 hours'");
    }

    #[test]
    fn test_index_method_support() {
        let d = dialect();
        assert!(d.supports_index_method("btree"));
        assert!(d.supports_index_method("hash"));
        assert!(d.supports_index_method("gin"));
        assert!(d.supports_index_method("gist"));
        assert!(d.supports_index_method("brin"));
        assert!(!d.supports_index_method("unknown"));
    }

    #[test]
    fn test_array_agg() {
        let d = dialect();
        assert_eq!(d.array_agg("name"), "array_agg(name)");
        assert_eq!(d.array_agg("r.permission"), "array_agg(r.permission)");
    }

    #[test]
    fn test_empty_array_literal() {
        let d = dialect();
        assert_eq!(d.empty_array_literal("text"), "ARRAY[]::text[]");
        assert_eq!(d.empty_array_literal("integer"), "ARRAY[]::integer[]");
    }

    #[test]
    fn test_coalesce_array() {
        let d = dialect();
        assert_eq!(
            d.coalesce_array("(SELECT array_agg(x) FROM t)", "text"),
            "COALESCE((SELECT array_agg(x) FROM t), ARRAY[]::text[])"
        );
    }

    #[test]
    fn test_serial_types() {
        let d = dialect();
        assert_eq!(d.serial_type(), "SERIAL");
        assert_eq!(d.bigserial_type(), "BIGSERIAL");
    }
}

#[cfg(feature = "mssql")]
mod mssql_dialect_tests {
    use super::*;

    fn dialect() -> MssqlDialect {
        MssqlDialect
    }

    #[test]
    fn test_backend_type() {
        assert_eq!(dialect().backend(), DatabaseBackend::MsSql);
    }

    #[test]
    fn test_param_placeholders() {
        let d = dialect();
        assert_eq!(d.param_placeholder(1), "@p1");
        assert_eq!(d.param_placeholder(2), "@p2");
        assert_eq!(d.param_placeholder(10), "@p10");
        assert_eq!(d.param_placeholder(100), "@p100");
    }

    #[test]
    fn test_field_type_mappings() {
        let d = dialect();

        // Basic types - note differences from PostgreSQL
        assert_eq!(d.field_type_to_sql(&FieldType::Serial), "INT IDENTITY(1,1)");
        assert_eq!(d.field_type_to_sql(&FieldType::Uuid), "UNIQUEIDENTIFIER");
        assert_eq!(d.field_type_to_sql(&FieldType::Boolean), "BIT");
        assert_eq!(d.field_type_to_sql(&FieldType::Integer), "INT");
        assert_eq!(d.field_type_to_sql(&FieldType::BigInt), "BIGINT");
        assert_eq!(d.field_type_to_sql(&FieldType::Float), "REAL");
        assert_eq!(d.field_type_to_sql(&FieldType::Double), "FLOAT");

        // Decimal
        assert_eq!(
            d.field_type_to_sql(&FieldType::Decimal { precision: 10, scale: 2 }),
            "DECIMAL(10, 2)"
        );

        // String types - uses NVARCHAR
        assert_eq!(
            d.field_type_to_sql(&FieldType::String { max_length: Some(100) }),
            "NVARCHAR(100)"
        );
        assert_eq!(
            d.field_type_to_sql(&FieldType::String { max_length: Some(5000) }),
            "NVARCHAR(MAX)"
        );
        assert_eq!(
            d.field_type_to_sql(&FieldType::String { max_length: None }),
            "NVARCHAR(MAX)"
        );
        assert_eq!(d.field_type_to_sql(&FieldType::Text), "NVARCHAR(MAX)");

        // Date/time types
        assert_eq!(d.field_type_to_sql(&FieldType::Date), "DATE");
        assert_eq!(d.field_type_to_sql(&FieldType::Time), "TIME");
        assert_eq!(d.field_type_to_sql(&FieldType::Timestamp), "DATETIMEOFFSET");

        // Complex types - JSON stored as string
        assert_eq!(d.field_type_to_sql(&FieldType::Json), "NVARCHAR(MAX)");
        assert_eq!(d.field_type_to_sql(&FieldType::Binary), "VARBINARY(MAX)");

        // Array type - stored as JSON
        assert_eq!(
            d.field_type_to_sql(&FieldType::Array(Box::new(FieldType::Integer))),
            "NVARCHAR(MAX)"
        );
    }

    #[test]
    fn test_now_function() {
        assert_eq!(dialect().now_function(), "GETUTCDATE()");
    }

    #[test]
    fn test_uuid_generate() {
        assert_eq!(dialect().uuid_generate(), "NEWID()");
    }

    #[test]
    fn test_ilike_expression() {
        let d = dialect();
        // MSSQL uses LOWER() workaround
        assert_eq!(d.ilike_expression("name", "@p1"), "LOWER(name) LIKE LOWER(@p1)");
        assert_eq!(d.ilike_expression("email", "@p2"), "LOWER(email) LIKE LOWER(@p2)");
    }

    #[test]
    fn test_nulls_order() {
        let d = dialect();

        // Default - no special handling
        assert_eq!(d.nulls_order("name", "ASC", NullsPosition::Default), "name ASC");

        // Nulls first - uses CASE WHEN
        assert_eq!(
            d.nulls_order("name", "ASC", NullsPosition::First),
            "CASE WHEN name IS NULL THEN 0 ELSE 1 END, name ASC"
        );

        // Nulls last - uses CASE WHEN with inverted logic
        assert_eq!(
            d.nulls_order("name", "ASC", NullsPosition::Last),
            "CASE WHEN name IS NULL THEN 1 ELSE 0 END, name ASC"
        );
    }

    #[test]
    fn test_pagination() {
        let d = dialect();
        // SQL Server 2012+ syntax
        assert_eq!(d.pagination_sql(10, 0), "OFFSET 0 ROWS FETCH NEXT 10 ROWS ONLY");
        assert_eq!(d.pagination_sql(25, 50), "OFFSET 50 ROWS FETCH NEXT 25 ROWS ONLY");
    }

    #[test]
    fn test_bool_literals() {
        let d = dialect();
        assert_eq!(d.bool_literal(true), "1");
        assert_eq!(d.bool_literal(false), "0");
    }

    #[test]
    fn test_quote_identifier() {
        let d = dialect();
        assert_eq!(d.quote_identifier("users"), "[users]");
        assert_eq!(d.quote_identifier("user_roles"), "[user_roles]");
        // Test escaping brackets
        assert_eq!(d.quote_identifier("table]name"), "[table]]name]");
    }

    #[test]
    fn test_for_update() {
        assert_eq!(dialect().for_update_sql(), "WITH (UPDLOCK, ROWLOCK)");
    }

    #[test]
    fn test_date_subtract_hours() {
        let d = dialect();
        assert_eq!(d.date_subtract_hours(24), "DATEADD(hour, -24, GETUTCDATE())");
        assert_eq!(d.date_subtract_hours(1), "DATEADD(hour, -1, GETUTCDATE())");
    }

    #[test]
    fn test_index_method_support() {
        let d = dialect();
        assert!(d.supports_index_method("btree"));
        assert!(d.supports_index_method("nonclustered"));
        assert!(d.supports_index_method("clustered"));
        // PostgreSQL-specific methods not supported
        assert!(!d.supports_index_method("gin"));
        assert!(!d.supports_index_method("gist"));
        assert!(!d.supports_index_method("brin"));
    }

    #[test]
    fn test_array_agg() {
        let d = dialect();
        assert_eq!(d.array_agg("name"), "STRING_AGG(name, ',')");
    }

    #[test]
    fn test_empty_array_literal() {
        let d = dialect();
        assert_eq!(d.empty_array_literal("text"), "''");
    }

    #[test]
    fn test_serial_types() {
        let d = dialect();
        assert_eq!(d.serial_type(), "INT IDENTITY(1,1)");
        assert_eq!(d.bigserial_type(), "BIGINT IDENTITY(1,1)");
    }
}

mod database_backend_tests {
    use super::*;

    #[test]
    fn test_from_url_postgres() {
        assert_eq!(
            DatabaseBackend::from_url("postgres://localhost/db"),
            Some(DatabaseBackend::Postgres)
        );
        assert_eq!(
            DatabaseBackend::from_url("postgresql://user:pass@host:5432/db"),
            Some(DatabaseBackend::Postgres)
        );
    }

    #[cfg(feature = "mssql")]
    #[test]
    fn test_from_url_mssql() {
        assert_eq!(
            DatabaseBackend::from_url("mssql://localhost/db"),
            Some(DatabaseBackend::MsSql)
        );
        assert_eq!(
            DatabaseBackend::from_url("sqlserver://user:pass@host:1433/db"),
            Some(DatabaseBackend::MsSql)
        );
    }

    #[test]
    fn test_from_url_unknown() {
        assert_eq!(DatabaseBackend::from_url("mysql://localhost/db"), None);
        assert_eq!(DatabaseBackend::from_url("sqlite://file.db"), None);
        assert_eq!(DatabaseBackend::from_url("invalid"), None);
    }

    #[test]
    fn test_backend_as_str() {
        assert_eq!(DatabaseBackend::Postgres.as_str(), "postgres");
        #[cfg(feature = "mssql")]
        assert_eq!(DatabaseBackend::MsSql.as_str(), "mssql");
    }

    #[test]
    fn test_backend_display() {
        assert_eq!(format!("{}", DatabaseBackend::Postgres), "postgres");
    }
}

mod nulls_position_tests {
    use super::*;

    #[test]
    fn test_default() {
        assert_eq!(NullsPosition::default(), NullsPosition::Default);
    }

    #[test]
    fn test_variants() {
        let _ = NullsPosition::Default;
        let _ = NullsPosition::First;
        let _ = NullsPosition::Last;
    }
}

mod dialect_factory_tests {
    use super::*;

    #[test]
    fn test_dialect_from_url_postgres() {
        let dialect = dialect_from_url("postgres://localhost/db");
        assert!(dialect.is_some());
        assert_eq!(dialect.unwrap().backend(), DatabaseBackend::Postgres);
    }

    #[test]
    fn test_dialect_from_url_invalid() {
        assert!(dialect_from_url("mysql://localhost/db").is_none());
        assert!(dialect_from_url("invalid").is_none());
    }

    #[test]
    fn test_dialect_for_backend_postgres() {
        let dialect = dialect_for_backend(DatabaseBackend::Postgres);
        assert_eq!(dialect.backend(), DatabaseBackend::Postgres);
    }

    #[cfg(feature = "mssql")]
    #[test]
    fn test_dialect_for_backend_mssql() {
        let dialect = dialect_for_backend(DatabaseBackend::MsSql);
        assert_eq!(dialect.backend(), DatabaseBackend::MsSql);
    }
}
