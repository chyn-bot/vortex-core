//! Domain Expression Parser
//!
//! Implements Odoo-style domain expressions for record-level access control.
//! Domain expressions are used to filter records based on field values and
//! context variables like current_user and current_company.
//!
//! # Example
//!
//! ```ignore
//! use vortex_security::domain::DomainExpr;
//!
//! // Parse a simple domain expression
//! let domain = DomainExpr::parse(r#"[("company_id", "=", current_company)]"#)?;
//!
//! // Convert to SQL
//! let (sql, params) = domain.to_sql(&ctx, &dialect, &mut 1);
//! // sql: "company_id = $1"
//! // params: [FieldValue::Uuid(company_id)]
//! ```

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use vortex_common::{Context, FieldValue, VortexError, VortexResult};

/// Domain expression AST node
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DomainExpr {
    /// Logical AND of multiple expressions
    And(Vec<DomainExpr>),
    /// Logical OR of multiple expressions
    Or(Vec<DomainExpr>),
    /// Logical NOT of an expression
    Not(Box<DomainExpr>),
    /// A single condition (field, operator, value)
    Condition {
        field: String,
        operator: DomainOp,
        value: DomainValue,
    },
    /// Always true (matches all records)
    True,
    /// Always false (matches no records)
    False,
}

/// Supported comparison operators
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DomainOp {
    /// Equal (=)
    Eq,
    /// Not equal (!=, <>)
    Ne,
    /// Less than (<)
    Lt,
    /// Less than or equal (<=)
    Lte,
    /// Greater than (>)
    Gt,
    /// Greater than or equal (>=)
    Gte,
    /// In a list of values (in)
    In,
    /// Not in a list of values (not in)
    NotIn,
    /// LIKE pattern match (like)
    Like,
    /// Case-insensitive LIKE (ilike)
    ILike,
    /// Is NULL (=, with null value)
    IsNull,
    /// Is NOT NULL (!=, with null value)
    IsNotNull,
    /// Child of (for hierarchical data)
    ChildOf,
    /// Parent of (for hierarchical data)
    ParentOf,
}

impl DomainOp {
    /// Parse an operator from a string
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "=" => Some(DomainOp::Eq),
            "!=" | "<>" | "not =" => Some(DomainOp::Ne),
            "<" => Some(DomainOp::Lt),
            "<=" => Some(DomainOp::Lte),
            ">" => Some(DomainOp::Gt),
            ">=" => Some(DomainOp::Gte),
            "in" => Some(DomainOp::In),
            "not in" => Some(DomainOp::NotIn),
            "like" => Some(DomainOp::Like),
            "ilike" => Some(DomainOp::ILike),
            "child_of" => Some(DomainOp::ChildOf),
            "parent_of" => Some(DomainOp::ParentOf),
            _ => None,
        }
    }

    /// Convert to SQL operator
    pub fn to_sql(&self) -> &'static str {
        match self {
            DomainOp::Eq => "=",
            DomainOp::Ne => "!=",
            DomainOp::Lt => "<",
            DomainOp::Lte => "<=",
            DomainOp::Gt => ">",
            DomainOp::Gte => ">=",
            DomainOp::In => "IN",
            DomainOp::NotIn => "NOT IN",
            DomainOp::Like => "LIKE",
            DomainOp::ILike => "ILIKE",
            DomainOp::IsNull => "IS NULL",
            DomainOp::IsNotNull => "IS NOT NULL",
            DomainOp::ChildOf => "IN", // Handled specially
            DomainOp::ParentOf => "IN", // Handled specially
        }
    }
}

/// Domain value types, including context variables
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum DomainValue {
    /// NULL value
    Null,
    /// Boolean value
    Bool(bool),
    /// Integer value
    Int(i64),
    /// Float value
    Float(f64),
    /// String value
    String(String),
    /// List of values (for IN operator)
    List(Vec<DomainValue>),
    /// Reference to current user ID
    CurrentUser,
    /// Reference to current company ID
    CurrentCompany,
    /// Reference to another field in the record
    FieldRef(String),
}

impl DomainValue {
    /// Resolve the value to a FieldValue given a context and optional record
    pub fn resolve(
        &self,
        ctx: &Context,
        record: Option<&HashMap<String, FieldValue>>,
    ) -> Option<FieldValue> {
        match self {
            DomainValue::Null => Some(FieldValue::Null),
            DomainValue::Bool(b) => Some(FieldValue::Bool(*b)),
            DomainValue::Int(i) => Some(FieldValue::Int(*i)),
            DomainValue::Float(f) => Some(FieldValue::Float(*f)),
            DomainValue::String(s) => Some(FieldValue::String(s.clone())),
            DomainValue::List(items) => {
                let resolved: Option<Vec<FieldValue>> = items
                    .iter()
                    .map(|v| v.resolve(ctx, record))
                    .collect();
                resolved.map(FieldValue::Array)
            }
            DomainValue::CurrentUser => ctx.user_id.map(|id| FieldValue::Uuid(id.0)),
            DomainValue::CurrentCompany => ctx.company_id.map(|id| FieldValue::Uuid(id.0)),
            DomainValue::FieldRef(field) => record.and_then(|r| r.get(field).cloned()),
        }
    }
}

impl DomainExpr {
    /// Create a new AND expression
    pub fn and(exprs: Vec<DomainExpr>) -> Self {
        if exprs.is_empty() {
            DomainExpr::True
        } else if exprs.len() == 1 {
            exprs.into_iter().next().unwrap()
        } else {
            DomainExpr::And(exprs)
        }
    }

    /// Create a new OR expression
    pub fn or(exprs: Vec<DomainExpr>) -> Self {
        if exprs.is_empty() {
            DomainExpr::False
        } else if exprs.len() == 1 {
            exprs.into_iter().next().unwrap()
        } else {
            DomainExpr::Or(exprs)
        }
    }

    /// Create a new NOT expression
    pub fn not(expr: DomainExpr) -> Self {
        DomainExpr::Not(Box::new(expr))
    }

    /// Create a simple equality condition
    pub fn eq(field: impl Into<String>, value: DomainValue) -> Self {
        DomainExpr::Condition {
            field: field.into(),
            operator: DomainOp::Eq,
            value,
        }
    }

    /// Parse a domain expression from Odoo-style string format
    ///
    /// Supports formats like:
    /// - `[("field", "=", "value")]`
    /// - `[("field", "=", current_user)]`
    /// - `["|", ("a", "=", 1), ("b", "=", 2)]`
    /// - `["&", ("a", "=", 1), ("b", "=", 2)]`
    /// - `["!", ("active", "=", false)]`
    pub fn parse(input: &str) -> VortexResult<Self> {
        let input = input.trim();

        // Handle empty or trivial cases
        if input.is_empty() || input == "[]" || input == "(1=1)" || input == "true" {
            return Ok(DomainExpr::True);
        }

        if input == "false" || input == "(1=0)" {
            return Ok(DomainExpr::False);
        }

        // Parse the domain expression
        let parser = DomainParser::new(input);
        parser.parse()
    }

    /// Convert to SQL WHERE clause with parameterized values
    ///
    /// Returns the SQL string and the parameter values to bind.
    /// Uses the dialect to generate proper placeholders ($1, @p1, etc.)
    pub fn to_sql(
        &self,
        ctx: &Context,
        dialect: &dyn SqlDialect,
        param_idx: &mut i32,
    ) -> (String, Vec<FieldValue>) {
        match self {
            DomainExpr::True => ("1=1".to_string(), vec![]),
            DomainExpr::False => ("1=0".to_string(), vec![]),

            DomainExpr::And(exprs) => {
                if exprs.is_empty() {
                    return ("1=1".to_string(), vec![]);
                }
                let mut all_params = Vec::new();
                let conditions: Vec<String> = exprs
                    .iter()
                    .map(|e| {
                        let (sql, params) = e.to_sql(ctx, dialect, param_idx);
                        all_params.extend(params);
                        format!("({})", sql)
                    })
                    .collect();
                (conditions.join(" AND "), all_params)
            }

            DomainExpr::Or(exprs) => {
                if exprs.is_empty() {
                    return ("1=0".to_string(), vec![]);
                }
                let mut all_params = Vec::new();
                let conditions: Vec<String> = exprs
                    .iter()
                    .map(|e| {
                        let (sql, params) = e.to_sql(ctx, dialect, param_idx);
                        all_params.extend(params);
                        format!("({})", sql)
                    })
                    .collect();
                (format!("({})", conditions.join(" OR ")), all_params)
            }

            DomainExpr::Not(expr) => {
                let (sql, params) = expr.to_sql(ctx, dialect, param_idx);
                (format!("NOT ({})", sql), params)
            }

            DomainExpr::Condition { field, operator, value } => {
                // Resolve the value
                let resolved = value.resolve(ctx, None);

                // Handle NULL comparisons
                if matches!(value, DomainValue::Null) {
                    return match operator {
                        DomainOp::Eq | DomainOp::IsNull => {
                            (format!("{} IS NULL", field), vec![])
                        }
                        DomainOp::Ne | DomainOp::IsNotNull => {
                            (format!("{} IS NOT NULL", field), vec![])
                        }
                        _ => (format!("{} IS NULL", field), vec![]),
                    };
                }

                // Handle field references
                if let DomainValue::FieldRef(ref_field) = value {
                    return (
                        format!("{} {} {}", field, operator.to_sql(), ref_field),
                        vec![],
                    );
                }

                // Handle list values for IN/NOT IN
                if let DomainValue::List(items) = value {
                    if let Some(FieldValue::Array(values)) = resolved {
                        let placeholders: Vec<String> = values
                            .iter()
                            .map(|_| {
                                let p = dialect.param_placeholder(*param_idx);
                                *param_idx += 1;
                                p
                            })
                            .collect();
                        let sql = format!(
                            "{} {} ({})",
                            field,
                            operator.to_sql(),
                            placeholders.join(", ")
                        );
                        return (sql, values);
                    }
                    return ("1=0".to_string(), vec![]);
                }

                // Standard comparison
                if let Some(fv) = resolved {
                    let placeholder = dialect.param_placeholder(*param_idx);
                    *param_idx += 1;

                    // Handle ILIKE for case-insensitive matching
                    let sql = match operator {
                        DomainOp::ILike => dialect.ilike_expression(field, &placeholder),
                        _ => format!("{} {} {}", field, operator.to_sql(), placeholder),
                    };

                    (sql, vec![fv])
                } else {
                    // Context variable not available, return FALSE
                    ("1=0".to_string(), vec![])
                }
            }
        }
    }

    /// Evaluate the expression against a record
    ///
    /// Used for in-memory access checks when the record is already loaded.
    pub fn evaluate(
        &self,
        ctx: &Context,
        record: &HashMap<String, FieldValue>,
    ) -> bool {
        match self {
            DomainExpr::True => true,
            DomainExpr::False => false,

            DomainExpr::And(exprs) => exprs.iter().all(|e| e.evaluate(ctx, record)),
            DomainExpr::Or(exprs) => exprs.iter().any(|e| e.evaluate(ctx, record)),
            DomainExpr::Not(expr) => !expr.evaluate(ctx, record),

            DomainExpr::Condition { field, operator, value } => {
                let record_value = record.get(field);
                let compare_value = value.resolve(ctx, Some(record));

                match (record_value, compare_value) {
                    (None, _) => matches!(operator, DomainOp::IsNull),
                    (Some(FieldValue::Null), _) => matches!(operator, DomainOp::IsNull),
                    (Some(_), None) => false, // Context variable not available

                    (Some(rv), Some(cv)) => {
                        match operator {
                            DomainOp::Eq => rv == &cv,
                            DomainOp::Ne => rv != &cv,
                            DomainOp::IsNull => matches!(rv, FieldValue::Null),
                            DomainOp::IsNotNull => !matches!(rv, FieldValue::Null),

                            DomainOp::Lt | DomainOp::Lte | DomainOp::Gt | DomainOp::Gte => {
                                compare_ordered(rv, &cv, operator)
                            }

                            DomainOp::In => {
                                if let FieldValue::Array(arr) = cv {
                                    arr.contains(rv)
                                } else {
                                    false
                                }
                            }
                            DomainOp::NotIn => {
                                if let FieldValue::Array(arr) = cv {
                                    !arr.contains(rv)
                                } else {
                                    true
                                }
                            }

                            DomainOp::Like | DomainOp::ILike => {
                                if let (FieldValue::String(s), FieldValue::String(pattern)) = (rv, &cv) {
                                    let pattern = pattern
                                        .replace('%', ".*")
                                        .replace('_', ".");

                                    if matches!(operator, DomainOp::ILike) {
                                        regex::Regex::new(&format!("(?i)^{}$", pattern))
                                            .map(|re| re.is_match(s))
                                            .unwrap_or(false)
                                    } else {
                                        regex::Regex::new(&format!("^{}$", pattern))
                                            .map(|re| re.is_match(s))
                                            .unwrap_or(false)
                                    }
                                } else {
                                    false
                                }
                            }

                            // ChildOf/ParentOf require hierarchical queries
                            DomainOp::ChildOf | DomainOp::ParentOf => false,
                        }
                    }
                }
            }
        }
    }
}

/// Compare two FieldValues for ordering
fn compare_ordered(a: &FieldValue, b: &FieldValue, op: &DomainOp) -> bool {
    match (a, b) {
        (FieldValue::Int(a), FieldValue::Int(b)) => match op {
            DomainOp::Lt => a < b,
            DomainOp::Lte => a <= b,
            DomainOp::Gt => a > b,
            DomainOp::Gte => a >= b,
            _ => false,
        },
        (FieldValue::Float(a), FieldValue::Float(b)) => match op {
            DomainOp::Lt => a < b,
            DomainOp::Lte => a <= b,
            DomainOp::Gt => a > b,
            DomainOp::Gte => a >= b,
            _ => false,
        },
        (FieldValue::String(a), FieldValue::String(b)) => match op {
            DomainOp::Lt => a < b,
            DomainOp::Lte => a <= b,
            DomainOp::Gt => a > b,
            DomainOp::Gte => a >= b,
            _ => false,
        },
        (FieldValue::Timestamp(a), FieldValue::Timestamp(b)) => match op {
            DomainOp::Lt => a < b,
            DomainOp::Lte => a <= b,
            DomainOp::Gt => a > b,
            DomainOp::Gte => a >= b,
            _ => false,
        },
        _ => false,
    }
}

/// SQL dialect trait for generating database-specific SQL
pub trait SqlDialect: Send + Sync {
    /// Generate a parameter placeholder (e.g., $1 for Postgres, @p1 for MSSQL)
    fn param_placeholder(&self, idx: i32) -> String;

    /// Generate an ILIKE expression (case-insensitive LIKE)
    fn ilike_expression(&self, field: &str, placeholder: &str) -> String;
}

/// PostgreSQL dialect implementation
pub struct PostgresDialect;

impl SqlDialect for PostgresDialect {
    fn param_placeholder(&self, idx: i32) -> String {
        format!("${}", idx)
    }

    fn ilike_expression(&self, field: &str, placeholder: &str) -> String {
        format!("{} ILIKE {}", field, placeholder)
    }
}

/// MSSQL dialect implementation
pub struct MssqlDialect;

impl SqlDialect for MssqlDialect {
    fn param_placeholder(&self, idx: i32) -> String {
        format!("@p{}", idx)
    }

    fn ilike_expression(&self, field: &str, placeholder: &str) -> String {
        format!("LOWER({}) LIKE LOWER({})", field, placeholder)
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain Parser
// ─────────────────────────────────────────────────────────────────────────────

/// Parser for Odoo-style domain expressions
struct DomainParser<'a> {
    input: &'a str,
    pos: usize,
}

impl<'a> DomainParser<'a> {
    fn new(input: &'a str) -> Self {
        Self { input, pos: 0 }
    }

    fn parse(mut self) -> VortexResult<DomainExpr> {
        self.skip_whitespace();

        // Expect opening bracket
        if !self.consume_char('[') {
            return Err(VortexError::ValidationFailed(
                "Domain expression must start with '['".to_string(),
            ));
        }

        let mut exprs = Vec::new();
        let mut operators: Vec<char> = Vec::new();

        loop {
            self.skip_whitespace();

            // Check for end of list
            if self.peek_char() == Some(']') {
                self.consume_char(']');
                break;
            }

            // Check for logical operators
            if self.peek_char() == Some('"') {
                let token = self.parse_string()?;
                match token.as_str() {
                    "&" => operators.push('&'),
                    "|" => operators.push('|'),
                    "!" => operators.push('!'),
                    _ => {
                        return Err(VortexError::ValidationFailed(format!(
                            "Unknown operator: {}",
                            token
                        )));
                    }
                }
                self.skip_whitespace();
                if self.peek_char() == Some(',') {
                    self.consume_char(',');
                }
                continue;
            }

            // Parse a condition tuple
            if self.peek_char() == Some('(') {
                let condition = self.parse_condition()?;
                exprs.push(condition);

                self.skip_whitespace();
                if self.peek_char() == Some(',') {
                    self.consume_char(',');
                }
                continue;
            }

            // Unknown token
            return Err(VortexError::ValidationFailed(format!(
                "Unexpected character at position {}: {:?}",
                self.pos,
                self.peek_char()
            )));
        }

        // Build the expression tree from operators and conditions
        self.build_expression_tree(exprs, operators)
    }

    fn build_expression_tree(
        &self,
        mut exprs: Vec<DomainExpr>,
        operators: Vec<char>,
    ) -> VortexResult<DomainExpr> {
        if exprs.is_empty() {
            return Ok(DomainExpr::True);
        }

        if operators.is_empty() {
            // No explicit operators, default to AND
            return Ok(DomainExpr::and(exprs));
        }

        // Process operators in reverse (stack-based)
        let mut result_stack: Vec<DomainExpr> = Vec::new();

        for expr in exprs.drain(..).rev() {
            result_stack.push(expr);
        }

        for op in operators.iter().rev() {
            match op {
                '!' => {
                    if let Some(expr) = result_stack.pop() {
                        result_stack.push(DomainExpr::not(expr));
                    }
                }
                '&' => {
                    if result_stack.len() >= 2 {
                        let b = result_stack.pop().unwrap();
                        let a = result_stack.pop().unwrap();
                        result_stack.push(DomainExpr::and(vec![a, b]));
                    }
                }
                '|' => {
                    if result_stack.len() >= 2 {
                        let b = result_stack.pop().unwrap();
                        let a = result_stack.pop().unwrap();
                        result_stack.push(DomainExpr::or(vec![a, b]));
                    }
                }
                _ => {}
            }
        }

        // If multiple expressions remain, AND them together
        Ok(DomainExpr::and(result_stack))
    }

    fn parse_condition(&mut self) -> VortexResult<DomainExpr> {
        // Consume opening parenthesis
        if !self.consume_char('(') {
            return Err(VortexError::ValidationFailed(
                "Expected '(' for condition".to_string(),
            ));
        }

        self.skip_whitespace();

        // Parse field name
        let field = self.parse_string()?;

        self.skip_whitespace();
        if !self.consume_char(',') {
            return Err(VortexError::ValidationFailed(
                "Expected ',' after field name".to_string(),
            ));
        }

        self.skip_whitespace();

        // Parse operator
        let op_str = self.parse_string()?;
        let operator = DomainOp::from_str(&op_str).ok_or_else(|| {
            VortexError::ValidationFailed(format!("Unknown operator: {}", op_str))
        })?;

        self.skip_whitespace();
        if !self.consume_char(',') {
            return Err(VortexError::ValidationFailed(
                "Expected ',' after operator".to_string(),
            ));
        }

        self.skip_whitespace();

        // Parse value
        let value = self.parse_value()?;

        self.skip_whitespace();

        // Consume closing parenthesis
        if !self.consume_char(')') {
            return Err(VortexError::ValidationFailed(
                "Expected ')' to close condition".to_string(),
            ));
        }

        Ok(DomainExpr::Condition { field, operator, value })
    }

    fn parse_value(&mut self) -> VortexResult<DomainValue> {
        self.skip_whitespace();

        let ch = self.peek_char();

        match ch {
            // String value
            Some('"') | Some('\'') => {
                let s = self.parse_string()?;
                Ok(DomainValue::String(s))
            }

            // List value
            Some('[') => self.parse_list(),

            // Boolean or null or context variable (unquoted)
            Some('t') | Some('T') | Some('f') | Some('F') | Some('n') | Some('N')
            | Some('c') | Some('C') => {
                let ident = self.parse_identifier()?;
                match ident.to_lowercase().as_str() {
                    "true" => Ok(DomainValue::Bool(true)),
                    "false" => Ok(DomainValue::Bool(false)),
                    "null" | "none" => Ok(DomainValue::Null),
                    "current_user" => Ok(DomainValue::CurrentUser),
                    "current_company" => Ok(DomainValue::CurrentCompany),
                    _ => Ok(DomainValue::FieldRef(ident)),
                }
            }

            // Number
            Some(c) if c.is_ascii_digit() || c == '-' || c == '+' => {
                let num_str = self.parse_number_string()?;
                if num_str.contains('.') {
                    let f: f64 = num_str.parse().map_err(|_| {
                        VortexError::ValidationFailed(format!("Invalid float: {}", num_str))
                    })?;
                    Ok(DomainValue::Float(f))
                } else {
                    let i: i64 = num_str.parse().map_err(|_| {
                        VortexError::ValidationFailed(format!("Invalid integer: {}", num_str))
                    })?;
                    Ok(DomainValue::Int(i))
                }
            }

            // Field reference or other identifier
            Some(_) => {
                let ident = self.parse_identifier()?;
                Ok(DomainValue::FieldRef(ident))
            }

            None => Err(VortexError::ValidationFailed(
                "Unexpected end of input while parsing value".to_string(),
            )),
        }
    }

    fn parse_list(&mut self) -> VortexResult<DomainValue> {
        if !self.consume_char('[') {
            return Err(VortexError::ValidationFailed(
                "Expected '[' for list".to_string(),
            ));
        }

        let mut items = Vec::new();

        loop {
            self.skip_whitespace();

            if self.peek_char() == Some(']') {
                self.consume_char(']');
                break;
            }

            let value = self.parse_value()?;
            items.push(value);

            self.skip_whitespace();
            if self.peek_char() == Some(',') {
                self.consume_char(',');
            }
        }

        Ok(DomainValue::List(items))
    }

    fn parse_string(&mut self) -> VortexResult<String> {
        let quote = self.peek_char();
        if quote != Some('"') && quote != Some('\'') {
            return Err(VortexError::ValidationFailed(
                "Expected string literal".to_string(),
            ));
        }
        let quote = quote.unwrap();
        self.consume_char(quote);

        let mut result = String::new();
        while let Some(ch) = self.peek_char() {
            if ch == quote {
                self.consume_char(quote);
                return Ok(result);
            }
            if ch == '\\' {
                self.consume_char('\\');
                if let Some(escaped) = self.peek_char() {
                    match escaped {
                        'n' => result.push('\n'),
                        'r' => result.push('\r'),
                        't' => result.push('\t'),
                        '\\' => result.push('\\'),
                        c if c == quote => result.push(quote),
                        c => result.push(c),
                    }
                    self.advance();
                }
            } else {
                result.push(ch);
                self.advance();
            }
        }

        Err(VortexError::ValidationFailed(
            "Unterminated string literal".to_string(),
        ))
    }

    fn parse_identifier(&mut self) -> VortexResult<String> {
        let mut result = String::new();
        while let Some(ch) = self.peek_char() {
            if ch.is_alphanumeric() || ch == '_' {
                result.push(ch);
                self.advance();
            } else {
                break;
            }
        }
        if result.is_empty() {
            Err(VortexError::ValidationFailed(
                "Expected identifier".to_string(),
            ))
        } else {
            Ok(result)
        }
    }

    fn parse_number_string(&mut self) -> VortexResult<String> {
        let mut result = String::new();

        // Optional sign
        if let Some(ch) = self.peek_char() {
            if ch == '+' || ch == '-' {
                result.push(ch);
                self.advance();
            }
        }

        // Digits and decimal point
        while let Some(ch) = self.peek_char() {
            if ch.is_ascii_digit() || ch == '.' {
                result.push(ch);
                self.advance();
            } else {
                break;
            }
        }

        if result.is_empty() || result == "+" || result == "-" {
            Err(VortexError::ValidationFailed(
                "Expected number".to_string(),
            ))
        } else {
            Ok(result)
        }
    }

    fn skip_whitespace(&mut self) {
        while let Some(ch) = self.peek_char() {
            if ch.is_whitespace() {
                self.advance();
            } else {
                break;
            }
        }
    }

    fn peek_char(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }

    fn consume_char(&mut self, expected: char) -> bool {
        if self.peek_char() == Some(expected) {
            self.advance();
            true
        } else {
            false
        }
    }

    fn advance(&mut self) {
        if let Some(ch) = self.peek_char() {
            self.pos += ch.len_utf8();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;
    use vortex_common::{CompanyId, UserId};

    fn test_context() -> Context {
        Context::authenticated(
            UserId(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
            CompanyId(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap()),
        )
    }

    #[test]
    fn test_parse_empty() {
        let domain = DomainExpr::parse("[]").unwrap();
        assert_eq!(domain, DomainExpr::True);
    }

    #[test]
    fn test_parse_simple_eq() {
        let domain = DomainExpr::parse(r#"[("name", "=", "test")]"#).unwrap();
        match domain {
            DomainExpr::Condition { field, operator, value } => {
                assert_eq!(field, "name");
                assert_eq!(operator, DomainOp::Eq);
                assert_eq!(value, DomainValue::String("test".to_string()));
            }
            _ => panic!("Expected Condition"),
        }
    }

    #[test]
    fn test_parse_current_user() {
        let domain = DomainExpr::parse(r#"[("user_id", "=", current_user)]"#).unwrap();
        match domain {
            DomainExpr::Condition { field, operator, value } => {
                assert_eq!(field, "user_id");
                assert_eq!(operator, DomainOp::Eq);
                assert_eq!(value, DomainValue::CurrentUser);
            }
            _ => panic!("Expected Condition"),
        }
    }

    #[test]
    fn test_parse_current_company() {
        let domain = DomainExpr::parse(r#"[("company_id", "=", current_company)]"#).unwrap();
        match domain {
            DomainExpr::Condition { field, operator, value } => {
                assert_eq!(field, "company_id");
                assert_eq!(operator, DomainOp::Eq);
                assert_eq!(value, DomainValue::CurrentCompany);
            }
            _ => panic!("Expected Condition"),
        }
    }

    #[test]
    fn test_parse_integer() {
        let domain = DomainExpr::parse(r#"[("count", ">", 5)]"#).unwrap();
        match domain {
            DomainExpr::Condition { field, operator, value } => {
                assert_eq!(field, "count");
                assert_eq!(operator, DomainOp::Gt);
                assert_eq!(value, DomainValue::Int(5));
            }
            _ => panic!("Expected Condition"),
        }
    }

    #[test]
    fn test_parse_boolean() {
        let domain = DomainExpr::parse(r#"[("active", "=", true)]"#).unwrap();
        match domain {
            DomainExpr::Condition { value, .. } => {
                assert_eq!(value, DomainValue::Bool(true));
            }
            _ => panic!("Expected Condition"),
        }
    }

    #[test]
    fn test_parse_null() {
        let domain = DomainExpr::parse(r#"[("deleted_at", "=", null)]"#).unwrap();
        match domain {
            DomainExpr::Condition { value, .. } => {
                assert_eq!(value, DomainValue::Null);
            }
            _ => panic!("Expected Condition"),
        }
    }

    #[test]
    fn test_parse_or() {
        let domain = DomainExpr::parse(r#"["|", ("a", "=", 1), ("b", "=", 2)]"#).unwrap();
        match domain {
            DomainExpr::Or(exprs) => {
                assert_eq!(exprs.len(), 2);
            }
            _ => panic!("Expected Or"),
        }
    }

    #[test]
    fn test_to_sql_simple() {
        let domain = DomainExpr::parse(r#"[("name", "=", "test")]"#).unwrap();
        let ctx = test_context();
        let dialect = PostgresDialect;
        let (sql, params) = domain.to_sql(&ctx, &dialect, &mut 1);

        assert_eq!(sql, "name = $1");
        assert_eq!(params.len(), 1);
        assert_eq!(params[0], FieldValue::String("test".to_string()));
    }

    #[test]
    fn test_to_sql_current_company() {
        let domain = DomainExpr::parse(r#"[("company_id", "=", current_company)]"#).unwrap();
        let ctx = test_context();
        let dialect = PostgresDialect;
        let (sql, params) = domain.to_sql(&ctx, &dialect, &mut 1);

        assert_eq!(sql, "company_id = $1");
        assert_eq!(params.len(), 1);
        assert_eq!(
            params[0],
            FieldValue::Uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap())
        );
    }

    #[test]
    fn test_to_sql_null() {
        let domain = DomainExpr::parse(r#"[("deleted_at", "=", null)]"#).unwrap();
        let ctx = test_context();
        let dialect = PostgresDialect;
        let (sql, params) = domain.to_sql(&ctx, &dialect, &mut 1);

        assert_eq!(sql, "deleted_at IS NULL");
        assert!(params.is_empty());
    }

    #[test]
    fn test_evaluate_simple() {
        let domain = DomainExpr::parse(r#"[("name", "=", "test")]"#).unwrap();
        let ctx = test_context();

        let mut record = HashMap::new();
        record.insert("name".to_string(), FieldValue::String("test".to_string()));

        assert!(domain.evaluate(&ctx, &record));

        record.insert("name".to_string(), FieldValue::String("other".to_string()));
        assert!(!domain.evaluate(&ctx, &record));
    }

    #[test]
    fn test_evaluate_current_user() {
        let domain = DomainExpr::parse(r#"[("user_id", "=", current_user)]"#).unwrap();
        let ctx = test_context();

        let mut record = HashMap::new();
        record.insert(
            "user_id".to_string(),
            FieldValue::Uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap()),
        );

        assert!(domain.evaluate(&ctx, &record));

        record.insert(
            "user_id".to_string(),
            FieldValue::Uuid(Uuid::parse_str("00000000-0000-0000-0000-000000000099").unwrap()),
        );
        assert!(!domain.evaluate(&ctx, &record));
    }
}
