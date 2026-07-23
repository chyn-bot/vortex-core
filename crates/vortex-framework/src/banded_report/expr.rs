//! Sandboxed expression evaluator for banded reports.
//!
//! Grammar (no code execution — only refs, arithmetic, comparisons, and a
//! fixed function set):
//!
//! ```text
//! expr    := or
//! or      := and ('||' and)*
//! and     := cmp ('&&' cmp)*
//! cmp     := add (('=='|'!='|'<'|'>'|'<='|'>=') add)?
//! add     := mul (('+'|'-') mul)*
//! mul     := unary (('*'|'/'|'%') unary)*
//! unary   := ('!'|'-') unary | primary
//! primary := number | string | ref | bool | null | call | '(' expr ')'
//! ref     := '$F{' name '}' | '$P{' name '}' | '$V{' name '}'
//! call    := ident '(' (expr (',' expr)*)? ')'
//! ```
//!
//! `+` adds when both sides are numeric, otherwise concatenates as text — the
//! ergonomic choice for building labels like `"Page " + page()`.

use std::collections::BTreeMap;

/// A runtime value. Numbers are `f64`; format masks handle presentation
/// rounding so display precision is deterministic.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Num(f64),
    Str(String),
    Bool(bool),
    Null,
}

impl Value {
    pub fn as_num(&self) -> Option<f64> {
        match self {
            Value::Num(n) => Some(*n),
            Value::Str(s) => s.trim().parse::<f64>().ok(),
            Value::Bool(b) => Some(if *b { 1.0 } else { 0.0 }),
            Value::Null => None,
        }
    }
    pub fn truthy(&self) -> bool {
        match self {
            Value::Num(n) => *n != 0.0,
            Value::Str(s) => !s.is_empty(),
            Value::Bool(b) => *b,
            Value::Null => false,
        }
    }
    pub fn to_display(&self) -> String {
        match self {
            Value::Num(n) => fmt_num_plain(*n),
            Value::Str(s) => s.clone(),
            Value::Bool(b) => b.to_string(),
            Value::Null => String::new(),
        }
    }
}

/// Everything an expression can read. Borrowed so the layout walk can reuse
/// one context and swap the current row / variable snapshot cheaply.
pub struct EvalCtx<'a> {
    pub row: &'a BTreeMap<String, String>,
    pub params: &'a BTreeMap<String, String>,
    pub vars: &'a BTreeMap<String, f64>,
    pub page: u32,
    pub pages: u32,
    pub row_num: u32,
}

impl<'a> EvalCtx<'a> {
    /// A context with no data — for static-only expressions and previews.
    pub fn empty() -> EvalCtxOwned {
        EvalCtxOwned::default()
    }
}

/// Owned backing store so callers can build a context without juggling
/// lifetimes (used by tests and the no-data band path).
#[derive(Default)]
pub struct EvalCtxOwned {
    pub row: BTreeMap<String, String>,
    pub params: BTreeMap<String, String>,
    pub vars: BTreeMap<String, f64>,
    pub page: u32,
    pub pages: u32,
    pub row_num: u32,
}

impl EvalCtxOwned {
    pub fn ctx(&self) -> EvalCtx<'_> {
        EvalCtx {
            row: &self.row,
            params: &self.params,
            vars: &self.vars,
            page: self.page,
            pages: self.pages,
            row_num: self.row_num,
        }
    }
}

/// Evaluate `src` and return its display string, applying `mask` if given.
/// Any parse/eval error degrades to an empty string (reports never crash on a
/// bad expression — they render blank, like Jasper's whenNull).
pub fn eval_display(src: &str, ctx: &EvalCtx, mask: Option<&str>) -> String {
    match eval(src, ctx) {
        Ok(v) => match mask {
            Some(m) if !m.is_empty() => apply_mask(&v, m),
            _ => v.to_display(),
        },
        Err(_) => String::new(),
    }
}

/// Evaluate `src` to a `Value`.
pub fn eval(src: &str, ctx: &EvalCtx) -> Result<Value, String> {
    let toks = lex(src)?;
    let mut p = Parser { toks, pos: 0 };
    let v = p.parse_expr(ctx)?;
    if p.pos != p.toks.len() {
        return Err("unexpected trailing tokens".into());
    }
    Ok(v)
}

// ─── Lexer ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Num(f64),
    Str(String),
    Ident(String),
    Ref(char, String), // ('F'|'P'|'V', name)
    Op(String),
    LParen,
    RParen,
    Comma,
}

fn lex(src: &str) -> Result<Vec<Tok>, String> {
    let b: Vec<char> = src.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < b.len() {
        let c = b[i];
        if c.is_whitespace() {
            i += 1;
            continue;
        }
        // Reference: $F{name} / $P{name} / $V{name}
        if c == '$' && i + 2 < b.len() && b[i + 2] == '{' {
            let kind = b[i + 1];
            if !matches!(kind, 'F' | 'P' | 'V') {
                return Err(format!("bad reference ${kind}"));
            }
            let mut j = i + 3;
            let mut name = String::new();
            while j < b.len() && b[j] != '}' {
                name.push(b[j]);
                j += 1;
            }
            if j >= b.len() {
                return Err("unterminated reference".into());
            }
            out.push(Tok::Ref(kind, name.trim().to_string()));
            i = j + 1;
            continue;
        }
        // String literal (single or double quotes).
        if c == '\'' || c == '"' {
            let quote = c;
            let mut j = i + 1;
            let mut s = String::new();
            while j < b.len() && b[j] != quote {
                if b[j] == '\\' && j + 1 < b.len() {
                    s.push(b[j + 1]);
                    j += 2;
                    continue;
                }
                s.push(b[j]);
                j += 1;
            }
            if j >= b.len() {
                return Err("unterminated string".into());
            }
            out.push(Tok::Str(s));
            i = j + 1;
            continue;
        }
        // Number.
        if c.is_ascii_digit() || (c == '.' && i + 1 < b.len() && b[i + 1].is_ascii_digit()) {
            let mut j = i;
            let mut num = String::new();
            while j < b.len() && (b[j].is_ascii_digit() || b[j] == '.') {
                num.push(b[j]);
                j += 1;
            }
            let n = num.parse::<f64>().map_err(|_| format!("bad number '{num}'"))?;
            out.push(Tok::Num(n));
            i = j;
            continue;
        }
        // Identifier / keyword / function name.
        if c.is_alphabetic() || c == '_' {
            let mut j = i;
            let mut id = String::new();
            while j < b.len() && (b[j].is_alphanumeric() || b[j] == '_') {
                id.push(b[j]);
                j += 1;
            }
            out.push(Tok::Ident(id));
            i = j;
            continue;
        }
        // Operators & punctuation.
        match c {
            '(' => {
                out.push(Tok::LParen);
                i += 1;
            }
            ')' => {
                out.push(Tok::RParen);
                i += 1;
            }
            ',' => {
                out.push(Tok::Comma);
                i += 1;
            }
            '+' | '-' | '*' | '/' | '%' => {
                out.push(Tok::Op(c.to_string()));
                i += 1;
            }
            '=' | '!' | '<' | '>' => {
                if i + 1 < b.len() && b[i + 1] == '=' {
                    out.push(Tok::Op(format!("{c}=")));
                    i += 2;
                } else if c == '!' || c == '<' || c == '>' {
                    out.push(Tok::Op(c.to_string()));
                    i += 1;
                } else {
                    return Err(format!("stray '{c}' (use == for equality)"));
                }
            }
            '&' | '|' => {
                if i + 1 < b.len() && b[i + 1] == c {
                    out.push(Tok::Op(format!("{c}{c}")));
                    i += 2;
                } else {
                    return Err(format!("stray '{c}'"));
                }
            }
            _ => return Err(format!("unexpected character '{c}'")),
        }
    }
    Ok(out)
}

// ─── Parser (recursive descent, evaluates as it goes) ────────────────────

struct Parser {
    toks: Vec<Tok>,
    pos: usize,
}

impl Parser {
    fn peek(&self) -> Option<&Tok> {
        self.toks.get(self.pos)
    }
    fn is_op(&self, want: &[&str]) -> Option<String> {
        if let Some(Tok::Op(o)) = self.peek() {
            if want.contains(&o.as_str()) {
                return Some(o.clone());
            }
        }
        None
    }

    fn parse_expr(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        self.parse_or(ctx)
    }

    fn parse_or(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        let mut left = self.parse_and(ctx)?;
        while self.is_op(&["||"]).is_some() {
            self.pos += 1;
            let right = self.parse_and(ctx)?;
            left = Value::Bool(left.truthy() || right.truthy());
        }
        Ok(left)
    }

    fn parse_and(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        let mut left = self.parse_cmp(ctx)?;
        while self.is_op(&["&&"]).is_some() {
            self.pos += 1;
            let right = self.parse_cmp(ctx)?;
            left = Value::Bool(left.truthy() && right.truthy());
        }
        Ok(left)
    }

    fn parse_cmp(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        let left = self.parse_add(ctx)?;
        if let Some(op) = self.is_op(&["==", "!=", "<", ">", "<=", ">="]) {
            self.pos += 1;
            let right = self.parse_add(ctx)?;
            return Ok(Value::Bool(compare(&left, &right, &op)));
        }
        Ok(left)
    }

    fn parse_add(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        let mut left = self.parse_mul(ctx)?;
        while let Some(op) = self.is_op(&["+", "-"]) {
            self.pos += 1;
            let right = self.parse_mul(ctx)?;
            left = if op == "+" {
                match (left.as_num(), right.as_num()) {
                    (Some(a), Some(b)) => Value::Num(a + b),
                    // string concatenation fallback
                    _ => Value::Str(format!("{}{}", left.to_display(), right.to_display())),
                }
            } else {
                let a = left.as_num().ok_or("non-numeric subtraction")?;
                let b = right.as_num().ok_or("non-numeric subtraction")?;
                Value::Num(a - b)
            };
        }
        Ok(left)
    }

    fn parse_mul(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        let mut left = self.parse_unary(ctx)?;
        while let Some(op) = self.is_op(&["*", "/", "%"]) {
            self.pos += 1;
            let right = self.parse_unary(ctx)?;
            let a = left.as_num().ok_or("non-numeric operand")?;
            let b = right.as_num().ok_or("non-numeric operand")?;
            left = match op.as_str() {
                "*" => Value::Num(a * b),
                "/" => Value::Num(if b == 0.0 { 0.0 } else { a / b }),
                _ => Value::Num(if b == 0.0 { 0.0 } else { a % b }),
            };
        }
        Ok(left)
    }

    fn parse_unary(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        if let Some(op) = self.is_op(&["!", "-"]) {
            self.pos += 1;
            let v = self.parse_unary(ctx)?;
            return Ok(match op.as_str() {
                "!" => Value::Bool(!v.truthy()),
                _ => Value::Num(-v.as_num().ok_or("non-numeric negation")?),
            });
        }
        self.parse_primary(ctx)
    }

    fn parse_primary(&mut self, ctx: &EvalCtx) -> Result<Value, String> {
        let tok = self.peek().cloned().ok_or("unexpected end of expression")?;
        match tok {
            Tok::Num(n) => {
                self.pos += 1;
                Ok(Value::Num(n))
            }
            Tok::Str(s) => {
                self.pos += 1;
                Ok(Value::Str(s))
            }
            Tok::Ref(kind, name) => {
                self.pos += 1;
                Ok(lookup_ref(kind, &name, ctx))
            }
            Tok::LParen => {
                self.pos += 1;
                let v = self.parse_expr(ctx)?;
                match self.peek() {
                    Some(Tok::RParen) => {
                        self.pos += 1;
                        Ok(v)
                    }
                    _ => Err("expected ')'".into()),
                }
            }
            Tok::Ident(id) => {
                self.pos += 1;
                match id.as_str() {
                    "true" => Ok(Value::Bool(true)),
                    "false" => Ok(Value::Bool(false)),
                    "null" => Ok(Value::Null),
                    _ => {
                        // Function call.
                        if !matches!(self.peek(), Some(Tok::LParen)) {
                            return Err(format!("unknown identifier '{id}'"));
                        }
                        self.pos += 1; // consume '('
                        let mut args = Vec::new();
                        if !matches!(self.peek(), Some(Tok::RParen)) {
                            loop {
                                args.push(self.parse_expr(ctx)?);
                                match self.peek() {
                                    Some(Tok::Comma) => {
                                        self.pos += 1;
                                    }
                                    _ => break,
                                }
                            }
                        }
                        match self.peek() {
                            Some(Tok::RParen) => self.pos += 1,
                            _ => return Err("expected ')' after arguments".into()),
                        }
                        call_fn(&id, args, ctx)
                    }
                }
            }
            _ => Err("unexpected token".into()),
        }
    }
}

fn lookup_ref(kind: char, name: &str, ctx: &EvalCtx) -> Value {
    let raw = match kind {
        'F' => ctx.row.get(name).cloned(),
        'P' => ctx.params.get(name).cloned(),
        'V' => return ctx.vars.get(name).map(|n| Value::Num(*n)).unwrap_or(Value::Num(0.0)),
        _ => None,
    };
    match raw {
        Some(s) => Value::Str(s),
        None => Value::Null,
    }
}

fn compare(a: &Value, b: &Value, op: &str) -> bool {
    // Numeric comparison when both coerce to numbers, else lexical.
    let ord = match (a.as_num(), b.as_num()) {
        (Some(x), Some(y)) => x.partial_cmp(&y),
        _ => Some(a.to_display().cmp(&b.to_display())),
    };
    use std::cmp::Ordering::*;
    match op {
        "==" => ord == Some(Equal),
        "!=" => ord != Some(Equal),
        "<" => ord == Some(Less),
        ">" => ord == Some(Greater),
        "<=" => matches!(ord, Some(Less) | Some(Equal)),
        ">=" => matches!(ord, Some(Greater) | Some(Equal)),
        _ => false,
    }
}

fn call_fn(name: &str, args: Vec<Value>, _ctx: &EvalCtx) -> Result<Value, String> {
    let arg = |i: usize| args.get(i).cloned().unwrap_or(Value::Null);
    match name {
        "if" => Ok(if arg(0).truthy() { arg(1) } else { arg(2) }),
        "coalesce" => Ok(args.into_iter().find(|v| v.truthy()).unwrap_or(Value::Null)),
        "concat" => Ok(Value::Str(args.iter().map(|v| v.to_display()).collect())),
        "upper" => Ok(Value::Str(arg(0).to_display().to_uppercase())),
        "lower" => Ok(Value::Str(arg(0).to_display().to_lowercase())),
        "trim" => Ok(Value::Str(arg(0).to_display().trim().to_string())),
        "abs" => Ok(Value::Num(arg(0).as_num().unwrap_or(0.0).abs())),
        "round" => {
            let n = arg(0).as_num().unwrap_or(0.0);
            let d = arg(1).as_num().unwrap_or(0.0) as i32;
            let f = 10f64.powi(d);
            Ok(Value::Num((n * f).round() / f))
        }
        "format" => {
            let mask = arg(1).to_display();
            Ok(Value::Str(apply_mask(&arg(0), &mask)))
        }
        "page" => Ok(Value::Num(_ctx.page as f64)),
        "pages" => Ok(Value::Num(_ctx.pages as f64)),
        "rowNum" => Ok(Value::Num(_ctx.row_num as f64)),
        _ => Err(format!("unknown function '{name}'")),
    }
}

// ─── Format masks ────────────────────────────────────────────────────────

/// Apply a number or date mask to a value. Number masks use `#`, `0`, `,`
/// (grouping) and `.` (decimals), with optional literal prefix/suffix. Date
/// masks (`yyyy`, `MM`, `dd`, `HH`, `mm`, `ss`) format an ISO-ish string.
pub fn apply_mask(v: &Value, mask: &str) -> String {
    if is_date_mask(mask) {
        return apply_date_mask(&v.to_display(), mask);
    }
    match v.as_num() {
        Some(n) => apply_num_mask(n, mask),
        None => v.to_display(),
    }
}

fn is_date_mask(mask: &str) -> bool {
    mask.contains("yyyy") || mask.contains("MM") || mask.contains("dd") || mask.contains("HH")
}

fn apply_num_mask(n: f64, mask: &str) -> String {
    // Split optional literal prefix/suffix from the numeric pattern.
    let start = mask.find(['#', '0']).unwrap_or(0);
    let end = mask.rfind(['#', '0']).map(|i| i + 1).unwrap_or(mask.len());
    let prefix = &mask[..start];
    let pattern = &mask[start..end];
    let suffix = &mask[end..];

    let decimals = pattern.split_once('.').map(|(_, d)| d.chars().filter(|c| *c == '0' || *c == '#').count()).unwrap_or(0);
    let grouped = pattern.contains(',');

    let neg = n < 0.0;
    let rounded = format!("{:.*}", decimals, n.abs());
    let (int_part, frac_part) = match rounded.split_once('.') {
        Some((i, f)) => (i.to_string(), f.to_string()),
        None => (rounded.clone(), String::new()),
    };
    let int_fmt = if grouped { group_thousands(&int_part) } else { int_part };
    let mut body = int_fmt;
    if decimals > 0 {
        body.push('.');
        body.push_str(&frac_part);
    }
    format!("{}{}{}{}", prefix, if neg { "-" } else { "" }, body, suffix)
}

fn group_thousands(digits: &str) -> String {
    let bytes: Vec<char> = digits.chars().collect();
    let mut out = String::new();
    let n = bytes.len();
    for (idx, ch) in bytes.iter().enumerate() {
        if idx > 0 && (n - idx) % 3 == 0 {
            out.push(',');
        }
        out.push(*ch);
    }
    out
}

fn apply_date_mask(iso: &str, mask: &str) -> String {
    // Parse leading YYYY-MM-DD[ T]HH:MM:SS from a Postgres text timestamp.
    let s = iso.trim();
    let get = |a: usize, b: usize| s.get(a..b).unwrap_or("");
    let year = get(0, 4);
    let month = get(5, 7);
    let day = get(8, 10);
    let hour = get(11, 13);
    let min = get(14, 16);
    let sec = get(17, 19);
    if year.is_empty() {
        return iso.to_string();
    }
    mask.replace("yyyy", year)
        .replace("MM", month)
        .replace("dd", day)
        .replace("HH", hour)
        .replace("mm", min)
        .replace("ss", sec)
}

/// Plain numeric rendering that drops trailing `.0` for whole numbers.
fn fmt_num_plain(n: f64) -> String {
    if n.fract() == 0.0 && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        // Trim to a reasonable precision without scientific notation.
        let s = format!("{:.6}", n);
        let s = s.trim_end_matches('0').trim_end_matches('.');
        s.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx_with(row: &[(&str, &str)], vars: &[(&str, f64)], page: u32, pages: u32) -> EvalCtxOwned {
        let mut c = EvalCtxOwned::default();
        for (k, v) in row {
            c.row.insert(k.to_string(), v.to_string());
        }
        for (k, v) in vars {
            c.vars.insert(k.to_string(), *v);
        }
        c.page = page;
        c.pages = pages;
        c.row_num = 1;
        c
    }

    #[test]
    fn arithmetic_and_refs() {
        let o = ctx_with(&[("qty", "3"), ("price", "4.5")], &[], 1, 1);
        assert_eq!(eval("$F{qty} * $F{price}", &o.ctx()).unwrap(), Value::Num(13.5));
    }

    #[test]
    fn string_concat_with_plus() {
        let o = ctx_with(&[], &[], 2, 7);
        assert_eq!(eval_display("\"Page \" + page() + \" of \" + pages()", &o.ctx(), None), "Page 2 of 7");
    }

    #[test]
    fn if_and_comparison() {
        let o = ctx_with(&[("amt", "150")], &[], 1, 1);
        assert_eq!(eval_display("if($F{amt} > 100, \"BIG\", \"small\")", &o.ctx(), None), "BIG");
    }

    #[test]
    fn variable_lookup_and_mask() {
        let o = ctx_with(&[], &[("total", 1234567.5)], 1, 1);
        assert_eq!(eval_display("$V{total}", &o.ctx(), Some("#,##0.00")), "1,234,567.50");
    }

    #[test]
    fn negative_number_mask() {
        let o = EvalCtxOwned::default();
        assert_eq!(eval_display("0 - 2500.5", &o.ctx(), Some("RM #,##0.00")), "RM -2,500.50");
    }

    #[test]
    fn date_mask() {
        let o = ctx_with(&[("d", "2026-07-19 13:45:30")], &[], 1, 1);
        assert_eq!(eval_display("$F{d}", &o.ctx(), Some("dd/MM/yyyy")), "19/07/2026");
    }

    #[test]
    fn coalesce_and_upper() {
        let o = ctx_with(&[("a", ""), ("b", "hello")], &[], 1, 1);
        assert_eq!(eval_display("upper(coalesce($F{a}, $F{b}))", &o.ctx(), None), "HELLO");
    }

    #[test]
    fn bad_expr_is_blank_not_panic() {
        let o = EvalCtxOwned::default();
        assert_eq!(eval_display("$F{x} + (", &o.ctx(), None), "");
    }

    #[test]
    fn division_by_zero_is_zero() {
        let o = EvalCtxOwned::default();
        assert_eq!(eval("5 / 0", &o.ctx()).unwrap(), Value::Num(0.0));
    }
}
