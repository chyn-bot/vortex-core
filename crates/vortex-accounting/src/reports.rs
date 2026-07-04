//! Financial reports — trial balance, general ledger, aged AR/AP,
//! P&L and balance sheet. Registered through `Plugin::reports()`, served
//! by the framework at `GET /reports/{code}?format=html|csv` (plus any
//! report-specific query params documented per report).
//!
//! All figures come from **posted** moves only.

use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::Row;

const REPORT_STYLE: &str = "<style>\
body{font-family:sans-serif;margin:2em;color:#111}\
h1{margin-bottom:0}.sub{color:#666;margin-top:2px;margin-bottom:1.5em}\
table{border-collapse:collapse;width:100%}\
th,td{border:1px solid #ddd;padding:6px 8px;text-align:left}\
th{background:#f5f5f5}\
td.num,th.num{text-align:right;font-variant-numeric:tabular-nums}\
tr.total{font-weight:bold;background:#fafafa}\
tr.section th{background:#eee}\
@media print{body{margin:0}}\
</style>";

fn money(d: Decimal) -> String {
    d.round_dp(2).to_string()
}

fn esc(s: &str) -> String {
    vortex_plugin_sdk::framework::html_escape(s)
}

fn date_clause(params: &ReportParams) -> (String, String) {
    // Returns (SQL predicate on m.move_date, human label).
    let from = params.get("from").unwrap_or("");
    let to = params.get("to").unwrap_or("");
    let mut clauses = Vec::new();
    let mut label = Vec::new();
    // Values are injected as literals only after strict date validation.
    if let Ok(d) = from.parse::<vortex_plugin_sdk::chrono::NaiveDate>() {
        clauses.push(format!("m.move_date >= '{d}'"));
        label.push(format!("from {d}"));
    }
    if let Ok(d) = to.parse::<vortex_plugin_sdk::chrono::NaiveDate>() {
        clauses.push(format!("m.move_date <= '{d}'"));
        label.push(format!("to {d}"));
    }
    let sql = if clauses.is_empty() {
        String::new()
    } else {
        format!(" AND {}", clauses.join(" AND "))
    };
    let label = if label.is_empty() {
        "all dates".to_string()
    } else {
        label.join(" ")
    };
    (sql, label)
}

fn html_page(title: &str, subtitle: &str, table: &str) -> String {
    format!(
        "<!DOCTYPE html><html><head><title>{t}</title>{style}</head><body>\
         <h1>{t}</h1><p class=\"sub\">{s}</p>{table}</body></html>",
        t = esc(title),
        s = esc(subtitle),
        style = REPORT_STYLE,
        table = table,
    )
}

fn csv_escape(s: &str) -> String {
    if s.contains(',') || s.contains('"') || s.contains('\n') {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ─── Report definitions ──────────────────────────────────────────────────

pub fn report_defs() -> Vec<ReportDef> {
    vec![
        trial_balance(),
        general_ledger(),
        aged("accounting.aged_receivables", "Aged Receivables", true),
        aged("accounting.aged_payables", "Aged Payables", false),
        profit_and_loss(),
        balance_sheet(),
        sst02(),
        tax_detail(),
        einvoice_register(),
        statement_of_account(),
        bank_reconciliation(),
        asset_register(),
        pl_by_dimension(),
    ]
}

/// Fixed Asset Register in MFRS 116 note format: cost b/f, additions,
/// disposals, accumulated depreciation, NBV. Params: `from`, `to`
/// (default: current calendar year).
fn asset_register() -> ReportDef {
    ReportDef::new(
        "accounting.asset_register",
        "Fixed Asset Register",
        "MFRS 116 movement note: cost, additions, disposals, depreciation, net book value",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            use vortex_plugin_sdk::chrono::Datelike;
            let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
            let year_start =
                vortex_plugin_sdk::chrono::NaiveDate::from_ymd_opt(today.year(), 1, 1).unwrap();
            let from = params
                .get("from")
                .unwrap_or("")
                .parse::<vortex_plugin_sdk::chrono::NaiveDate>()
                .unwrap_or(year_start);
            let to = params
                .get("to")
                .unwrap_or("")
                .parse::<vortex_plugin_sdk::chrono::NaiveDate>()
                .unwrap_or(today);
            let rows = vortex_plugin_sdk::sqlx::query(
                "SELECT a.name, a.reference, a.cost, a.start_date, a.state, \
                        (SELECT m.move_date FROM acc_move m WHERE m.id = a.disposal_move_id) AS disposal_date, \
                        COALESCE((SELECT SUM(d.amount) FROM acc_asset_depreciation d \
                                  WHERE d.asset_id = a.id AND d.state = 'posted' AND d.dep_date < $1), 0) AS dep_bf, \
                        COALESCE((SELECT SUM(d.amount) FROM acc_asset_depreciation d \
                                  WHERE d.asset_id = a.id AND d.state = 'posted' \
                                    AND d.dep_date BETWEEN $1 AND $2), 0) AS dep_period \
                 FROM acc_asset a WHERE a.state <> 'draft' ORDER BY a.start_date, a.name",
            )
            .bind(from)
            .bind(to)
            .fetch_all(&state.db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            struct Line {
                name: String,
                cost_bf: Decimal,
                additions: Decimal,
                disposals: Decimal,
                dep_bf: Decimal,
                dep_period: Decimal,
                nbv: Decimal,
            }
            let mut lines = Vec::new();
            for r in &rows {
                let cost: Decimal = r.get("cost");
                let start: vortex_plugin_sdk::chrono::NaiveDate = r.get("start_date");
                let disposal: Option<vortex_plugin_sdk::chrono::NaiveDate> = r.get("disposal_date");
                let addition = start >= from && start <= to;
                let disposed_in_period =
                    disposal.map(|d| d >= from && d <= to).unwrap_or(false);
                // Fully out before the window: skip.
                if disposal.map(|d| d < from).unwrap_or(false) {
                    continue;
                }
                let dep_bf: Decimal = r.get("dep_bf");
                let dep_period: Decimal = r.get("dep_period");
                let cost_bf = if addition { Decimal::ZERO } else { cost };
                let additions = if addition { cost } else { Decimal::ZERO };
                let disposals = if disposed_in_period { cost } else { Decimal::ZERO };
                let nbv = if disposed_in_period {
                    Decimal::ZERO
                } else {
                    cost - dep_bf - dep_period
                };
                let name: String = r.get("name");
                let reference: Option<String> = r.get("reference");
                lines.push(Line {
                    name: reference.map(|x| format!("{name} ({x})")).unwrap_or(name),
                    cost_bf,
                    additions,
                    disposals,
                    dep_bf,
                    dep_period,
                    nbv,
                });
            }
            let subtitle = format!("{from} to {to}");
            match params.format {
                ReportFormat::Csv => {
                    let mut csv = String::from(
                        "asset,cost_bf,additions,disposals,dep_bf,dep_period,nbv\n",
                    );
                    for l in &lines {
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            csv_escape(&l.name),
                            money(l.cost_bf),
                            money(l.additions),
                            money(l.disposals),
                            money(l.dep_bf),
                            money(l.dep_period),
                            money(l.nbv),
                        ));
                    }
                    Ok(ReportOutput::csv("asset-register.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Asset</th><th class=\"num\">Cost b/f</th>\
                         <th class=\"num\">Additions</th><th class=\"num\">Disposals (cost)</th>\
                         <th class=\"num\">Acc. dep. b/f</th><th class=\"num\">Depreciation</th>\
                         <th class=\"num\">NBV</th></tr>",
                    );
                    let mut t = [Decimal::ZERO; 6];
                    for l in &lines {
                        let vals =
                            [l.cost_bf, l.additions, l.disposals, l.dep_bf, l.dep_period, l.nbv];
                        table.push_str(&format!("<tr><td>{}</td>", esc(&l.name)));
                        for (i, v) in vals.iter().enumerate() {
                            t[i] += v;
                            table.push_str(&format!("<td class=\"num\">{}</td>", money(*v)));
                        }
                        table.push_str("</tr>");
                    }
                    table.push_str("<tr class=\"total\"><td>Total</td>");
                    for v in t {
                        table.push_str(&format!("<td class=\"num\">{}</td>", money(v)));
                    }
                    table.push_str("</tr></table>");
                    Ok(ReportOutput::html(
                        "asset-register.html",
                        html_page("Fixed Asset Register", &subtitle, &table),
                    ))
                }
            }
        },
    )
}

/// P&L grouped by analytic dimension. Params: `dim` = project |
/// department (default project), `from`, `to`.
fn pl_by_dimension() -> ReportDef {
    ReportDef::new(
        "accounting.pl_by_dimension",
        "P&L by Dimension",
        "Income and expenses per project or department dimension",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let dim = if params.get("dim") == Some("department") {
                "department_id"
            } else {
                "project_id"
            };
            let (date_sql, date_label) = date_clause(&params);
            let sql = format!(
                "SELECT COALESCE(d.code || ' ' || d.name, '(untagged)') AS dimension, \
                        SUM(CASE WHEN a.account_type IN ('income', 'income_other') \
                            THEN l.credit - l.debit ELSE 0 END) AS income, \
                        SUM(CASE WHEN a.account_type LIKE 'expense%' \
                            THEN l.debit - l.credit ELSE 0 END) AS expense \
                 FROM acc_move_line l \
                 JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted'{date_sql} \
                 JOIN acc_account a ON a.id = l.account_id \
                 LEFT JOIN acc_dimension d ON d.id = l.{dim} \
                 WHERE a.account_type IN ('income', 'income_other') \
                    OR a.account_type LIKE 'expense%' \
                 GROUP BY 1 ORDER BY 1"
            );
            let rows = vortex_plugin_sdk::sqlx::query(&sql)
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
            match params.format {
                ReportFormat::Csv => {
                    let mut csv = String::from("dimension,income,expense,result\n");
                    for r in &rows {
                        let income: Decimal = r.get("income");
                        let expense: Decimal = r.get("expense");
                        csv.push_str(&format!(
                            "{},{},{},{}\n",
                            csv_escape(&r.get::<String, _>("dimension")),
                            money(income),
                            money(expense),
                            money(income - expense),
                        ));
                    }
                    Ok(ReportOutput::csv("pl-by-dimension.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Dimension</th><th class=\"num\">Income</th>\
                         <th class=\"num\">Expenses</th><th class=\"num\">Result</th></tr>",
                    );
                    let mut ti = Decimal::ZERO;
                    let mut te = Decimal::ZERO;
                    for r in &rows {
                        let income: Decimal = r.get("income");
                        let expense: Decimal = r.get("expense");
                        ti += income;
                        te += expense;
                        table.push_str(&format!(
                            "<tr><td>{}</td><td class=\"num\">{}</td>\
                             <td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                            esc(&r.get::<String, _>("dimension")),
                            money(income),
                            money(expense),
                            money(income - expense),
                        ));
                    }
                    table.push_str(&format!(
                        "<tr class=\"total\"><td>Total</td><td class=\"num\">{}</td>\
                         <td class=\"num\">{}</td><td class=\"num\">{}</td></tr></table>",
                        money(ti),
                        money(te),
                        money(ti - te),
                    ));
                    Ok(ReportOutput::html(
                        "pl-by-dimension.html",
                        html_page("P&L by Dimension", &date_label, &table),
                    ))
                }
            }
        },
    )
}

/// Ageing bucket upper bounds from `acc_config.aging_buckets`
/// (JSONB int array), falling back to the classic 30/60/90/120.
async fn aging_buckets(state: &AppState) -> Vec<i64> {
    let raw: Option<vortex_plugin_sdk::serde_json::Value> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT aging_buckets FROM acc_config ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .ok()
    .flatten();
    let mut buckets: Vec<i64> = raw
        .and_then(|v| {
            v.as_array().map(|a| a.iter().filter_map(|x| x.as_i64()).filter(|n| *n > 0).collect())
        })
        .unwrap_or_default();
    buckets.sort_unstable();
    buckets.dedup();
    if buckets.is_empty() {
        buckets = vec![30, 60, 90, 120];
    }
    buckets
}

/// Human labels for bucket columns: "1–30", "31–60", …, "120+".
fn bucket_labels(buckets: &[i64]) -> Vec<String> {
    let mut labels = Vec::new();
    let mut lo = 1;
    for b in buckets {
        labels.push(format!("{lo}\u{2013}{b}"));
        lo = b + 1;
    }
    labels.push(format!("{}+", buckets.last().copied().unwrap_or(0)));
    labels
}

/// Trial balance — per-account debit/credit totals and balance.
/// Params: `from`, `to` (ISO dates, optional).
fn trial_balance() -> ReportDef {
    ReportDef::new(
        "accounting.trial_balance",
        "Trial Balance",
        "Per-account debit/credit totals and balance over a period (posted entries)",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let (date_sql, date_label) = date_clause(&params);
            let sql = format!(
                "SELECT a.code, a.name, a.account_type, \
                        COALESCE(SUM(l.debit), 0) AS debit, \
                        COALESCE(SUM(l.credit), 0) AS credit \
                 FROM acc_account a \
                 LEFT JOIN (acc_move_line l \
                     JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted'{date_sql}) \
                     ON l.account_id = a.id \
                 WHERE a.active \
                 GROUP BY a.id, a.code, a.name, a.account_type \
                 HAVING COALESCE(SUM(l.debit), 0) <> 0 OR COALESCE(SUM(l.credit), 0) <> 0 \
                 ORDER BY a.code"
            );
            let rows = vortex_plugin_sdk::sqlx::query(&sql)
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            let mut total_debit = Decimal::ZERO;
            let mut total_credit = Decimal::ZERO;
            let data: Vec<(String, String, Decimal, Decimal)> = rows
                .iter()
                .map(|r| {
                    let d: Decimal = r.get("debit");
                    let c: Decimal = r.get("credit");
                    total_debit += d;
                    total_credit += c;
                    (r.get("code"), r.get("name"), d, c)
                })
                .collect();

            match params.format {
                ReportFormat::Csv => {
                    let mut csv = String::from("code,account,debit,credit,balance\n");
                    for (code, name, d, c) in &data {
                        csv.push_str(&format!(
                            "{},{},{},{},{}\n",
                            csv_escape(code),
                            csv_escape(name),
                            money(*d),
                            money(*c),
                            money(*d - *c),
                        ));
                    }
                    Ok(ReportOutput::csv("trial-balance.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Code</th><th>Account</th>\
                         <th class=\"num\">Debit</th><th class=\"num\">Credit</th>\
                         <th class=\"num\">Balance</th></tr>",
                    );
                    for (code, name, d, c) in &data {
                        table.push_str(&format!(
                            "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td>\
                             <td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                            esc(code),
                            esc(name),
                            money(*d),
                            money(*c),
                            money(*d - *c),
                        ));
                    }
                    table.push_str(&format!(
                        "<tr class=\"total\"><td colspan=\"2\">Totals</td>\
                         <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                         <td class=\"num\">{}</td></tr></table>",
                        money(total_debit),
                        money(total_credit),
                        money(total_debit - total_credit),
                    ));
                    Ok(ReportOutput::html(
                        "trial-balance.html",
                        html_page("Trial Balance", &date_label, &table),
                    ))
                }
            }
        },
    )
}

/// General ledger — every posted line for one account.
/// Params: `account` (code, required), `from`, `to`.
fn general_ledger() -> ReportDef {
    ReportDef::new(
        "accounting.general_ledger",
        "General Ledger",
        "Posted lines for one account with a running balance (?account=<code>)",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let Some(account_code) = params.get("account") else {
                return Err(VortexError::ValidationFailed(
                    "pass ?account=<code>, e.g. ?account=1200".to_string(),
                ));
            };
            let (date_sql, date_label) = date_clause(&params);
            let sql = format!(
                "SELECT m.number, m.move_date::text AS move_date, l.name, \
                        COALESCE(p.name, '') AS partner, l.debit, l.credit \
                 FROM acc_move_line l \
                 JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted'{date_sql} \
                 JOIN acc_account a ON a.id = l.account_id \
                 LEFT JOIN contacts p ON p.id = l.partner_id \
                 WHERE a.code = $1 \
                 ORDER BY m.move_date, m.number, l.sequence"
            );
            let rows = vortex_plugin_sdk::sqlx::query(&sql)
                .bind(account_code)
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            let subtitle = format!("account {account_code} · {date_label}");
            match params.format {
                ReportFormat::Csv => {
                    let mut csv =
                        String::from("number,date,label,partner,debit,credit,balance\n");
                    let mut bal = Decimal::ZERO;
                    for r in &rows {
                        let d: Decimal = r.get("debit");
                        let c: Decimal = r.get("credit");
                        bal += d - c;
                        let number: Option<String> = r.get("number");
                        let name: Option<String> = r.get("name");
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            csv_escape(number.as_deref().unwrap_or("/")),
                            r.get::<String, _>("move_date"),
                            csv_escape(name.as_deref().unwrap_or("")),
                            csv_escape(&r.get::<String, _>("partner")),
                            money(d),
                            money(c),
                            money(bal),
                        ));
                    }
                    Ok(ReportOutput::csv("general-ledger.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Number</th><th>Date</th><th>Label</th><th>Partner</th>\
                         <th class=\"num\">Debit</th><th class=\"num\">Credit</th>\
                         <th class=\"num\">Balance</th></tr>",
                    );
                    let mut bal = Decimal::ZERO;
                    for r in &rows {
                        let d: Decimal = r.get("debit");
                        let c: Decimal = r.get("credit");
                        bal += d - c;
                        let number: Option<String> = r.get("number");
                        let name: Option<String> = r.get("name");
                        table.push_str(&format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                             <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                             <td class=\"num\">{}</td></tr>",
                            esc(number.as_deref().unwrap_or("/")),
                            esc(&r.get::<String, _>("move_date")),
                            esc(name.as_deref().unwrap_or("")),
                            esc(&r.get::<String, _>("partner")),
                            money(d),
                            money(c),
                            money(bal),
                        ));
                    }
                    table.push_str("</table>");
                    Ok(ReportOutput::html(
                        "general-ledger.html",
                        html_page("General Ledger", &subtitle, &table),
                    ))
                }
            }
        },
    )
}

/// Aged open documents by partner in 30-day buckets.
fn aged(code: &'static str, title: &'static str, receivable: bool) -> ReportDef {
    let description = if receivable {
        "Open customer invoices by partner in configurable ageing buckets (Settings ▸ aging buckets)"
    } else {
        "Open vendor bills by partner in configurable ageing buckets (Settings ▸ aging buckets)"
    };
    ReportDef::new(
        code,
        title,
        description,
        vec![ReportFormat::Html, ReportFormat::Csv],
        move |state, params| async move {
            let type_filter = if receivable {
                "m.move_type = 'customer_invoice'"
            } else {
                "m.move_type = 'vendor_bill'"
            };
            let buckets = aging_buckets(&state).await;
            // Dynamic bucket columns b0..bn from validated integers only.
            let mut cases = String::new();
            let mut lo = 1i64;
            for (i, hi) in buckets.iter().enumerate() {
                cases.push_str(&format!(
                    "SUM(CASE WHEN CURRENT_DATE - m.due_date BETWEEN {lo} AND {hi} \
                     THEN m.amount_residual ELSE 0 END) AS b{i}, "
                ));
                lo = hi + 1;
            }
            let last = buckets.len();
            let over = buckets.last().copied().unwrap_or(0);
            cases.push_str(&format!(
                "SUM(CASE WHEN CURRENT_DATE - m.due_date > {over} \
                 THEN m.amount_residual ELSE 0 END) AS b{last}, "
            ));
            let sql = format!(
                "SELECT p.name AS partner, \
                    SUM(CASE WHEN m.due_date IS NULL OR m.due_date >= CURRENT_DATE \
                        THEN m.amount_residual ELSE 0 END) AS current, \
                    {cases} \
                    SUM(m.amount_residual) AS total \
                 FROM acc_move m JOIN contacts p ON p.id = m.partner_id \
                 WHERE m.state = 'posted' AND {type_filter} \
                   AND m.payment_state IN ('not_paid', 'partial') \
                   AND m.amount_residual > 0 \
                 GROUP BY p.name ORDER BY total DESC"
            );
            let rows = vortex_plugin_sdk::sqlx::query(&sql)
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            let mut cols: Vec<String> = vec!["current".into()];
            cols.extend((0..=last).map(|i| format!("b{i}")));
            cols.push("total".into());
            let mut headers: Vec<String> = vec!["Current".into()];
            headers.extend(bucket_labels(&buckets));
            headers.push("Total".into());
            match params.format {
                ReportFormat::Csv => {
                    let mut csv = String::from("partner");
                    for h in &headers {
                        csv.push_str(&format!(",{}", csv_escape(h)));
                    }
                    csv.push('\n');
                    for r in &rows {
                        let partner: String = r.get("partner");
                        csv.push_str(&csv_escape(&partner));
                        for col in &cols {
                            csv.push_str(&format!(",{}", money(r.get(col.as_str()))));
                        }
                        csv.push('\n');
                    }
                    Ok(ReportOutput::csv(&format!("{}.csv", title.to_lowercase().replace(' ', "-")), csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from("<table><tr><th>Partner</th>");
                    for h in &headers {
                        table.push_str(&format!("<th class=\"num\">{}</th>", esc(h)));
                    }
                    table.push_str("</tr>");
                    let mut totals = vec![Decimal::ZERO; cols.len()];
                    for r in &rows {
                        let partner: String = r.get("partner");
                        table.push_str(&format!("<tr><td>{}</td>", esc(&partner)));
                        for (i, col) in cols.iter().enumerate() {
                            let v: Decimal = r.get(col.as_str());
                            totals[i] += v;
                            table.push_str(&format!("<td class=\"num\">{}</td>", money(v)));
                        }
                        table.push_str("</tr>");
                    }
                    table.push_str("<tr class=\"total\"><td>Total</td>");
                    for t in totals {
                        table.push_str(&format!("<td class=\"num\">{}</td>", money(t)));
                    }
                    table.push_str("</tr></table>");
                    Ok(ReportOutput::html(
                        &format!("{}.html", title.to_lowercase().replace(' ', "-")),
                        html_page(title, "as of today", &table),
                    ))
                }
            }
        },
    )
}

/// Statement of Account — every posted AR/AP ledger line for one
/// partner with a running balance. Params: `partner` (contact UUID,
/// required), `from`, `to`.
fn statement_of_account() -> ReportDef {
    ReportDef::new(
        "accounting.statement_of_account",
        "Statement of Account",
        "Per-partner AR/AP ledger with running balance — send to customers for collections",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let partner: vortex_plugin_sdk::uuid::Uuid = params
                .get("partner")
                .unwrap_or("")
                .parse()
                .map_err(|_| {
                    VortexError::ValidationFailed(
                        "pass ?partner=<contact uuid> — see /accounting/tax-profiles for IDs".into(),
                    )
                })?;
            let (date_sql, date_label) = date_clause(&params);
            let partner_name: String = vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT name FROM contacts WHERE id = $1",
            )
            .bind(partner)
            .fetch_optional(&state.db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?
            .unwrap_or_else(|| "Unknown partner".into());
            let sql = format!(
                "SELECT m.move_date, m.number, m.move_type, COALESCE(m.ref, '') AS ref, \
                        l.debit, l.credit \
                 FROM acc_move_line l \
                 JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted'{date_sql} \
                 JOIN acc_account a ON a.id = l.account_id \
                 WHERE l.partner_id = $1 \
                   AND a.account_type IN ('asset_receivable', 'liability_payable') \
                 ORDER BY m.move_date, m.created_at"
            );
            let rows = vortex_plugin_sdk::sqlx::query(&sql)
                .bind(partner)
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
            let mut balance = Decimal::ZERO;
            match params.format {
                ReportFormat::Csv => {
                    let mut csv = String::from("date,number,type,ref,debit,credit,balance\n");
                    for r in &rows {
                        let debit: Decimal = r.get("debit");
                        let credit: Decimal = r.get("credit");
                        balance += debit - credit;
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("move_date"),
                            csv_escape(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                            csv_escape(&r.get::<String, _>("move_type")),
                            csv_escape(&r.get::<String, _>("ref")),
                            money(debit),
                            money(credit),
                            money(balance),
                        ));
                    }
                    Ok(ReportOutput::csv("statement-of-account.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Date</th><th>Number</th><th>Type</th><th>Ref</th>\
                         <th class=\"num\">Debit</th><th class=\"num\">Credit</th>\
                         <th class=\"num\">Balance</th></tr>",
                    );
                    for r in &rows {
                        let debit: Decimal = r.get("debit");
                        let credit: Decimal = r.get("credit");
                        balance += debit - credit;
                        table.push_str(&format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                             <td class=\"num\">{}</td><td class=\"num\">{}</td>\
                             <td class=\"num\">{}</td></tr>",
                            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("move_date"),
                            esc(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                            esc(&r.get::<String, _>("move_type").replace('_', " ")),
                            esc(&r.get::<String, _>("ref")),
                            money(debit),
                            money(credit),
                            money(balance),
                        ));
                    }
                    table.push_str(&format!(
                        "<tr class=\"total\"><td colspan=\"6\">Balance due</td>\
                         <td class=\"num\">{}</td></tr></table>",
                        money(balance),
                    ));
                    Ok(ReportOutput::html(
                        "statement-of-account.html",
                        html_page(
                            &format!("Statement of Account — {partner_name}"),
                            &date_label,
                            &table,
                        ),
                    ))
                }
            }
        },
    )
}

/// Bank reconciliation statement — per bank journal: book balance,
/// matched vs unmatched statement lines, outstanding GL items.
fn bank_reconciliation() -> ReportDef {
    ReportDef::new(
        "accounting.bank_reconciliation",
        "Bank Reconciliation",
        "Per bank journal: GL book balance, unmatched statement lines and outstanding book items",
        vec![ReportFormat::Html],
        |state, _params| async move {
            let journals = vortex_plugin_sdk::sqlx::query(
                "SELECT j.id, j.code, j.name, j.default_account_id \
                 FROM acc_journal j WHERE j.journal_type IN ('bank','cash') AND j.active \
                 ORDER BY j.code",
            )
            .fetch_all(&state.db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
            let mut body = String::new();
            for j in &journals {
                let jid: vortex_plugin_sdk::uuid::Uuid = j.get("id");
                let account: Option<vortex_plugin_sdk::uuid::Uuid> = j.get("default_account_id");
                let Some(account) = account else { continue };
                let book: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
                    "SELECT COALESCE(SUM(l.debit - l.credit), 0) FROM acc_move_line l \
                     JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
                     WHERE l.account_id = $1",
                )
                .bind(account)
                .fetch_one(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                let unmatched_stmt: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
                    "SELECT COALESCE(SUM(b.amount), 0) FROM acc_bank_statement_line b \
                     JOIN acc_bank_statement s ON s.id = b.statement_id \
                     WHERE s.journal_id = $1 AND b.matched_line_id IS NULL",
                )
                .bind(jid)
                .fetch_one(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                let outstanding: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
                    "SELECT COALESCE(SUM(l.debit - l.credit), 0) FROM acc_move_line l \
                     JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
                     WHERE l.account_id = $1 \
                       AND NOT EXISTS (SELECT 1 FROM acc_bank_statement_line b \
                                       WHERE b.matched_line_id = l.id)",
                )
                .bind(account)
                .fetch_one(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                body.push_str(&format!(
                    "<tr class=\"section\"><th colspan=\"2\">{} — {}</th></tr>\
                     <tr><td>Book balance (GL)</td><td class=\"num\">{}</td></tr>\
                     <tr><td>Outstanding book items (not on any statement)</td><td class=\"num\">{}</td></tr>\
                     <tr><td>Unmatched statement lines</td><td class=\"num\">{}</td></tr>\
                     <tr class=\"total\"><td>Reconciled bank balance</td><td class=\"num\">{}</td></tr>",
                    esc(&j.get::<String, _>("code")),
                    esc(&j.get::<String, _>("name")),
                    money(book),
                    money(outstanding),
                    money(unmatched_stmt),
                    money(book - outstanding + unmatched_stmt),
                ));
            }
            let table = format!(
                "<table><tr><th>Item</th><th class=\"num\">Amount (MYR)</th></tr>{body}</table>"
            );
            Ok(ReportOutput::html(
                "bank-reconciliation.html",
                html_page("Bank Reconciliation", "as of today", &table),
            ))
        },
    )
}

/// Shared engine for the two grouped statements (P&L, balance sheet):
/// per-account signed balances grouped into titled sections.
async fn grouped_statement(
    state: &AppState,
    sections: &[(&str, &[&str], bool)], // (title, account_types, flip_sign)
    date_sql: &str,
) -> VortexResult<Vec<(String, Vec<(String, String, Decimal)>, Decimal)>> {
    let mut out = Vec::new();
    for (title, types, flip) in sections {
        let type_list = types
            .iter()
            .map(|t| format!("'{t}'"))
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "SELECT a.code, a.name, \
                    COALESCE(SUM(l.debit), 0) - COALESCE(SUM(l.credit), 0) AS balance \
             FROM acc_account a \
             LEFT JOIN (acc_move_line l \
                 JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted'{date_sql}) \
                 ON l.account_id = a.id \
             WHERE a.active AND a.account_type IN ({type_list}) \
             GROUP BY a.id, a.code, a.name \
             HAVING COALESCE(SUM(l.debit), 0) - COALESCE(SUM(l.credit), 0) <> 0 \
             ORDER BY a.code"
        );
        let rows = vortex_plugin_sdk::sqlx::query(&sql)
            .fetch_all(&state.db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        let mut section_total = Decimal::ZERO;
        let accounts: Vec<(String, String, Decimal)> = rows
            .iter()
            .map(|r| {
                let mut bal: Decimal = r.get("balance");
                if *flip {
                    bal = -bal;
                }
                section_total += bal;
                (r.get("code"), r.get("name"), bal)
            })
            .collect();
        out.push((title.to_string(), accounts, section_total));
    }
    Ok(out)
}

fn render_grouped(
    title: &str,
    subtitle: &str,
    sections: &[(String, Vec<(String, String, Decimal)>, Decimal)],
    bottom_label: &str,
    bottom_value: Decimal,
    format: &ReportFormat,
) -> ReportOutput {
    match format {
        ReportFormat::Csv => {
            let mut csv = String::from("section,code,account,amount\n");
            for (section, accounts, total) in sections {
                for (code, name, bal) in accounts {
                    csv.push_str(&format!(
                        "{},{},{},{}\n",
                        csv_escape(section),
                        csv_escape(code),
                        csv_escape(name),
                        money(*bal),
                    ));
                }
                csv.push_str(&format!("{},,TOTAL,{}\n", csv_escape(section), money(*total)));
            }
            csv.push_str(&format!(",,{},{}\n", csv_escape(bottom_label), money(bottom_value)));
            ReportOutput::csv(
                &format!("{}.csv", title.to_lowercase().replace(' ', "-")),
                csv.into_bytes(),
            )
        }
        _ => {
            let mut table =
                String::from("<table><tr><th>Code</th><th>Account</th><th class=\"num\">Amount</th></tr>");
            for (section, accounts, total) in sections {
                table.push_str(&format!(
                    "<tr class=\"section\"><th colspan=\"3\">{}</th></tr>",
                    esc(section)
                ));
                for (code, name, bal) in accounts {
                    table.push_str(&format!(
                        "<tr><td>{}</td><td>{}</td><td class=\"num\">{}</td></tr>",
                        esc(code),
                        esc(name),
                        money(*bal),
                    ));
                }
                table.push_str(&format!(
                    "<tr class=\"total\"><td colspan=\"2\">Total {}</td><td class=\"num\">{}</td></tr>",
                    esc(section),
                    money(*total),
                ));
            }
            table.push_str(&format!(
                "<tr class=\"total\"><td colspan=\"2\">{}</td><td class=\"num\">{}</td></tr></table>",
                esc(bottom_label),
                money(bottom_value),
            ));
            ReportOutput::html(
                &format!("{}.html", title.to_lowercase().replace(' ', "-")),
                html_page(title, subtitle, &table),
            )
        }
    }
}

/// P&L — income vs expenses over a period. Params: `from`, `to`.
fn profit_and_loss() -> ReportDef {
    ReportDef::new(
        "accounting.profit_and_loss",
        "Profit & Loss",
        "Income and expenses by account over a period (posted entries)",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let (date_sql, date_label) = date_clause(&params);
            // Income accounts carry credit balances → flip so revenue is positive.
            let sections = grouped_statement(
                &state,
                &[
                    ("Income", &["income", "income_other"], true),
                    (
                        "Expenses",
                        &["expense", "expense_depreciation", "expense_direct_cost"],
                        false,
                    ),
                ],
                &date_sql,
            )
            .await?;
            let income = sections[0].2;
            let expenses = sections[1].2;
            Ok(render_grouped(
                "Profit & Loss",
                &date_label,
                &sections,
                "Net Profit",
                income - expenses,
                &params.format,
            ))
        },
    )
}

/// Balance sheet as of a date. Params: `to` (as-of date, optional).
fn balance_sheet() -> ReportDef {
    ReportDef::new(
        "accounting.balance_sheet",
        "Balance Sheet",
        "Assets, liabilities and equity as of a date (?to=YYYY-MM-DD)",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            // Only an upper bound makes sense for a balance sheet.
            let to = params.get("to").unwrap_or("");
            let date_sql = match to.parse::<vortex_plugin_sdk::chrono::NaiveDate>() {
                Ok(d) => format!(" AND m.move_date <= '{d}'"),
                Err(_) => String::new(),
            };
            let label = if date_sql.is_empty() {
                "as of today".to_string()
            } else {
                format!("as of {to}")
            };
            let sections = grouped_statement(
                &state,
                &[
                    (
                        "Assets",
                        &[
                            "asset_cash",
                            "asset_bank",
                            "asset_receivable",
                            "asset_current",
                            "asset_fixed",
                            "asset_non_current",
                        ],
                        false,
                    ),
                    (
                        "Liabilities",
                        &["liability_payable", "liability_current", "liability_non_current"],
                        true,
                    ),
                    ("Equity", &["equity"], true),
                ],
                &date_sql,
            )
            .await?;
            let assets = sections[0].2;
            let liab = sections[1].2;
            let equity = sections[2].2;
            // Retained earnings (income − expenses to date) balances the sheet.
            let pl = grouped_statement(
                &state,
                &[
                    ("Income", &["income", "income_other"], true),
                    (
                        "Expenses",
                        &["expense", "expense_depreciation", "expense_direct_cost"],
                        false,
                    ),
                ],
                &date_sql,
            )
            .await?;
            let earnings = pl[0].2 - pl[1].2;
            Ok(render_grouped(
                "Balance Sheet",
                &label,
                &sections,
                &format!(
                    "Check: Assets − Liabilities − Equity − Current Earnings ({}) ",
                    money(earnings)
                ),
                assets - liab - equity - earnings,
                &params.format,
            ))
        },
    )
}

// ─── Malaysian tax reports (Phase 1) ─────────────────────────────────────

/// The last COMPLETED bi-monthly SST taxable period before `today`.
/// Periods are Jan–Feb, Mar–Apr, May–Jun, Jul–Aug, Sep–Oct, Nov–Dec.
fn last_sst_period(today: vortex_plugin_sdk::chrono::NaiveDate) -> (
    vortex_plugin_sdk::chrono::NaiveDate,
    vortex_plugin_sdk::chrono::NaiveDate,
) {
    use vortex_plugin_sdk::chrono::{Datelike, NaiveDate};
    // First month of the CURRENT period (1,3,5,7,9,11), then step back 2.
    let cur_start_month = if today.month() % 2 == 0 { today.month() - 1 } else { today.month() };
    let (from_y, from_m) = if cur_start_month <= 2 {
        (today.year() - 1, cur_start_month + 10)
    } else {
        (today.year(), cur_start_month - 2)
    };
    let from = NaiveDate::from_ymd_opt(from_y, from_m, 1).expect("valid period start");
    // Period end = day before the current period's start.
    let to = NaiveDate::from_ymd_opt(today.year(), cur_start_month, 1)
        .expect("valid period start")
        .pred_opt()
        .expect("valid period end");
    (from, to)
}

/// SST-02 return worksheet — output vs input tax by SST category over a
/// taxable period. Params: `from`, `to` (default: last completed
/// bi-monthly period). Figures read from posted GL tax lines
/// (`tax_base_amount`), so they reconcile with the ledger by construction.
fn sst02() -> ReportDef {
    ReportDef::new(
        "accounting.sst02",
        "SST-02 Return Worksheet",
        "Sales & Service Tax return: taxable value and tax by category, output vs input",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
            let (def_from, def_to) = last_sst_period(today);
            let from = params
                .get("from")
                .and_then(|s| s.parse().ok())
                .unwrap_or(def_from);
            let to = params.get("to").and_then(|s| s.parse().ok()).unwrap_or(def_to);
            let rows = crate::tax::sst_return(&state.db, None, from, to).await?;

            let label = |c: &str| match c {
                "sales_tax_5" => "Sales Tax 5%",
                "sales_tax_10" => "Sales Tax 10%",
                "service_tax_6" => "Service Tax 6%",
                "service_tax_8" => "Service Tax 8%",
                "exempt" => "Exempt",
                "zero_rated" => "Zero-rated",
                _ => "Out of scope",
            };
            let subtitle = format!("Taxable period {from} to {to}");

            match params.format {
                ReportFormat::Csv => {
                    let mut csv =
                        String::from("direction,category,taxable_value,tax_amount\n");
                    for r in &rows {
                        csv.push_str(&format!(
                            "{},{},{},{}\n",
                            r.direction,
                            label(&r.sst_category),
                            money(r.taxable_value),
                            money(r.tax_amount),
                        ));
                    }
                    Ok(ReportOutput::csv("sst02.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::new();
                    for direction in ["output", "input"] {
                        let section: Vec<_> =
                            rows.iter().filter(|r| r.direction == direction).collect();
                        table.push_str(&format!(
                            "<table><tr class=\"section\"><th colspan=\"3\">{} tax</th></tr>\
                             <tr><th>Category</th><th class=\"num\">Taxable Value (RM)</th>\
                             <th class=\"num\">Tax (RM)</th></tr>",
                            if direction == "output" { "Output (sales)" } else { "Input (purchases)" },
                        ));
                        let mut tv = Decimal::ZERO;
                        let mut ta = Decimal::ZERO;
                        for r in &section {
                            tv += r.taxable_value;
                            ta += r.tax_amount;
                            table.push_str(&format!(
                                "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                                label(&r.sst_category),
                                money(r.taxable_value),
                                money(r.tax_amount),
                            ));
                        }
                        table.push_str(&format!(
                            "<tr class=\"total\"><td>Total</td><td class=\"num\">{}</td>\
                             <td class=\"num\">{}</td></tr></table><br/>",
                            money(tv),
                            money(ta),
                        ));
                    }
                    Ok(ReportOutput::html(
                        "sst02.html",
                        html_page("SST-02 Return Worksheet", &subtitle, &table),
                    ))
                }
            }
        },
    )
}

/// Tax audit detail — every posted GL tax line with its document, partner
/// and taxable base. This is the MyInvois ↔ SST-02 consistency artifact.
/// Params: `from`, `to` (default: last completed bi-monthly period).
fn tax_detail() -> ReportDef {
    ReportDef::new(
        "accounting.tax_detail",
        "Tax Detail Listing",
        "Every posted tax line: document, partner, taxable base and tax amount",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
            let (def_from, def_to) = last_sst_period(today);
            let from: vortex_plugin_sdk::chrono::NaiveDate = params
                .get("from")
                .and_then(|s| s.parse().ok())
                .unwrap_or(def_from);
            let to: vortex_plugin_sdk::chrono::NaiveDate =
                params.get("to").and_then(|s| s.parse().ok()).unwrap_or(def_to);

            let rows = vortex_plugin_sdk::sqlx::query(
                "SELECT m.number, m.move_date, m.move_type, t.name AS tax_name, \
                        COALESCE(c.name, '') AS partner, \
                        COALESCE(l.tax_base_amount, 0) AS base, \
                        (CASE WHEN l.credit > 0 THEN l.credit ELSE -l.debit END) AS tax \
                 FROM acc_move_line l \
                 JOIN acc_move m ON m.id = l.move_id AND m.state = 'posted' \
                 JOIN taxes t ON t.id = l.tax_id \
                 LEFT JOIN contacts c ON c.id = m.partner_id \
                 WHERE l.tax_id IS NOT NULL AND m.move_date BETWEEN $1 AND $2 \
                 ORDER BY m.move_date, m.number",
            )
            .bind(from)
            .bind(to)
            .fetch_all(&state.db)
            .await
            .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

            let subtitle = format!("Period {from} to {to} — {} tax lines", rows.len());
            match params.format {
                ReportFormat::Csv => {
                    let mut csv =
                        String::from("date,number,type,partner,tax,taxable_base,tax_amount\n");
                    for r in &rows {
                        let d: vortex_plugin_sdk::chrono::NaiveDate = r.get("move_date");
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{}\n",
                            d,
                            csv_escape(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                            csv_escape(&r.get::<String, _>("move_type")),
                            csv_escape(&r.get::<String, _>("partner")),
                            csv_escape(&r.get::<String, _>("tax_name")),
                            money(r.get("base")),
                            money(r.get("tax")),
                        ));
                    }
                    Ok(ReportOutput::csv("tax-detail.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Date</th><th>Number</th><th>Type</th><th>Partner</th>\
                         <th>Tax</th><th class=\"num\">Taxable Base</th><th class=\"num\">Tax</th></tr>",
                    );
                    let mut total_base = Decimal::ZERO;
                    let mut total_tax = Decimal::ZERO;
                    for r in &rows {
                        let d: vortex_plugin_sdk::chrono::NaiveDate = r.get("move_date");
                        let base: Decimal = r.get("base");
                        let tax: Decimal = r.get("tax");
                        total_base += base;
                        total_tax += tax;
                        table.push_str(&format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td>\
                             <td class=\"num\">{}</td><td class=\"num\">{}</td></tr>",
                            d,
                            esc(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                            esc(&r.get::<String, _>("move_type")),
                            esc(&r.get::<String, _>("partner")),
                            esc(&r.get::<String, _>("tax_name")),
                            money(base),
                            money(tax),
                        ));
                    }
                    table.push_str(&format!(
                        "<tr class=\"total\"><td colspan=\"5\">Totals</td>\
                         <td class=\"num\">{}</td><td class=\"num\">{}</td></tr></table>",
                        money(total_base),
                        money(total_tax),
                    ));
                    Ok(ReportOutput::html(
                        "tax-detail.html",
                        html_page("Tax Detail Listing", &subtitle, &table),
                    ))
                }
            }
        },
    )
}

#[cfg(test)]
mod sst_period_tests {
    use super::last_sst_period;
    use vortex_plugin_sdk::chrono::NaiveDate;

    fn d(y: i32, m: u32, day: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, day).unwrap()
    }

    #[test]
    fn mid_period_returns_previous_period() {
        // Today in Jul–Aug period → last completed is May–Jun.
        assert_eq!(last_sst_period(d(2026, 7, 4)), (d(2026, 5, 1), d(2026, 6, 30)));
        assert_eq!(last_sst_period(d(2026, 8, 31)), (d(2026, 5, 1), d(2026, 6, 30)));
    }

    #[test]
    fn january_wraps_to_previous_year() {
        // Jan–Feb period → last completed is Nov–Dec of prior year.
        assert_eq!(last_sst_period(d(2026, 1, 15)), (d(2025, 11, 1), d(2025, 12, 31)));
        assert_eq!(last_sst_period(d(2026, 2, 28)), (d(2025, 11, 1), d(2025, 12, 31)));
    }

    #[test]
    fn march_gets_jan_feb() {
        assert_eq!(last_sst_period(d(2026, 3, 1)), (d(2026, 1, 1), d(2026, 2, 28)));
    }
}

/// e-Invoice submission register — document ↔ LHDN UUID ↔ status ↔ SST,
/// the audit artifact reconciled against SST-02. Params: from, to.
fn einvoice_register() -> ReportDef {
    ReportDef::new(
        "accounting.einvoice_register",
        "e-Invoice Register",
        "Every e-invoice with its LHDN identifiers, status, and tax amount",
        vec![ReportFormat::Html, ReportFormat::Csv],
        |state, params| async move {
            let (date_sql, date_label) = date_clause(&params);
            let sql = format!(
                "SELECT m.number, m.move_date, c.name AS partner, m.total_amount, m.tax_amount, \
                        e.status, e.doc_type_code, e.lhdn_uuid, e.submitted_at, e.validated_at \
                 FROM acc_einvoice e \
                 JOIN acc_move m ON m.id = e.move_id AND m.state = 'posted'{date_sql} \
                 LEFT JOIN contacts c ON c.id = m.partner_id \
                 ORDER BY m.move_date, m.number"
            );
            let rows = vortex_plugin_sdk::sqlx::query(&sql)
                .fetch_all(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
            match params.format {
                ReportFormat::Csv => {
                    let mut csv = String::from(
                        "number,date,partner,total,tax,doc_type,status,lhdn_uuid,submitted_at,validated_at\n",
                    );
                    for r in &rows {
                        csv.push_str(&format!(
                            "{},{},{},{},{},{},{},{},{},{}\n",
                            csv_escape(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("move_date"),
                            csv_escape(r.get::<Option<String>, _>("partner").as_deref().unwrap_or("")),
                            money(r.get("total_amount")),
                            money(r.get("tax_amount")),
                            r.get::<String, _>("doc_type_code"),
                            r.get::<String, _>("status"),
                            r.get::<Option<String>, _>("lhdn_uuid").as_deref().unwrap_or(""),
                            r.get::<Option<vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>>, _>("submitted_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
                            r.get::<Option<vortex_plugin_sdk::chrono::DateTime<vortex_plugin_sdk::chrono::Utc>>, _>("validated_at").map(|d| d.to_rfc3339()).unwrap_or_default(),
                        ));
                    }
                    Ok(ReportOutput::csv("einvoice-register.csv", csv.into_bytes()))
                }
                _ => {
                    let mut table = String::from(
                        "<table><tr><th>Number</th><th>Date</th><th>Partner</th>\
                         <th class=\"num\">Total</th><th class=\"num\">Tax</th>\
                         <th>Type</th><th>Status</th><th>LHDN UUID</th></tr>",
                    );
                    for r in &rows {
                        table.push_str(&format!(
                            "<tr><td>{}</td><td>{}</td><td>{}</td><td class=\"num\">{}</td>\
                             <td class=\"num\">{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                            esc(r.get::<Option<String>, _>("number").as_deref().unwrap_or("/")),
                            r.get::<vortex_plugin_sdk::chrono::NaiveDate, _>("move_date"),
                            esc(r.get::<Option<String>, _>("partner").as_deref().unwrap_or("")),
                            money(r.get("total_amount")),
                            money(r.get("tax_amount")),
                            esc(&r.get::<String, _>("doc_type_code")),
                            esc(&r.get::<String, _>("status")),
                            esc(r.get::<Option<String>, _>("lhdn_uuid").as_deref().unwrap_or("")),
                        ));
                    }
                    table.push_str("</table>");
                    Ok(ReportOutput::html(
                        "einvoice-register.html",
                        html_page("e-Invoice Register", &date_label, &table),
                    ))
                }
            }
        },
    )
}
