//! Banking operations: statement import + matching, post-dated
//! cheques, AR↔AP contra, credit control.

use vortex_plugin_sdk::chrono::NaiveDate;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::orm::ConnectionPool;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use crate::service::{self, MoveLine, NewMove};

// ─── Statement import ────────────────────────────────────────────────────

/// One parsed CSV row: (date, description, signed amount).
pub type ParsedLine = (NaiveDate, String, Decimal);

/// Parse a bank-statement CSV. Accepts `date,description,amount` with
/// an optional header row; date `YYYY-MM-DD` or `DD/MM/YYYY`; amount
/// with optional thousands separators, negative = money out. Pure —
/// unit-tested.
pub fn parse_statement_csv(content: &str) -> Result<Vec<ParsedLine>, String> {
    let mut out = Vec::new();
    for (i, raw) in content.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() {
            continue;
        }
        let fields = split_csv(line);
        if fields.len() < 3 {
            return Err(format!("line {}: expected date,description,amount", i + 1));
        }
        let date_s = fields[0].trim();
        let date = date_s
            .parse::<NaiveDate>()
            .or_else(|_| NaiveDate::parse_from_str(date_s, "%d/%m/%Y"))
            .map_err(|_| format!("line {}: bad date {date_s:?}", i + 1));
        let date = match date {
            Ok(d) => d,
            Err(e) => {
                if i == 0 {
                    continue; // header row
                }
                return Err(e);
            }
        };
        let amount_s: String = fields
            .last()
            .unwrap()
            .trim()
            .chars()
            .filter(|c| c.is_ascii_digit() || *c == '.' || *c == '-')
            .collect();
        let amount: Decimal = amount_s
            .parse()
            .map_err(|_| format!("line {}: bad amount", i + 1))?;
        let description = fields[1..fields.len() - 1].join(",").trim().to_string();
        out.push((date, description, amount.round_dp(2)));
    }
    if out.is_empty() {
        return Err("no statement lines found".into());
    }
    Ok(out)
}

fn split_csv(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut cur = String::new();
    let mut quoted = false;
    for ch in line.chars() {
        match ch {
            '"' => quoted = !quoted,
            ',' if !quoted => fields.push(std::mem::take(&mut cur)),
            _ => cur.push(ch),
        }
    }
    fields.push(cur);
    fields
}

/// Candidate GL lines for a statement line: unmatched bank-account
/// lines, scored by amount + date proximity. Pure scoring, DB fetch.
pub fn match_score(
    stmt_amount: Decimal,
    stmt_date: NaiveDate,
    gl_signed: Decimal,
    gl_date: NaiveDate,
) -> i32 {
    if stmt_amount != gl_signed {
        return 0;
    }
    let days = (stmt_date - gl_date).num_days().abs();
    match days {
        0 => 100,
        1..=3 => 80,
        4..=7 => 60,
        8..=30 => 30,
        _ => 5,
    }
}

/// Best automatic matches for every unmatched line of a statement:
/// `(statement_line_id, gl_line_id, score)`.
pub async fn auto_match_suggestions(
    db: &PgPool,
    statement_id: Uuid,
) -> VortexResult<Vec<(Uuid, Uuid, i32)>> {
    let journal_account: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT j.default_account_id FROM acc_bank_statement s \
         JOIN acc_journal j ON j.id = s.journal_id WHERE s.id = $1",
    )
    .bind(statement_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    .flatten();
    let Some(bank_account) = journal_account else {
        return Err(VortexError::ValidationFailed(
            "the statement's journal has no default bank account".into(),
        ));
    };

    let stmt_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT id, line_date, amount FROM acc_bank_statement_line \
         WHERE statement_id = $1 AND matched_line_id IS NULL",
    )
    .bind(statement_id)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // Unmatched GL lines on the bank account (not referenced by any
    // statement line), signed: debit = money in.
    let gl_lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, m.move_date, (l.debit - l.credit) AS signed \
         FROM acc_move_line l JOIN acc_move m ON m.id = l.move_id \
         WHERE l.account_id = $1 AND m.state = 'posted' \
           AND NOT EXISTS (SELECT 1 FROM acc_bank_statement_line b \
                           WHERE b.matched_line_id = l.id)",
    )
    .bind(bank_account)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let mut used: std::collections::HashSet<Uuid> = Default::default();
    let mut out = Vec::new();
    for sl in &stmt_lines {
        let sid: Uuid = sl.get("id");
        let sdate: NaiveDate = sl.get("line_date");
        let samount: Decimal = sl.get("amount");
        let mut best: Option<(Uuid, i32)> = None;
        for gl in &gl_lines {
            let gid: Uuid = gl.get("id");
            if used.contains(&gid) {
                continue;
            }
            let score = match_score(samount, sdate, gl.get("signed"), gl.get("move_date"));
            if score > 0 && best.map(|(_, s)| score > s).unwrap_or(true) {
                best = Some((gid, score));
            }
        }
        if let Some((gid, score)) = best {
            used.insert(gid);
            out.push((sid, gid, score));
        }
    }
    Ok(out)
}

pub async fn match_line(
    db: &PgPool,
    statement_line_id: Uuid,
    gl_line_id: Uuid,
    user_id: Uuid,
) -> VortexResult<()> {
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_bank_statement_line \
         SET matched_line_id = $2, matched_by = $3, matched_at = NOW() WHERE id = $1",
    )
    .bind(statement_line_id)
    .bind(gl_line_id)
    .bind(user_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(())
}

/// Finalize when every line is matched; flips state to reconciled.
pub async fn finalize_statement(db: &PgPool, statement_id: Uuid) -> VortexResult<()> {
    let unmatched: i64 = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COUNT(*) FROM acc_bank_statement_line \
         WHERE statement_id = $1 AND matched_line_id IS NULL",
    )
    .bind(statement_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    if unmatched > 0 {
        return Err(VortexError::ValidationFailed(format!(
            "{unmatched} statement line(s) still unmatched"
        )));
    }
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_bank_statement SET state = 'reconciled' WHERE id = $1",
    )
    .bind(statement_id)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(())
}

/// Quick-post a counterpart for an unmatched line (bank charges,
/// interest) and match it in one step: bank ↔ chosen account.
pub async fn quick_counterpart(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    statement_line_id: Uuid,
    counter_account: Uuid,
) -> VortexResult<Uuid> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT b.line_date, b.description, b.amount, j.default_account_id, s.company_id \
         FROM acc_bank_statement_line b \
         JOIN acc_bank_statement s ON s.id = b.statement_id \
         JOIN acc_journal j ON j.id = s.journal_id \
         WHERE b.id = $1 AND b.matched_line_id IS NULL",
    )
    .bind(statement_line_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("line not found or already matched".into()));
    };
    let bank_account: Option<Uuid> = r.get("default_account_id");
    let Some(bank_account) = bank_account else {
        return Err(VortexError::ValidationFailed("journal has no bank account".into()));
    };
    let amount: Decimal = r.get("amount");
    let date: NaiveDate = r.get("line_date");
    let description: String = r.get("description");
    let company_id: Option<Uuid> = r.get("company_id");
    let abs = amount.abs();
    let lines = if amount > Decimal::ZERO {
        vec![
            MoveLine::debit(bank_account, abs, Some(&description)),
            MoveLine::credit(counter_account, abs, Some(&description)),
        ]
    } else {
        vec![
            MoveLine::debit(counter_account, abs, Some(&description)),
            MoveLine::credit(bank_account, abs, Some(&description)),
        ]
    };
    let (move_id, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: date,
            move_type: "entry",
            ref_: Some(&description),
            narration: None,
            partner_id: None,
            origin_ref: Some("acc_bank_statement_line"),
            company_id,
            lines,
        },
    )
    .await?;
    let gl_line: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_move_line WHERE move_id = $1 AND account_id = $2 LIMIT 1",
    )
    .bind(move_id)
    .bind(bank_account)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    match_line(db, statement_line_id, gl_line, user_id).await?;
    Ok(move_id)
}

// ─── Post-dated cheques ──────────────────────────────────────────────────

async fn pdc_accounts(db: &PgPool, company_id: Option<Uuid>) -> VortexResult<(Uuid, Uuid)> {
    let received = service::account_by_code(db, company_id, "1150").await?;
    let issued = service::account_by_code(db, company_id, "2150").await?;
    match (received, issued) {
        (Some(r), Some(i)) => Ok((r, i)),
        _ => Err(VortexError::ValidationFailed("PDC accounts 1150/2150 missing".into())),
    }
}

/// Record a PDC: received cheques debit the PDC holding account and
/// credit AR (settling the partner immediately, AutoCount-style);
/// issued cheques mirror on AP.
pub async fn record_pdc(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    company_id: Option<Uuid>,
    direction: &str,
    partner_id: Uuid,
    cheque_no: &str,
    bank_name: Option<&str>,
    amount: Decimal,
    maturity_date: NaiveDate,
    memo: Option<&str>,
    posting_date: NaiveDate,
) -> VortexResult<Uuid> {
    if amount <= Decimal::ZERO {
        return Err(VortexError::ValidationFailed("amount must be positive".into()));
    }
    let (pdc_received, pdc_issued) = pdc_accounts(db, company_id).await?;
    let received = direction == "received";
    let counterpart_role = if received { "receivable" } else { "payable" };
    let Some(counterpart) =
        service::partner_account(db, company_id, Some(partner_id), counterpart_role).await?
    else {
        return Err(VortexError::ValidationFailed(format!("no {counterpart_role} account")));
    };
    let label = format!("PDC {cheque_no}");
    let lines = if received {
        vec![
            MoveLine::debit(pdc_received, amount, Some(&label)),
            MoveLine::credit(counterpart, amount, Some(&label)).with_partner(partner_id),
        ]
    } else {
        vec![
            MoveLine::debit(counterpart, amount, Some(&label)).with_partner(partner_id),
            MoveLine::credit(pdc_issued, amount, Some(&label)),
        ]
    };
    let (holding_move, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: posting_date,
            move_type: "entry",
            ref_: Some(&label),
            narration: memo,
            partner_id: Some(partner_id),
            origin_ref: None,
            company_id,
            lines,
        },
    )
    .await?;
    let id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_pdc (direction, partner_id, cheque_no, bank_name, amount, \
                              maturity_date, holding_move_id, memo, company_id, created_by) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING id",
    )
    .bind(direction)
    .bind(partner_id)
    .bind(cheque_no)
    .bind(bank_name)
    .bind(amount)
    .bind(maturity_date)
    .bind(holding_move)
    .bind(memo)
    .bind(company_id)
    .bind(user_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(id)
}

/// Clear one matured PDC: holding account → bank.
pub async fn clear_pdc(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    pdc_id: Uuid,
    posting_date: NaiveDate,
) -> VortexResult<Uuid> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT direction, cheque_no, amount, company_id, state FROM acc_pdc WHERE id = $1",
    )
    .bind(pdc_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("PDC not found".into()));
    };
    if r.get::<String, _>("state") != "holding" {
        return Err(VortexError::ValidationFailed("only holding PDCs can clear".into()));
    }
    let direction: String = r.get("direction");
    let cheque_no: String = r.get("cheque_no");
    let amount: Decimal = r.get("amount");
    let company_id: Option<Uuid> = r.get("company_id");
    let (pdc_received, pdc_issued) = pdc_accounts(db, company_id).await?;
    let bank = service::account_by_type(db, company_id, "asset_bank")
        .await?
        .ok_or_else(|| VortexError::ValidationFailed("no bank account".into()))?;
    let label = format!("PDC {cheque_no} cleared");
    let lines = if direction == "received" {
        vec![
            MoveLine::debit(bank, amount, Some(&label)),
            MoveLine::credit(pdc_received, amount, Some(&label)),
        ]
    } else {
        vec![
            MoveLine::debit(pdc_issued, amount, Some(&label)),
            MoveLine::credit(bank, amount, Some(&label)),
        ]
    };
    let (clearing_move, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "BNK",
            move_date: posting_date,
            move_type: "entry",
            ref_: Some(&label),
            narration: None,
            partner_id: None,
            origin_ref: Some("acc_pdc"),
            company_id,
            lines,
        },
    )
    .await?;
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_pdc SET state = 'cleared', clearing_move_id = $2 WHERE id = $1",
    )
    .bind(pdc_id)
    .bind(clearing_move)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(clearing_move)
}

/// Bounce: reverse the holding entry and flag the cheque.
pub async fn bounce_pdc(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    pdc_id: Uuid,
    posting_date: NaiveDate,
) -> VortexResult<()> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT holding_move_id, state FROM acc_pdc WHERE id = $1",
    )
    .bind(pdc_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("PDC not found".into()));
    };
    if r.get::<String, _>("state") != "holding" {
        return Err(VortexError::ValidationFailed("only holding PDCs can bounce".into()));
    }
    if let Some(holding) = r.get::<Option<Uuid>, _>("holding_move_id") {
        service::reverse_move(db, seq_pool, holding, posting_date, user_id).await?;
    }
    vortex_plugin_sdk::sqlx::query("UPDATE acc_pdc SET state = 'bounced' WHERE id = $1")
        .bind(pdc_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(())
}

/// Clear every matured holding PDC (daily scheduled action body).
pub async fn mature_due_pdcs(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
) -> VortexResult<u32> {
    let due: Vec<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_pdc WHERE state = 'holding' AND maturity_date <= CURRENT_DATE",
    )
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();
    let mut cleared = 0;
    for id in due {
        if clear_pdc(db, seq_pool, user_id, id, today).await.is_ok() {
            cleared += 1;
        }
    }
    Ok(cleared)
}

/// Scheduler entrypoint: clear matured PDCs on the primary DB as the
/// oldest active user (system actor — same convention as other
/// background posters).
pub async fn run_pdc_maturity(state: &vortex_plugin_sdk::framework::AppState) -> VortexResult<()> {
    let user: Option<Uuid> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM users WHERE active ORDER BY created_at LIMIT 1",
    )
    .fetch_optional(&state.db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(user) = user else {
        return Ok(());
    };
    let cleared = mature_due_pdcs(&state.db, &state.pool, user).await?;
    if cleared > 0 {
        vortex_plugin_sdk::tracing::info!("PDC maturity run cleared {cleared} cheque(s)");
    }
    Ok(())
}

// ─── Contra (AR ↔ AP offset) ─────────────────────────────────────────────

/// Offset a partner's open receivables against their open payables:
/// one GEN move (debit AP / credit AR for the matched total), each
/// side reconciled against its documents. Returns the contra move.
pub async fn contra(
    db: &PgPool,
    seq_pool: &ConnectionPool,
    user_id: Uuid,
    company_id: Option<Uuid>,
    partner_id: Uuid,
    ar_moves: &[Uuid],
    ap_moves: &[Uuid],
    date: NaiveDate,
) -> VortexResult<Uuid> {
    let mut ar_open = Decimal::ZERO;
    let mut ar_lines = Vec::new(); // (line_id, open)
    for id in ar_moves {
        if let Some((line, open, is_debit)) = crate::documents::open_counterpart_line(db, *id).await? {
            if open > Decimal::ZERO && is_debit {
                ar_open += open;
                ar_lines.push((*id, line, open));
            }
        }
    }
    let mut ap_open = Decimal::ZERO;
    let mut ap_lines = Vec::new();
    for id in ap_moves {
        if let Some((line, open, is_debit)) = crate::documents::open_counterpart_line(db, *id).await? {
            if open > Decimal::ZERO && !is_debit {
                ap_open += open;
                ap_lines.push((*id, line, open));
            }
        }
    }
    let matched = ar_open.min(ap_open);
    if matched <= Decimal::ZERO {
        return Err(VortexError::ValidationFailed(
            "nothing to contra — need open AR and AP for this partner".into(),
        ));
    }
    let receivable = service::partner_account(db, company_id, Some(partner_id), "receivable")
        .await?
        .ok_or_else(|| VortexError::ValidationFailed("no receivable account".into()))?;
    let payable = service::partner_account(db, company_id, Some(partner_id), "payable")
        .await?
        .ok_or_else(|| VortexError::ValidationFailed("no payable account".into()))?;
    let (contra_move, _) = service::create_and_post(
        db,
        seq_pool,
        user_id,
        &NewMove {
            journal_code: "GEN",
            move_date: date,
            move_type: "entry",
            ref_: Some("AR/AP contra"),
            narration: None,
            partner_id: Some(partner_id),
            origin_ref: Some("acc_contra"),
            company_id,
            lines: vec![
                MoveLine::debit(payable, matched, Some("Contra")).with_partner(partner_id),
                MoveLine::credit(receivable, matched, Some("Contra")).with_partner(partner_id),
            ],
        },
    )
    .await?;
    // The contra move's own lines to reconcile against each side.
    let contra_ar_line: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_move_line WHERE move_id = $1 AND account_id = $2",
    )
    .bind(contra_move)
    .bind(receivable)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let contra_ap_line: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT id FROM acc_move_line WHERE move_id = $1 AND account_id = $2",
    )
    .bind(contra_move)
    .bind(payable)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    // FIFO-allocate the matched amount across each side.
    let mut remaining = matched;
    for (doc_id, doc_line, open) in &ar_lines {
        if remaining <= Decimal::ZERO {
            break;
        }
        let take = remaining.min(*open);
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_partial_reconcile \
                (debit_line_id, credit_line_id, amount, company_id, created_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(doc_line)
        .bind(contra_ar_line)
        .bind(take)
        .bind(company_id)
        .bind(user_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        remaining -= take;
        crate::documents::refresh_payment_state(db, *doc_id).await?;
    }
    let mut remaining = matched;
    for (doc_id, doc_line, open) in &ap_lines {
        if remaining <= Decimal::ZERO {
            break;
        }
        let take = remaining.min(*open);
        vortex_plugin_sdk::sqlx::query(
            "INSERT INTO acc_partial_reconcile \
                (debit_line_id, credit_line_id, amount, company_id, created_by) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(contra_ap_line)
        .bind(doc_line)
        .bind(take)
        .bind(company_id)
        .bind(user_id)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
        remaining -= take;
        crate::documents::refresh_payment_state(db, *doc_id).await?;
    }
    Ok(contra_move)
}

// ─── Credit control ──────────────────────────────────────────────────────

/// Partner exposure check: `Ok(None)` = fine, `Ok(Some(msg))` = warn,
/// `Err` = blocked. Called by post_invoice for customer invoices.
pub async fn check_credit_limit(
    db: &PgPool,
    partner_id: Uuid,
    additional: Decimal,
) -> VortexResult<Option<String>> {
    let policy: String = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT credit_limit_policy FROM acc_config ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    .unwrap_or_else(|| "off".into());
    if policy == "off" {
        return Ok(None);
    }
    let limit: Option<Decimal> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT credit_limit FROM contacts WHERE id = $1",
    )
    .bind(partner_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    .flatten();
    let Some(limit) = limit.filter(|l| *l > Decimal::ZERO) else {
        return Ok(None);
    };
    let exposure: Decimal = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT COALESCE(SUM(amount_residual), 0) FROM acc_move \
         WHERE partner_id = $1 AND state = 'posted' \
           AND move_type IN ('customer_invoice') AND payment_state <> 'paid'",
    )
    .bind(partner_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let after = exposure + additional;
    if after <= limit {
        return Ok(None);
    }
    let msg = format!(
        "credit limit exceeded: exposure RM {after} vs limit RM {limit}"
    );
    if policy == "block" {
        Err(VortexError::ValidationFailed(msg))
    } else {
        Ok(Some(msg))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;

    fn d(s: &str) -> NaiveDate {
        s.parse().unwrap()
    }

    #[test]
    fn csv_parsing_handles_headers_formats_and_quotes() {
        let csv = "date,description,amount\n\
                   2026-07-01,\"MAYBANK, TRANSFER\",1500.00\n\
                   02/07/2026,ATM WITHDRAWAL,-200.50\n";
        let lines = parse_statement_csv(csv).unwrap();
        assert_eq!(lines.len(), 2);
        assert_eq!(lines[0], (d("2026-07-01"), "\"MAYBANK, TRANSFER\"".replace('"', ""), dec!(1500.00)));
        assert_eq!(lines[1].2, dec!(-200.50));
    }

    #[test]
    fn csv_rejects_garbage() {
        assert!(parse_statement_csv("").is_err());
        assert!(parse_statement_csv("2026-07-01,desc\n").is_err());
        assert!(parse_statement_csv("header\n2026-13-45,desc,10\n").is_err());
    }

    #[test]
    fn match_scoring_prefers_exact_dates() {
        let a = dec!(100);
        assert_eq!(match_score(a, d("2026-07-04"), a, d("2026-07-04")), 100);
        assert!(match_score(a, d("2026-07-04"), a, d("2026-07-02")) > match_score(a, d("2026-07-04"), a, d("2026-07-20")));
        assert_eq!(match_score(a, d("2026-07-04"), dec!(99), d("2026-07-04")), 0);
    }
}
