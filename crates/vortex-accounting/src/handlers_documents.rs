//! AR/AP document handlers — customer invoices, vendor bills, payments.
//! All lifecycle actions go through [`crate::documents`], the same API
//! adopting modules use.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

use crate::documents::{self, NewPayment, PaymentDirection};
use crate::handlers::{
    audit_move, date_or_today, dec_or_zero, default_company, money, opt_str, page_shell,
    redirect, render_sidebar,
};

pub fn document_routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/accounting/invoices", get(list_invoices))
        .route("/accounting/bills", get(list_bills))
        .route("/accounting/documents/new", get(new_document_form))
        .route("/accounting/documents/create", post(create_document))
        .route("/accounting/documents/{id}", get(document_detail))
        .route("/accounting/documents/{id}/lines", post(add_doc_line))
        .route(
            "/accounting/documents/{id}/lines/{line_id}/delete",
            post(delete_doc_line),
        )
        .route("/accounting/documents/{id}/post", post(post_document))
        .route("/accounting/documents/{id}/pay", post(pay_document))
        .route("/accounting/documents/{id}/print", get(print_document))
        .route("/accounting/payments", get(list_payments))
}

/// Print view — a standalone, letterhead-style page (no sidebar) for
/// the browser's print dialog / save-as-PDF. Malaysian conventions:
/// "TAX INVOICE" title when SST-registered, seller TIN/SST/BRN block,
/// per-rate SST summary, LHDN UUID + validation link once validated.
async fn print_document(
    State(app_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    use vortex_plugin_sdk::rust_decimal::Decimal;
    let esc = vortex_plugin_sdk::framework::html_escape;
    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT m.number, m.move_type, m.state, m.invoice_date, m.due_date, m.ref, \
                m.untaxed_amount, m.tax_amount, m.total_amount, m.amount_residual, \
                m.payment_state, m.narration, \
                p.name AS partner_name, p.street, p.street2, p.city, p.zip, \
                p.email AS partner_email, p.phone AS partner_phone, \
                tp.tin AS partner_tin, tp.sst_registration AS partner_sst \
         FROM acc_move m \
         JOIN contacts p ON p.id = m.partner_id \
         LEFT JOIN acc_partner_tax_profile tp ON tp.contact_id = p.id \
         WHERE m.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (StatusCode::NOT_FOUND, "Document not found").into_response();
    };
    let company = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(co.name, 'Company') AS name, c.company_tin, c.company_id_value, \
                c.company_sst_registration, c.company_address1, c.company_address2, \
                c.company_city, c.company_postcode, c.company_phone, c.company_email \
         FROM acc_config c LEFT JOIN companies co ON co.id = c.company_id \
         ORDER BY c.company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();
    let lines = vortex_plugin_sdk::sqlx::query(
        "SELECT l.description, l.quantity, l.unit_price, l.classification_code, \
                t.name AS tax_name, t.amount AS tax_rate \
         FROM acc_invoice_line l LEFT JOIN taxes t ON t.id = l.tax_id \
         WHERE l.move_id = $1 ORDER BY l.sequence",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    // Per-rate SST summary off the posted GL tax lines.
    let tax_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT t.name, SUM(l.credit - l.debit) AS tax, SUM(COALESCE(l.tax_base_amount,0)) AS base \
         FROM acc_move_line l JOIN taxes t ON t.id = l.tax_id \
         WHERE l.move_id = $1 GROUP BY t.name ORDER BY t.name",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let einv = vortex_plugin_sdk::sqlx::query(
        "SELECT status, lhdn_uuid, validation_link FROM acc_einvoice WHERE move_id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten();

    let move_type: String = head.get("move_type");
    let state: String = head.get("state");
    let sst_registered = company
        .as_ref()
        .and_then(|c| c.get::<Option<String>, _>("company_sst_registration"))
        .filter(|s| !s.is_empty())
        .is_some();
    let title = match move_type.as_str() {
        "customer_invoice" if sst_registered => "TAX INVOICE",
        "customer_invoice" => "INVOICE",
        "customer_credit_note" => "CREDIT NOTE",
        "vendor_bill" => "VENDOR BILL",
        "vendor_credit_note" => "DEBIT NOTE",
        _ => "DOCUMENT",
    };
    let cval = |k: &str| -> String {
        company
            .as_ref()
            .and_then(|c| c.try_get::<Option<String>, _>(k).ok().flatten())
            .map(|v| esc(&v))
            .unwrap_or_default()
    };
    let company_name = company
        .as_ref()
        .map(|c| esc(&c.get::<String, _>("name")))
        .unwrap_or_else(|| "Company".into());
    let hval = |k: &str| -> String {
        head.try_get::<Option<String>, _>(k)
            .ok()
            .flatten()
            .map(|v| esc(&v))
            .unwrap_or_default()
    };

    let mut line_trs = String::new();
    for l in &lines {
        let qty: Decimal = l.get("quantity");
        let price: Decimal = l.get("unit_price");
        let rate: Option<Decimal> = l.try_get::<Option<Decimal>, _>("tax_rate").ok().flatten();
        line_trs.push_str(&format!(
            "<tr><td>{}</td><td class=\"num\">{}</td><td class=\"num\">{}</td>\
             <td>{}</td><td>{}</td><td class=\"num\">{}</td></tr>",
            esc(&l.get::<String, _>("description")),
            qty.normalize(),
            money(price),
            esc(l.get::<Option<String>, _>("classification_code").as_deref().unwrap_or("")),
            rate.map(|r| format!("{}%", r.normalize())).unwrap_or_default(),
            money((qty * price).round_dp(2)),
        ));
    }
    let mut tax_trs = String::new();
    for t in &tax_rows {
        tax_trs.push_str(&format!(
            "<tr><td colspan=\"5\" class=\"num\">{} (on {})</td><td class=\"num\">{}</td></tr>",
            esc(&t.get::<String, _>("name")),
            money(t.get("base")),
            money(t.get("tax")),
        ));
    }
    let einv_block = einv
        .map(|e| {
            let status: String = e.get("status");
            if status == "valid" {
                let link = e
                    .get::<Option<String>, _>("validation_link")
                    .unwrap_or_default();
                // LHDN's visual-representation requirement: the QR
                // encodes the validation link.
                let qr = if link.is_empty() {
                    String::new()
                } else {
                    vortex_plugin_sdk::framework::qr_svg(&link, 110)
                        .map(|svg| format!("<div class=\"qr\">{svg}</div>"))
                        .unwrap_or_default()
                };
                format!(
                    "<div class=\"einv\">{qr}<div><b>LHDN e-Invoice validated</b><br/>UUID {}<br/>\
                     <span class=\"mono\">{}</span><br/>Scan the QR to verify with LHDN MyInvois.</div></div>",
                    esc(e.get::<Option<String>, _>("lhdn_uuid").as_deref().unwrap_or("")),
                    esc(&link),
                )
            } else {
                String::new()
            }
        })
        .unwrap_or_default();
    // Company logo (uploaded in Accounting Settings, FileStore-backed).
    let logo_html = match app_state.files.get(&db_ctx.db_name, "company/logo").await {
        Ok(Some(_)) => r#"<img src="/accounting/company-logo" alt="" style="max-height:64px;max-width:220px;margin-bottom:6px"/>"#,
        _ => "",
    };
    let draft_mark = if state != "posted" {
        r#"<div class="watermark">DRAFT</div>"#
    } else {
        ""
    };

    let html = format!(
        r##"<!DOCTYPE html><html><head><meta charset="utf-8"><title>{number} — {title}</title>
<style>{css}
body {{ max-width: 21cm; margin: 1.2cm auto; position: relative; }}
.head {{ display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 1.2em; }}
.head h1 {{ font-size: 1.5em; letter-spacing: 0.06em; }}
.seller p, .buyer p {{ margin: 1px 0; font-size: 0.85em; }}
.seller .name {{ font-size: 1.1em; font-weight: 700; }}
.meta td {{ padding: 1px 8px 1px 0; font-size: 0.85em; border: none; }}
.parties {{ display: flex; justify-content: space-between; gap: 2em; margin-bottom: 1em; }}
.num {{ text-align: right; font-variant-numeric: tabular-nums; }}
.mono {{ font-family: monospace; font-size: 0.75em; word-break: break-all; }}
.totals td {{ font-weight: 600; }}
.einv {{ margin-top: 1em; padding: 0.6em 0.8em; border: 1px solid #ccc; border-radius: 4px; font-size: 0.8em; display: flex; gap: 1em; align-items: center; }}
.einv .qr svg {{ display: block; }}
.footer {{ margin-top: 2em; font-size: 0.75em; color: #666; }}
.watermark {{ position: absolute; top: 35%; left: 20%; font-size: 6em; color: rgba(200,0,0,0.12); transform: rotate(-25deg); pointer-events: none; }}
.printbar {{ text-align: right; margin-bottom: 1em; }}
.printbar button {{ padding: 0.4em 1.2em; cursor: pointer; }}
@media print {{ .printbar {{ display: none; }} }}
</style></head><body>
{draft_mark}
<div class="printbar"><button onclick="window.print()">Print / Save as PDF</button></div>
<div class="head">
  <div class="seller">
    {logo_html}
    <p class="name">{company_name}</p>
    <p>{addr1}</p><p>{addr2}</p><p>{postcode} {city}</p>
    <p>TIN: {ctin} · BRN: {cbrn}</p>
    <p>{sst_line}</p>
    <p>{cphone} · {cemail}</p>
  </div>
  <div style="text-align:right">
    <h1>{title}</h1>
    <table class="meta" style="margin-left:auto">
      <tr><td>Number</td><td><b>{number}</b></td></tr>
      <tr><td>Date</td><td>{date}</td></tr>
      <tr><td>Due</td><td>{due}</td></tr>
      <tr><td>Reference</td><td>{reference}</td></tr>
    </table>
  </div>
</div>
<div class="parties"><div class="buyer">
  <p style="font-size:0.75em;color:#666">BILL TO</p>
  <p><b>{partner}</b></p>
  <p>{pstreet}</p><p>{pstreet2}</p><p>{pzip} {pcity}</p>
  <p>{ptin_line}</p>
  <p>{pphone} {pemail}</p>
</div></div>
<table class="table table-sm" style="table-layout:fixed;width:100%">
<colgroup><col/><col style="width:4.5rem"/><col style="width:7rem"/><col style="width:4.5rem"/><col style="width:8rem"/><col style="width:8.5rem"/></colgroup>
<thead><tr><th>Description</th><th class="num">Qty</th><th class="num">Unit Price</th><th>Class</th><th>Tax</th><th class="num">Amount (MYR)</th></tr></thead>
<tbody>{line_trs}</tbody>
<tfoot>
<tr><td colspan="5" class="num">Subtotal</td><td class="num">{untaxed}</td></tr>
{tax_trs}
<tr class="totals"><td colspan="5" class="num">TOTAL</td><td class="num">{total}</td></tr>
<tr><td colspan="5" class="num">Balance due</td><td class="num">{residual}</td></tr>
</tfoot>
</table>
{einv_block}
<div class="footer">This is a computer-generated document. {narration}</div>
</body></html>"##,
        css = vortex_plugin_sdk::framework::user_reports::REPORT_CSS,
        number = hval("number"),
        title = title,
        company_name = company_name,
        addr1 = cval("company_address1"),
        addr2 = cval("company_address2"),
        postcode = cval("company_postcode"),
        city = cval("company_city"),
        ctin = cval("company_tin"),
        cbrn = cval("company_id_value"),
        sst_line = if sst_registered {
            format!("SST Reg. No: {}", cval("company_sst_registration"))
        } else {
            String::new()
        },
        cphone = cval("company_phone"),
        cemail = cval("company_email"),
        date = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("invoice_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_default(),
        due = head
            .try_get::<Option<vortex_plugin_sdk::chrono::NaiveDate>, _>("due_date")
            .ok()
            .flatten()
            .map(|d| d.to_string())
            .unwrap_or_default(),
        reference = hval("ref"),
        partner = hval("partner_name"),
        pstreet = hval("street"),
        pstreet2 = hval("street2"),
        pzip = hval("zip"),
        pcity = hval("city"),
        ptin_line = {
            let tin = hval("partner_tin");
            if tin.is_empty() { String::new() } else { format!("TIN: {tin}") }
        },
        pphone = hval("partner_phone"),
        pemail = hval("partner_email"),
        line_trs = line_trs,
        tax_trs = tax_trs,
        untaxed = money(head.get("untaxed_amount")),
        total = money(head.get("total_amount")),
        residual = money(head.get("amount_residual")),
        einv_block = einv_block,
        draft_mark = draft_mark,
        narration = hval("narration"),
    );
    Html(html).into_response()
}

fn doc_family(move_type: &str) -> (&'static str, &'static str, &'static str) {
    // (list title, list url, partner filter)
    if move_type.starts_with("customer") {
        ("Customer Invoices", "/accounting/invoices", "customer")
    } else {
        ("Vendor Bills", "/accounting/bills", "supplier")
    }
}

const DOC_TYPES: &[(&str, &str)] = &[
    ("customer_invoice", "Customer Invoice"),
    ("customer_credit_note", "Customer Credit Note"),
    ("vendor_bill", "Vendor Bill"),
    ("vendor_credit_note", "Vendor Credit Note"),
];

fn doc_type_label(t: &str) -> &'static str {
    DOC_TYPES.iter().find(|(k, _)| *k == t).map(|(_, l)| *l).unwrap_or("Document")
}

async fn doc_partner_options(
    db: &vortex_plugin_sdk::sqlx::PgPool,
    kind: &str,
    selected: Option<Uuid>,
) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sql = if kind == "customer" {
        "SELECT id, name FROM contacts WHERE active AND contact_type IN ('customer','both') ORDER BY name"
    } else {
        "SELECT id, name FROM contacts WHERE active AND contact_type IN ('supplier','both') ORDER BY name"
    };
    let rows = vortex_plugin_sdk::sqlx::query(sql).fetch_all(db).await.unwrap_or_default();
    let mut out = String::new();
    for row in rows {
        let id: Uuid = row.get("id");
        let name: String = row.get("name");
        let sel = if Some(id) == selected { " selected" } else { "" };
        out.push_str(&format!(
            r#"<option value="{id}"{sel}>{name}</option>"#,
            id = id,
            sel = sel,
            name = esc(&name)
        ));
    }
    out
}

async fn tax_options(db: &vortex_plugin_sdk::sqlx::PgPool, use_kind: &str) -> String {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT id, name FROM taxes WHERE active AND type_tax_use IN ($1, 'none') ORDER BY name",
    )
    .bind(use_kind)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    let mut out = String::from(r#"<option value="">— no tax —</option>"#);
    for row in rows {
        let id: Uuid = row.get("id");
        let name: String = row.get("name");
        out.push_str(&format!(
            r#"<option value="{id}">{name}</option>"#,
            id = id,
            name = esc(&name)
        ));
    }
    out
}

// ─────────────────────────────────────────────────────────────────────────
// Lists
// ─────────────────────────────────────────────────────────────────────────

async fn document_list(
    state: Arc<AppState>,
    db: vortex_plugin_sdk::sqlx::PgPool,
    user: AuthUser,
    db_ctx: DatabaseContext,
    query: HashMap<String, String>,
    customer_side: bool,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let (title, base_url, _) = if customer_side {
        ("Customer Invoices", "/accounting/invoices", "customer")
    } else {
        ("Vendor Bills", "/accounting/bills", "supplier")
    };
    let type_filter = if customer_side {
        "m.move_type IN ('customer_invoice','customer_credit_note')"
    } else {
        "m.move_type IN ('vendor_bill','vendor_credit_note')"
    };
    let new_url = if customer_side {
        "/accounting/documents/new?kind=customer_invoice"
    } else {
        "/accounting/documents/new?kind=vendor_bill"
    };

    // Customer side also shows the LHDN e-invoice status inline —
    // every invoice's compliance state is visible on the register
    // itself (the e-Invoice Queue page is only the operational
    // monitor for the same data).
    let (from, select) = if customer_side {
        (
            "acc_move m JOIN contacts p ON p.id = m.partner_id \
             LEFT JOIN acc_einvoice e ON e.move_id = m.id",
            "m.id, COALESCE(m.number, '/') AS number, p.name AS partner_name, \
             m.invoice_date::text AS invoice_date, m.due_date::text AS due_date, \
             m.total_amount::text AS total_amount, m.amount_residual::text AS amount_residual, \
             m.state, m.payment_state, COALESCE(e.status, '') AS lhdn",
        )
    } else {
        (
            "acc_move m JOIN contacts p ON p.id = m.partner_id",
            "m.id, COALESCE(m.number, '/') AS number, p.name AS partner_name, \
             m.invoice_date::text AS invoice_date, m.due_date::text AS due_date, \
             m.total_amount::text AS total_amount, m.amount_residual::text AS amount_residual, \
             m.state, m.payment_state",
        )
    };
    let mut config = ListConfig::new(title, "acc_move")
        .custom_from(from)
        .custom_select(select)
        .base_filter(type_filter)
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("m.number"))
        .column(ListColumn::new("partner_name", "Partner").sortable().searchable().sql_expr("p.name"))
        .column(ListColumn::new("invoice_date", "Date").sortable().sql_expr("m.invoice_date"))
        .column(ListColumn::new("due_date", "Due").sortable().sql_expr("m.due_date"))
        .column(ListColumn::new("total_amount", "Total").sortable().sql_expr("m.total_amount"))
        .column(ListColumn::new("amount_residual", "Open").sortable().sql_expr("m.amount_residual"))
        .column(
            ListColumn::new("state", "Status")
                .filterable(&[("draft", "Draft"), ("posted", "Posted"), ("cancelled", "Cancelled")])
                .badge(&[
                    ("draft", "Draft", "badge-ghost"),
                    ("posted", "Posted", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("m.state"),
        )
        .column(
            ListColumn::new("payment_state", "Payment")
                .filterable(&[
                    ("not_paid", "Not Paid"),
                    ("partial", "Partial"),
                    ("paid", "Paid"),
                    ("reversed", "Reversed"),
                ])
                .badge(&[
                    ("not_paid", "Not Paid", "badge-warning"),
                    ("partial", "Partial", "badge-info"),
                    ("paid", "Paid", "badge-success"),
                    ("reversed", "Reversed", "badge-ghost"),
                ])
                .sql_expr("m.payment_state"),
        )
        .detail_url("/accounting/documents/{id}")
        .create(
            if customer_side { "New Invoice" } else { "New Bill" },
            new_url,
        )
        .default_sort("invoice_date")
        .group_by_options(&[("partner_name", "Partner"), ("payment_state", "Payment")]);
    if customer_side {
        config = config.column(
            ListColumn::new("lhdn", "LHDN")
                .filterable(&[
                    ("ready", "Ready"),
                    ("exported", "Exported"),
                    ("submitted", "Submitted"),
                    ("valid", "Valid"),
                    ("invalid", "Invalid"),
                    ("cancelled", "Cancelled"),
                ])
                .badge(&[
                    ("ready", "Ready", "badge-ghost"),
                    ("exported", "Exported", "badge-info"),
                    ("submitted", "Submitted", "badge-info"),
                    ("valid", "Valid", "badge-success"),
                    ("invalid", "Invalid", "badge-error"),
                    ("cancelled", "Cancelled", "badge-warning"),
                ])
                .sql_expr("COALESCE(e.status, '')"),
        );
    }

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "document list query failed");
            return Html("<h1>Failed to load documents</h1>").into_response();
        }
    };
    let list_html = render_list(&config, &result, &params, base_url);
    Html(page_shell(&sidebar, title, &list_html)).into_response()
}

async fn list_invoices(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    document_list(state, db, user, db_ctx, query, true).await
}

async fn list_bills(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    document_list(state, db, user, db_ctx, query, false).await
}

async fn list_payments(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let config = ListConfig::new("Payments", "acc_move")
        .custom_from(
            "acc_move m JOIN acc_journal j ON j.id = m.journal_id \
             LEFT JOIN contacts p ON p.id = m.partner_id",
        )
        .custom_select(
            "m.id, COALESCE(m.number, '/') AS number, j.code AS journal_code, \
             COALESCE(p.name, '') AS partner_name, m.move_date::text AS move_date, \
             COALESCE(m.ref, '') AS ref, m.total_amount::text AS total_amount, m.state",
        )
        .base_filter("m.move_type = 'payment'")
        .column(ListColumn::new("number", "Number").sortable().code().sql_expr("m.number"))
        .column(ListColumn::new("partner_name", "Partner").searchable().sql_expr("p.name"))
        .column(ListColumn::new("journal_code", "Journal").sql_expr("j.code"))
        .column(ListColumn::new("move_date", "Date").sortable().sql_expr("m.move_date"))
        .column(ListColumn::new("ref", "Memo").searchable().sql_expr("m.ref"))
        .column(
            ListColumn::new("state", "Status")
                .badge(&[
                    ("draft", "Draft", "badge-ghost"),
                    ("posted", "Posted", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("m.state"),
        )
        .detail_url("/accounting/moves/{id}")
        .default_sort("move_date");

    let params = ListParams::from_query(&query);
    let result = match execute_list(&db, &config, &params).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "payments list query failed");
            return Html("<h1>Failed to load payments</h1>").into_response();
        }
    };
    let list_html = render_list(&config, &result, &params, "/accounting/payments");
    Html(page_shell(&sidebar, "Payments", &list_html)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Create
// ─────────────────────────────────────────────────────────────────────────

async fn new_document_form(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar(&state, &user, &db_ctx);
    let kind = query.get("kind").map(String::as_str).unwrap_or("customer_invoice");
    let (family_title, family_url, partner_kind) = doc_family(kind);
    let partners = doc_partner_options(&db, partner_kind, None).await;

    let type_options: String = DOC_TYPES
        .iter()
        .filter(|(k, _)| k.starts_with(if partner_kind == "customer" { "customer" } else { "vendor" }))
        .map(|(k, l)| {
            let sel = if *k == kind { " selected" } else { "" };
            format!(r#"<option value="{k}"{sel}>{l}</option>"#)
        })
        .collect();

    let currency_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT code, name FROM currencies WHERE active ORDER BY (code <> 'MYR'), code",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let currency_options: String = currency_rows
        .iter()
        .map(|r| {
            let code: String = r.get("code");
            let name: String = r.get("name");
            format!(
                r#"<option value="{code}">{code} — {name}</option>"#,
                code = vortex_plugin_sdk::framework::html_escape(&code),
                name = vortex_plugin_sdk::framework::html_escape(&name),
            )
        })
        .collect();

    let content = format!(
        r#"<div class="max-w-xl">
<a href="{family_url}" class="btn btn-ghost btn-sm mb-4">← Back to {family_title}</a>
<h1 class="text-2xl font-bold mb-6">New {label}</h1>
<form method="POST" action="/accounting/documents/create">
<div class="card bg-base-100 shadow"><div class="card-body">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Type</span></label>
<select name="move_type" class="select select-bordered select-sm">{type_options}</select>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Partner *</span></label>
<select name="partner_id" class="select select-bordered select-sm" required>{partners}</select>
</div>
<div class="grid grid-cols-2 gap-3">
<div class="form-control mb-3">
<label class="label"><span class="label-text">Document Date</span></label>
<input name="invoice_date" type="date" class="input input-bordered input-sm"/>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Due Date</span></label>
<input name="due_date" type="date" class="input input-bordered input-sm"/>
</div>
</div>
<div class="form-control mb-3">
<label class="label"><span class="label-text">Currency</span></label>
<select name="currency_code" class="select select-bordered select-sm">{currency_options}</select>
</div>
<button type="submit" class="btn btn-primary btn-sm">Create Draft</button>
</div></div>
</form>
<p class="text-sm opacity-60 mt-4">Lines are added on the document page; posting expands them into balanced journal lines.</p>
</div>"#,
        family_url = family_url,
        family_title = family_title,
        label = doc_type_label(kind),
        type_options = type_options,
        partners = partners,
        currency_options = currency_options,
    );
    Html(page_shell(&sidebar, "New Document", &content)).into_response()
}

async fn create_document(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let move_type = form
        .get("move_type")
        .map(String::as_str)
        .unwrap_or("customer_invoice")
        .to_string();
    let Some(partner_id) = form.get("partner_id").and_then(|s| s.parse::<Uuid>().ok()) else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::BAD_REQUEST,
            "Partner is required",
        )
            .into_response();
    };
    let invoice_date = date_or_today(&form, "invoice_date");
    let due_date = form
        .get("due_date")
        .and_then(|s| s.parse::<vortex_plugin_sdk::chrono::NaiveDate>().ok());
    let company_id = default_company(&db).await;

    // The UI creates an *empty* draft header and lands on the detail page
    // where lines are added one at a time. `documents::create_invoice`
    // enforces "≥ 1 line, positive total" — correct for adopting modules
    // that build a full document in one shot, but wrong for this two-step
    // flow — so the header is inserted directly here. Totals stay at zero
    // until lines are added; the positive-total guard still applies when the
    // draft is posted (`post_invoice`).
    let journal_code = if move_type.starts_with("customer") { "SAL" } else { "PUR" };
    let journal_id = match crate::service::journal_by_code(&db, company_id, journal_code).await {
        Ok(Some((jid, _))) => jid,
        Ok(None) => {
            return (
                vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Html(format!("<p>Cannot create document: no '{journal_code}' journal configured</p>")),
            )
                .into_response();
        }
        Err(e) => {
            error!(error = %e, "journal lookup failed");
            return (
                vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Html("<p>Cannot create document: journal lookup failed</p>".to_string()),
            )
                .into_response();
        }
    };

    // Optional non-MYR currency from the form.
    let currency_id: Option<Uuid> = match form.get("currency_code").map(String::as_str) {
        Some(code) if !code.is_empty() && code != "MYR" => {
            vortex_plugin_sdk::sqlx::query_scalar(
                "SELECT id FROM currencies WHERE code = $1 AND active",
            )
            .bind(code)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
        }
        _ => None,
    };

    let created: Result<Uuid, _> = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_move \
            (journal_id, move_date, move_type, partner_id, invoice_date, due_date, \
             company_id, created_by, updated_by, currency_id) \
         VALUES ($1, $2, $3, $4, $2, $5, $6, $7, $7, $8) \
         RETURNING id",
    )
    .bind(journal_id)
    .bind(invoice_date)
    .bind(&move_type)
    .bind(partner_id)
    .bind(due_date)
    .bind(company_id)
    .bind(user.id)
    .bind(currency_id)
    .fetch_one(&db)
    .await;

    match created {
        Ok(id) => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "created").await;
            redirect(&format!("/accounting/documents/{id}"))
        }
        Err(e) => {
            error!(error = %e, "document header insert failed");
            (
                vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                Html(format!(
                    "<p>Cannot create document: {}</p>",
                    vortex_plugin_sdk::framework::html_escape(&e.to_string())
                )),
            )
                .into_response()
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Detail
// ─────────────────────────────────────────────────────────────────────────

async fn document_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::html_escape;
    let sidebar = render_sidebar(&state, &user, &db_ctx);

    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT m.number, m.move_type, m.state, m.payment_state, \
                m.invoice_date::text AS invoice_date, m.due_date::text AS due_date, \
                m.untaxed_amount, m.tax_amount, m.total_amount, m.amount_residual, \
                m.origin_ref, p.name AS partner_name \
         FROM acc_move m JOIN contacts p ON p.id = m.partner_id \
         WHERE m.id = $1 AND m.move_type <> 'entry'",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return (
            vortex_plugin_sdk::axum::http::StatusCode::NOT_FOUND,
            "Document not found",
        )
            .into_response();
    };

    let number: Option<String> = head.get("number");
    let number = number.unwrap_or_else(|| "/".to_string());
    let move_type: String = head.get("move_type");
    let doc_state: String = head.get("state");
    let payment_state: String = head.get("payment_state");
    let partner_name: String = head.get("partner_name");
    let invoice_date: Option<String> = head.get("invoice_date");
    let due_date: Option<String> = head.get("due_date");
    let untaxed: Decimal = head.get("untaxed_amount");
    let tax: Decimal = head.get("tax_amount");
    let total: Decimal = head.get("total_amount");
    let residual: Decimal = head.get("amount_residual");
    let origin_ref: Option<String> = head.get("origin_ref");
    let is_draft = doc_state == "draft";
    let (family_title, family_url, _) = doc_family(&move_type);
    let use_kind = if move_type.starts_with("customer") { "sale" } else { "purchase" };

    // Document lines. Customer documents show the LHDN classification
    // per line — required on every e-invoice line.
    let customer_doc = use_kind == "sale";
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.id, l.description, l.quantity, l.unit_price, l.classification_code, \
                t.name AS tax_name \
         FROM acc_invoice_line l LEFT JOIN taxes t ON t.id = l.tax_id \
         WHERE l.move_id = $1 ORDER BY l.sequence",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut lines_html = String::new();
    for row in &line_rows {
        let line_id: Uuid = row.get("id");
        let description: String = row.get("description");
        let quantity: Decimal = row.get("quantity");
        let unit_price: Decimal = row.get("unit_price");
        let tax_name: Option<String> = row.get("tax_name");
        let class_cell = if customer_doc {
            format!(
                "<td><span class=\"badge badge-ghost badge-sm\" title=\"LHDN classification\">{}</span></td>",
                esc(row.get::<Option<String>, _>("classification_code").as_deref().unwrap_or("022")),
            )
        } else {
            String::new()
        };
        let delete_btn = if is_draft {
            format!(
                r#"<form method="POST" action="/accounting/documents/{id}/lines/{line_id}/delete" style="display:inline">
<button class="btn btn-ghost btn-xs text-error" onclick="return confirm('Remove this line?')">✕</button></form>"#
            )
        } else {
            String::new()
        };
        lines_html.push_str(&format!(
            r#"<tr><td>{description}</td><td class="text-right font-mono">{qty}</td>
<td class="text-right font-mono">{price}</td><td>{tax}</td>{class_cell}
<td class="text-right font-mono">{subtotal}</td><td>{delete_btn}</td></tr>"#,
            description = esc(&description),
            qty = quantity.normalize(),
            price = money(unit_price),
            tax = esc(tax_name.as_deref().unwrap_or("")),
            class_cell = class_cell,
            subtotal = money((quantity * unit_price).round_dp(2)),
            delete_btn = delete_btn,
        ));
    }

    let add_line_form = if is_draft {
        let taxes = tax_options(&db, use_kind).await;
        // LHDN classification — required on every e-invoice line, so
        // it is entered where the line is entered (customer docs).
        let class_field = if customer_doc {
            let opts: String = vortex_plugin_sdk::sqlx::query(
                "SELECT code, description FROM acc_lhdn_code \
                 WHERE code_type = 'classification' AND active ORDER BY code",
            )
            .fetch_all(&db)
            .await
            .unwrap_or_default()
            .iter()
            .map(|r| {
                let code: String = r.get("code");
                let sel = if code == "022" { " selected" } else { "" };
                format!(
                    "<option value=\"{code}\"{sel}>{code} — {}</option>",
                    esc(&r.get::<String, _>("description")),
                )
            })
            .collect();
            format!(
                r#"<div class="form-control col-span-3">
<label class="label py-0"><span class="label-text-alt">LHDN Classification</span></label>
<select name="classification_code" class="select select-bordered select-sm w-full">{opts}</select>
</div>"#
            )
        } else {
            String::new()
        };
        let desc_span = if customer_doc { "col-span-4" } else { "col-span-5" };
        let btn_span = if customer_doc { "col-span-12 md:col-span-12" } else { "col-span-2" };
        format!(
            r#"<div class="card bg-base-100 shadow mt-4"><div class="card-body py-4">
<h3 class="font-semibold mb-2">Add Line</h3>
<form method="POST" action="/accounting/documents/{id}/lines" class="grid grid-cols-12 gap-2 items-end">
<div class="form-control {desc_span}">
<label class="label py-0"><span class="label-text-alt">Description *</span></label>
<input name="description" class="input input-bordered input-sm" required/>
</div>
<div class="form-control col-span-1">
<label class="label py-0"><span class="label-text-alt">Qty</span></label>
<input name="quantity" type="number" step="0.0001" min="0.0001" value="1" class="input input-bordered input-sm"/>
</div>
<div class="form-control col-span-2">
<label class="label py-0"><span class="label-text-alt">Unit Price</span></label>
<input name="unit_price" type="number" step="0.01" class="input input-bordered input-sm"/>
</div>
<div class="form-control col-span-2">
<label class="label py-0"><span class="label-text-alt">Tax</span></label>
<select name="tax_id" class="select select-bordered select-sm">{taxes}</select>
</div>
{class_field}
<div class="{btn_span}">
<button class="btn btn-primary btn-sm w-full md:w-auto">Add</button>
</div>
</form>
</div></div>"#
        )
    } else {
        String::new()
    };

    // Actions
    let mut actions = String::new();
    actions.push_str(&format!(
        r#"<a href="/accounting/documents/{id}/print" target="_blank" class="btn btn-outline btn-sm">Print</a> "#
    ));
    if is_draft {
        actions.push_str(&format!(
            r#"<form method="POST" action="/accounting/documents/{id}/post" style="display:inline">
<button class="btn btn-success btn-sm">Post</button></form>"#
        ));
    } else if doc_state == "posted" && (payment_state == "not_paid" || payment_state == "partial") {
        actions.push_str(&format!(
            r#"<form method="POST" action="/accounting/documents/{id}/pay" class="flex items-center gap-2">
<input name="amount" type="number" step="0.01" min="0.01" value="{residual}" class="input input-bordered input-sm w-32"/>
<select name="journal_code" class="select select-bordered select-sm w-24">
<option value="BNK">Bank</option><option value="CSH">Cash</option>
</select>
<button class="btn btn-primary btn-sm">Register Payment</button>
</form>"#,
            residual = money(residual),
        ));
    }

    // Related payments (via reconciliation)
    let payment_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT DISTINCT pm.id, pm.number, pm.move_date::text AS move_date, pr.amount \
         FROM acc_partial_reconcile pr \
         JOIN acc_move_line dl ON dl.id = pr.debit_line_id \
         JOIN acc_move_line cl ON cl.id = pr.credit_line_id \
         JOIN acc_move_line pl ON pl.id IN (pr.debit_line_id, pr.credit_line_id) \
         JOIN acc_move pm ON pm.id = pl.move_id AND pm.id <> $1 \
         WHERE dl.move_id = $1 OR cl.move_id = $1 \
         ORDER BY pm.number",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut payments_html = String::new();
    for row in &payment_rows {
        let pid: Uuid = row.get("id");
        let pnumber: Option<String> = row.get("number");
        let pdate: String = row.get("move_date");
        let amount: Decimal = row.get("amount");
        payments_html.push_str(&format!(
            r#"<tr><td><a class="link" href="/accounting/moves/{pid}">{num}</a></td>
<td>{date}</td><td class="text-right font-mono">{amount}</td></tr>"#,
            pid = pid,
            num = esc(pnumber.as_deref().unwrap_or("/")),
            date = esc(&pdate),
            amount = money(amount),
        ));
    }
    let payments_block = if payments_html.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="card bg-base-100 shadow mt-4"><div class="card-body py-4">
<h3 class="font-semibold mb-2">Payments</h3>
<table class="table table-sm"><thead><tr><th>Number</th><th>Date</th><th class="text-right">Allocated</th></tr></thead>
<tbody>{payments_html}</tbody></table>
</div></div>"#
        )
    };

    let payment_badge = match payment_state.as_str() {
        "paid" => r#"<span class="badge badge-success">Paid</span>"#,
        "partial" => r#"<span class="badge badge-info">Partial</span>"#,
        "reversed" => r#"<span class="badge badge-ghost">Reversed</span>"#,
        _ if doc_state == "posted" => r#"<span class="badge badge-warning">Not Paid</span>"#,
        _ => "",
    };
    let state_badge = match doc_state.as_str() {
        "draft" => r#"<span class="badge badge-ghost">Draft</span>"#,
        "posted" => r#"<span class="badge badge-success">Posted</span>"#,
        _ => r#"<span class="badge badge-error">Cancelled</span>"#,
    };
    let origin_block = origin_ref
        .map(|o| {
            format!(
                r#"<div class="text-xs opacity-60 mt-2">Origin: <span class="font-mono">{}</span></div>"#,
                esc(&o)
            )
        })
        .unwrap_or_default();
    let gl_link = if doc_state == "posted" {
        format!(
            r#"<a class="link text-sm" href="/accounting/moves/{id}">View journal entry →</a>"#
        )
    } else {
        String::new()
    };

    let history_panel = vortex_plugin_sdk::framework::render_audit_trail(&db, "acc_move", id).await;
    let einvoice_panel = crate::handlers_einvoice::einvoice_widget(&db, id).await;

    let class_header = if customer_doc { "<th>Class</th>" } else { "" };
    // Fixed column grid: description flexes, everything else is a
    // stable width, so rows never jiggle as content changes.
    let colgroup = if customer_doc {
        r#"<colgroup><col/><col style="width:6rem"/><col style="width:9rem"/><col style="width:12rem"/><col style="width:6rem"/><col style="width:9rem"/><col style="width:3.5rem"/></colgroup>"#
    } else {
        r#"<colgroup><col/><col style="width:6rem"/><col style="width:9rem"/><col style="width:12rem"/><col style="width:9rem"/><col style="width:3.5rem"/></colgroup>"#
    };
    let foot_span = if customer_doc { 5 } else { 4 };
    let content = format!(
        r#"<div class="w-full">
<a href="{family_url}" class="btn btn-ghost btn-sm mb-4">← Back to {family_title}</a>
<div class="flex items-center justify-between mb-4">
<h1 class="text-2xl font-bold">{number} <span class="text-base opacity-60 font-normal">{type_label}</span> {state_badge} {payment_badge}</h1>
<div>{actions}</div>
</div>
<div class="card bg-base-100 shadow"><div class="card-body py-4">
<div class="grid grid-cols-4 gap-4 text-sm">
<div><span class="opacity-60">Partner</span><br/>{partner}</div>
<div><span class="opacity-60">Date</span><br/>{invoice_date}</div>
<div><span class="opacity-60">Due</span><br/>{due_date}</div>
<div><span class="opacity-60">Open Amount</span><br/><span class="font-mono">{residual}</span></div>
</div>
{origin_block}
{gl_link}
</div></div>
{einvoice_panel}
<div class="card bg-base-100 shadow mt-4"><div class="card-body py-4">
<h3 class="font-semibold mb-2">Lines</h3>
<div class="overflow-x-auto"><table class="table table-sm table-fixed w-full">
{colgroup}
<thead><tr><th>Description</th><th class="text-right">Qty</th><th class="text-right">Unit Price</th><th>Tax</th>{class_header}<th class="text-right">Subtotal</th><th></th></tr></thead>
<tbody>{lines}</tbody>
<tfoot>
<tr><td colspan="{foot_span}" class="text-right">Untaxed</td><td class="text-right font-mono">{untaxed}</td><td></td></tr>
<tr><td colspan="{foot_span}" class="text-right">Tax</td><td class="text-right font-mono">{tax}</td><td></td></tr>
<tr class="font-bold"><td colspan="{foot_span}" class="text-right">Total</td><td class="text-right font-mono">{total}</td><td></td></tr>
</tfoot>
</table></div>
</div></div>
{add_line_form}
{payments_block}
<div class="mt-6">{history}</div>
</div>"#,
        family_url = family_url,
        family_title = family_title,
        number = esc(&number),
        type_label = doc_type_label(&move_type),
        state_badge = state_badge,
        payment_badge = payment_badge,
        actions = actions,
        partner = esc(&partner_name),
        invoice_date = esc(invoice_date.as_deref().unwrap_or("—")),
        due_date = esc(due_date.as_deref().unwrap_or("—")),
        residual = money(residual),
        origin_block = origin_block,
        gl_link = gl_link,
        lines = lines_html,
        untaxed = money(untaxed),
        tax = money(tax),
        total = money(total),
        add_line_form = add_line_form,
        payments_block = payments_block,
        history = history_panel,
    );

    Html(page_shell(&sidebar, &format!("{number}"), &content)).into_response()
}

// ─────────────────────────────────────────────────────────────────────────
// Lines + lifecycle
// ─────────────────────────────────────────────────────────────────────────

async fn add_doc_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let Some(description) = opt_str(&form, "description") else {
        return redirect(&format!("/accounting/documents/{id}"));
    };
    let quantity = {
        let q = dec_or_zero(&form, "quantity");
        if q <= Decimal::ZERO { Decimal::ONE } else { q }
    };
    let unit_price = dec_or_zero(&form, "unit_price");
    let tax_id = form
        .get("tax_id")
        .filter(|s| !s.is_empty())
        .and_then(|s| s.parse::<Uuid>().ok());
    let classification = form
        .get("classification_code")
        .map(|s| s.trim())
        .filter(|s| !s.is_empty());
    let company_id = default_company(&db).await;

    let result = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO acc_invoice_line \
            (move_id, sequence, description, quantity, unit_price, tax_id, \
             classification_code, company_id) \
         SELECT $1, COALESCE(MAX(l.sequence), 0) + 10, $2, $3, $4, $5, $6, $7 \
         FROM acc_move m LEFT JOIN acc_invoice_line l ON l.move_id = m.id \
         WHERE m.id = $1 AND m.state = 'draft' \
         GROUP BY m.id",
    )
    .bind(id)
    .bind(description)
    .bind(quantity)
    .bind(unit_price)
    .bind(tax_id)
    .bind(classification)
    .bind(company_id)
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "document line insert failed");
    }
    let _ = documents::refresh_document_totals(&db, id).await;
    redirect(&format!("/accounting/documents/{id}"))
}

async fn delete_doc_line(
    State(_state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Path((id, line_id)): Path<(Uuid, Uuid)>,
) -> Response {
    let result = vortex_plugin_sdk::sqlx::query(
        "DELETE FROM acc_invoice_line l USING acc_move m \
         WHERE l.id = $1 AND l.move_id = $2 AND m.id = l.move_id AND m.state = 'draft'",
    )
    .bind(line_id)
    .bind(id)
    .execute(&db)
    .await;
    if let Err(e) = result {
        error!(error = %e, "document line delete failed");
    }
    let _ = documents::refresh_document_totals(&db, id).await;
    redirect(&format!("/accounting/documents/{id}"))
}

async fn post_document(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    match documents::post_invoice(&db, &state.pool, id, user.id).await {
        Ok(number) => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "posted").await;
            vortex_plugin_sdk::tracing::info!(number = %number, "document posted");
            // e-Invoice hook: create the LHDN row (auto-submits in API
            // mode). Best-effort — a mis-set profile must not block
            // posting; the e-invoice queue surfaces what needs fixing.
            if let Err(e) =
                crate::einvois::jobs::after_post(&state, &db, &db_ctx.db_name, id).await
            {
                vortex_plugin_sdk::tracing::warn!("einvoice after_post: {e}");
            }
            redirect(&format!("/accounting/documents/{id}"))
        }
        Err(e) => (
            vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                r#"<p>Cannot post: {}</p><p><a href="/accounting/documents/{id}">← back to the document</a></p>"#,
                vortex_plugin_sdk::framework::html_escape(&e.to_string())
            )),
        )
            .into_response(),
    }
}

async fn pay_document(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
    vortex_plugin_sdk::axum::extract::Form(form): vortex_plugin_sdk::axum::extract::Form<
        HashMap<String, String>,
    >,
) -> Response {
    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT move_type, partner_id, company_id, amount_residual FROM acc_move \
         WHERE id = $1 AND state = 'posted' AND move_type <> 'entry'",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    .ok()
    .flatten() else {
        return redirect(&format!("/accounting/documents/{id}"));
    };
    let move_type: String = head.get("move_type");
    let partner_id: Option<Uuid> = head.get("partner_id");
    let company_id: Option<Uuid> = head.get("company_id");
    let residual: Decimal = head.get("amount_residual");
    let Some(partner_id) = partner_id else {
        return redirect(&format!("/accounting/documents/{id}"));
    };

    let amount = {
        let a = dec_or_zero(&form, "amount");
        if a <= Decimal::ZERO { residual } else { a.min(residual) }
    };
    let journal_code = form
        .get("journal_code")
        .map(String::as_str)
        .filter(|s| *s == "BNK" || *s == "CSH")
        .unwrap_or("BNK");
    // Customer invoices are settled by inbound money; vendor bills by
    // outbound. Credit notes settle the other way around.
    let customer = move_type.starts_with("customer");
    let credit_note = move_type.ends_with("credit_note");
    let direction = if customer ^ credit_note {
        PaymentDirection::Inbound
    } else {
        PaymentDirection::Outbound
    };
    let today = vortex_plugin_sdk::chrono::Utc::now().date_naive();

    match documents::register_payment(
        &db,
        &state.pool,
        user.id,
        &NewPayment {
            partner_id,
            direction,
            journal_code,
            currency_code: None,
            amount,
            payment_date: today,
            memo: opt_str(&form, "memo"),
            company_id,
            allocate_to: vec![id],
        },
    )
    .await
    {
        Ok(_payment_id) => {
            audit_move(&state, &db_ctx, &db, user.id, &user.username, id, "payment_registered")
                .await;
            redirect(&format!("/accounting/documents/{id}"))
        }
        Err(e) => (
            vortex_plugin_sdk::axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            Html(format!(
                r#"<p>Cannot register payment: {}</p><p><a href="/accounting/documents/{id}">← back to the document</a></p>"#,
                vortex_plugin_sdk::framework::html_escape(&e.to_string())
            )),
        )
            .into_response(),
    }
}
