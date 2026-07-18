//! IWK HTTP handlers — a fast bill list (list framework + scalability
//! knobs) and a branded, print-style sewerage bill page that mirrors the
//! real "Bil Perkhidmatan Pembetungan". Bills are generated in bulk (see
//! the billing-run seeder), so there is no hand-create form here.

use std::sync::Arc;

use serde::Deserialize;
use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::tracing::error;
use vortex_plugin_sdk::uuid::Uuid;

pub fn public_routes() -> Router<Arc<AppState>> {
    Router::new()
}

pub fn routes() -> Router<Arc<AppState>> {
    Router::new()
        .route("/iwk", get(list_bills))
        .route("/iwk/bills/{id}", get(bill_detail))
        .route("/iwk/gl", get(gl_page))
        .route("/iwk/gl/post/{run_id}", post(post_run))
        .route("/iwk/accounts", get(list_accounts))
        .route("/iwk/accounts/new", get(register_form))
        .route("/iwk/accounts/create", post(register_submit))
        .route("/iwk/accounts/{id}", get(account_detail))
        .route("/iwk/billing", get(billing_page))
        .route("/iwk/billing/generate", post(generate_submit))
        .route("/iwk/payments", get(payments_page))
        .route("/iwk/payments/history", get(payments_history))
        .route("/iwk/payments/register", post(payment_register))
        .route("/iwk/payments/import", post(payment_import))
        .route("/iwk/payments/post", post(payment_post))
        .route("/iwk/customers/{id}", get(customer_ledger_page))
}

/// Platform HTML shell. Delegates to the canonical `render_app_shell` so IWK
/// pages get the *same* chrome as the rest of the app — crucially the mobile
/// top bar + hamburger + overlay that toggle the sidebar. The previous
/// hand-rolled shell omitted them, so on a narrow/mobile viewport the sidebar
/// was off-screen with no way to open it (couldn't navigate or reach Home).
fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    vortex_plugin_sdk::framework::render_app_shell(&format!("{title} - Vortex"), sidebar, content)
}

fn sidebar_for(state: &AppState, user: &AuthUser, db_ctx: &DatabaseContext) -> String {
    let display_name = user.full_name.as_deref().unwrap_or(&user.username);
    let initials = vortex_plugin_sdk::framework::get_initials(display_name);
    vortex_plugin_sdk::framework::build_sidebar(
        "iwk",
        display_name,
        &initials,
        &db_ctx.installed_modules,
        user.is_admin(),
        &state.plugin_registry,
        &user.roles,
        &db_ctx.custom_apps_html,
    )
}

/// GET /iwk — the bill list. Search (trigram-prefiltered), sort, and
/// pagination come from the list framework; the count uses the reltuples
/// estimate on large unfiltered browses.
async fn list_bills(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };

    let config = ListConfig::new("IWK Bills", "iwk_bill")
        .custom_from("iwk_bill b JOIN contacts c ON c.id = b.contact_id")
        .custom_select(
            "b.id, b.bill_no, b.account_no, c.name AS customer_name, \
             b.category, b.system_type, \
             to_char(b.total, 'FM999990.00') AS total, \
             to_char(b.bill_date, 'DD/MM/YYYY') AS bill_date, \
             b.record_state",
        )
        .column(ListColumn::new("bill_no", "Bill No").sortable().searchable().code().sql_expr("b.bill_no"))
        .column(ListColumn::new("account_no", "Account No").sortable().searchable().code().sql_expr("b.account_no"))
        .column(ListColumn::new("customer_name", "Customer").sql_expr("c.name"))
        .column(
            ListColumn::new("category", "Category")
                .sortable()
                .filterable(&[("domestic", "Domestic"), ("commercial", "Commercial")])
                .badge(&[
                    ("domestic", "Domestic", "badge-info"),
                    ("commercial", "Commercial", "badge-secondary"),
                ])
                .sql_expr("b.category"),
        )
        .column(ListColumn::new("system_type", "System").sql_expr("b.system_type"))
        .column(ListColumn::new("total", "Total (RM)").sortable().sql_expr("b.total"))
        .column(ListColumn::new("bill_date", "Bill Date").sortable().sql_expr("b.bill_date"))
        .column(
            ListColumn::new("record_state", "Status")
                .filterable(&[("issued", "Issued"), ("paid", "Paid"), ("cancelled", "Cancelled")])
                .badge(&[
                    ("issued", "Issued", "badge-info"),
                    ("paid", "Paid", "badge-success"),
                    ("cancelled", "Cancelled", "badge-error"),
                ])
                .sql_expr("b.record_state"),
        )
        .detail_url("/iwk/bills/{id}")
        .default_sort("bill_no")
        // Scalability knobs (see the list-scalability work): join is
        // cardinality-preserving (contacts FK→PK), bill_no+id index-served
        // order, trigram search prefilter on the base table's columns.
        .count_estimate_from("iwk_bill")
        .tiebreak("b.id")
        .search_prefilter("iwk_bill b");

    let params = ListParams::from_query(&query);
    let table = match execute_list(&db, &config, &params).await {
        Ok(result) => render_list(&config, &result, &params, "/iwk"),
        Err(e) => {
            error!("iwk bill list failed: {e}");
            format!("<div class=\"alert alert-error\">List error: {e}</div>")
        }
    };

    let content = format!(
        r##"<div class="flex items-center justify-between mb-6">
<h1 class="text-2xl font-bold">IWK Bills <span class="text-base-content/40 text-base font-normal">Bil Perkhidmatan Pembetungan</span></h1>
</div>{table}"##,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "IWK Bills", &content)).into_response()
}

/// GET /iwk/bills/{id} — the branded, print-style sewerage bill.
async fn bill_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    headers: vortex_plugin_sdk::axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let back_href = vortex_plugin_sdk::framework::list_return_href(&headers, "/iwk");

    // Money + dates formatted in SQL so rendering is pure string interpolation.
    let row = match vortex_plugin_sdk::sqlx::query(
        r#"SELECT b.bill_no, b.account_no, b.category, b.system_type, b.units, b.months,
                  to_char(b.bill_date,'DD/MM/YYYY')  AS bill_date,
                  to_char(b.due_date,'DD/MM/YYYY')   AS due_date,
                  to_char(b.period_start,'FMDD Month YYYY') AS period_start,
                  to_char(b.period_end,'FMDD Month YYYY')   AS period_end,
                  to_char(b.prev_balance,'FM999990.00')   AS prev_balance,
                  to_char(b.payments,'FM999990.00')       AS payments,
                  to_char(b.current_charge,'FM999990.00') AS current_charge,
                  to_char(b.adjustments,'FM999990.00')    AS adjustments,
                  to_char(b.rounding,'FM999990.00')       AS rounding,
                  to_char(b.total,'FM999990.00')          AS total,
                  b.jompay_biller, b.jompay_ref, b.record_state, b.contact_id,
                  c.name AS customer_name, c.street, c.street2, c.city, c.zip
           FROM iwk_bill b JOIN contacts c ON c.id = b.contact_id
           WHERE b.id = $1"#,
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "Bill not found").into_response(),
        Err(e) => {
            error!("iwk bill fetch failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Load failed").into_response();
        }
    };

    let lines = vortex_plugin_sdk::sqlx::query(
        r#"SELECT description, to_char(rate,'FM999990.00') AS rate, months, units,
                  to_char(amount,'FM999990.00') AS amount
           FROM iwk_bill_line WHERE bill_id = $1 ORDER BY sequence"#,
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let g = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };

    // The customer is the core contact — link the bill back to its record.
    let contact_href = row
        .try_get::<Uuid, _>("contact_id")
        .map(|cid| format!("/contacts/{cid}"))
        .unwrap_or_else(|_| "/contacts".to_string());

    let bill_no = g("bill_no");
    let account_no = g("account_no");
    let category = g("category");
    let system_type = g("system_type");
    let units: i32 = row.try_get("units").unwrap_or(1);
    let months: i32 = row.try_get("months").unwrap_or(6);
    let cat_label = if category == "commercial" { "Komersial / Commercial" } else { "Domestik / Domestic" };
    let sys_label = if system_type == "individual" { "Individu / Individual" } else { "Bersambung / Connected" };

    // Address block from the contact.
    let addr = [g("street"), g("street2"), format!("{} {}", g("zip"), g("city")).trim().to_string()]
        .into_iter()
        .filter(|s| !s.trim().is_empty())
        .map(|s| esc(&s))
        .collect::<Vec<_>>()
        .join("<br>");

    // Charge-line rows (the RM x.xx × N Bulan × U Unit breakdown).
    let mut line_rows = String::new();
    for l in &lines {
        let desc: String = l.try_get("description").unwrap_or_default();
        let rate: Option<String> = l.try_get("rate").ok().flatten();
        let lmonths: i32 = l.try_get("months").unwrap_or(0);
        let lunits: i32 = l.try_get("units").unwrap_or(0);
        let amount: Option<String> = l.try_get("amount").ok().flatten();
        let basis = if lmonths > 0 {
            format!("RM {} × {} Bulan × {} Unit", rate.unwrap_or_default(), lmonths, lunits)
        } else {
            String::new()
        };
        line_rows.push_str(&format!(
            r#"<tr><td class="py-1">{desc}<div class="text-xs opacity-60">{basis}</div></td>
<td class="py-1 text-right font-mono">{amount}</td></tr>"#,
            desc = esc(&desc), basis = basis, amount = amount.unwrap_or_default(),
        ));
    }

    // Status badge (issued / paid / cancelled).
    let record_state = g("record_state");
    let bar = match record_state.as_str() {
        "paid" => r#"<span class="badge badge-success">Paid</span>"#,
        "cancelled" => r#"<span class="badge badge-error">Cancelled</span>"#,
        _ => r#"<span class="badge badge-info">Issued</span>"#,
    };

    let money = |k: &str| esc(&g(k));

    let bill = format!(
        r##"<div class="max-w-4xl mx-auto">
<div class="flex items-center justify-between mb-3 no-print">
  <a href="{back}" class="btn btn-ghost btn-sm">← Back to Bills</a>
  <div class="flex items-center gap-2">{bar}
    <a href="{contact_href}" class="btn btn-sm btn-outline">View customer</a>
    <button onclick="window.print()" class="btn btn-sm btn-outline">Print</button></div>
</div>

<div class="bg-white text-slate-800 rounded-lg shadow p-6 md:p-8" id="bill">
  <!-- Header -->
  <div class="flex items-start justify-between border-b-2 border-[#0a7c6a] pb-3">
    <div>
      <div class="text-2xl font-extrabold text-[#0a7c6a] leading-none">Indah<span class="text-[#5bb85b]">Water</span></div>
      <div class="text-[10px] uppercase tracking-wide text-slate-500 mt-1">Syarikat Air Sisa Negara</div>
      <div class="text-xs mt-2 font-semibold">INDAH WATER KONSORTIUM SDN. BHD. (211763-P)</div>
      <div class="text-[11px] text-slate-500">No. 44, Jalan Dungun, Damansara Heights, 50490 Kuala Lumpur</div>
    </div>
    <div class="text-right text-sm">
      <div class="font-bold text-[#0a7c6a]">Bil Perkhidmatan Pembetungan</div>
      <div class="text-xs mt-1">No. Bil: <span class="font-mono">{bill_no}</span></div>
      <div class="text-xs">Tarikh Bil: <span class="font-mono">{bill_date}</span></div>
    </div>
  </div>

  <!-- Customer + account grid -->
  <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 text-sm">
    <div>
      <div class="text-[11px] uppercase text-slate-400">Nama & Alamat</div>
      <a href="{contact_href}" class="font-semibold text-[#0a7c6a] hover:underline no-print-plain">{customer}</a>
      <div class="text-xs text-slate-600">{addr}</div>
    </div>
    <div class="md:text-right space-y-0.5">
      <div><span class="text-slate-400">No. Akaun Pembetungan:</span> <span class="font-mono">{account_no}</span></div>
      <div><span class="text-slate-400">Bil Untuk Tempoh:</span> {period_start} – {period_end}</div>
      <div><span class="text-slate-400">Jenis Sistem:</span> {sys_label}</div>
      <div><span class="text-slate-400">Kategori Pelanggan:</span> {cat_label}</div>
    </div>
  </div>

  <!-- Charge summary -->
  <table class="w-full text-sm mt-6 border-t border-slate-200">
    <thead><tr class="text-[11px] uppercase text-slate-400 text-left">
      <th class="py-2">Butir-butir Bil</th><th class="py-2 text-right">Jumlah (RM)</th>
    </tr></thead>
    <tbody class="align-top">
      <tr><td class="py-1">Baki Terdahulu</td><td class="py-1 text-right font-mono">{prev_balance}</td></tr>
      <tr><td class="py-1">Bayaran Telah Diterima</td><td class="py-1 text-right font-mono">{payments}</td></tr>
      {line_rows}
      <tr><td class="py-1">Pelarasan</td><td class="py-1 text-right font-mono">{adjustments}</td></tr>
      <tr><td class="py-1">Penggenapan</td><td class="py-1 text-right font-mono">{rounding}</td></tr>
    </tbody>
    <tfoot>
      <tr class="border-t-2 border-[#0a7c6a] font-bold">
        <td class="py-2">Jumlah Selepas Penggenapan</td>
        <td class="py-2 text-right font-mono text-[#0a7c6a]">RM {total}</td>
      </tr>
    </tfoot>
  </table>

  <div class="flex items-center justify-between mt-4 text-sm bg-[#f0f9f4] rounded p-3">
    <div>Sila bayar sebelum: <span class="font-bold">{due_date}</span></div>
    <div class="text-right">
      <div class="text-[11px] uppercase text-slate-400">JomPAY online</div>
      <div>Biller Code: <span class="font-mono font-bold">{jompay_biller}</span></div>
      <div>Ref-1: <span class="font-mono">{jompay_ref}</span></div>
    </div>
  </div>

  <div class="text-[10px] text-slate-400 mt-4 border-t border-slate-200 pt-2">
    Caj minima dikira pada kadar {cat_label} ({sys_label}) — {months} bulan × {units} unit.
    Untuk pertanyaan hubungi 03-22847828. Notis PDPA dilampirkan untuk rujukan.
  </div>
</div></div>"##,
        back = esc(&back_href),
        contact_href = esc(&contact_href),
        bar = bar,
        bill_no = esc(&bill_no),
        bill_date = money("bill_date"),
        customer = esc(&g("customer_name")),
        addr = addr,
        account_no = esc(&account_no),
        period_start = money("period_start"),
        period_end = money("period_end"),
        sys_label = sys_label,
        cat_label = cat_label,
        prev_balance = money("prev_balance"),
        payments = money("payments"),
        line_rows = line_rows,
        adjustments = money("adjustments"),
        rounding = money("rounding"),
        total = money("total"),
        due_date = money("due_date"),
        jompay_biller = esc(&g("jompay_biller")),
        jompay_ref = esc(&g("jompay_ref")),
        months = months,
        units = units,
    );

    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, &format!("Bill {bill_no}"), &bill)).into_response()
}

/// Format a `Decimal` as `1,234,567.89` (thousands-grouped, 2dp) for the
/// finance panels. Kept local so the GL page reads like the printed bill.
fn fmt_rm(d: rust_decimal::Decimal) -> String {
    let s = format!("{:.2}", d.round_dp(2));
    let (sign, s) = match s.strip_prefix('-') {
        Some(rest) => ("-", rest.to_string()),
        None => ("", s),
    };
    let (int_part, frac) = s.split_once('.').unwrap_or((s.as_str(), "00"));
    let mut grouped = String::new();
    let bytes = int_part.as_bytes();
    for (i, ch) in bytes.iter().enumerate() {
        if i > 0 && (bytes.len() - i) % 3 == 0 {
            grouped.push(',');
        }
        grouped.push(*ch as char);
    }
    format!("{sign}{grouped}.{frac}")
}

/// GET /iwk/gl — GL posting + subledger↔ledger reconciliation.
/// The reconciliation card is the control: subledger AR must equal the GL
/// Sewerage Receivables balance (variance 0). Below it, each billing run can
/// be posted once as a single summarized journal.
async fn gl_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let sidebar = sidebar_for(&state, &user, &db_ctx);

    let recon = match crate::gl::reconciliation(&db, None).await {
        Ok(r) => r,
        Err(e) => {
            error!("iwk reconciliation failed: {e}");
            let body = format!("<div class=\"alert alert-error\">Reconciliation error: {}</div>", esc(&e));
            return Html(page_shell(&sidebar, "IWK GL", &body)).into_response();
        }
    };

    let reconciled = recon.variance.is_zero();
    let (variance_class, variance_note) = if reconciled {
        ("text-success", "Reconciled — subledger matches the ledger.")
    } else {
        ("text-error", "Out of balance — some billing runs are not yet posted to the GL.")
    };

    // Billing runs with their posted state.
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT br.id, \
                to_char(br.started_at,'DD/MM/YYYY HH24:MI') AS started, \
                br.total_items, \
                gb.move_number, \
                to_char(gb.ar_total,'FM999,999,990.00') AS ar_total, \
                to_char(gb.posted_at,'DD/MM/YYYY') AS posted_at, \
                (gb.run_id IS NOT NULL) AS posted \
         FROM batch_run br LEFT JOIN iwk_gl_batch gb ON gb.run_id = br.id \
         WHERE br.run_kind = 'iwk.billing_run' \
         ORDER BY br.started_at DESC",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut run_rows = String::new();
    for r in &rows {
        let id: Uuid = match r.try_get("id") { Ok(v) => v, Err(_) => continue };
        let started: String = r.try_get("started").ok().flatten().unwrap_or_default();
        let items: i64 = r.try_get("total_items").unwrap_or(0);
        let posted: bool = r.try_get("posted").unwrap_or(false);
        let action = if posted {
            let num: String = r.try_get("move_number").ok().flatten().unwrap_or_default();
            let amt: String = r.try_get("ar_total").ok().flatten().unwrap_or_default();
            let on: String = r.try_get("posted_at").ok().flatten().unwrap_or_default();
            format!(
                "<td><span class=\"badge badge-success\">Posted</span></td>\
                 <td class=\"font-mono\">{num}</td><td class=\"text-right font-mono\">RM {amt}</td><td>{on}</td>",
                num = esc(&num), amt = esc(&amt), on = esc(&on),
            )
        } else {
            format!(
                "<td><span class=\"badge badge-warning\">Not posted</span></td>\
                 <td colspan=\"2\"></td>\
                 <td><form method=\"post\" action=\"/iwk/gl/post/{id}\">\
                 <button class=\"btn btn-primary btn-xs\" type=\"submit\">Post to GL</button></form></td>",
            )
        };
        run_rows.push_str(&format!(
            "<tr><td class=\"font-mono text-xs\">{started}</td><td class=\"text-right\">{items}</td>{action}</tr>",
            started = esc(&started), items = items, action = action,
        ));
    }
    if run_rows.is_empty() {
        run_rows.push_str("<tr><td colspan=\"6\" class=\"text-center opacity-60 py-4\">No billing runs yet.</td></tr>");
    }

    let content = format!(
        r##"<div class="flex items-center justify-between mb-6">
  <h1 class="text-2xl font-bold">General Ledger <span class="text-base-content/40 text-base font-normal">Summarized posting &amp; reconciliation</span></h1>
  <a href="/iwk" class="btn btn-ghost btn-sm">← Bills</a>
</div>

<div class="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
  <div class="card bg-base-100 shadow"><div class="card-body">
    <div class="text-xs uppercase opacity-60">Subledger AR (iwk_bill)</div>
    <div class="text-2xl font-bold font-mono">RM {subledger}</div>
    <div class="text-xs opacity-60">Outstanding on issued bills</div>
  </div></div>
  <div class="card bg-base-100 shadow"><div class="card-body">
    <div class="text-xs uppercase opacity-60">GL control (Sewerage Receivables)</div>
    <div class="text-2xl font-bold font-mono">RM {gl}</div>
    <div class="text-xs opacity-60">Posted journal balance</div>
  </div></div>
  <div class="card bg-base-100 shadow"><div class="card-body">
    <div class="text-xs uppercase opacity-60">Variance</div>
    <div class="text-2xl font-bold font-mono {vclass}">RM {variance}</div>
    <div class="text-xs opacity-60">{vnote}</div>
  </div></div>
</div>

<div class="text-sm mb-2 opacity-70">{posted_runs} of {total_runs} billing runs posted to the GL. Each run posts one balanced journal (Dr Sewerage Receivables / Cr Sewerage Revenue); per-customer detail stays in the bill subledger.</div>

<div class="card bg-base-100 shadow"><div class="card-body overflow-x-auto">
  <table class="table table-sm">
    <thead><tr><th>Run</th><th class="text-right">Bills</th><th>State</th><th>Journal</th><th class="text-right">Amount</th><th>Posted / Action</th></tr></thead>
    <tbody>{run_rows}</tbody>
  </table>
</div></div>"##,
        subledger = fmt_rm(recon.subledger_ar),
        gl = fmt_rm(recon.gl_ar),
        variance = fmt_rm(recon.variance),
        vclass = variance_class,
        vnote = variance_note,
        posted_runs = recon.runs_posted,
        total_runs = recon.runs_total,
        run_rows = run_rows,
    );

    Html(page_shell(&sidebar, "IWK GL", &content)).into_response()
}

/// POST /iwk/gl/post/{run_id} — post one billing run's totals to the GL.
async fn post_run(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Path(run_id): Path<Uuid>,
) -> Response {
    match crate::gl::post_run_to_gl(&db, &state.pool, user.id, None, run_id).await {
        Ok(_) => Redirect::to("/iwk/gl").into_response(),
        Err(e) => {
            error!("iwk GL post failed: {e}");
            (StatusCode::BAD_REQUEST, format!("Post failed: {e}")).into_response()
        }
    }
}

// ─── Customer registration → contract ────────────────────────────────────

#[derive(Deserialize)]
struct RegisterForm {
    name: String,
    #[serde(default)]
    street: String,
    #[serde(default)]
    city: String,
    #[serde(default)]
    phone: String,
    category: String,
    system_type: String,
    #[serde(default)]
    units: String,
    billing_cycle: String,
    #[serde(default)]
    connection_date: String,
    #[serde(default)]
    deposit: String,
}

/// GET /iwk/accounts/new — register a customer and open a contract.
async fn register_form(
    State(state): State<Arc<AppState>>,
    Db(_db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    let today = chrono::Utc::now().date_naive();

    let flash = match q.get("ok") {
        Some(acct) => format!(
            "<div class=\"alert alert-success mb-4\">Customer registered — sewerage account <span class=\"font-mono font-bold\">{}</span> opened. \
             It will be billed on the next generation run.</div>",
            esc(acct)
        ),
        None => String::new(),
    };

    let content = format!(
        r##"<div class="max-w-2xl mx-auto">
<div class="flex items-center justify-between mb-6">
  <h1 class="text-2xl font-bold">Register Customer <span class="text-base-content/40 text-base font-normal">open a sewerage contract</span></h1>
  <a href="/iwk" class="btn btn-ghost btn-sm">← Bills</a>
</div>
{flash}
<form method="post" action="/iwk/accounts/create" class="card bg-base-100 shadow"><div class="card-body space-y-4">
  <div class="text-xs uppercase opacity-60">Customer</div>
  <label class="form-control"><span class="label-text">Name</span>
    <input name="name" required class="input input-bordered" placeholder="Full name / company"></label>
  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
    <label class="form-control"><span class="label-text">Street</span><input name="street" class="input input-bordered"></label>
    <label class="form-control"><span class="label-text">City</span><input name="city" class="input input-bordered"></label>
  </div>
  <label class="form-control"><span class="label-text">Phone</span><input name="phone" class="input input-bordered"></label>

  <div class="divider my-1"></div>
  <div class="text-xs uppercase opacity-60">Contract</div>
  <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
    <label class="form-control"><span class="label-text">Category</span>
      <select name="category" class="select select-bordered"><option value="domestic">Domestic</option><option value="commercial">Commercial</option></select></label>
    <label class="form-control"><span class="label-text">System type</span>
      <select name="system_type" class="select select-bordered"><option value="connected">Connected</option><option value="individual">Individual</option></select></label>
    <label class="form-control"><span class="label-text">Billable units</span>
      <input name="units" type="number" min="1" value="1" class="input input-bordered"></label>
    <label class="form-control"><span class="label-text">Billing cycle</span>
      <select name="billing_cycle" class="select select-bordered"><option value="semi_annual">Semi-annual (6 months)</option><option value="quarterly">Quarterly (3 months)</option><option value="monthly">Monthly</option></select></label>
    <label class="form-control"><span class="label-text">Connection date</span>
      <input name="connection_date" type="date" value="{today}" class="input input-bordered"></label>
    <label class="form-control"><span class="label-text">Deposit (RM)</span>
      <input name="deposit" type="number" step="0.01" min="0" value="0.00" class="input input-bordered"></label>
  </div>
  <div class="text-xs opacity-60">The tariff is applied automatically from the rate card at billing time. First bill is due on the connection date.</div>
  <div class="flex justify-end"><button class="btn btn-primary" type="submit">Register &amp; open account</button></div>
</div></form></div>"##,
        flash = flash,
        today = today,
    );
    Html(page_shell(&sidebar, "Register Customer", &content)).into_response()
}

/// POST /iwk/accounts/create — create the contact + contract.
async fn register_submit(
    Db(db): Db,
    Extension(_user): Extension<AuthUser>,
    Form(form): Form<RegisterForm>,
) -> Response {
    let units: i32 = form.units.trim().parse().unwrap_or(1).max(1);
    let deposit = form.deposit.trim().parse::<rust_decimal::Decimal>().unwrap_or_default();
    let connection_date = chrono::NaiveDate::parse_from_str(form.connection_date.trim(), "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());

    match crate::billing::register_customer(
        &db,
        form.name.trim(),
        form.street.trim(),
        form.city.trim(),
        form.phone.trim(),
        &form.category,
        &form.system_type,
        units,
        &form.billing_cycle,
        connection_date,
        deposit,
    )
    .await
    {
        Ok(r) => Redirect::to(&format!("/iwk/accounts/new?ok={}", r.account_no)).into_response(),
        Err(e) => {
            error!("iwk register failed: {e}");
            (StatusCode::BAD_REQUEST, format!("Registration failed: {e}")).into_response()
        }
    }
}

/// GET /iwk/accounts — the contract register (list of sewerage accounts).
async fn list_accounts(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };

    let config = ListConfig::new("Contracts", "iwk_account")
        .custom_from("iwk_account a JOIN contacts c ON c.id = a.contact_id")
        .custom_select(
            "a.id, a.account_no, c.name AS customer_name, a.category, a.system_type, \
             a.billing_cycle, a.status, to_char(a.next_bill_date, 'DD/MM/YYYY') AS next_bill_date",
        )
        .column(ListColumn::new("account_no", "Account No").sortable().searchable().code().sql_expr("a.account_no"))
        .column(ListColumn::new("customer_name", "Customer").sql_expr("c.name"))
        .column(
            ListColumn::new("category", "Category")
                .filterable(&[("domestic", "Domestic"), ("commercial", "Commercial")])
                .badge(&[("domestic", "Domestic", "badge-info"), ("commercial", "Commercial", "badge-secondary")])
                .sql_expr("a.category"),
        )
        .column(ListColumn::new("system_type", "System").sql_expr("a.system_type"))
        .column(ListColumn::new("billing_cycle", "Cycle").sql_expr("a.billing_cycle"))
        .column(ListColumn::new("next_bill_date", "Next bill").sortable().sql_expr("a.next_bill_date"))
        .column(
            ListColumn::new("status", "Status")
                .filterable(&[("active", "Active"), ("suspended", "Suspended"), ("terminated", "Terminated")])
                .badge(&[
                    ("active", "Active", "badge-success"),
                    ("suspended", "Suspended", "badge-warning"),
                    ("terminated", "Terminated", "badge-error"),
                ])
                .sql_expr("a.status"),
        )
        .detail_url("/iwk/accounts/{id}")
        .default_sort("account_no")
        .count_estimate_from("iwk_account")
        .tiebreak("a.id")
        .search_prefilter("iwk_account a");

    let params = ListParams::from_query(&query);
    let table = match execute_list(&db, &config, &params).await {
        Ok(result) => render_list(&config, &result, &params, "/iwk/accounts"),
        Err(e) => {
            error!("iwk account list failed: {e}");
            format!("<div class=\"alert alert-error\">List error: {e}</div>")
        }
    };

    let content = format!(
        r##"<div class="flex items-center justify-between mb-6">
<h1 class="text-2xl font-bold">Contracts <span class="text-base-content/40 text-base font-normal">Sewerage accounts</span></h1>
<a href="/iwk/accounts/new" class="btn btn-primary btn-sm">+ Register customer</a>
</div>{table}"##,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Contracts", &content)).into_response()
}

/// GET /iwk/accounts/{id} — a contract: terms, customer, and its bills.
async fn account_detail(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    headers: vortex_plugin_sdk::axum::http::HeaderMap,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    let back_href = vortex_plugin_sdk::framework::list_return_href(&headers, "/iwk/accounts");

    let row = match vortex_plugin_sdk::sqlx::query(
        "SELECT a.account_no, a.category, a.system_type, a.units, a.billing_cycle, a.status, \
                to_char(a.deposit,'FM999,990.00') AS deposit, \
                to_char(a.connection_date,'DD/MM/YYYY') AS connection_date, \
                to_char(a.next_bill_date,'DD/MM/YYYY') AS next_bill_date, \
                a.contact_id, c.name AS customer_name, c.street, c.city, c.phone \
         FROM iwk_account a JOIN contacts c ON c.id = a.contact_id WHERE a.id = $1",
    )
    .bind(id)
    .fetch_optional(&db)
    .await
    {
        Ok(Some(r)) => r,
        Ok(None) => return (StatusCode::NOT_FOUND, "Contract not found").into_response(),
        Err(e) => {
            error!("iwk account fetch failed: {e}");
            return (StatusCode::INTERNAL_SERVER_ERROR, "Load failed").into_response();
        }
    };

    let g = |k: &str| -> String { row.try_get::<Option<String>, _>(k).ok().flatten().unwrap_or_default() };
    let account_no = g("account_no");
    let contact_id = row.try_get::<Uuid, _>("contact_id").map(|c| c.to_string()).unwrap_or_default();
    let units: i32 = row.try_get("units").unwrap_or(1);
    let status = g("status");
    let status_badge = match status.as_str() {
        "suspended" => "badge-warning",
        "terminated" => "badge-error",
        _ => "badge-success",
    };

    // Bills on this contract.
    let bills = vortex_plugin_sdk::sqlx::query(
        "SELECT id, bill_no, to_char(bill_date,'DD/MM/YYYY') AS bill_date, \
                to_char(period_start,'DD/MM/YYYY') AS ps, to_char(period_end,'DD/MM/YYYY') AS pe, \
                to_char(total,'FM999,990.00') AS total, record_state \
         FROM iwk_bill WHERE account_id = $1 ORDER BY period_start DESC LIMIT 100",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();

    let mut bill_rows = String::new();
    for b in &bills {
        let bid: Uuid = match b.try_get("id") { Ok(v) => v, Err(_) => continue };
        let no: String = b.try_get("bill_no").ok().flatten().unwrap_or_default();
        let bd: String = b.try_get("bill_date").ok().flatten().unwrap_or_default();
        let ps: String = b.try_get("ps").ok().flatten().unwrap_or_default();
        let pe: String = b.try_get("pe").ok().flatten().unwrap_or_default();
        let total: String = b.try_get("total").ok().flatten().unwrap_or_default();
        let st: String = b.try_get("record_state").unwrap_or_default();
        let st_badge = match st.as_str() { "paid" => "badge-success", "cancelled" => "badge-error", _ => "badge-info" };
        bill_rows.push_str(&format!(
            "<tr class=\"hover cursor-pointer\" onclick=\"location.href='/iwk/bills/{bid}'\">\
             <td class=\"font-mono text-xs\">{no}</td><td>{ps} – {pe}</td><td>{bd}</td>\
             <td class=\"text-right font-mono\">RM {total}</td><td><span class=\"badge {st_badge} badge-sm\">{st}</span></td></tr>",
            bid = bid, no = esc(&no), ps = esc(&ps), pe = esc(&pe), bd = esc(&bd),
            total = esc(&total), st_badge = st_badge, st = esc(&st),
        ));
    }
    if bill_rows.is_empty() {
        bill_rows.push_str("<tr><td colspan=\"5\" class=\"text-center opacity-60 py-4\">No bills yet — will be generated on the next billing run.</td></tr>");
    }

    // Payment history on this contract.
    let payments = vortex_plugin_sdk::sqlx::query(
        "SELECT payment_no, to_char(payment_date,'DD/MM/YYYY') AS pdate, method, reference, \
                to_char(amount,'FM999,990.00') AS amount, to_char(allocated,'FM999,990.00') AS allocated, \
                to_char(credit,'FM999,990.00') AS credit, posted \
         FROM iwk_payment WHERE account_id = $1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(id)
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut pay_rows = String::new();
    for p in &payments {
        let no: String = p.try_get("payment_no").ok().flatten().unwrap_or_default();
        let pdate: String = p.try_get("pdate").ok().flatten().unwrap_or_default();
        let method: String = p.try_get("method").unwrap_or_default();
        let reference: String = p.try_get("reference").ok().flatten().unwrap_or_default();
        let amount: String = p.try_get("amount").ok().flatten().unwrap_or_default();
        let alloc: String = p.try_get("allocated").ok().flatten().unwrap_or_default();
        let credit: String = p.try_get("credit").ok().flatten().unwrap_or_default();
        let posted: bool = p.try_get("posted").unwrap_or(false);
        let badge = if posted { "<span class=\"badge badge-success badge-sm\">Posted</span>" } else { "<span class=\"badge badge-warning badge-sm\">Unposted</span>" };
        pay_rows.push_str(&format!(
            "<tr><td class=\"font-mono text-xs\">{no}</td><td>{pdate}</td><td>{method}</td>\
             <td class=\"font-mono text-xs\">{reference}</td><td class=\"text-right font-mono\">RM {amount}</td>\
             <td class=\"text-right font-mono\">{alloc}</td><td class=\"text-right font-mono\">{credit}</td><td>{badge}</td></tr>",
            no = esc(&no), pdate = esc(&pdate), method = esc(&method), reference = esc(&reference),
            amount = esc(&amount), alloc = esc(&alloc), credit = esc(&credit), badge = badge,
        ));
    }
    if pay_rows.is_empty() {
        pay_rows.push_str("<tr><td colspan=\"8\" class=\"text-center opacity-60 py-4\">No payments recorded.</td></tr>");
    }

    let addr = [g("street"), g("city")].into_iter().filter(|s| !s.trim().is_empty()).map(|s| esc(&s)).collect::<Vec<_>>().join(", ");

    let content = format!(
        r##"<div class="max-w-4xl mx-auto">
<div class="flex items-center justify-between mb-4">
  <a href="{back}" class="btn btn-ghost btn-sm">← Contracts</a>
  <span class="badge {status_badge}">{status}</span>
</div>

<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <div class="flex items-start justify-between">
    <div>
      <h1 class="text-2xl font-bold font-mono">{account_no}</h1>
      <div class="mt-1"><a href="/contacts/{contact_id}" class="link link-primary font-semibold">{customer}</a></div>
      <div class="text-sm opacity-60">{addr} {phone}</div>
    </div>
    <a href="/iwk/billing" class="btn btn-sm btn-outline">Generate bills</a>
  </div>
  <div class="divider my-2"></div>
  <div class="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
    <div><div class="opacity-60 text-xs uppercase">Category</div>{category}</div>
    <div><div class="opacity-60 text-xs uppercase">System</div>{system_type}</div>
    <div><div class="opacity-60 text-xs uppercase">Units</div>{units}</div>
    <div><div class="opacity-60 text-xs uppercase">Billing cycle</div>{cycle}</div>
    <div><div class="opacity-60 text-xs uppercase">Connected</div>{connected}</div>
    <div><div class="opacity-60 text-xs uppercase">Next bill</div>{next_bill}</div>
    <div><div class="opacity-60 text-xs uppercase">Deposit</div>RM {deposit}</div>
  </div>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body overflow-x-auto">
  <h2 class="font-semibold mb-2">Bills</h2>
  <table class="table table-sm">
    <thead><tr><th>Bill No</th><th>Period</th><th>Date</th><th class="text-right">Total</th><th>Status</th></tr></thead>
    <tbody>{bill_rows}</tbody>
  </table>
</div></div>

<div class="card bg-base-100 shadow mt-6"><div class="card-body overflow-x-auto">
  <div class="flex items-center justify-between mb-2">
    <h2 class="font-semibold">Payments</h2>
    <a href="/iwk/payments" class="btn btn-xs btn-outline">Register payment</a>
  </div>
  <table class="table table-sm">
    <thead><tr><th>Payment</th><th>Date</th><th>Method</th><th>Ref</th><th class="text-right">Amount</th><th class="text-right">Allocated</th><th class="text-right">Credit</th><th>GL</th></tr></thead>
    <tbody>{pay_rows}</tbody>
  </table>
</div></div></div>"##,
        back = esc(&back_href),
        pay_rows = pay_rows,
        status_badge = status_badge,
        status = esc(&status),
        account_no = esc(&account_no),
        contact_id = esc(&contact_id),
        customer = esc(&g("customer_name")),
        addr = addr,
        phone = esc(&g("phone")),
        category = esc(&g("category")),
        system_type = esc(&g("system_type")),
        units = units,
        cycle = esc(&g("billing_cycle")),
        connected = esc(&g("connection_date")),
        next_bill = esc(&g("next_bill_date")),
        deposit = esc(&g("deposit")),
        bill_rows = bill_rows,
    );
    Html(page_shell(&sidebar, &format!("Contract {account_no}"), &content)).into_response()
}

// ─── Recurring bill generation ───────────────────────────────────────────

#[derive(Deserialize)]
struct GenerateForm {
    #[serde(default)]
    period_end: String,
}

/// GET /iwk/billing — run the recurring generator for a period.
async fn billing_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    let today = chrono::Utc::now().date_naive();

    let due = crate::billing::due_count(&db, today).await.unwrap_or(0);

    let flash = match q.get("generated") {
        Some(n) => format!(
            "<div class=\"alert alert-success mb-4\">Generated <span class=\"font-bold\">{}</span> bill(s). \
             <a href=\"/iwk/gl\" class=\"link\">Post to the GL →</a></div>",
            esc(n)
        ),
        None => String::new(),
    };

    // Recent recurring runs (source = recurring; the bulk seed run has none).
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT to_char(started_at,'DD/MM/YYYY HH24:MI') AS started, total_items, status, \
                COALESCE(params->>'period_end','') AS period_end \
         FROM batch_run WHERE run_kind = 'iwk.billing_run' ORDER BY started_at DESC LIMIT 10",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut run_rows = String::new();
    for r in &rows {
        let started: String = r.try_get("started").ok().flatten().unwrap_or_default();
        let items: i64 = r.try_get("total_items").unwrap_or(0);
        let status: String = r.try_get("status").unwrap_or_default();
        let period: String = r.try_get("period_end").unwrap_or_default();
        run_rows.push_str(&format!(
            "<tr><td class=\"font-mono text-xs\">{}</td><td>{}</td><td class=\"text-right\">{}</td><td><span class=\"badge badge-ghost\">{}</span></td></tr>",
            esc(&started), esc(&period), items, esc(&status),
        ));
    }
    if run_rows.is_empty() {
        run_rows.push_str("<tr><td colspan=\"4\" class=\"text-center opacity-60 py-4\">No runs yet.</td></tr>");
    }

    let content = format!(
        r##"<div class="max-w-3xl mx-auto">
<div class="flex items-center justify-between mb-6">
  <h1 class="text-2xl font-bold">Generate Bills <span class="text-base-content/40 text-base font-normal">recurring billing run</span></h1>
  <a href="/iwk" class="btn btn-ghost btn-sm">← Bills</a>
</div>
{flash}
<div class="card bg-base-100 shadow mb-6"><div class="card-body">
  <div class="text-sm opacity-70">Bills are generated from <b>active contracts</b> whose cycle is due on or before the period-end date — one bill each, priced from the current tariff. Safe to re-run: a contract-period is never billed twice.</div>
  <div class="stats bg-base-200 my-2"><div class="stat"><div class="stat-title">Contracts due as of today</div><div class="stat-value text-primary">{due}</div></div></div>
  <form method="post" action="/iwk/billing/generate" class="flex items-end gap-3">
    <label class="form-control"><span class="label-text">Bill everything due on/before</span>
      <input name="period_end" type="date" value="{today}" class="input input-bordered"></label>
    <button class="btn btn-primary" type="submit">Generate bills</button>
  </form>
</div></div>

<div class="card bg-base-100 shadow"><div class="card-body overflow-x-auto">
  <h2 class="font-semibold mb-2">Recent runs</h2>
  <table class="table table-sm"><thead><tr><th>Started</th><th>Period end</th><th class="text-right">Bills</th><th>Status</th></tr></thead>
  <tbody>{run_rows}</tbody></table>
</div></div></div>"##,
        flash = flash,
        due = due,
        today = today,
        run_rows = run_rows,
    );
    Html(page_shell(&sidebar, "Generate Bills", &content)).into_response()
}

/// POST /iwk/billing/generate — run the generator for the chosen period.
async fn generate_submit(Db(db): Db, Extension(_user): Extension<AuthUser>, Form(form): Form<GenerateForm>) -> Response {
    let period_end = chrono::NaiveDate::parse_from_str(form.period_end.trim(), "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    match crate::billing::generate_bills_for_period(&db, period_end).await {
        Ok(s) => Redirect::to(&format!("/iwk/billing?generated={}", s.bill_count)).into_response(),
        Err(e) => {
            error!("iwk generate failed: {e}");
            (StatusCode::BAD_REQUEST, format!("Generation failed: {e}")).into_response()
        }
    }
}

// ─── Payments (capture → allocate → summarized GL) ───────────────────────

#[derive(Deserialize)]
struct PaymentForm {
    account_no: String,
    amount: String,
    #[serde(default)]
    payment_date: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    reference: String,
}

#[derive(Deserialize)]
struct ImportForm {
    #[serde(default)]
    body: String,
    #[serde(default)]
    payment_date: String,
    #[serde(default)]
    method: String,
}

/// GET /iwk/payments — register/import payments, post collections to the GL.
async fn payments_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(q): Query<std::collections::HashMap<String, String>>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    let today = chrono::Utc::now().date_naive();

    let recon = crate::gl::reconciliation(&db, None).await.ok();
    let (unposted, advances) = recon
        .as_ref()
        .map(|r| (r.unposted_payments, fmt_rm(r.advances)))
        .unwrap_or((0, "0.00".into()));

    let mut flash = String::new();
    if let Some(no) = q.get("ok") {
        let credit = q.get("credit").map(|s| s.as_str()).unwrap_or("0");
        flash = format!(
            "<div class=\"alert alert-success mb-4\">Payment <span class=\"font-mono font-bold\">{}</span> recorded.{}</div>",
            esc(no),
            if credit != "0" && !credit.is_empty() { format!(" RM {} went to account credit.", esc(credit)) } else { String::new() },
        );
    } else if let Some(n) = q.get("imported") {
        let errs = q.get("errors").map(|s| s.as_str()).unwrap_or("0");
        flash = format!(
            "<div class=\"alert alert-info mb-4\">Imported <b>{}</b> payment(s), <b>{}</b> error(s).</div>",
            esc(n), esc(errs),
        );
    } else if let Some(mv) = q.get("posted") {
        flash = format!(
            "<div class=\"alert alert-success mb-4\">Collections posted to the GL as <span class=\"font-mono\">{}</span> (Dr Bank / Cr Receivables).</div>",
            esc(mv),
        );
    }

    // Recent payments.
    let rows = vortex_plugin_sdk::sqlx::query(
        "SELECT p.payment_no, a.account_no, c.name AS customer, \
                to_char(p.amount,'FM999,990.00') AS amount, to_char(p.allocated,'FM999,990.00') AS allocated, \
                to_char(p.credit,'FM999,990.00') AS credit, p.method, \
                to_char(p.payment_date,'DD/MM/YYYY') AS pdate, p.posted \
         FROM iwk_payment p JOIN iwk_account a ON a.id = p.account_id JOIN contacts c ON c.id = p.contact_id \
         ORDER BY p.created_at DESC LIMIT 20",
    )
    .fetch_all(&db)
    .await
    .unwrap_or_default();
    let mut pay_rows = String::new();
    for r in &rows {
        let no: String = r.try_get("payment_no").ok().flatten().unwrap_or_default();
        let acct: String = r.try_get("account_no").unwrap_or_default();
        let cust: String = r.try_get("customer").ok().flatten().unwrap_or_default();
        let amt: String = r.try_get("amount").ok().flatten().unwrap_or_default();
        let alloc: String = r.try_get("allocated").ok().flatten().unwrap_or_default();
        let cr: String = r.try_get("credit").ok().flatten().unwrap_or_default();
        let method: String = r.try_get("method").unwrap_or_default();
        let pdate: String = r.try_get("pdate").ok().flatten().unwrap_or_default();
        let posted: bool = r.try_get("posted").unwrap_or(false);
        let badge = if posted { "<span class=\"badge badge-success badge-sm\">Posted</span>" } else { "<span class=\"badge badge-warning badge-sm\">Unposted</span>" };
        pay_rows.push_str(&format!(
            "<tr><td class=\"font-mono text-xs\">{no}</td><td class=\"font-mono text-xs\">{acct}</td><td>{cust}</td>\
             <td class=\"text-right font-mono\">{amt}</td><td class=\"text-right font-mono\">{alloc}</td>\
             <td class=\"text-right font-mono\">{cr}</td><td>{method}</td><td>{pdate}</td><td>{badge}</td></tr>",
            no = esc(&no), acct = esc(&acct), cust = esc(&cust), amt = esc(&amt),
            alloc = esc(&alloc), cr = esc(&cr), method = esc(&method), pdate = esc(&pdate), badge = badge,
        ));
    }
    if pay_rows.is_empty() {
        pay_rows.push_str("<tr><td colspan=\"9\" class=\"text-center opacity-60 py-4\">No payments yet.</td></tr>");
    }

    let post_btn = if unposted > 0 {
        format!(
            "<form method=\"post\" action=\"/iwk/payments/post\"><button class=\"btn btn-primary btn-sm\" type=\"submit\">Post {} collection(s) to GL</button></form>",
            unposted
        )
    } else {
        "<span class=\"text-sm opacity-60\">No unposted collections.</span>".to_string()
    };

    let content = format!(
        r##"<div class="max-w-5xl mx-auto">
<div class="flex items-center justify-between mb-6">
  <h1 class="text-2xl font-bold">Payments <span class="text-base-content/40 text-base font-normal">collections &amp; allocation</span></h1>
  <a href="/iwk/gl" class="btn btn-ghost btn-sm">GL →</a>
</div>
{flash}
<div class="flex items-center justify-between bg-base-100 rounded p-3 shadow mb-6">
  <div class="flex gap-6 text-sm">
    <div><span class="opacity-60">Unposted collections:</span> <b>{unposted}</b></div>
    <div><span class="opacity-60">Customer advances:</span> <b>RM {advances}</b></div>
  </div>
  {post_btn}
</div>

<div class="grid grid-cols-1 md:grid-cols-2 gap-6 mb-6">
  <div class="card bg-base-100 shadow"><div class="card-body">
    <h2 class="font-semibold">Register a payment</h2>
    <form method="post" action="/iwk/payments/register" class="space-y-3">
      <label class="form-control"><span class="label-text">Account no</span><input name="account_no" required class="input input-bordered" placeholder="PB0000400001"></label>
      <div class="grid grid-cols-2 gap-3">
        <label class="form-control"><span class="label-text">Amount (RM)</span><input name="amount" type="number" step="0.01" min="0" required class="input input-bordered"></label>
        <label class="form-control"><span class="label-text">Date</span><input name="payment_date" type="date" value="{today}" class="input input-bordered"></label>
      </div>
      <div class="grid grid-cols-2 gap-3">
        <label class="form-control"><span class="label-text">Method</span><select name="method" class="select select-bordered"><option value="counter">Counter</option><option value="jompay">JomPAY</option><option value="bank">Bank</option><option value="cash">Cash</option></select></label>
        <label class="form-control"><span class="label-text">Reference</span><input name="reference" class="input input-bordered"></label>
      </div>
      <button class="btn btn-primary" type="submit">Register payment</button>
    </form>
  </div></div>

  <div class="card bg-base-100 shadow"><div class="card-body">
    <h2 class="font-semibold">Bulk import (collection file)</h2>
    <form method="post" action="/iwk/payments/import" class="space-y-3">
      <label class="form-control"><span class="label-text">One per line: <span class="font-mono">account_no,amount,reference</span></span>
        <textarea name="body" rows="6" class="textarea textarea-bordered font-mono text-xs" placeholder="PB0000400001,252.00,JMP-9931&#10;PB0000400002,60.00,JMP-9932"></textarea></label>
      <div class="grid grid-cols-2 gap-3">
        <label class="form-control"><span class="label-text">Date</span><input name="payment_date" type="date" value="{today}" class="input input-bordered"></label>
        <label class="form-control"><span class="label-text">Method</span><select name="method" class="select select-bordered"><option value="jompay">JomPAY</option><option value="bank">Bank</option><option value="import">Import</option></select></label>
      </div>
      <button class="btn btn-outline" type="submit">Import batch</button>
    </form>
  </div></div>
</div>

<div class="card bg-base-100 shadow"><div class="card-body overflow-x-auto">
  <div class="flex items-center justify-between mb-2"><h2 class="font-semibold">Recent payments</h2><a href="/iwk/payments/history" class="btn btn-xs btn-outline">View all history →</a></div>
  <table class="table table-sm">
    <thead><tr><th>Payment</th><th>Account</th><th>Customer</th><th class="text-right">Amount</th><th class="text-right">Allocated</th><th class="text-right">Credit</th><th>Method</th><th>Date</th><th>GL</th></tr></thead>
    <tbody>{pay_rows}</tbody>
  </table>
</div></div></div>"##,
        flash = flash,
        unposted = unposted,
        advances = advances,
        post_btn = post_btn,
        today = today,
        pay_rows = pay_rows,
    );
    Html(page_shell(&sidebar, "Payments", &content)).into_response()
}

/// POST /iwk/payments/register — capture one payment.
async fn payment_register(Db(db): Db, Extension(_user): Extension<AuthUser>, Form(form): Form<PaymentForm>) -> Response {
    let account_id: Option<Uuid> =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT id FROM iwk_account WHERE account_no = $1")
            .bind(form.account_no.trim())
            .fetch_optional(&db)
            .await
            .ok()
            .flatten();
    let Some(account_id) = account_id else {
        return (StatusCode::BAD_REQUEST, format!("Unknown account '{}'", form.account_no)).into_response();
    };
    let amount = match form.amount.trim().parse::<rust_decimal::Decimal>() {
        Ok(a) => a,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid amount").into_response(),
    };
    let date = chrono::NaiveDate::parse_from_str(form.payment_date.trim(), "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    let method = if form.method.trim().is_empty() { "counter" } else { form.method.trim() };

    match crate::payment::register_payment(&db, account_id, amount, date, method, form.reference.trim(), None).await {
        Ok(r) => Redirect::to(&format!("/iwk/payments?ok={}&credit={}", r.payment_no, r.credit)).into_response(),
        Err(e) => {
            error!("iwk payment register failed: {e}");
            (StatusCode::BAD_REQUEST, format!("Payment failed: {e}")).into_response()
        }
    }
}

/// POST /iwk/payments/import — bulk import a collection file.
async fn payment_import(Db(db): Db, Extension(_user): Extension<AuthUser>, Form(form): Form<ImportForm>) -> Response {
    let date = chrono::NaiveDate::parse_from_str(form.payment_date.trim(), "%Y-%m-%d")
        .unwrap_or_else(|_| chrono::Utc::now().date_naive());
    let method = if form.method.trim().is_empty() { "import" } else { form.method.trim() };
    match crate::payment::import_payments(&db, &form.body, date, method).await {
        Ok(s) => Redirect::to(&format!("/iwk/payments?imported={}&errors={}", s.count, s.errors.len())).into_response(),
        Err(e) => {
            error!("iwk payment import failed: {e}");
            (StatusCode::BAD_REQUEST, format!("Import failed: {e}")).into_response()
        }
    }
}

/// POST /iwk/payments/post — post all unposted collections to the GL.
async fn payment_post(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
) -> Response {
    match crate::payment::post_payments_to_gl(&db, &state.pool, user.id, None).await {
        Ok(s) => Redirect::to(&format!("/iwk/payments?posted={}", s.move_number)).into_response(),
        Err(e) => {
            error!("iwk payment post failed: {e}");
            (StatusCode::BAD_REQUEST, format!("Post failed: {e}")).into_response()
        }
    }
}

/// GET /iwk/payments/history — full, searchable payment history.
async fn payments_history(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Query(query): Query<std::collections::HashMap<String, String>>,
) -> Response {
    use vortex_plugin_sdk::framework::list::{
        execute_list, render_list, ListColumn, ListConfig, ListParams,
    };

    let config = ListConfig::new("Payment History", "iwk_payment")
        .custom_from("iwk_payment p JOIN iwk_account a ON a.id = p.account_id JOIN contacts c ON c.id = p.contact_id")
        .custom_select(
            "p.id, p.payment_no, a.account_no, c.name AS customer, \
             to_char(p.amount,'FM999,990.00') AS amount, to_char(p.allocated,'FM999,990.00') AS allocated, \
             to_char(p.credit,'FM999,990.00') AS credit, p.method, \
             to_char(p.payment_date,'DD/MM/YYYY') AS payment_date, \
             CASE WHEN p.posted THEN 'posted' ELSE 'unposted' END AS posted",
        )
        .column(ListColumn::new("payment_no", "Payment No").sortable().searchable().code().sql_expr("p.payment_no"))
        .column(ListColumn::new("account_no", "Account").code().sql_expr("a.account_no"))
        .column(ListColumn::new("customer", "Customer").sql_expr("c.name"))
        .column(ListColumn::new("amount", "Amount (RM)").sql_expr("p.amount"))
        .column(ListColumn::new("allocated", "Allocated").sql_expr("p.allocated"))
        .column(ListColumn::new("credit", "Credit").sql_expr("p.credit"))
        .column(
            ListColumn::new("method", "Method")
                .filterable(&[
                    ("jompay", "JomPAY"), ("counter", "Counter"), ("bank", "Bank"),
                    ("cash", "Cash"), ("import", "Import"),
                ])
                .sql_expr("p.method"),
        )
        .column(ListColumn::new("payment_date", "Date").sortable().sql_expr("p.payment_date"))
        .column(
            ListColumn::new("posted", "GL")
                .filterable(&[("posted", "Posted"), ("unposted", "Unposted")])
                .badge(&[("posted", "Posted", "badge-success"), ("unposted", "Unposted", "badge-warning")])
                .sql_expr("(CASE WHEN p.posted THEN 'posted' ELSE 'unposted' END)"),
        )
        .default_sort("payment_no")
        .count_estimate_from("iwk_payment")
        .tiebreak("p.id")
        .search_prefilter("iwk_payment p");

    let params = ListParams::from_query(&query);
    let table = match execute_list(&db, &config, &params).await {
        Ok(result) => render_list(&config, &result, &params, "/iwk/payments/history"),
        Err(e) => {
            error!("iwk payment history failed: {e}");
            format!("<div class=\"alert alert-error\">List error: {e}</div>")
        }
    };
    let content = format!(
        r##"<div class="flex items-center justify-between mb-6">
<h1 class="text-2xl font-bold">Payment History <span class="text-base-content/40 text-base font-normal">all collections</span></h1>
<a href="/iwk/payments" class="btn btn-primary btn-sm">Register / import</a>
</div>{table}"##,
    );
    let sidebar = sidebar_for(&state, &user, &db_ctx);
    Html(page_shell(&sidebar, "Payment History", &content)).into_response()
}

/// GET /iwk/customers/{id} — the customer ledger: every account and every
/// transaction (bills debit, payments credit) with a running balance.
async fn customer_ledger_page(
    State(state): State<Arc<AppState>>,
    Db(db): Db,
    Extension(user): Extension<AuthUser>,
    Extension(db_ctx): Extension<DatabaseContext>,
    Path(id): Path<Uuid>,
) -> Response {
    let esc = vortex_plugin_sdk::framework::ui::html_escape;
    let sidebar = sidebar_for(&state, &user, &db_ctx);

    let name: String =
        vortex_plugin_sdk::sqlx::query_scalar("SELECT name FROM contacts WHERE id = $1")
            .bind(id)
            .fetch_optional(&db)
            .await
            .ok()
            .flatten()
            .unwrap_or_default();
    if name.is_empty() {
        return (StatusCode::NOT_FOUND, "Customer not found").into_response();
    }

    let entries = crate::ledger::customer_ledger(&db, id).await.unwrap_or_default();
    let mut rows = String::new();
    for e in &entries {
        let (dr, cr) = (
            if e.debit.is_zero() { String::new() } else { format!("RM {}", fmt_rm(e.debit)) },
            if e.credit.is_zero() { String::new() } else { format!("RM {}", fmt_rm(e.credit)) },
        );
        let label = if e.kind == "bill" { format!("Bill {}", e.reference) } else { format!("Payment {}", e.reference) };
        let bal_cls = if e.balance.is_sign_negative() { "text-success" } else { "" };
        rows.push_str(&format!(
            "<tr><td>{date}</td><td>{label}</td><td class=\"font-mono text-xs\">{acct}</td>\
             <td class=\"text-right font-mono\">{dr}</td><td class=\"text-right font-mono\">{cr}</td>\
             <td class=\"text-right font-mono {bal_cls}\">RM {bal}</td></tr>",
            date = esc(&e.date), label = esc(&label), acct = esc(&e.account_no),
            dr = esc(&dr), cr = esc(&cr), bal_cls = bal_cls, bal = fmt_rm(e.balance),
        ));
    }
    if rows.is_empty() {
        rows.push_str("<tr><td colspan=\"6\" class=\"text-center opacity-60 py-4\">No transactions.</td></tr>");
    }
    let closing = entries.last().map(|e| e.balance).unwrap_or_default();

    let content = format!(
        r##"<div class="max-w-4xl mx-auto">
<div class="flex items-center justify-between mb-4 no-print">
  <a href="/contacts/{id}" class="btn btn-ghost btn-sm">← Customer</a>
  <button onclick="window.print()" class="btn btn-sm btn-outline">Print</button>
</div>
<div class="card bg-base-100 shadow"><div class="card-body">
  <div class="flex items-start justify-between">
    <div><h1 class="text-2xl font-bold">{name}</h1><div class="text-sm opacity-60">Sewerage account statement</div></div>
    <div class="text-right"><div class="text-xs uppercase opacity-60">Balance due</div><div class="text-2xl font-bold font-mono">RM {closing}</div></div>
  </div>
  <div class="divider my-2"></div>
  <table class="table table-sm">
    <thead><tr><th>Date</th><th>Transaction</th><th>Account</th><th class="text-right">Debit</th><th class="text-right">Credit</th><th class="text-right">Balance</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>
  <div class="text-xs opacity-60 mt-2">Debit = billed · Credit = paid · a negative balance is customer credit in advance.</div>
</div></div></div>"##,
        id = esc(&id.to_string()),
        name = esc(&name),
        closing = fmt_rm(closing),
        rows = rows,
    );
    Html(page_shell(&sidebar, &format!("Ledger — {name}"), &content)).into_response()
}
