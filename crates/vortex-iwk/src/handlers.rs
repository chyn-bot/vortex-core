//! IWK HTTP handlers — a fast bill list (list framework + scalability
//! knobs) and a branded, print-style sewerage bill page that mirrors the
//! real "Bil Perkhidmatan Pembetungan". Bills are generated in bulk (see
//! the billing-run seeder), so there is no hand-create form here.

use std::sync::Arc;

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
}

/// Platform HTML shell: sidebar, vendored assets, mobile layout.
/// (Uses the static `tailwind.css` — the runtime Play-CDN was retired.)
fn page_shell(sidebar: &str, title: &str, content: &str) -> String {
    format!(
        r##"<!DOCTYPE html><html data-theme="dark"><head>
<script>(function(){{var t=localStorage.getItem('theme');if(t)document.documentElement.setAttribute('data-theme',t)}})()</script>
<title>{title} - Vortex</title>
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<link href="/static/vendor/daisyui.min.css" rel="stylesheet"/>
<link href="/static/vortex.css?v=21" rel="stylesheet"/>
<script src="/static/vortex.js?v=21" defer></script>
<link href="/static/tailwind.css?v=21" rel="stylesheet"/>
</head>
<body class="min-h-screen bg-base-200"><div class="flex">{sidebar}
<main class="flex-1 p-4 lg:p-6 min-w-0">{content}</main>
</div></body></html>"##,
        title = title, sidebar = sidebar, content = content,
    )
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
