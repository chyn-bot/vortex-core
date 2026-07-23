//! Demo: render the built-in "invoice" starter template with sample rows.
//! Writes `invoice.html`, and `invoice.pdf` when built with `--features
//! pdf-chromium` (needs a Chromium binary; honours `$VORTEX_CHROMIUM`).
//!
//!   cargo run -p vortex-framework --example report_demo -- /path/out
//!   cargo run -p vortex-framework --features pdf-chromium --example report_demo -- /path/out

use std::collections::BTreeMap;
use vortex_framework::banded_report as br;

fn row(name: &str, qty: &str, price: &str, amount: &str, partner: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("name".into(), name.into());
    m.insert("quantity".into(), qty.into());
    m.insert("price".into(), price.into());
    m.insert("amount".into(), amount.into());
    m.insert("partner".into(), partner.into());
    m.insert("date".into(), "2026-07-19".into());
    m
}

#[tokio::main]
async fn main() {
    let out_dir = std::env::args().nth(1).unwrap_or_else(|| ".".into());
    let doc = br::sample_layout("invoice", "INVOICE  INV-2026-0042").expect("invoice sample");
    let layout: br::ReportLayout = serde_json::from_value(doc).expect("parse layout");

    let rows = vec![
        row("Enterprise licence — annual", "1", "48000.00", "48000.00", "Tenaga Nasional Berhad"),
        row("Implementation services", "120", "350.00", "42000.00", "Tenaga Nasional Berhad"),
        row("Premium support (12 mo)", "1", "12000.00", "12000.00", "Tenaga Nasional Berhad"),
        row("On-site training", "3", "2500.00", "7500.00", "Tenaga Nasional Berhad"),
    ];

    let params = BTreeMap::new();
    let html = br::render_layout_html(&layout, &rows, &params);
    let html_path = format!("{out_dir}/invoice.html");
    std::fs::write(&html_path, &html).expect("write html");
    eprintln!("wrote {html_path}");

    // PDF: exact page geometry from the layout → Chromium prints 1:1.
    if vortex_framework::pdf::available() {
        let opts = br::pdf_options_for(&layout);
        match vortex_framework::pdf::html_to_pdf(&html, &opts).await {
            Ok(bytes) => {
                let pdf_path = format!("{out_dir}/invoice.pdf");
                std::fs::write(&pdf_path, &bytes).expect("write pdf");
                eprintln!("wrote {pdf_path} ({} bytes)", bytes.len());
            }
            Err(e) => eprintln!("PDF render failed: {e}"),
        }
    } else {
        eprintln!("PDF backend not compiled in (rebuild with --features pdf-chromium)");
    }
}
