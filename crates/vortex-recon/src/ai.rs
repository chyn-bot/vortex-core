//! AI OCR extraction — a pluggable document-source adapter.
//!
//! Two request *shapes* cover the field: Anthropic's Messages API (Claude —
//! native PDF + image) and the OpenAI-style chat-completions API (OpenAI,
//! DeepSeek, and any OpenAI-compatible endpoint via a custom base URL). The
//! tenant configures provider + model + key in `/recon/ai`; this module turns a
//! scanned invoice into a normalized [`Extracted`] the review grid can load.
//!
//! The model is asked for STRICT JSON only; we defensively slice the first
//! `{`..`}` in case it wraps the object in prose or code fences.

use base64::Engine as _;
use serde::Deserialize;

/// Decrypted, in-memory provider config. The API key lives here only for the
/// duration of a call — at rest it is AES-256-GCM encrypted (VORTEX_SECRET_KEY).
pub struct AiConfig {
    pub provider: String, // anthropic | openai | deepseek | custom
    pub model: String,
    pub base_url: String, // already resolved (preset default or tenant override)
    pub api_key: String,
    /// Opt-in: for image scans, also ask the vision model for each line's
    /// vertical position on the page (extra tokens = extra cost), so the
    /// "click a line → highlight on the document" feature works on images too.
    /// Ignored for PDFs (they carry a text layer we locate from directly).
    pub image_locate: bool,
}

/// Request family a provider belongs to.
enum Shape {
    Anthropic,
    OpenAi,
}

impl AiConfig {
    fn shape(&self) -> Shape {
        match self.provider.as_str() {
            "anthropic" => Shape::Anthropic,
            _ => Shape::OpenAi, // openai | deepseek | custom
        }
    }
}

/// One extracted invoice line. All fields optional — the reviewer fixes gaps.
#[derive(Debug, Default, Deserialize)]
pub struct ExtractedLine {
    #[serde(default)]
    pub line_no: Option<i64>,
    #[serde(default)]
    pub supplier_sku: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub uom: Option<String>,
    #[serde(default)]
    pub qty: Option<f64>,
    /// Printed unit price, BEFORE discount and BEFORE tax.
    #[serde(default)]
    pub unit_price: Option<f64>,
    /// Line discount percentage (e.g. 5 = 5% off); 0 if none.
    #[serde(default)]
    pub discount_pct: Option<f64>,
    /// Line discount as a money amount, when the invoice prints it that way; 0 if none.
    #[serde(default)]
    pub discount_amt: Option<f64>,
    /// Per-line tax amount — only when SST is printed per line; else 0.
    #[serde(default)]
    pub tax: Option<f64>,
    /// Normalized vertical position of this line on the page (top edge, 0..1 of
    /// page height). Only requested/populated when `image_locate` is on and the
    /// scan is an image; `None` otherwise.
    #[serde(default, rename = "y")]
    pub doc_y: Option<f64>,
    /// Normalized height of this line's band (0..1 of page height). Pairs with
    /// `doc_y`. `None` when not requested.
    #[serde(default, rename = "h")]
    pub doc_h: Option<f64>,
}

/// The header + lines extracted from one invoice document.
#[derive(Debug, Default, Deserialize)]
pub struct Extracted {
    #[serde(default)]
    pub supplier_no: Option<String>,
    #[serde(default)]
    pub supplier_name: Option<String>,
    #[serde(default)]
    pub invoice_no: Option<String>,
    #[serde(default)]
    pub invoice_date: Option<String>,
    #[serde(default)]
    pub currency: Option<String>,
    /// Printed subtotal EXCLUDING tax ("TOTAL EXCL SST").
    #[serde(default)]
    pub subtotal: Option<f64>,
    /// Printed invoice-level tax total ("SST") when tax is not shown per line.
    #[serde(default)]
    pub tax_total: Option<f64>,
    /// Printed grand total INCLUDING tax ("TOTAL INCL SST").
    #[serde(default)]
    pub doc_total: Option<f64>,
    #[serde(default)]
    pub lines: Vec<ExtractedLine>,
}

/// Token counts reported by the provider for one extraction call. Costs are
/// derived from these downstream against the editable per-model pricing table.
#[derive(Debug, Default, Clone, Copy)]
pub struct Usage {
    pub input_tokens: u64,
    pub output_tokens: u64,
}

const PROMPT: &str = "\
You are an OCR data-extraction engine for supplier invoices. Read the attached \
invoice and return ONLY a single JSON object — no prose, no markdown fences — \
matching exactly this shape:
{\"supplier_name\":string|null,\"supplier_no\":string|null,\"invoice_no\":string|null,\
\"invoice_date\":\"YYYY-MM-DD\"|null,\"currency\":string|null,\"subtotal\":number|null,\
\"tax_total\":number|null,\"doc_total\":number|null,\
\"lines\":[{\"line_no\":integer,\"supplier_sku\":string|null,\"description\":string|null,\
\"uom\":string|null,\"qty\":number,\"unit_price\":number,\"discount_pct\":number,\
\"discount_amt\":number,\"tax\":number}]}
Rules:
- unit_price is the printed per-unit price, BEFORE any discount and BEFORE tax.
- discount_pct is the line discount when shown as a PERCENTAGE (e.g. a 'DISC %' column). 0 if none.
- discount_amt is the line discount when shown as a MONEY AMOUNT (e.g. a 'Discount' column \
in currency). 0 if none. Use whichever the invoice prints; do not put a percentage in \
discount_amt or an amount in discount_pct.
- tax is the LINE tax amount ONLY when the invoice prints SST/tax per line; if SST \
is shown only as a single footer figure, set every line's tax to 0 and instead put \
that figure in tax_total.
- subtotal is the printed total EXCLUDING tax (e.g. 'TOTAL EXCL SST', or the sum of \
the line AMOUNT column).
- tax_total is the printed tax/SST total (the footer 'SST' figure).
- doc_total is the printed grand total INCLUDING tax ('TOTAL INCL SST').
- qty is the invoiced quantity for that line.
- currency is the ISO code (e.g. MYR, USD) or the symbol shown.
- Numbers must be plain: no thousands separators, no currency symbols.
- supplier_no is the supplier's account/vendor code if printed, else null.
- If a value is absent, use null (or 0 for discount_pct/tax). Output JSON only.";

/// Extra instruction appended when `image_locate` is on and the scan is an
/// image — asks the vision model to also locate each line vertically so the UI
/// can highlight it. Kept separate so PDF/no-locate calls don't pay for it.
const LOCATE_ADDENDUM: &str = "\
ADDITIONALLY, for EACH line object include two extra numeric fields \"y\" and \"h\": \
the vertical position of that line item's row on the page, expressed as a fraction \
of the total page height. \"y\" is the top edge of the row (0 = very top of page, \
1 = very bottom) and \"h\" is the row's height as a fraction of page height \
(a typical single-line row is roughly 0.02–0.05). Estimate from where the row \
visually sits in the image. These locate the line on the scan.";

// Long invoices (dozens of line items) need plenty of output room, or the JSON
// array is cut off mid-line and can't be parsed.
const MAX_TOKENS: u32 = 8192;

/// A minimal 16×16 white PNG, used only by `test_connection` to exercise the
/// vision path without shipping a real document. Base64 of a valid PNG.
const TEST_IMAGE_PNG_B64: &str = "iVBORw0KGgoAAAANSUhEUgAAABAAAAAQCAYAAAAf8/9hAAAAHElEQVR42mP8z8BQz0AEYBxVSFvFqAKKAgB18wX9formfQAAAABJRU5ErkJggg==";

/// Assemble the extraction prompt: base rules, the optional image-locate
/// addendum, and any self-learned operator corrections (which override the
/// generic rules). Shared by the live call and the batch submitter so both
/// paths extract identically.
fn build_prompt(image_locate: bool, is_image: bool, hints: &[String]) -> String {
    let mut prompt = if image_locate && is_image {
        format!("{PROMPT}\n{LOCATE_ADDENDUM}")
    } else {
        PROMPT.to_string()
    };
    let clean: Vec<&str> = hints.iter().map(|h| h.trim()).filter(|h| !h.is_empty()).collect();
    if !clean.is_empty() {
        prompt.push_str(
            "\n\nOPERATOR CORRECTIONS — these rules come from prior reviewer feedback on this \
             supplier's invoices. They OVERRIDE the generic rules above when they conflict; \
             follow every one:",
        );
        for h in clean {
            prompt.push_str("\n- ");
            prompt.push_str(h);
        }
    }
    prompt
}

/// Parse a single Anthropic Messages result (`{content, usage}`) into the
/// extracted invoice + token usage. Reused by the live path and the batch
/// results reader. Tolerates a JSON body truncated at the token cap.
fn parse_message(message: &serde_json::Value) -> Result<(Extracted, Usage), String> {
    let usage = Usage {
        input_tokens: message["usage"]["input_tokens"].as_u64().unwrap_or(0),
        output_tokens: message["usage"]["output_tokens"].as_u64().unwrap_or(0),
    };
    let text = message["content"]
        .as_array()
        .and_then(|arr| arr.iter().find_map(|b| b.get("text").and_then(|t| t.as_str())))
        .ok_or_else(|| "No text in message".to_string())?;
    let json = slice_json_object(text)
        .ok_or_else(|| format!("Model did not return JSON: {}", trunc(text)))?;
    match serde_json::from_str::<Extracted>(json) {
        Ok(ex) => Ok((ex, usage)),
        Err(e) => match repair_truncated(json) {
            Some(fixed) => serde_json::from_str::<Extracted>(&fixed)
                .map(|ex| (ex, usage))
                .map_err(|_| format!("Could not parse extracted JSON: {e}")),
            None => Err(format!("Could not parse extracted JSON: {e}")),
        },
    }
}

/// One document to include in a batch extraction request.
pub struct BatchDoc {
    /// Stable id echoed back in the results (we use the recon_batch UUID).
    pub custom_id: String,
    pub bytes: Vec<u8>,
    pub mime: String,
    pub hints: Vec<String>,
}

/// Status of a submitted Anthropic message batch.
#[derive(Debug, Default)]
pub struct BatchStatus {
    /// Provider status string ("in_progress" | "ended" | …).
    pub status: String,
    pub ended: bool,
    pub processing: u64,
    pub succeeded: u64,
    pub errored: u64,
    pub results_url: Option<String>,
}

/// One line of a batch results file.
pub struct BatchResult {
    pub custom_id: String,
    pub outcome: Result<(Extracted, Usage), String>,
}

fn anthropic_batch_client() -> Result<reqwest::Client, String> {
    reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(120))
        .build()
        .map_err(|e| format!("HTTP client init failed: {e}"))
}

/// Submit a set of documents to the Anthropic Message Batches API. Returns the
/// provider batch id (`msgbatch_…`). Anthropic-only (the only vision provider
/// with batching); errors otherwise.
pub async fn submit_batch(cfg: &AiConfig, docs: &[BatchDoc]) -> Result<String, String> {
    if !matches!(cfg.shape(), Shape::Anthropic) {
        return Err("Batch extraction requires an Anthropic (Claude) provider.".into());
    }
    if cfg.api_key.trim().is_empty() {
        return Err("No API key configured.".into());
    }
    if docs.is_empty() {
        return Err("Nothing queued to submit.".into());
    }
    let requests: Vec<serde_json::Value> = docs
        .iter()
        .map(|d| {
            let b64 = base64::engine::general_purpose::STANDARD.encode(&d.bytes);
            let is_pdf = d.mime.eq_ignore_ascii_case("application/pdf");
            let is_image = d.mime.starts_with("image/");
            let doc = if is_pdf {
                serde_json::json!({"type":"document","source":{"type":"base64","media_type":"application/pdf","data":b64}})
            } else {
                serde_json::json!({"type":"image","source":{"type":"base64","media_type":d.mime,"data":b64}})
            };
            let prompt = build_prompt(cfg.image_locate, is_image, &d.hints);
            serde_json::json!({
                "custom_id": d.custom_id,
                "params": {
                    "model": cfg.model,
                    "max_tokens": MAX_TOKENS,
                    "messages": [{"role":"user","content":[doc, {"type":"text","text":prompt}]}],
                }
            })
        })
        .collect();

    let client = anthropic_batch_client()?;
    let url = format!("{}/v1/messages/batches", cfg.base_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("x-api-key", &cfg.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&serde_json::json!({ "requests": requests }))
        .send()
        .await
        .map_err(|e| format!("Batch submit request failed: {e}"))?;
    let status = resp.status();
    let raw = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Anthropic batch submit {}: {}", status, trunc(&raw)));
    }
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("Bad batch envelope: {e}"))?;
    v["id"].as_str().map(|s| s.to_string()).ok_or_else(|| format!("No batch id in response: {}", trunc(&raw)))
}

/// Poll a submitted batch's status.
pub async fn poll_batch(cfg: &AiConfig, batch_id: &str) -> Result<BatchStatus, String> {
    let client = anthropic_batch_client()?;
    let url = format!("{}/v1/messages/batches/{}", cfg.base_url.trim_end_matches('/'), batch_id);
    let resp = client
        .get(&url)
        .header("x-api-key", &cfg.api_key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
        .map_err(|e| format!("Batch poll failed: {e}"))?;
    let status = resp.status();
    let raw = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Anthropic batch poll {}: {}", status, trunc(&raw)));
    }
    let v: serde_json::Value = serde_json::from_str(&raw).map_err(|e| format!("Bad batch envelope: {e}"))?;
    let ps = v["processing_status"].as_str().unwrap_or("").to_string();
    Ok(BatchStatus {
        ended: ps == "ended",
        processing: v["request_counts"]["processing"].as_u64().unwrap_or(0),
        succeeded: v["request_counts"]["succeeded"].as_u64().unwrap_or(0),
        errored: v["request_counts"]["errored"].as_u64().unwrap_or(0)
            + v["request_counts"]["canceled"].as_u64().unwrap_or(0)
            + v["request_counts"]["expired"].as_u64().unwrap_or(0),
        results_url: v["results_url"].as_str().map(|s| s.to_string()),
        status: ps,
    })
}

/// Download and parse a finished batch's results (JSONL). Each line maps a
/// `custom_id` to either the extracted invoice or an error message.
pub async fn fetch_batch_results(cfg: &AiConfig, results_url: &str) -> Result<Vec<BatchResult>, String> {
    let client = anthropic_batch_client()?;
    let resp = client
        .get(results_url)
        .header("x-api-key", &cfg.api_key)
        .header("anthropic-version", "2023-06-01")
        .send()
        .await
        .map_err(|e| format!("Batch results fetch failed: {e}"))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("Anthropic batch results {}: {}", status, trunc(&body)));
    }
    let mut out = Vec::new();
    for line in body.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let v: serde_json::Value = match serde_json::from_str(line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        let custom_id = v["custom_id"].as_str().unwrap_or("").to_string();
        if custom_id.is_empty() {
            continue;
        }
        let result = &v["result"];
        let outcome = match result["type"].as_str() {
            Some("succeeded") => parse_message(&result["message"]),
            Some("errored") => Err(format!(
                "provider error: {}",
                trunc(&result["error"].to_string())
            )),
            Some(other) => Err(format!("request {other}")),
            None => Err("unknown result".into()),
        };
        out.push(BatchResult { custom_id, outcome });
    }
    Ok(out)
}

/// Run extraction against the configured provider. `mime` comes from the stored
/// attachment (e.g. `application/pdf`, `image/png`). Returns a user-facing error
/// string on any failure so the handler can surface it verbatim.
pub async fn extract(
    cfg: &AiConfig,
    file_bytes: &[u8],
    mime: &str,
    hints: &[String],
) -> Result<(Extracted, Usage), String> {
    if cfg.api_key.trim().is_empty() {
        return Err("No API key configured. Set one in Configuration ▸ AI Extraction.".into());
    }
    let b64 = base64::engine::general_purpose::STANDARD.encode(file_bytes);
    let is_pdf = mime.eq_ignore_ascii_case("application/pdf");
    let is_image = mime.starts_with("image/");

    let prompt = build_prompt(cfg.image_locate, is_image, hints);

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(90))
        .build()
        .map_err(|e| format!("HTTP client init failed: {e}"))?;

    let (text, usage) = match cfg.shape() {
        Shape::Anthropic => anthropic_call(&client, cfg, &b64, mime, is_pdf, &prompt).await?,
        Shape::OpenAi => {
            if is_pdf {
                return Err(
                    "This provider accepts images only (PNG/JPEG). PDF extraction is supported on \
                     Claude/Anthropic — upload an image, or switch the provider to Anthropic."
                        .into(),
                );
            }
            openai_call(&client, cfg, &b64, mime, &prompt).await?
        }
    };

    let json = slice_json_object(&text)
        .ok_or_else(|| format!("Model did not return JSON. First 200 chars: {}", trunc(&text)))?;
    match serde_json::from_str::<Extracted>(json) {
        Ok(ex) => Ok((ex, usage)),
        // A very long invoice can still exhaust the output budget and cut the
        // JSON off mid-array. Salvage it: keep every complete line object and
        // close the array — the reviewer adds any dropped tail line by hand.
        Err(e) => match repair_truncated(json) {
            Some(fixed) => serde_json::from_str::<Extracted>(&fixed)
                .map(|ex| (ex, usage))
                .map_err(|_| format!("Could not parse extracted JSON: {e}")),
            None => Err(format!("Could not parse extracted JSON: {e}")),
        },
    }
}

async fn anthropic_call(
    client: &reqwest::Client,
    cfg: &AiConfig,
    b64: &str,
    mime: &str,
    is_pdf: bool,
    prompt: &str,
) -> Result<(String, Usage), String> {
    let doc = if is_pdf {
        serde_json::json!({
            "type": "document",
            "source": {"type": "base64", "media_type": "application/pdf", "data": b64}
        })
    } else {
        serde_json::json!({
            "type": "image",
            "source": {"type": "base64", "media_type": mime, "data": b64}
        })
    };
    let body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": MAX_TOKENS,
        "messages": [{"role": "user", "content": [doc, {"type": "text", "text": prompt}]}],
    });
    let url = format!("{}/v1/messages", cfg.base_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("x-api-key", &cfg.api_key)
        .header("anthropic-version", "2023-06-01")
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request to {} failed: {e}", cfg.provider))?;
    let status = resp.status();
    let raw = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("{} returned {}: {}", cfg.provider, status, trunc(&raw)));
    }
    // { "content": [ { "type": "text", "text": "..." } ], "usage": {...} }
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("Bad JSON envelope: {e}"))?;
    let usage = Usage {
        input_tokens: v["usage"]["input_tokens"].as_u64().unwrap_or(0),
        output_tokens: v["usage"]["output_tokens"].as_u64().unwrap_or(0),
    };
    v["content"]
        .as_array()
        .and_then(|arr| arr.iter().find_map(|b| b.get("text").and_then(|t| t.as_str())))
        .map(|s| (s.to_string(), usage))
        .ok_or_else(|| format!("No text in response: {}", trunc(&raw)))
}

async fn openai_call(
    client: &reqwest::Client,
    cfg: &AiConfig,
    b64: &str,
    mime: &str,
    prompt: &str,
) -> Result<(String, Usage), String> {
    let data_url = format!("data:{mime};base64,{b64}");
    let body = serde_json::json!({
        "model": cfg.model,
        "max_tokens": MAX_TOKENS,
        "messages": [{
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": data_url}}
            ]
        }],
    });
    let url = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));
    let resp = client
        .post(&url)
        .header("authorization", format!("Bearer {}", cfg.api_key))
        .header("content-type", "application/json")
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Request to {} failed: {e}", cfg.provider))?;
    let status = resp.status();
    let raw = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(format!("{} returned {}: {}", cfg.provider, status, trunc(&raw)));
    }
    // { "choices": [ { "message": { "content": "..." } } ], "usage": {...} }
    let v: serde_json::Value =
        serde_json::from_str(&raw).map_err(|e| format!("Bad JSON envelope: {e}"))?;
    // OpenAI-style: prompt_tokens / completion_tokens.
    let usage = Usage {
        input_tokens: v["usage"]["prompt_tokens"].as_u64().unwrap_or(0),
        output_tokens: v["usage"]["completion_tokens"].as_u64().unwrap_or(0),
    };
    v["choices"][0]["message"]["content"]
        .as_str()
        .map(|s| (s.to_string(), usage))
        .ok_or_else(|| format!("No content in response: {}", trunc(&raw)))
}

/// Slice the first balanced-looking JSON object: from the first `{` to the last
/// `}`. Tolerates code fences / prose around the object.
/// Repair a JSON object whose trailing `lines` array was cut off mid-item
/// (model hit the output limit): keep up to the last complete `}` and close the
/// array + object. Returns `None` when the JSON already looks complete.
fn repair_truncated(json: &str) -> Option<String> {
    if json.trim_end().ends_with('}') {
        return None; // looks complete — a different parse error, don't touch it
    }
    let last = json.rfind('}')?;
    Some(format!("{}]}}", &json[..=last]))
}

fn slice_json_object(text: &str) -> Option<&str> {
    let start = text.find('{')?;
    let end = text.rfind('}')?;
    if end > start {
        Some(&text[start..=end])
    } else {
        None
    }
}

fn trunc(s: &str) -> String {
    s.chars().take(200).collect()
}

/// Lightweight connectivity/credentials check for a provider config. Sends a
/// tiny text-only prompt (no document) so it's cheap, and surfaces the
/// provider's own error verbatim — which is what pinpoints a bad model name
/// (e.g. `deepseek-v4-pro`), a wrong key, or an unreachable base URL. Returns
/// `Ok(reply)` on a 2xx with the model's short reply, `Err(message)` otherwise.
pub async fn test_connection(cfg: &AiConfig) -> Result<String, String> {
    if cfg.api_key.trim().is_empty() {
        return Err("No API key — paste one to test.".into());
    }
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| format!("HTTP client init failed: {e}"))?;
    let ping = "This is a connectivity test. Reply with just the word OK.";
    // A tiny (16×16 white) PNG so the test exercises the SAME image/vision path
    // extraction uses — a text-only ping would pass on a model that can't read
    // images (the likely reason a non-vision model "can't extract").
    let png_b64 = TEST_IMAGE_PNG_B64;

    let (url, resp) = match cfg.shape() {
        Shape::Anthropic => {
            let url = format!("{}/v1/messages", cfg.base_url.trim_end_matches('/'));
            let body = serde_json::json!({
                "model": cfg.model,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": png_b64}},
                    {"type": "text", "text": ping}
                ]}],
            });
            let resp = client
                .post(&url)
                .header("x-api-key", &cfg.api_key)
                .header("anthropic-version", "2023-06-01")
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await;
            (url, resp)
        }
        Shape::OpenAi => {
            let url = format!("{}/chat/completions", cfg.base_url.trim_end_matches('/'));
            let data_url = format!("data:image/png;base64,{png_b64}");
            let body = serde_json::json!({
                "model": cfg.model,
                "max_tokens": 16,
                "messages": [{"role": "user", "content": [
                    {"type": "text", "text": ping},
                    {"type": "image_url", "image_url": {"url": data_url}}
                ]}],
            });
            let resp = client
                .post(&url)
                .header("authorization", format!("Bearer {}", cfg.api_key))
                .header("content-type", "application/json")
                .json(&body)
                .send()
                .await;
            (url, resp)
        }
    };
    let resp = resp.map_err(|e| format!("Could not reach {url}: {e}"))?;
    let status = resp.status();
    let raw = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        // The provider's error body names the real problem (unknown model,
        // invalid key, no access) — pass it through, trimmed.
        return Err(format!("{} {}: {}", cfg.provider, status, trunc(&raw)));
    }
    // Pull a short reply snippet to prove a real round-trip.
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap_or_default();
    let reply = match cfg.shape() {
        Shape::Anthropic => v["content"]
            .as_array()
            .and_then(|a| a.iter().find_map(|b| b.get("text").and_then(|t| t.as_str())))
            .unwrap_or("")
            .to_string(),
        Shape::OpenAi => v["choices"][0]["message"]["content"].as_str().unwrap_or("").to_string(),
    };
    Ok(if reply.trim().is_empty() {
        "Connected — model responded.".to_string()
    } else {
        format!("Connected — model replied: {}", trunc(reply.trim()))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slices_json_from_fenced_prose() {
        let t = "Here you go:\n```json\n{\"invoice_no\":\"A1\",\"lines\":[]}\n```\nthanks";
        let j = slice_json_object(t).unwrap();
        let e: Extracted = serde_json::from_str(j).unwrap();
        assert_eq!(e.invoice_no.as_deref(), Some("A1"));
    }

    #[test]
    fn salvages_truncated_lines_array() {
        // Model output cut off mid-line (hit the token cap).
        let cut = r#"{"doc_total":100,"lines":[{"qty":1,"unit_price":2},{"qty":3,"unit_pri"#;
        let fixed = repair_truncated(cut).unwrap();
        let e: Extracted = serde_json::from_str(&fixed).unwrap();
        assert_eq!(e.lines.len(), 1); // the one complete line survives
        assert!(repair_truncated(r#"{"lines":[]}"#).is_none()); // complete → untouched
    }

    #[test]
    fn parses_lines_with_missing_fields() {
        let j = r#"{"doc_total":100.5,"lines":[{"qty":2,"unit_price":50.25}]}"#;
        let e: Extracted = serde_json::from_str(j).unwrap();
        assert_eq!(e.lines.len(), 1);
        assert_eq!(e.lines[0].qty, Some(2.0));
        assert!(e.lines[0].tax.is_none());
    }
}
