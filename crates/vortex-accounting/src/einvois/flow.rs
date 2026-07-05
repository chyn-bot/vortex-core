//! e-Invoice orchestration: assemble UBL payloads from the ledger,
//! drive the status lifecycle, archive evidence, emit events.

use vortex_plugin_sdk::chrono::Utc;
use vortex_plugin_sdk::common::{VortexError, VortexResult};
use vortex_plugin_sdk::rust_decimal::Decimal;
use vortex_plugin_sdk::serde_json::{json, Value};
use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use super::client::{self, MyInvoisApi, SubmitDoc};
use super::ubl::{self, Address, DocLine, EinvoiceDoc, LineTax, Party, TaxSubtotal};
use vortex_plugin_sdk::framework::AppState;

#[derive(Debug, Clone)]
pub struct EinvoiceSettings {
    pub mode: String,
    pub production: bool,
    pub client_id: Option<String>,
    pub client_secret: Option<String>,
    pub auto_submit: bool,
    pub consolidated_partner_id: Option<Uuid>,
    pub doc_version: String,
}

pub async fn settings(db: &PgPool) -> VortexResult<EinvoiceSettings> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT mode, environment, client_id, client_secret_enc, auto_submit, \
                consolidated_partner_id, doc_version \
         FROM acc_einvoice_settings ORDER BY company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(row) = row else {
        return Ok(EinvoiceSettings {
            mode: "portal".into(),
            production: false,
            client_id: None,
            client_secret: None,
            auto_submit: false,
            consolidated_partner_id: None,
            doc_version: "1.0".into(),
        });
    };
    let secret = row
        .get::<Option<Vec<u8>>, _>("client_secret_enc")
        .and_then(|enc| {
            let key = vortex_plugin_sdk::security::crypto::master_key();
            vortex_plugin_sdk::security::crypto::decrypt_str(&enc, &key).ok()
        });
    Ok(EinvoiceSettings {
        mode: row.get("mode"),
        production: row.get::<String, _>("environment") == "production",
        client_id: row.get("client_id"),
        client_secret: secret,
        auto_submit: row.get("auto_submit"),
        consolidated_partner_id: row.get("consolidated_partner_id"),
        doc_version: row.get("doc_version"),
    })
}

/// LHDN doc type for a move type (customer documents only in v1;
/// self-billed vendor documents are a follow-up).
pub fn doc_type_for(move_type: &str) -> Option<&'static str> {
    match move_type {
        "customer_invoice" => Some("01"),
        "customer_credit_note" => Some("02"),
        _ => None,
    }
}

/// Create the e-invoice row for a freshly posted customer document
/// (idempotent; respects the partner's consolidated opt-out flag).
pub async fn ensure_einvoice(db: &PgPool, move_id: Uuid) -> VortexResult<Option<Uuid>> {
    let Some(head) = vortex_plugin_sdk::sqlx::query(
        "SELECT m.move_type, m.state, m.company_id, m.partner_id, \
                COALESCE(p.einvoice_optout, false) AS optout \
         FROM acc_move m \
         LEFT JOIN acc_partner_tax_profile p ON p.contact_id = m.partner_id \
         WHERE m.id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?
    else {
        return Ok(None);
    };
    let move_type: String = head.get("move_type");
    let state: String = head.get("state");
    let Some(doc_type) = doc_type_for(&move_type) else {
        return Ok(None);
    };
    if state != "posted" {
        return Err(VortexError::ValidationFailed(
            "e-invoices are created for posted documents".into(),
        ));
    }
    let optout: bool = head.get("optout");
    if optout {
        return Ok(None); // reaches LHDN via the monthly consolidated doc
    }
    let company_id: Option<Uuid> = head.get("company_id");
    let id: Uuid = vortex_plugin_sdk::sqlx::query_scalar(
        "INSERT INTO acc_einvoice (move_id, doc_type_code, company_id) \
         VALUES ($1, $2, $3) \
         ON CONFLICT (move_id) DO UPDATE SET updated_at = NOW() \
         RETURNING id",
    )
    .bind(move_id)
    .bind(doc_type)
    .bind(company_id)
    .fetch_one(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(Some(id))
}

async fn company_party(db: &PgPool) -> VortexResult<Party> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT c.company_tin, c.company_id_type, c.company_id_value, \
                c.company_sst_registration, c.company_msic_code, \
                c.company_business_activity, c.company_address1, c.company_address2, \
                c.company_city, c.company_postcode, c.company_state_code, \
                c.company_country_code, c.company_phone, c.company_email, \
                COALESCE(co.name, 'Company') AS company_name \
         FROM acc_config c \
         LEFT JOIN companies co ON co.id = c.company_id \
         ORDER BY c.company_id NULLS LAST LIMIT 1",
    )
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed(
            "no acc_config row — configure Accounting Settings first".into(),
        ));
    };
    let tin: Option<String> = r.get("company_tin");
    let Some(tin) = tin.filter(|t| !t.is_empty()) else {
        return Err(VortexError::ValidationFailed(
            "company TIN not set — fill Accounting Settings ▸ Company Tax Identity".into(),
        ));
    };
    Ok(Party {
        name: r.get("company_name"),
        tin,
        id_type: r.get::<Option<String>, _>("company_id_type").unwrap_or_else(|| "BRN".into()),
        id_value: r.get::<Option<String>, _>("company_id_value").unwrap_or_else(|| "NA".into()),
        sst_registration: r.get("company_sst_registration"),
        msic: r.get::<Option<String>, _>("company_msic_code").map(|code| {
            (
                code,
                r.get::<Option<String>, _>("company_business_activity")
                    .unwrap_or_else(|| "Business activities".into()),
            )
        }),
        address: Address {
            line1: r.get::<Option<String>, _>("company_address1").unwrap_or_else(|| "NA".into()),
            line2: r.get::<Option<String>, _>("company_address2").unwrap_or_default(),
            city: r.get::<Option<String>, _>("company_city").unwrap_or_else(|| "NA".into()),
            postcode: r
                .get::<Option<String>, _>("company_postcode")
                .unwrap_or_else(|| "00000".into()),
            state_code: r
                .get::<Option<String>, _>("company_state_code")
                .unwrap_or_else(|| "14".into()),
            country_code: r
                .get::<Option<String>, _>("company_country_code")
                .unwrap_or_else(|| "MYS".into()),
        },
        phone: r.get::<Option<String>, _>("company_phone").unwrap_or_else(|| "NA".into()),
        email: r.get("company_email"),
    })
}

async fn buyer_party(db: &PgPool, partner_id: Uuid) -> VortexResult<Party> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT ct.name, ct.street, ct.street2, ct.city, ct.zip, ct.phone, ct.email, \
                p.tin, p.id_type, p.id_value, p.sst_registration, \
                p.einvoice_email, p.state_code, p.country_code \
         FROM contacts ct \
         LEFT JOIN acc_partner_tax_profile p ON p.contact_id = ct.id \
         WHERE ct.id = $1",
    )
    .bind(partner_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = row else {
        return Err(VortexError::ValidationFailed("partner not found".into()));
    };
    let tin: Option<String> = r.get("tin");
    let Some(tin) = tin.filter(|t| !t.is_empty()) else {
        return Err(VortexError::ValidationFailed(
            "partner has no TIN — fill the Partner Tax Profile (or mark the partner consolidated-only)".into(),
        ));
    };
    Ok(Party {
        name: r.get("name"),
        tin,
        id_type: r.get::<Option<String>, _>("id_type").unwrap_or_else(|| "BRN".into()),
        id_value: r.get::<Option<String>, _>("id_value").unwrap_or_else(|| "NA".into()),
        sst_registration: r.get("sst_registration"),
        msic: None,
        address: Address {
            line1: r.get::<Option<String>, _>("street").unwrap_or_else(|| "NA".into()),
            line2: r.get::<Option<String>, _>("street2").unwrap_or_default(),
            city: r.get::<Option<String>, _>("city").unwrap_or_else(|| "NA".into()),
            postcode: r.get::<Option<String>, _>("zip").unwrap_or_else(|| "00000".into()),
            state_code: r.get::<Option<String>, _>("state_code").unwrap_or_else(|| "17".into()),
            country_code: r
                .get::<Option<String>, _>("country_code")
                .unwrap_or_else(|| "MYS".into()),
        },
        phone: r.get::<Option<String>, _>("phone").unwrap_or_else(|| "NA".into()),
        email: r
            .get::<Option<String>, _>("einvoice_email")
            .or_else(|| r.get::<Option<String>, _>("email")),
    })
}

/// Assemble the fully-resolved UBL document for a posted customer
/// document. Tax blocks come from the GL tax lines (Phase 1), so the
/// e-invoice can never disagree with SST-02.
pub async fn payload_for(db: &PgPool, move_id: Uuid) -> VortexResult<(Uuid, EinvoiceDoc)> {
    let einvoice = vortex_plugin_sdk::sqlx::query(
        "SELECT e.id, e.doc_type_code, e.consolidated, m.number, m.partner_id, \
                m.untaxed_amount, m.tax_amount, m.total_amount, m.reversed_move_id, \
                m.move_type, m.invoice_date \
         FROM acc_einvoice e JOIN acc_move m ON m.id = e.move_id \
         WHERE e.move_id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let Some(r) = einvoice else {
        return Err(VortexError::ValidationFailed("no e-invoice row for this document".into()));
    };
    let einvoice_id: Uuid = r.get("id");
    let doc_type: String = r.get("doc_type_code");
    let number: Option<String> = r.get("number");
    let number = number.ok_or_else(|| {
        VortexError::ValidationFailed("document has no number — post it first".into())
    })?;
    let partner_id: Option<Uuid> = r.get("partner_id");

    let settings_ = settings(db).await?;
    let supplier = company_party(db).await?;
    let buyer = match partner_id {
        Some(pid) => buyer_party(db, pid).await?,
        None => Party::general_public(),
    };

    // Commercial lines with their tax codes.
    let line_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT l.description, l.quantity, l.unit_price, l.classification_code, l.uom_code, \
                t.amount AS tax_rate, cfg.myinvois_tax_type, cfg.exemption_reason, \
                t.price_include, t.amount_type \
         FROM acc_invoice_line l \
         LEFT JOIN taxes t ON t.id = l.tax_id \
         LEFT JOIN acc_tax_config cfg ON cfg.tax_id = l.tax_id \
         WHERE l.move_id = $1 ORDER BY l.sequence",
    )
    .bind(move_id)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

    let mut lines = Vec::new();
    for (i, lr) in line_rows.iter().enumerate() {
        let quantity: Decimal = lr.get("quantity");
        let unit_price: Decimal = lr.get("unit_price");
        let gross = (quantity * unit_price).round_dp(2);
        let tax = match lr.get::<Option<Decimal>, _>("tax_rate") {
            Some(rate) => {
                // Reconstruct the per-line tax the way posting did.
                let price_include: bool = lr.get("price_include");
                let amount_type: String = lr.get("amount_type");
                let (base, tax_amount) = if amount_type == "fixed" {
                    (gross, rate.round_dp(2))
                } else if price_include {
                    let base =
                        (gross / (Decimal::ONE + rate / Decimal::from(100))).round_dp(2);
                    (base, (gross - base).round_dp(2))
                } else {
                    (gross, (gross * rate / Decimal::from(100)).round_dp(2))
                };
                let _ = base;
                Some(LineTax {
                    code: lr
                        .get::<Option<String>, _>("myinvois_tax_type")
                        .unwrap_or_else(|| "06".into()),
                    rate_percent: rate,
                    amount: tax_amount,
                    exemption_reason: lr.get("exemption_reason"),
                })
            }
            None => None,
        };
        lines.push(DocLine {
            id: (i + 1).to_string(),
            description: lr.get("description"),
            quantity,
            unit_price,
            subtotal: gross,
            classification_code: lr
                .get::<Option<String>, _>("classification_code")
                .unwrap_or_else(|| "022".into()),
            uom_code: lr.get::<Option<String>, _>("uom_code").unwrap_or_else(|| "C62".into()),
            tax,
        });
    }

    // Document tax subtotals straight from the GL tax lines.
    let subtotal_rows = vortex_plugin_sdk::sqlx::query(
        "SELECT COALESCE(cfg.myinvois_tax_type, '06') AS code, t.amount AS rate, \
                COALESCE(l.tax_base_amount, 0) AS taxable, \
                (CASE WHEN l.credit > 0 THEN l.credit ELSE l.debit END) AS amount, \
                cfg.exemption_reason \
         FROM acc_move_line l \
         JOIN taxes t ON t.id = l.tax_id \
         LEFT JOIN acc_tax_config cfg ON cfg.tax_id = l.tax_id \
         WHERE l.move_id = $1 AND l.tax_id IS NOT NULL \
         ORDER BY t.name",
    )
    .bind(move_id)
    .fetch_all(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    let tax_subtotals: Vec<TaxSubtotal> = subtotal_rows
        .iter()
        .map(|sr| TaxSubtotal {
            code: sr.get("code"),
            rate_percent: sr.get("rate"),
            taxable: sr.get("taxable"),
            amount: sr.get("amount"),
            exemption_reason: sr.get("exemption_reason"),
        })
        .collect();

    // Billing reference for credit notes: the reversed/original doc.
    let billing_reference = if doc_type == "02" {
        vortex_plugin_sdk::sqlx::query(
            "SELECT m2.number, e2.lhdn_uuid \
             FROM acc_move m JOIN acc_move m2 ON m2.reversed_move_id = m.id OR m.reversed_move_id = m2.id \
             LEFT JOIN acc_einvoice e2 ON e2.move_id = m2.id \
             WHERE m.id = $1 AND m2.move_type = 'customer_invoice' LIMIT 1",
        )
        .bind(move_id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .and_then(|r| {
            let n: Option<String> = r.get("number");
            let u: Option<String> = r.get("lhdn_uuid");
            Some((n?, u.unwrap_or_default()))
        })
    } else {
        None
    };

    let doc = EinvoiceDoc {
        doc_type_code: doc_type,
        version: settings_.doc_version,
        number,
        issued_at: Utc::now(),
        currency: "MYR".into(),
        exchange_rate: Decimal::ONE,
        supplier,
        buyer,
        lines,
        tax_subtotals,
        untaxed: r.get("untaxed_amount"),
        tax_total: r.get("tax_amount"),
        total: r.get("total_amount"),
        billing_reference,
        invoice_period: None,
    };
    Ok((einvoice_id, doc))
}

/// Archive evidence in the FileStore and stamp the row.
async fn archive(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    einvoice_id: Uuid,
    kind: &str, // "payload" | "response"
    bytes: &[u8],
    content_type: &str,
) -> VortexResult<String> {
    let key = format!("einvoice/{einvoice_id}-{kind}.{}", if content_type.contains("json") { "json" } else { "xml" });
    state
        .files
        .put(db_name, &key, bytes, Some(content_type))
        .await
        .map_err(|e| VortexError::Internal(format!("archive failed: {e}")))?;
    let col = if kind == "payload" { "payload_file_key" } else { "response_file_key" };
    let sql = format!("UPDATE acc_einvoice SET {col} = $2 WHERE id = $1");
    vortex_plugin_sdk::sqlx::query(&sql)
        .bind(einvoice_id)
        .bind(&key)
        .execute(db)
        .await
        .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok(key)
}

/// Portal-mode export: build, archive, mark exported. Returns
/// (filename, xml) for download.
pub async fn export_xml(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    move_id: Uuid,
) -> VortexResult<(String, String)> {
    let (einvoice_id, doc) = payload_for(db, move_id).await?;
    let xml = ubl::build_xml(&doc);
    let sha = super::sha256_hex(xml.as_bytes());
    archive(state, db, db_name, einvoice_id, "payload", xml.as_bytes(), "application/xml").await?;
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_einvoice SET status = 'exported', payload_sha256 = $2 \
         WHERE id = $1 AND status IN ('ready', 'exported', 'invalid')",
    )
    .bind(einvoice_id)
    .bind(&sha)
    .execute(db)
    .await
    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
    Ok((format!("{}.xml", doc.number.replace('/', "-")), xml))
}

/// API-mode submission (used by the submit job). Idempotent: documents
/// already submitted/valid are left alone.
pub async fn submit_via_api(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    move_id: Uuid,
    api: &dyn MyInvoisApi,
) -> Result<(), String> {
    let status: Option<String> = vortex_plugin_sdk::sqlx::query_scalar(
        "SELECT status FROM acc_einvoice WHERE move_id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;
    match status.as_deref() {
        Some("ready") | Some("exported") | Some("invalid") => {}
        Some(other) => {
            vortex_plugin_sdk::tracing::info!(
                "einvoice for move {move_id} is '{other}' — skipping submit (idempotent)"
            );
            return Ok(());
        }
        None => return Err("no e-invoice row".into()),
    }

    let (einvoice_id, doc) = payload_for(db, move_id).await.map_err(|e| e.to_string())?;
    let xml = ubl::build_xml(&doc);
    let sha = super::sha256_hex(xml.as_bytes());
    archive(state, db, db_name, einvoice_id, "payload", xml.as_bytes(), "application/xml")
        .await
        .map_err(|e| e.to_string())?;

    let result = api
        .submit(vec![SubmitDoc { code_number: doc.number.clone(), xml: xml.into_bytes() }])
        .await?;

    if let Some((_, uuid)) = result.accepted.first() {
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_einvoice SET status = 'submitted', submission_uid = $2, \
                    lhdn_uuid = $3, payload_sha256 = $4, submitted_at = NOW(), error_json = NULL \
             WHERE id = $1",
        )
        .bind(einvoice_id)
        .bind(&result.submission_uid)
        .bind(uuid)
        .bind(&sha)
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;
        Ok(())
    } else {
        let err = result
            .rejected
            .first()
            .map(|(_, e)| e.clone())
            .unwrap_or_else(|| json!({"error": "document not accepted"}));
        let human = human_lhdn_error(&err);
        let stored = json!({ "message": human, "raw": err });
        vortex_plugin_sdk::sqlx::query(
            "UPDATE acc_einvoice SET status = 'invalid', error_json = $2 WHERE id = $1",
        )
        .bind(einvoice_id)
        .bind(&stored)
        .execute(db)
        .await
        .map_err(|e| e.to_string())?;
        Err(format!("LHDN rejected: {human}"))
    }
}

/// Flatten LHDN's nested validation error into the field messages a
/// user can act on ("Enter valid e-mail address - SUPPLIER; …").
fn human_lhdn_error(err: &Value) -> String {
    let details: Vec<String> = err
        .pointer("/error/details")
        .and_then(|d| d.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|d| d.get("message").and_then(|m| m.as_str()))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    if !details.is_empty() {
        return details.join(" · ");
    }
    err.pointer("/error/message")
        .and_then(|m| m.as_str())
        .map(str::to_string)
        .unwrap_or_else(|| err.to_string())
}

/// Poll job body: resolve the submission's final status.
/// Returns Ok(true) when terminal, Ok(false) to poll again.
pub async fn poll_via_api(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    move_id: Uuid,
    api: &dyn MyInvoisApi,
    portal_base: &str,
) -> Result<bool, String> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT id, submission_uid, lhdn_uuid, status FROM acc_einvoice WHERE move_id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;
    let Some(row) = row else { return Err("no e-invoice row".into()) };
    let einvoice_id: Uuid = row.get("id");
    let status: String = row.get("status");
    if status != "submitted" {
        return Ok(true); // already terminal
    }
    let Some(submission_uid) = row.get::<Option<String>, _>("submission_uid") else {
        return Err("submitted without submission_uid".into());
    };

    let sub = api.submission_status(&submission_uid).await?;
    if sub.overall == "InProgress" {
        return Ok(false);
    }
    let mine = sub
        .documents
        .iter()
        .find(|d| Some(d.lhdn_uuid.as_str()) == row.get::<Option<String>, _>("lhdn_uuid").as_deref())
        .or(sub.documents.first());
    let Some(docst) = mine else { return Ok(false) };

    match docst.status.as_str() {
        "Valid" => {
            let link = docst
                .long_id
                .as_ref()
                .map(|lid| format!("{portal_base}/{}/share/{lid}", docst.lhdn_uuid));
            vortex_plugin_sdk::sqlx::query(
                "UPDATE acc_einvoice SET status = 'valid', long_id = $2, \
                        validation_link = $3, validated_at = NOW() WHERE id = $1",
            )
            .bind(einvoice_id)
            .bind(&docst.long_id)
            .bind(&link)
            .execute(db)
            .await
            .map_err(|e| e.to_string())?;
            let _ = vortex_plugin_sdk::framework::webhooks::emit(
                &state.db,
                db,
                db_name,
                "accounting.einvoice.validated",
                json!({ "move_id": move_id, "lhdn_uuid": docst.lhdn_uuid, "link": link }),
            )
            .await;
            Ok(true)
        }
        "Invalid" | "Rejected" => {
            let details = api.document_details(&docst.lhdn_uuid).await.unwrap_or(Value::Null);
            archive(
                state,
                db,
                db_name,
                einvoice_id,
                "response",
                details.to_string().as_bytes(),
                "application/json",
            )
            .await
            .map_err(|e| e.to_string())?;
            vortex_plugin_sdk::sqlx::query(
                "UPDATE acc_einvoice SET status = 'invalid', error_json = $2 WHERE id = $1",
            )
            .bind(einvoice_id)
            .bind(&details)
            .execute(db)
            .await
            .map_err(|e| e.to_string())?;
            let _ = vortex_plugin_sdk::framework::webhooks::emit(
                &state.db,
                db,
                db_name,
                "accounting.einvoice.rejected",
                json!({ "move_id": move_id, "lhdn_uuid": docst.lhdn_uuid }),
            )
            .await;
            Ok(true)
        }
        _ => Ok(false),
    }
}

/// Cancel a validated document within LHDN's 72-hour window.
pub async fn cancel_via_api(
    db: &PgPool,
    move_id: Uuid,
    reason: &str,
    api: &dyn MyInvoisApi,
) -> Result<(), String> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT id, lhdn_uuid, status, validated_at FROM acc_einvoice WHERE move_id = $1",
    )
    .bind(move_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?;
    let Some(row) = row else { return Err("no e-invoice row".into()) };
    let status: String = row.get("status");
    if status != "valid" {
        return Err(format!("only valid documents can be cancelled (status is '{status}')"));
    }
    if let Some(validated_at) = row.get::<Option<vortex_plugin_sdk::chrono::DateTime<Utc>>, _>("validated_at") {
        if Utc::now() - validated_at > vortex_plugin_sdk::chrono::Duration::hours(72) {
            return Err("the 72-hour LHDN cancellation window has passed — issue a credit note".into());
        }
    }
    let Some(uuid) = row.get::<Option<String>, _>("lhdn_uuid") else {
        return Err("no LHDN uuid".into());
    };
    api.cancel(&uuid, reason).await?;
    let einvoice_id: Uuid = row.get("id");
    vortex_plugin_sdk::sqlx::query(
        "UPDATE acc_einvoice SET status = 'cancelled', cancelled_at = NOW() WHERE id = $1",
    )
    .bind(einvoice_id)
    .execute(db)
    .await
    .map_err(|e| e.to_string())?;
    Ok(())
}

/// Portal base for validation links, by environment.
pub fn portal_base(production: bool) -> &'static str {
    if production { client::PRODUCTION_PORTAL } else { client::SANDBOX_PORTAL }
}

// ─── Taxpayer TIN lookup (Search TIN / Validate TIN) ─────────────────────

/// Build an API client from the tenant's e-invoice settings, or say
/// exactly what is missing. Used by the on-demand TIN actions.
pub async fn api_client_from_settings(db: &PgPool) -> Result<client::LhdnClient, String> {
    let settings = settings(db).await.map_err(|e| e.to_string())?;
    if settings.mode != "api" {
        return Err("e-invoice mode is 'portal' — switch to API mode in e-Invoice Settings".into());
    }
    let (Some(id), Some(secret)) = (settings.client_id.clone(), settings.client_secret.clone())
    else {
        return Err("MyInvois client ID / secret not configured".into());
    };
    client::LhdnClient::new(settings.production, id, secret)
}

/// Search LHDN for the TIN matching a partner tax profile's ID
/// (BRN/NRIC/passport/army) and name. Returns the TIN when found.
pub async fn search_tin_for_profile(db: &PgPool, profile_id: Uuid) -> Result<Option<String>, String> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT p.id_type, p.id_value, ct.name FROM acc_partner_tax_profile p \
         JOIN contacts ct ON ct.id = p.contact_id WHERE p.id = $1",
    )
    .bind(profile_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or("profile not found")?;
    let id_type: Option<String> = row.get("id_type");
    let id_value: Option<String> = row.get("id_value");
    let name: String = row.get("name");
    let (Some(id_type), Some(id_value)) = (
        id_type.filter(|s| !s.is_empty()),
        id_value.filter(|s| !s.is_empty()),
    ) else {
        return Err("fill in ID type and ID value (BRN/NRIC) first — LHDN searches by them".into());
    };
    // LHDN wants bare digits/letters — strip dashes, spaces, dots.
    let id_value: String = id_value.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let api = api_client_from_settings(db).await?;
    // ID-only first: it is the precise key. LHDN ANDs the criteria,
    // so a name spelled differently from the registration would turn
    // a correct ID into a false "not found" — only add the name when
    // the ID alone finds nothing.
    if let Some(tin) = api.search_tin(&id_type, &id_value, None).await? {
        return Ok(Some(tin));
    }
    api.search_tin(&id_type, &id_value, Some(&name)).await
}

/// Validate the profile's stored TIN against its ID pair per LHDN.
pub async fn validate_tin_for_profile(db: &PgPool, profile_id: Uuid) -> Result<bool, String> {
    let row = vortex_plugin_sdk::sqlx::query(
        "SELECT tin, id_type, id_value FROM acc_partner_tax_profile WHERE id = $1",
    )
    .bind(profile_id)
    .fetch_optional(db)
    .await
    .map_err(|e| e.to_string())?
    .ok_or("profile not found")?;
    let tin: Option<String> = row.get("tin");
    let id_type: Option<String> = row.get("id_type");
    let id_value: Option<String> = row.get("id_value");
    let (Some(tin), Some(id_type), Some(id_value)) = (
        tin.filter(|s| !s.is_empty()),
        id_type.filter(|s| !s.is_empty()),
        id_value.filter(|s| !s.is_empty()),
    ) else {
        return Err("TIN, ID type and ID value must all be filled to validate".into());
    };
    let tin: String = tin.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let id_value: String = id_value.chars().filter(|c| c.is_ascii_alphanumeric()).collect();
    let api = api_client_from_settings(db).await?;
    api.validate_tin(&tin, &id_type, &id_value).await
}
