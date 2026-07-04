//! UBL 2.1 e-invoice XML builder — LHDN MyInvois document version 1.0
//! (unsigned; the proven submission path — see docs/MYINVOIS_NOTES.md).
//!
//! Pure: a fully-resolved [`EinvoiceDoc`] in, XML out. All free text is
//! XML-escaped; amounts are 2-dp; quantities 4-dp. Field structure
//! ports the working Odoo implementation:
//!
//! - `IssueDate`/`IssueTime` are the **submission moment in UTC**, not
//!   the accounting date (LHDN rejects stale timestamps).
//! - TaxScheme is always `OTH` (`UN/ECE 5153`, agency 6).
//! - Classification is emitted twice per line (`PTC` and `CLASS`).
//! - Credit/debit/refund notes carry a `BillingReference` to the
//!   original document's number and LHDN UUID.
//! - Consolidated B2C uses the General Public buyer
//!   (TIN `EI00000000010`) and an `InvoicePeriod`.

use vortex_plugin_sdk::chrono::{DateTime, NaiveDate, Utc};
use vortex_plugin_sdk::rust_decimal::Decimal;

#[derive(Debug, Clone)]
pub struct Address {
    pub line1: String,
    pub line2: String,
    pub city: String,
    pub postcode: String,
    /// LHDN state code ('01'–'17')
    pub state_code: String,
    /// LHDN country code (e.g. 'MYS')
    pub country_code: String,
}

#[derive(Debug, Clone)]
pub struct Party {
    pub name: String,
    pub tin: String,
    /// BRN | NRIC | PASSPORT | ARMY
    pub id_type: String,
    pub id_value: String,
    pub sst_registration: Option<String>,
    /// (code, description) — required on the supplier side
    pub msic: Option<(String, String)>,
    pub address: Address,
    pub phone: String,
    pub email: Option<String>,
}

impl Party {
    /// The LHDN consolidated-B2C "General Public" buyer.
    pub fn general_public() -> Self {
        Self {
            name: "General Public".into(),
            tin: "EI00000000010".into(),
            id_type: "BRN".into(),
            id_value: "NA".into(),
            sst_registration: None,
            msic: None,
            address: Address {
                line1: "NA".into(),
                line2: String::new(),
                city: "NA".into(),
                postcode: "00000".into(),
                state_code: "17".into(),
                country_code: "MYS".into(),
            },
            phone: "NA".into(),
            email: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct LineTax {
    /// LHDN tax type code: 01 sales, 02 service, E exempt, 06 n/a
    pub code: String,
    pub rate_percent: Decimal,
    pub amount: Decimal,
    pub exemption_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct DocLine {
    pub id: String,
    pub description: String,
    pub quantity: Decimal,
    pub unit_price: Decimal,
    pub subtotal: Decimal,
    pub classification_code: String,
    pub uom_code: String,
    pub tax: Option<LineTax>,
}

#[derive(Debug, Clone)]
pub struct TaxSubtotal {
    pub code: String,
    pub rate_percent: Decimal,
    pub taxable: Decimal,
    pub amount: Decimal,
    pub exemption_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct EinvoiceDoc {
    /// LHDN doc type: 01/02/03/04, 11–14 self-billed
    pub doc_type_code: String,
    /// Document version — "1.0" (unsigned)
    pub version: String,
    pub number: String,
    /// Submission moment (UTC) — becomes IssueDate/IssueTime
    pub issued_at: DateTime<Utc>,
    pub currency: String,
    /// MYR-per-unit rate when currency ≠ MYR (else 1.0)
    pub exchange_rate: Decimal,
    pub supplier: Party,
    pub buyer: Party,
    pub lines: Vec<DocLine>,
    pub tax_subtotals: Vec<TaxSubtotal>,
    pub untaxed: Decimal,
    pub tax_total: Decimal,
    pub total: Decimal,
    /// (original number, original LHDN uuid) for credit/debit/refund notes
    pub billing_reference: Option<(String, String)>,
    /// Consolidated B2C period
    pub invoice_period: Option<(NaiveDate, NaiveDate)>,
}

fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

fn m(d: Decimal) -> String {
    format!("{:.2}", d.round_dp(2))
}

fn q(d: Decimal) -> String {
    format!("{}", d.round_dp(4).normalize())
}

/// Keep digits and `+` only (LHDN phone rule).
pub fn sanitize_phone(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| c.is_ascii_digit() || *c == '+').collect();
    if cleaned.is_empty() { "NA".into() } else { cleaned }
}

fn party_xml(tag: &str, p: &Party, industry: bool) -> String {
    let mut out = format!("<cac:{tag}><cac:Party>");
    if industry {
        if let Some((code, desc)) = &p.msic {
            out.push_str(&format!(
                r#"<cbc:IndustryClassificationCode name="{}">{}</cbc:IndustryClassificationCode>"#,
                esc(desc),
                esc(code)
            ));
        }
    }
    out.push_str(&format!(
        r#"<cac:PartyIdentification><cbc:ID schemeID="TIN">{}</cbc:ID></cac:PartyIdentification>"#,
        esc(&p.tin)
    ));
    out.push_str(&format!(
        r#"<cac:PartyIdentification><cbc:ID schemeID="{}">{}</cbc:ID></cac:PartyIdentification>"#,
        esc(&p.id_type),
        esc(&p.id_value)
    ));
    if let Some(sst) = &p.sst_registration {
        out.push_str(&format!(
            r#"<cac:PartyIdentification><cbc:ID schemeID="SST">{}</cbc:ID></cac:PartyIdentification>"#,
            esc(sst)
        ));
    }
    out.push_str(&format!(
        "<cac:PostalAddress><cbc:CityName>{}</cbc:CityName><cbc:PostalZone>{}</cbc:PostalZone>\
         <cbc:CountrySubentityCode>{}</cbc:CountrySubentityCode>\
         <cac:AddressLine><cbc:Line>{}</cbc:Line></cac:AddressLine>\
         <cac:AddressLine><cbc:Line>{}</cbc:Line></cac:AddressLine>\
         <cac:Country><cbc:IdentificationCode listID=\"ISO3166-1\" listAgencyID=\"6\">{}</cbc:IdentificationCode></cac:Country>\
         </cac:PostalAddress>",
        esc(&p.address.city),
        esc(&p.address.postcode),
        esc(&p.address.state_code),
        esc(&p.address.line1),
        esc(&p.address.line2),
        esc(&p.address.country_code),
    ));
    out.push_str(&format!(
        "<cac:PartyLegalEntity><cbc:RegistrationName>{}</cbc:RegistrationName></cac:PartyLegalEntity>",
        esc(&p.name)
    ));
    out.push_str(&format!(
        "<cac:Contact><cbc:Telephone>{}</cbc:Telephone><cbc:ElectronicMail>{}</cbc:ElectronicMail></cac:Contact>",
        esc(&sanitize_phone(&p.phone)),
        esc(p.email.as_deref().unwrap_or("NA")),
    ));
    out.push_str("</cac:Party></cac:");
    out.push_str(tag);
    out.push('>');
    out
}

fn tax_category(code: &str, percent: Decimal, exemption: Option<&str>) -> String {
    let reason = exemption
        .map(|r| format!("<cbc:TaxExemptionReason>{}</cbc:TaxExemptionReason>", esc(r)))
        .unwrap_or_default();
    format!(
        "<cac:TaxCategory><cbc:ID>{}</cbc:ID><cbc:Percent>{}</cbc:Percent>{}\
         <cac:TaxScheme><cbc:ID schemeID=\"UN/ECE 5153\" schemeAgencyID=\"6\">OTH</cbc:ID></cac:TaxScheme>\
         </cac:TaxCategory>",
        esc(code),
        m(percent),
        reason,
    )
}

/// Build the UBL 2.1 invoice XML (LHDN MyInvois shape, version 1.0).
pub fn build_xml(doc: &EinvoiceDoc) -> String {
    let cur = esc(&doc.currency);
    let mut x = String::with_capacity(8192);
    x.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
    x.push_str(
        r#"<Invoice xmlns="urn:oasis:names:specification:ubl:schema:xsd:Invoice-2" xmlns:cac="urn:oasis:names:specification:ubl:schema:xsd:CommonAggregateComponents-2" xmlns:cbc="urn:oasis:names:specification:ubl:schema:xsd:CommonBasicComponents-2">"#,
    );
    x.push_str(&format!("<cbc:ID>{}</cbc:ID>", esc(&doc.number)));
    x.push_str(&format!(
        "<cbc:IssueDate>{}</cbc:IssueDate><cbc:IssueTime>{}Z</cbc:IssueTime>",
        doc.issued_at.format("%Y-%m-%d"),
        doc.issued_at.format("%H:%M:%S"),
    ));
    x.push_str(&format!(
        r#"<cbc:InvoiceTypeCode listVersionID="{}">{}</cbc:InvoiceTypeCode>"#,
        esc(&doc.version),
        esc(&doc.doc_type_code),
    ));
    x.push_str(&format!(
        "<cbc:DocumentCurrencyCode>{cur}</cbc:DocumentCurrencyCode>\
         <cbc:TaxCurrencyCode>{cur}</cbc:TaxCurrencyCode>",
    ));
    if let Some((start, end)) = &doc.invoice_period {
        x.push_str(&format!(
            "<cac:InvoicePeriod><cbc:StartDate>{start}</cbc:StartDate>\
             <cbc:EndDate>{end}</cbc:EndDate><cbc:Description>Monthly</cbc:Description></cac:InvoicePeriod>",
        ));
    }
    if let Some((number, uuid)) = &doc.billing_reference {
        x.push_str(&format!(
            "<cac:BillingReference><cac:InvoiceDocumentReference>\
             <cbc:ID>{}</cbc:ID><cbc:UUID>{}</cbc:UUID>\
             </cac:InvoiceDocumentReference></cac:BillingReference>",
            esc(number),
            esc(uuid),
        ));
    }
    x.push_str(&party_xml("AccountingSupplierParty", &doc.supplier, true));
    x.push_str(&party_xml("AccountingCustomerParty", &doc.buyer, false));

    // Exchange rate block (always emitted; 1.0 for MYR docs)
    x.push_str(&format!(
        "<cac:TaxExchangeRate><cbc:SourceCurrencyCode>{cur}</cbc:SourceCurrencyCode>\
         <cbc:TargetCurrencyCode>MYR</cbc:TargetCurrencyCode>\
         <cbc:CalculationRate>{}</cbc:CalculationRate></cac:TaxExchangeRate>",
        m(doc.exchange_rate),
    ));

    // Document-level TaxTotal with one subtotal per (code, rate)
    x.push_str(&format!(
        r#"<cac:TaxTotal><cbc:TaxAmount currencyID="{cur}">{}</cbc:TaxAmount>"#,
        m(doc.tax_total),
    ));
    for sub in &doc.tax_subtotals {
        x.push_str(&format!(
            r#"<cac:TaxSubtotal><cbc:TaxableAmount currencyID="{cur}">{}</cbc:TaxableAmount><cbc:TaxAmount currencyID="{cur}">{}</cbc:TaxAmount>{}</cac:TaxSubtotal>"#,
            m(sub.taxable),
            m(sub.amount),
            tax_category(&sub.code, sub.rate_percent, sub.exemption_reason.as_deref()),
        ));
    }
    x.push_str("</cac:TaxTotal>");

    // Monetary totals
    x.push_str(&format!(
        r#"<cac:LegalMonetaryTotal><cbc:LineExtensionAmount currencyID="{cur}">{u}</cbc:LineExtensionAmount><cbc:TaxExclusiveAmount currencyID="{cur}">{u}</cbc:TaxExclusiveAmount><cbc:TaxInclusiveAmount currencyID="{cur}">{t}</cbc:TaxInclusiveAmount><cbc:AllowanceTotalAmount currencyID="{cur}">0.00</cbc:AllowanceTotalAmount><cbc:ChargeTotalAmount currencyID="{cur}">0.00</cbc:ChargeTotalAmount><cbc:PayableRoundingAmount currencyID="{cur}">0.00</cbc:PayableRoundingAmount><cbc:PayableAmount currencyID="{cur}">{t}</cbc:PayableAmount></cac:LegalMonetaryTotal>"#,
        u = m(doc.untaxed),
        t = m(doc.total),
    ));

    // Lines
    for line in &doc.lines {
        let (line_tax_amount, line_tax_cat) = match &line.tax {
            Some(t) => (
                t.amount,
                tax_category(&t.code, t.rate_percent, t.exemption_reason.as_deref()),
            ),
            None => (Decimal::ZERO, tax_category("06", Decimal::ZERO, None)),
        };
        x.push_str(&format!(
            r#"<cac:InvoiceLine><cbc:ID>{id}</cbc:ID><cbc:InvoicedQuantity unitCode="{uom}">{qty}</cbc:InvoicedQuantity><cbc:LineExtensionAmount currencyID="{cur}">{sub}</cbc:LineExtensionAmount><cac:TaxTotal><cbc:TaxAmount currencyID="{cur}">{tax}</cbc:TaxAmount><cac:TaxSubtotal><cbc:TaxableAmount currencyID="{cur}">{sub}</cbc:TaxableAmount><cbc:TaxAmount currencyID="{cur}">{tax}</cbc:TaxAmount>{cat}</cac:TaxSubtotal></cac:TaxTotal><cac:Item><cbc:Description>{desc}</cbc:Description><cac:OriginCountry><cbc:IdentificationCode>MYS</cbc:IdentificationCode></cac:OriginCountry><cac:CommodityClassification><cbc:ItemClassificationCode listID="PTC">{class}</cbc:ItemClassificationCode></cac:CommodityClassification><cac:CommodityClassification><cbc:ItemClassificationCode listID="CLASS">{class}</cbc:ItemClassificationCode></cac:CommodityClassification></cac:Item><cac:Price><cbc:PriceAmount currencyID="{cur}">{price}</cbc:PriceAmount></cac:Price><cac:ItemPriceExtension><cbc:Amount currencyID="{cur}">{sub}</cbc:Amount></cac:ItemPriceExtension></cac:InvoiceLine>"#,
            id = esc(&line.id),
            uom = esc(&line.uom_code),
            qty = q(line.quantity),
            sub = m(line.subtotal),
            tax = m(line_tax_amount),
            cat = line_tax_cat,
            desc = esc(&line.description),
            class = esc(&line.classification_code),
            price = q(line.unit_price),
        ));
    }
    x.push_str("</Invoice>");
    x
}

#[cfg(test)]
mod tests {
    use super::*;
    use rust_decimal_macros::dec;
    use vortex_plugin_sdk::chrono::TimeZone;

    fn supplier() -> Party {
        Party {
            name: "Remicle Sdn Bhd".into(),
            tin: "C1234567890".into(),
            id_type: "BRN".into(),
            id_value: "202301012345".into(),
            sst_registration: Some("W10-1808-32000001".into()),
            msic: Some(("62010".into(), "Computer programming activities".into())),
            address: Address {
                line1: "Level 10, Menara Vortex".into(),
                line2: "Jalan Teknologi".into(),
                city: "Kuala Lumpur".into(),
                postcode: "50480".into(),
                state_code: "14".into(),
                country_code: "MYS".into(),
            },
            phone: "+603-1234 5678".into(),
            email: Some("billing@remicle.com".into()),
        }
    }

    fn buyer() -> Party {
        Party {
            name: "Acme & Sons <M> Sdn Bhd".into(),
            tin: "C9876543210".into(),
            id_type: "BRN".into(),
            id_value: "201501054321".into(),
            sst_registration: None,
            msic: None,
            address: Address {
                line1: "12 Jalan Acme".into(),
                line2: String::new(),
                city: "Shah Alam".into(),
                postcode: "40000".into(),
                state_code: "10".into(),
                country_code: "MYS".into(),
            },
            phone: "0123456789".into(),
            email: None,
        }
    }

    fn doc() -> EinvoiceDoc {
        EinvoiceDoc {
            doc_type_code: "01".into(),
            version: "1.0".into(),
            number: "SAL/2026/00042".into(),
            issued_at: Utc.with_ymd_and_hms(2026, 7, 4, 10, 30, 0).unwrap(),
            currency: "MYR".into(),
            exchange_rate: dec!(1.0),
            supplier: supplier(),
            buyer: buyer(),
            lines: vec![
                DocLine {
                    id: "1".into(),
                    description: "Consulting services".into(),
                    quantity: dec!(1),
                    unit_price: dec!(1000.00),
                    subtotal: dec!(1000.00),
                    classification_code: "022".into(),
                    uom_code: "C62".into(),
                    tax: Some(LineTax {
                        code: "02".into(),
                        rate_percent: dec!(8),
                        amount: dec!(80.00),
                        exemption_reason: None,
                    }),
                },
                DocLine {
                    id: "2".into(),
                    description: "Disbursement".into(),
                    quantity: dec!(1),
                    unit_price: dec!(100.00),
                    subtotal: dec!(100.00),
                    classification_code: "022".into(),
                    uom_code: "C62".into(),
                    tax: None,
                },
            ],
            tax_subtotals: vec![TaxSubtotal {
                code: "02".into(),
                rate_percent: dec!(8),
                taxable: dec!(1000.00),
                amount: dec!(80.00),
                exemption_reason: None,
            }],
            untaxed: dec!(1100.00),
            tax_total: dec!(80.00),
            total: dec!(1180.00),
            billing_reference: None,
            invoice_period: None,
        }
    }

    #[test]
    fn golden_invoice_structure() {
        let xml = build_xml(&doc());
        // Header rules
        assert!(xml.contains(r#"<cbc:InvoiceTypeCode listVersionID="1.0">01</cbc:InvoiceTypeCode>"#));
        assert!(xml.contains("<cbc:IssueDate>2026-07-04</cbc:IssueDate>"));
        assert!(xml.contains("<cbc:IssueTime>10:30:00Z</cbc:IssueTime>"));
        // Supplier identity incl. MSIC + escaped ampersand in buyer name
        assert!(xml.contains(r#"<cbc:IndustryClassificationCode name="Computer programming activities">62010</cbc:IndustryClassificationCode>"#));
        assert!(xml.contains(r#"<cbc:ID schemeID="TIN">C1234567890</cbc:ID>"#));
        assert!(xml.contains("Acme &amp; Sons &lt;M&gt; Sdn Bhd"));
        // Phone sanitized to digits and +
        assert!(xml.contains("<cbc:Telephone>+60312345678</cbc:Telephone>"));
        // Tax scheme OTH under UN/ECE 5153
        assert!(xml.contains(r#"<cac:TaxScheme><cbc:ID schemeID="UN/ECE 5153" schemeAgencyID="6">OTH</cbc:ID></cac:TaxScheme>"#));
        // Untaxed line gets category 06
        assert!(xml.contains("<cac:TaxCategory><cbc:ID>06</cbc:ID>"));
        // Classification appears under both list IDs
        assert!(xml.contains(r#"<cbc:ItemClassificationCode listID="PTC">022</cbc:ItemClassificationCode>"#));
        assert!(xml.contains(r#"<cbc:ItemClassificationCode listID="CLASS">022</cbc:ItemClassificationCode>"#));
        // Totals
        assert!(xml.contains(r#"<cbc:TaxInclusiveAmount currencyID="MYR">1180.00</cbc:TaxInclusiveAmount>"#));
        assert!(xml.contains(r#"<cbc:PayableAmount currencyID="MYR">1180.00</cbc:PayableAmount>"#));
        // Exchange rate emitted even for MYR
        assert!(xml.contains("<cbc:CalculationRate>1.00</cbc:CalculationRate>"));
        // No signature blocks in v1.0
        assert!(!xml.contains("UBLExtensions"));
        assert!(!xml.contains("Signature"));
    }

    #[test]
    fn credit_note_carries_billing_reference() {
        let mut d = doc();
        d.doc_type_code = "02".into();
        d.billing_reference = Some(("SAL/2026/00042".into(), "ABC123UUID".into()));
        let xml = build_xml(&d);
        assert!(xml.contains("<cac:BillingReference><cac:InvoiceDocumentReference>"));
        assert!(xml.contains("<cbc:UUID>ABC123UUID</cbc:UUID>"));
        assert!(xml.contains(r#">02</cbc:InvoiceTypeCode>"#));
    }

    #[test]
    fn consolidated_uses_general_public_and_period() {
        let mut d = doc();
        d.buyer = Party::general_public();
        d.invoice_period = Some((
            NaiveDate::from_ymd_opt(2026, 6, 1).unwrap(),
            NaiveDate::from_ymd_opt(2026, 6, 30).unwrap(),
        ));
        let xml = build_xml(&d);
        assert!(xml.contains(r#"<cbc:ID schemeID="TIN">EI00000000010</cbc:ID>"#));
        assert!(xml.contains("<cbc:RegistrationName>General Public</cbc:RegistrationName>"));
        assert!(xml.contains("<cbc:StartDate>2026-06-01</cbc:StartDate>"));
        assert!(xml.contains("<cbc:EndDate>2026-06-30</cbc:EndDate>"));
        assert!(xml.contains("<cbc:CountrySubentityCode>17</cbc:CountrySubentityCode>"));
    }

    #[test]
    fn phone_sanitization() {
        assert_eq!(sanitize_phone("+603-1234 5678"), "+60312345678");
        assert_eq!(sanitize_phone("(012) 345-6789"), "0123456789");
        assert_eq!(sanitize_phone(""), "NA");
    }
}
