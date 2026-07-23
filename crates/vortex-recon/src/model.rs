//! Reconciliation models — declared with `#[derive(Model)]`.
//!
//! Registry source of truth for the recon tables. `Plugin::models()`
//! returns these metas and the host projects them into
//! `ir_model` / `ir_model_field` after migrations (see
//! `vortex_orm::registry_sync`) — so there is **no hand-seeded registry
//! SQL** in the migrations. Keep each struct's fields in sync with its
//! table columns; `Option<T>` = optional, non-`Option` = required.
//!
//! - [`ReconBatch`]           — one per uploaded supplier invoice (the workbench record).
//! - [`VendorItemAlias`]      — supplier SKU → LSEO SKU + UOM pack factor (master data).
//! - [`SupplierApprovalMatrix`] — PV approval routing by supplier/division (master data).

use serde::{Deserialize, Serialize};
use uuid::Uuid;
use vortex_orm::prelude::Model;

/// The central reconciliation record — one per uploaded supplier invoice
/// document. Carries the extracted header, the ingest provenance, and the
/// lifecycle state (draft → extracted → matched → validated → approved).
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "recon_batch", module = "recon", name = "recon_batch", label = "Reconciliation")]
pub struct ReconBatch {
    #[vortex(primary_key)]
    pub id: Uuid,

    /// Stamped from the sequence after insert; not entered on the form.
    #[vortex(label = "Reference", ui_type = "string")]
    pub code: Option<String>,

    /// M3 supplier number (Supp_No), e.g. `101S008`. Nullable: a batch can be
    /// created by uploading a scanned PDF *before* the supplier is known
    /// (extraction fills it in later).
    #[vortex(label = "Supplier No", ui_type = "string")]
    pub supplier_no: Option<String>,

    #[vortex(label = "Supplier", ui_type = "string")]
    pub supplier_name: Option<String>,

    /// Invoice number exactly as extracted from the document.
    /// Original filename of the uploaded scanned invoice (shown in the inbox).
    #[vortex(label = "File", ui_type = "string")]
    pub scan_filename: Option<String>,

    #[vortex(label = "Invoice No", ui_type = "string")]
    pub invoice_no: Option<String>,

    /// Normalized base invoice number used for matching (M3 suffix/slash
    /// edits stripped: `I2512676-A` → `I2512676`, `4110123708/709` → base).
    #[vortex(label = "Invoice No (Canonical)", ui_type = "string")]
    pub invoice_no_canonical: Option<String>,

    #[vortex(label = "Invoice Date", ui_type = "date")]
    pub invoice_date: Option<String>,

    #[vortex(label = "Currency", ui_type = "string")]
    pub currency: Option<String>,

    #[vortex(label = "Currency Rate", ui_type = "number")]
    pub currency_rate: Option<f64>,

    /// Invoice grand total as extracted from the document.
    #[vortex(label = "Invoice Total", ui_type = "monetary")]
    pub doc_total: Option<f64>,

    /// Which ingest adapter produced the extracted data.
    #[vortex(label = "Source", selection = "myinvois,ocr_self,ocr_vision,manual")]
    pub source_provider: Option<String>,

    /// BRD phase: EDI-CSV suppliers (phase1) vs OCR-only suppliers (phase2).
    #[vortex(label = "Phase", selection = "phase1,phase2")]
    pub phase: Option<String>,

    /// M3 payment-voucher batch Proposal Number (P3PRPN) for PV grouping.
    #[vortex(label = "Proposal No", ui_type = "string")]
    pub proposal_no: Option<String>,

    /// Managed by the status bar, not the create form.
    #[vortex(label = "State", selection = "draft,extracted,matched,validated,approved,rejected")]
    pub record_state: String,

    #[vortex(label = "Active")]
    pub active: bool,
}

/// Master data: resolves a supplier's own item code to the LSEO SKU and
/// carries the UOM pack factor (supplier UOM → base UOM). Self-trains when a
/// reviewer remaps a line. Unique on `(supplier_no, supplier_sku)`.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "vendor_item_alias", module = "recon", name = "vendor_item_alias", label = "Vendor Item Alias")]
pub struct VendorItemAlias {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Supplier No", ui_type = "string")]
    pub supplier_no: String,

    /// The supplier's own item code (Supp_SKU) as printed on their invoice.
    #[vortex(label = "Supplier SKU", ui_type = "string")]
    pub supplier_sku: String,

    /// Supplier item description — used for trigram fuzzy match when no SKU
    /// is printed.
    #[vortex(label = "Supplier Description", ui_type = "text")]
    pub supplier_desc: Option<String>,

    /// LSEO item code (SKU), e.g. `LNA210C40`.
    #[vortex(label = "LSEO SKU", ui_type = "string")]
    pub lseo_sku: String,

    /// UOM printed on the supplier invoice, e.g. `CTN`.
    #[vortex(label = "Supplier UOM", ui_type = "string")]
    pub supplier_uom: Option<String>,

    /// LSEO basic UOM held in M3 (MMS001), e.g. `Dozen`.
    #[vortex(label = "Base UOM", ui_type = "string")]
    pub base_uom: Option<String>,

    /// Multiplier from supplier UOM to base UOM, e.g. `4` (1 CTN = 4 dozen).
    #[vortex(label = "Pack Factor", ui_type = "number")]
    pub pack_factor: Option<f64>,

    #[vortex(label = "Active")]
    pub active: bool,
}

/// Master data: PV approval routing. A supplier (+ division) maps to an
/// ordered chain of up to three approvers. Maker may override at runtime.
#[derive(Debug, Clone, Serialize, Deserialize, Model)]
#[vortex(table = "supplier_approval_matrix", module = "recon", name = "supplier_approval_matrix", label = "Supplier Approval Matrix")]
pub struct SupplierApprovalMatrix {
    #[vortex(primary_key)]
    pub id: Uuid,

    #[vortex(label = "Supplier No", ui_type = "string")]
    pub supplier_no: String,

    #[vortex(label = "Supplier", ui_type = "string")]
    pub supplier_name: Option<String>,

    #[vortex(label = "Division", ui_type = "string")]
    pub division: Option<String>,

    #[vortex(label = "1st Approver", ui_type = "string")]
    pub approver1_name: Option<String>,

    #[vortex(label = "1st Approver Email", ui_type = "string")]
    pub approver1_email: Option<String>,

    #[vortex(label = "2nd Approver", ui_type = "string")]
    pub approver2_name: Option<String>,

    #[vortex(label = "2nd Approver Email", ui_type = "string")]
    pub approver2_email: Option<String>,

    #[vortex(label = "3rd Approver", ui_type = "string")]
    pub approver3_name: Option<String>,

    #[vortex(label = "3rd Approver Email", ui_type = "string")]
    pub approver3_email: Option<String>,

    #[vortex(label = "Active")]
    pub active: bool,
}
