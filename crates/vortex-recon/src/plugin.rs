//! [`ReconPlugin`] — the Plugin impl. Everything is declarative:
//! state what you have, the host wires it.

use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_INIT: &str = include_str!("../migrations/001_init/postgres.sql");
const MIG_002_MASTER: &str = include_str!("../migrations/002_master_data/postgres.sql");
const MIG_003_OPERATIONAL: &str = include_str!("../migrations/003_operational/postgres.sql");
const MIG_004_UPLOAD: &str = include_str!("../migrations/004_upload/postgres.sql");
const MIG_005_M3_POOL: &str = include_str!("../migrations/005_m3_pool/postgres.sql");
const MIG_006_VALIDATION: &str = include_str!("../migrations/006_validation/postgres.sql");
const MIG_007_AI_CONFIG: &str = include_str!("../migrations/007_ai_config/postgres.sql");
const MIG_008_DISCOUNT_TAX: &str = include_str!("../migrations/008_discount_tax/postgres.sql");
const MIG_009_TAX_MODE: &str = include_str!("../migrations/009_tax_mode/postgres.sql");
const MIG_010_DISCOUNT_AMOUNT: &str =
    include_str!("../migrations/010_discount_amount/postgres.sql");
const MIG_011_INGEST_SOURCE: &str =
    include_str!("../migrations/011_ingest_source/postgres.sql");
const MIG_012_M3_VENDOR_ITEM: &str =
    include_str!("../migrations/012_m3_vendor_item/postgres.sql");
const MIG_013_M3_GL_ACCOUNT: &str =
    include_str!("../migrations/013_m3_gl_account/postgres.sql");
const MIG_014_STAGE_ACTIONS: &str =
    include_str!("../migrations/014_stage_actions/postgres.sql");
const MIG_015_GL_ENTRY: &str = include_str!("../migrations/015_gl_entry/postgres.sql");
const MIG_016_SKU_MASTER: &str = include_str!("../migrations/016_sku_master/postgres.sql");
const MIG_017_IMAGE_LOCATE: &str =
    include_str!("../migrations/017_image_locate/postgres.sql");
const MIG_018_AI_USAGE: &str = include_str!("../migrations/018_ai_usage/postgres.sql");
const MIG_019_EXTRACT_HINTS: &str =
    include_str!("../migrations/019_extract_hints/postgres.sql");
const MIG_020_AI_MULTI_PROVIDER: &str =
    include_str!("../migrations/020_ai_multi_provider/postgres.sql");
const MIG_021_BATCH_EXTRACTION: &str =
    include_str!("../migrations/021_batch_extraction/postgres.sql");
const MIG_022_AI_USAGE_MODE: &str =
    include_str!("../migrations/022_ai_usage_mode/postgres.sql");
const MIG_023_DESC_GL_KEY: &str =
    include_str!("../migrations/023_desc_gl_key/postgres.sql");

pub struct ReconPlugin;

impl ReconPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ReconPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for ReconPlugin {
    fn technical_name(&self) -> &'static str {
        "recon"
    }

    fn display_name(&self) -> &'static str {
        "Reconciliation"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::routes()
    }

    /// Anonymous portal surface — tenant-resolved from the request
    /// Host and 404 for tenants without this module installed.
    fn public_routes(&self) -> Router<Arc<AppState>> {
        handlers::public_routes()
    }

    /// Model-registry projection (Initiative #1). The host syncs these into
    /// `ir_model` / `ir_model_field` after migrations, so the registry always
    /// mirrors the code — no hand-seeded SQL in the migration.
    fn models(&self) -> Vec<&'static vortex_plugin_sdk::orm::model::ModelMeta> {
        use vortex_plugin_sdk::orm::model::Model;
        vec![
            <crate::model::ReconBatch as Model>::meta(),
            <crate::model::VendorItemAlias as Model>::meta(),
            <crate::model::SupplierApprovalMatrix as Model>::meta(),
        ]
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        // NOTE: the sidebar renderer (`build_sidebar_nav`) only collects plugin
        // entries from `MenuGroup::Operations` — entries placed in other groups
        // are silently dropped. Master-data screens therefore live under an
        // Operations "Configuration" submenu, not `Administration`.
        vec![
            // Analytics overview — pipeline funnel, verification KPIs, recent activity.
            MenuEntry::new("recon.dashboard", "Dashboard", "/recon/dashboard", MenuGroup::Operations)
                .with_icon("chart-bar")
                .with_priority(45),
            // The reconciliation workbench (bespoke handlers).
            MenuEntry::new("recon.list", "Reconciliation", "/recon", MenuGroup::Operations)
                .with_icon("clipboard-check")
                .with_priority(50),
            // Invoice upload inbox — separate step from reconciliation.
            MenuEntry::new("recon.upload", "Upload Invoices", "/recon/upload", MenuGroup::Operations)
                .with_icon("clipboard-list")
                .with_priority(55),
            // Batch extraction queue (async, cheaper) + manual submit.
            MenuEntry::new("recon.batch", "Batch Extraction", "/recon/batch", MenuGroup::Operations)
                .with_icon("bolt")
                .with_priority(56),
            // QA worklist — every invoice's captured-vs-M3 status at a glance.
            MenuEntry::new("recon.verify", "Verification", "/recon/verify", MenuGroup::Operations)
                .with_icon("check-circle")
                .with_priority(56),
            // M3 (ERP) data pool — bulk CSV/Excel import, linked at match time.
            MenuEntry::new("recon.m3", "M3 Data (ERP)", "/recon/m3", MenuGroup::Operations)
                .with_icon("diagram")
                .with_priority(57),
            // Master data — collapsible "Configuration" submenu; the leaves are
            // generic list/form CRUD from the registered models.
            MenuEntry::new("recon.config", "Configuration", "#", MenuGroup::Operations)
                .with_icon("cog")
                .with_priority(90),
            MenuEntry::new(
                "recon.vendor_item_alias",
                "Vendor Item Aliases",
                "/list/vendor_item_alias",
                MenuGroup::Operations,
            )
            .with_icon("tag")
            .with_priority(91)
            .under("recon.config"),
            MenuEntry::new(
                "recon.supplier_approval_matrix",
                "Approval Matrix",
                "/list/supplier_approval_matrix",
                MenuGroup::Operations,
            )
            .with_icon("check-circle")
            .with_priority(92)
            .under("recon.config"),
            // AI OCR provider settings (bespoke handler — encrypted API key).
            // Superadmin-only: holds the LLM API key + extraction cost lever.
            // The route enforces this too (see `ai_config_form`/`ai_config_save`).
            MenuEntry::new("recon.ai", "AI Extraction", "/recon/ai", MenuGroup::Operations)
                .with_icon("cog")
                .with_priority(93)
                .under("recon.config")
                .require_role("System Administrator"),
            // AI token usage + extraction cost — superadmin only (route enforces).
            MenuEntry::new("recon.ai_usage", "AI Usage & Cost", "/recon/ai/usage", MenuGroup::Operations)
                .with_icon("chart-bar")
                .with_priority(93)
                .under("recon.config")
                .require_role("System Administrator"),
            // Remote SFTP/FTP auto-pickup sources.
            MenuEntry::new("recon.ingest", "Auto-Pickup (SFTP/FTP)", "/recon/ingest", MenuGroup::Operations)
                .with_icon("cloud")
                .with_priority(94)
                .under("recon.config"),
            // GL account mapping (double-entry generation).
            MenuEntry::new("recon.gl", "GL Mapping", "/recon/gl", MenuGroup::Operations)
                .with_icon("cog")
                .with_priority(95)
                .under("recon.config"),
        ]
    }

    /// Background poller: every 5 minutes, pull from any ingest source whose
    /// interval has elapsed, across all active tenants.
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "recon.ingest_poll",
                    name: "Reconciliation: poll SFTP/FTP pickup folders",
                    schedule: Schedule::Every(std::time::Duration::from_secs(300)),
                    enabled_by_default: true,
                },
                |state| async move {
                    crate::handlers::poll_all_tenants(&state).await;
                    Ok(())
                },
            ),
            // Complete finished extraction batches (and auto-submit the queue
            // when the active profile has auto-submit enabled).
            ScheduledAction::new(
                ScheduledActionDef {
                    code: "recon.batch_poll",
                    name: "Reconciliation: complete/auto-submit extraction batches",
                    schedule: Schedule::Every(std::time::Duration::from_secs(120)),
                    enabled_by_default: true,
                },
                |state| async move {
                    crate::handlers::poll_batches_all_tenants(&state).await;
                    Ok(())
                },
            ),
        ]
    }

    /// Plugin-owned schema, applied per tenant on install.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_init",
                up_sql: MIG_001_INIT,
                down_sql: None,
                // record_stages (status bar) and the model registry are
                // core features this migration seeds rows into.
                requires_core_migration: Some("124_record_stages"),
            },
            PluginMigration {
                name: "002_master_data",
                up_sql: MIG_002_MASTER,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "003_operational",
                up_sql: MIG_003_OPERATIONAL,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "004_upload",
                up_sql: MIG_004_UPLOAD,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "005_m3_pool",
                up_sql: MIG_005_M3_POOL,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "006_validation",
                up_sql: MIG_006_VALIDATION,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "007_ai_config",
                up_sql: MIG_007_AI_CONFIG,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "008_discount_tax",
                up_sql: MIG_008_DISCOUNT_TAX,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "009_tax_mode",
                up_sql: MIG_009_TAX_MODE,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "010_discount_amount",
                up_sql: MIG_010_DISCOUNT_AMOUNT,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "011_ingest_source",
                up_sql: MIG_011_INGEST_SOURCE,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "012_m3_vendor_item",
                up_sql: MIG_012_M3_VENDOR_ITEM,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "013_m3_gl_account",
                up_sql: MIG_013_M3_GL_ACCOUNT,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "014_stage_actions",
                up_sql: MIG_014_STAGE_ACTIONS,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "015_gl_entry",
                up_sql: MIG_015_GL_ENTRY,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "016_sku_master",
                up_sql: MIG_016_SKU_MASTER,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "017_image_locate",
                up_sql: MIG_017_IMAGE_LOCATE,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "018_ai_usage",
                up_sql: MIG_018_AI_USAGE,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "019_extract_hints",
                up_sql: MIG_019_EXTRACT_HINTS,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "020_ai_multi_provider",
                up_sql: MIG_020_AI_MULTI_PROVIDER,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "021_batch_extraction",
                up_sql: MIG_021_BATCH_EXTRACTION,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "022_ai_usage_mode",
                up_sql: MIG_022_AI_USAGE_MODE,
                down_sql: None,
                requires_core_migration: None,
            },
            PluginMigration {
                name: "023_desc_gl_key",
                up_sql: MIG_023_DESC_GL_KEY,
                down_sql: None,
                requires_core_migration: None,
            },
        ]
    }
}
