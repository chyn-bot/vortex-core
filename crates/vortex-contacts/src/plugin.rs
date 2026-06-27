//! [`ContactsPlugin`] — the Plugin impl demonstrating every core
//! primitive on a single, simple module.

use std::sync::Arc;
use std::time::Duration;

use vortex_plugin_sdk::prelude::*;

use crate::handlers;

const MIG_001_TAGS: &str = include_str!("../migrations/001_contact_tags/postgres.sql");
const MIG_002_STREET3: &str = include_str!("../migrations/002_street3/postgres.sql");
const MIG_003_PIVOT_METADATA: &str =
    include_str!("../migrations/003_pivot_metadata/postgres.sql");
const MIG_004_LIST_URL: &str = include_str!("../migrations/004_list_url/postgres.sql");

pub struct ContactsPlugin;

impl ContactsPlugin {
    pub fn new() -> Self {
        Self
    }
}

impl Default for ContactsPlugin {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Plugin for ContactsPlugin {
    fn technical_name(&self) -> &'static str {
        "contacts"
    }

    fn display_name(&self) -> &'static str {
        "Contacts"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    /// CRUD routes for contacts.
    fn routes(&self) -> Router<Arc<AppState>> {
        handlers::contacts_routes()
    }

    /// Sidebar entry under Operations.
    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![MenuEntry::new(
            "contacts.list",
            "Contacts",
            "/contacts",
            MenuGroup::Operations,
        )
        .with_icon("users")
        .with_priority(10)]
    }

    /// Plugin-owned migration: the `contact_tags` extension tables.
    /// The core `contacts` table is owned by core migration 010;
    /// this plugin adds metadata on top.
    fn migrations(&self) -> Vec<PluginMigration> {
        vec![
            PluginMigration {
                name: "001_contact_tags",
                up_sql: MIG_001_TAGS,
                down_sql: None,
                requires_core_migration: Some("010_contacts"),
            },
            PluginMigration {
                name: "002_street3",
                up_sql: MIG_002_STREET3,
                down_sql: None,
                requires_core_migration: Some("010_contacts"),
            },
            PluginMigration {
                name: "003_pivot_metadata",
                up_sql: MIG_003_PIVOT_METADATA,
                down_sql: None,
                requires_core_migration: Some("122_model_registry"),
            },
            PluginMigration {
                name: "004_list_url",
                up_sql: MIG_004_LIST_URL,
                down_sql: None,
                requires_core_migration: Some("123_model_list_url"),
            },
        ]
    }

    /// Translations: menu label and common UI strings in en + ms.
    fn translations(&self) -> Vec<Translation> {
        vec![
            // English
            Translation::new("en", "contacts", "menu.title", "Contacts"),
            Translation::new("en", "contacts", "btn.new_contact", "New Contact"),
            Translation::new("en", "contacts", "field.name", "Name"),
            Translation::new("en", "contacts", "field.email", "Email"),
            Translation::new("en", "contacts", "field.phone", "Phone"),
            Translation::new("en", "contacts", "field.type", "Type"),
            Translation::new("en", "contacts", "type.customer", "Customer"),
            Translation::new("en", "contacts", "type.supplier", "Supplier"),
            Translation::new("en", "contacts", "msg.created", "Contact created successfully"),
            // Malay
            Translation::new("ms", "contacts", "menu.title", "Kenalan"),
            Translation::new("ms", "contacts", "btn.new_contact", "Kenalan Baru"),
            Translation::new("ms", "contacts", "field.name", "Nama"),
            Translation::new("ms", "contacts", "field.email", "E-mel"),
            Translation::new("ms", "contacts", "field.phone", "Telefon"),
            Translation::new("ms", "contacts", "field.type", "Jenis"),
            Translation::new("ms", "contacts", "type.customer", "Pelanggan"),
            Translation::new("ms", "contacts", "type.supplier", "Pembekal"),
            Translation::new("ms", "contacts", "msg.created", "Kenalan berjaya dicipta"),
        ]
    }

    /// Background job: deactivate contacts not updated in 365 days.
    /// Demonstrates the scheduler primitive on a real domain concern.
    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "contacts.deactivate_stale",
                name: "Contacts: deactivate stale contacts",
                schedule: Schedule::Every(Duration::from_secs(24 * 60 * 60)), // daily
                enabled_by_default: false, // opt-in — admins enable when ready
            },
            |state| async move {
                let result = vortex_plugin_sdk::sqlx::query(
                    "UPDATE contacts SET active = false \
                     WHERE active = true \
                     AND updated_at < NOW() - INTERVAL '365 days'",
                )
                .execute(&state.db)
                .await
                .map_err(|e| VortexError::QueryExecution(e.to_string()))?;
                let count = result.rows_affected();
                if count > 0 {
                    vortex_plugin_sdk::tracing::info!(
                        count = count as i64,
                        "deactivated stale contacts"
                    );
                }
                Ok(())
            },
        )]
    }

    /// Reports: Contact Directory in HTML, CSV, and JSON.
    fn reports(&self) -> Vec<ReportDef> {
        vec![ReportDef::new(
            "contacts.directory",
            "Contact Directory",
            "List of all active contacts with name, email, phone, and type",
            vec![ReportFormat::Html, ReportFormat::Csv, ReportFormat::Json],
            |state, params| async move {
                // Fetch active contacts.
                let rows: Vec<(String, Option<String>, Option<String>, String)> =
                    vortex_plugin_sdk::sqlx::query_as(
                        "SELECT name, email, phone, contact_type \
                         FROM contacts WHERE active ORDER BY name",
                    )
                    .fetch_all(&state.db)
                    .await
                    .map_err(|e| VortexError::QueryExecution(e.to_string()))?;

                match params.format {
                    ReportFormat::Html => {
                        let mut html = String::from(
                            "<!DOCTYPE html><html><head>\
                             <title>Contact Directory</title>\
                             <style>\
                             body{font-family:sans-serif;margin:2em}\
                             table{border-collapse:collapse;width:100%}\
                             th,td{border:1px solid #ddd;padding:8px;text-align:left}\
                             th{background:#f5f5f5}\
                             @media print{body{margin:0}}\
                             </style></head><body>\
                             <h1>Contact Directory</h1>\
                             <table><tr><th>Name</th><th>Email</th><th>Phone</th><th>Type</th></tr>",
                        );
                        for (name, email, phone, ctype) in &rows {
                            html.push_str(&format!(
                                "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                                vortex_plugin_sdk::framework::html_escape(name),
                                vortex_plugin_sdk::framework::html_escape(
                                    email.as_deref().unwrap_or("")
                                ),
                                vortex_plugin_sdk::framework::html_escape(
                                    phone.as_deref().unwrap_or("")
                                ),
                                vortex_plugin_sdk::framework::html_escape(ctype),
                            ));
                        }
                        html.push_str("</table></body></html>");
                        Ok(ReportOutput::html("contact-directory.html", html))
                    }
                    ReportFormat::Csv => {
                        let mut out = Vec::new();
                        out.extend_from_slice(b"Name,Email,Phone,Type\n");
                        for (name, email, phone, ctype) in &rows {
                            out.extend_from_slice(
                                format!(
                                    "\"{}\",\"{}\",\"{}\",\"{}\"\n",
                                    name,
                                    email.as_deref().unwrap_or(""),
                                    phone.as_deref().unwrap_or(""),
                                    ctype
                                )
                                .as_bytes(),
                            );
                        }
                        Ok(ReportOutput::csv("contact-directory.csv", out))
                    }
                    ReportFormat::Json => {
                        let data: Vec<vortex_plugin_sdk::serde_json::Value> = rows
                            .iter()
                            .map(|(name, email, phone, ctype)| {
                                vortex_plugin_sdk::serde_json::json!({
                                    "name": name,
                                    "email": email,
                                    "phone": phone,
                                    "type": ctype,
                                })
                            })
                            .collect();
                        ReportOutput::json("contact-directory.json", &data)
                            .map_err(|e| VortexError::Internal(e.to_string()))
                    }
                }
            },
        )]
    }
}
