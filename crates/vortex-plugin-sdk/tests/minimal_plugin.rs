//! Compile test: verify that a minimal plugin can be built using
//! only the SDK prelude — no direct dependency on any `vortex-*`
//! internal crate. If this test compiles, the SDK surface is
//! sufficient for the basic Plugin contract.

use vortex_plugin_sdk::prelude::*;

struct TestPlugin;

#[async_trait]
impl Plugin for TestPlugin {
    fn technical_name(&self) -> &'static str {
        "test_plugin"
    }

    fn display_name(&self) -> &'static str {
        "Test Plugin"
    }

    fn version(&self) -> &'static str {
        "0.1.0"
    }

    fn routes(&self) -> Router<Arc<AppState>> {
        Router::new()
    }

    fn menu_entries(&self) -> Vec<MenuEntry> {
        vec![MenuEntry::new(
            "test.list",
            "Test Items",
            "/test",
            MenuGroup::Operations,
        )]
    }

    fn migrations(&self) -> Vec<PluginMigration> {
        vec![PluginMigration {
            name: "001_test",
            up_sql: "CREATE TABLE IF NOT EXISTS test_items (id UUID PRIMARY KEY);",
            down_sql: Some("DROP TABLE IF EXISTS test_items;"),
            requires_core_migration: Some("001_initial_schema"),
        }]
    }

    fn translations(&self) -> Vec<Translation> {
        vec![
            Translation::new("en", "test_plugin", "menu.title", "Test Items"),
            Translation::new("ms", "test_plugin", "menu.title", "Item Ujian"),
        ]
    }

    fn scheduled_actions(&self) -> Vec<ScheduledAction> {
        vec![ScheduledAction::new(
            ScheduledActionDef {
                code: "test_plugin.heartbeat",
                name: "Test: heartbeat",
                schedule: Schedule::Every(std::time::Duration::from_secs(300)),
                enabled_by_default: false,
            },
            |_state| async move { Ok(()) },
        )]
    }

    fn reports(&self) -> Vec<ReportDef> {
        vec![ReportDef::new(
            "test_plugin.summary",
            "Test Summary",
            "A test report",
            vec![ReportFormat::Html, ReportFormat::Json],
            |_state, params| async move {
                match params.format {
                    ReportFormat::Html => Ok(ReportOutput::html("test.html", "<h1>Test</h1>")),
                    _ => ReportOutput::json("test.json", &serde_json::json!({"status": "ok"}))
                        .map_err(|e| VortexError::Internal(e.to_string())),
                }
            },
        )]
    }
}

/// This test only needs to compile — if it does, the SDK surface
/// is sufficient for the full Plugin contract. The runtime check
/// just verifies the trivial properties.
#[test]
fn sdk_prelude_covers_full_plugin_contract() {
    let plugin = TestPlugin;
    assert_eq!(plugin.technical_name(), "test_plugin");
    assert_eq!(plugin.display_name(), "Test Plugin");
    assert_eq!(plugin.version(), "0.1.0");
    assert_eq!(plugin.menu_entries().len(), 1);
    assert_eq!(plugin.migrations().len(), 1);
    assert_eq!(plugin.translations().len(), 2);
    assert_eq!(plugin.scheduled_actions().len(), 1);
    assert_eq!(plugin.reports().len(), 1);
}
