//! Auto-sync compiled-in plugins into the `installed_modules` table.
//!
//! ## The problem this solves
//!
//! Before Phase 0.6b, a new plugin crate becoming visible to
//! `vortex module list` required **three** separate changes:
//!
//! 1. Create the plugin crate (`crates/vortex-foo/`).
//! 2. Add it to the workspace + feature-gate it on `vortex-cli`.
//! 3. **Edit a core SQL migration** to insert a row into
//!    `installed_modules` with the plugin's metadata.
//!
//! Step 3 was the coupling bug. It meant the core's schema migrations
//! had to enumerate every downstream plugin by name — exactly the
//! contamination Phase 0.6 was meant to kill.
//!
//! ## The solution
//!
//! On server startup, walk every compiled-in plugin via the
//! [`PluginRegistry`] and upsert its metadata into `installed_modules`.
//! The `Plugin` trait already exposes `technical_name`, `display_name`,
//! and `version` — everything the registry row needs. Newly-added
//! plugins become visible to `vortex module list` the moment the
//! binary restarts; no SQL edits, no manual bootstrap.
//!
//! ## State preservation
//!
//! The sync **never overwrites the `state` column**. A plugin that was
//! previously marked `installed` stays `installed`; a plugin that's
//! new to the tenant DB gets `uninstalled` as its default. This keeps
//! install state an operator decision, not a side effect of
//! recompiling the binary.
//!
//! ## Not a replacement for `vortex module install`
//!
//! Sync only writes metadata rows. To **activate** a plugin — run its
//! migrations, flip it to `installed`, run `on_install` hooks — the
//! operator still calls `vortex module install <name>`. Sync exists so
//! that command has something to target.

use std::sync::Arc;

use anyhow::{Context, Result};
use sqlx::PgPool;
use tracing::{debug, info, warn};
use vortex_framework::{Plugin, PluginRegistry};

/// Walk every registered plugin and upsert its metadata into
/// `installed_modules`. Returns `(inserted, updated)` counts for
/// logging. Idempotent — safe to call on every startup.
///
/// This writes only to the primary tenant database. In multi-DB
/// deployments each tenant DB gets its own copy via the
/// `db_manager` path — sync should be called per-DB as tenants are
/// touched, not globally (that's a TODO for the multi-tenant
/// sweep).
pub async fn sync_plugins_to_installed_modules(
    pool: &PgPool,
    registry: &PluginRegistry,
) -> Result<(usize, usize)> {
    let mut inserted = 0usize;
    let mut updated = 0usize;

    for plugin in registry.plugins_iter() {
        let technical_name = plugin.technical_name();
        let display_name = plugin.display_name();
        let version = plugin.version();

        // Every compiled-in plugin is treated as an installable
        // application (`is_core=false, application=true`). The
        // historically-core modules `base` and `access_control` are
        // seeded by migration 003 with `is_core=true` and never go
        // through this sync path — an `ON CONFLICT DO UPDATE` here
        // leaves their `is_core` flag alone because we don't touch
        // it on update.
        let category = plugin.category();
        let summary = plugin.summary();

        let result = sqlx::query(
            r#"
            INSERT INTO installed_modules (
                technical_name, name, version, state, category, summary,
                is_core, application, sequence
            )
            VALUES ($1, $2, $3, 'uninstalled', $4, $5, false, true, 100)
            ON CONFLICT (technical_name) DO UPDATE
            SET name     = EXCLUDED.name,
                version  = EXCLUDED.version,
                category = EXCLUDED.category,
                summary  = EXCLUDED.summary,
                updated_at = NOW()
            RETURNING id, (xmax = 0) AS was_insert
            "#,
        )
        .bind(technical_name)
        .bind(display_name)
        .bind(version)
        .bind(category)
        .bind(summary)
        .fetch_one(pool)
        .await
        .with_context(|| format!("failed to upsert module '{}'", technical_name))?;

        // Postgres trick: `xmax = 0` on a RETURNING row means this
        // was an INSERT rather than an UPDATE, because `xmax` is
        // only set when the row existed and was re-versioned by the
        // DO UPDATE path.
        let module_uuid: uuid::Uuid = sqlx::Row::try_get(&result, "id")
            .with_context(|| format!("missing id for module '{}'", technical_name))?;
        let was_insert: bool = sqlx::Row::try_get(&result, "was_insert").unwrap_or(false);

        // Refresh this module's declared dependencies into
        // `module_dependencies` (delete-then-insert so removed deps don't
        // linger). Feeds the existing uninstall guard and the app detail
        // page's dependency graph.
        sqlx::query("DELETE FROM module_dependencies WHERE module_id = $1")
            .bind(module_uuid)
            .execute(pool)
            .await
            .with_context(|| format!("failed clearing deps for '{}'", technical_name))?;
        for dep in plugin.dependencies() {
            sqlx::query(
                "INSERT INTO module_dependencies (id, module_id, depends_on, optional) \
                 VALUES (gen_random_uuid(), $1, $2, false)",
            )
            .bind(module_uuid)
            .bind(dep)
            .execute(pool)
            .await
            .with_context(|| format!("failed recording dep '{}' -> '{}'", technical_name, dep))?;
        }
        if was_insert {
            inserted += 1;
            info!(
                technical_name = technical_name,
                display_name = display_name,
                state = "uninstalled",
                "registered new plugin in installed_modules"
            );
        } else {
            updated += 1;
            debug!(
                technical_name = technical_name,
                display_name = display_name,
                "refreshed metadata for already-registered plugin"
            );
        }
    }

    if inserted > 0 {
        info!(
            inserted = inserted as i64,
            updated = updated as i64,
            "plugin sync complete"
        );
    } else {
        debug!(
            updated = updated as i64,
            "plugin sync complete (no new plugins)"
        );
    }

    Ok((inserted, updated))
}

/// Convenience wrapper that swallows errors with a warning — useful
/// for startup paths where a sync failure should not prevent the
/// server from coming up. The plugin's routes still mount because
/// they're compiled in; only the module manager UI is affected.
pub async fn sync_plugins_best_effort(pool: &PgPool, registry: &Arc<PluginRegistry>) {
    match sync_plugins_to_installed_modules(pool, registry.as_ref()).await {
        Ok((inserted, updated)) if inserted > 0 => {
            info!(
                inserted = inserted as i64,
                updated = updated as i64,
                "plugin registry synced to installed_modules"
            );
        }
        Ok(_) => {}
        Err(e) => {
            warn!(
                error = %e,
                "plugin auto-sync to installed_modules failed (non-fatal)"
            );
        }
    }
}
