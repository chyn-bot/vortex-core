//! Platform i18n — translations, locale-aware formatting, and
//! per-user/per-company locale resolution.
//!
//! This module provides the primitives every vertical needs to go
//! international:
//!
//! - **[`Locale`]** — BCP 47 language + optional region, with
//!   a fallback chain so `ms-MY` → `ms` → `en`.
//! - **[`TranslationService`]** — in-memory cache of
//!   `(locale, module, key) → text` triples, loaded from the
//!   `translations` DB table at startup. Plugins seed their own
//!   translations via `Plugin::translations()`.
//! - **[`format_date`]**, **[`format_number`]** — locale-aware
//!   display for the two formatting concerns that trip up every
//!   ERP going international (date order and number separators).
//!
//! ## How translations are resolved
//!
//! ```text
//! handler receives request
//!     → resolve locale (user.locale || company.locale || Accept-Language || "en")
//!     → call service.t("dashboard.title", &locale)
//!     → service walks locale.fallback_chain() looking for a match
//!     → returns the first hit, or the key itself as the ultimate fallback
//! ```
//!
//! The "key itself is the fallback" convention means untranslated
//! strings show as their dotted key (`menu.work_orders`) rather
//! than crashing or showing nothing — which is ugly but
//! immediately obvious to developers and testers.
//!
//! ## How plugins contribute translations
//!
//! ```rust,ignore
//! impl Plugin for MyPlugin {
//!     fn translations(&self) -> Vec<Translation> {
//!         vec![
//!             Translation::new("en", "myplugin", "menu.title", "My Plugin"),
//!             Translation::new("ms", "myplugin", "menu.title", "Plugin Saya"),
//!         ]
//!     }
//! }
//! ```
//!
//! The host aggregates translations from every plugin at startup
//! and bulk-upserts them into the `translations` table. DB-resident
//! translations take precedence over code-shipped ones — an admin
//! or integrator can override any string by inserting a row directly.
//!
//! ## What this module does NOT provide (deferred)
//!
//! - **Askama template integration** (`{{ t("key") }}` filter) —
//!   requires custom Askama filters or a template-context struct;
//!   separate follow-up once the primitive is in place.
//! - **Pluralization** (`1 item` vs `5 items`) — needs a plural-
//!   rule engine like Fluent or ICU. The simple `t(key)` model
//!   handles the 95% ERP case (labels, buttons, menu items) but
//!   not count-dependent strings.
//! - **Right-to-left layout** (Arabic, Hebrew) — needs CSS
//!   `direction: rtl` support in the template layer.
//! - **Full CLDR data** — the `format_date` / `format_number`
//!   helpers hard-code conventions for ~15 language families. Edge
//!   cases (Amharic calendar, Hindi number system) need ICU4X.
//! - **Translation admin UI** — admins edit translations via SQL
//!   or a future settings page.

use std::collections::HashMap;
use std::sync::Arc;

use sqlx::PgPool;
use tracing::{info, warn};

use vortex_common::{VortexError, VortexResult};

pub mod format;
pub mod locale;

pub use format::{format_date, format_number};
pub use locale::{locale_from_accept_language, Locale, DEFAULT_LOCALE};

/// A single translation entry — the unit of data plugins contribute
/// and the `translations` table stores.
#[derive(Debug, Clone)]
pub struct Translation {
    /// BCP 47 locale code (`en`, `ms-MY`, `zh-CN`).
    pub locale: String,
    /// Module / plugin that owns this string — e.g. `core`, `eam`,
    /// `sales`. Used for scoping and for admin-UI filtering.
    pub module: String,
    /// Dotted key — e.g. `menu.dashboard`, `btn.save`,
    /// `status.active`. Convention: lowercase, dot-separated
    /// hierarchy matching the UI location.
    pub key: String,
    /// The translated text.
    pub value: String,
}

impl Translation {
    pub fn new(
        locale: impl Into<String>,
        module: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        Self {
            locale: locale.into(),
            module: module.into(),
            key: key.into(),
            value: value.into(),
        }
    }
}

/// In-memory translation cache. Loaded from the `translations` DB
/// table at startup; plugins contribute additional entries via
/// `Plugin::translations()` which are upserted before the cache
/// is built.
///
/// Thread-safe (`Arc<TranslationService>`) — stored on `AppState`
/// and shared across all handlers.
pub struct TranslationService {
    /// `locale → (key → value)`. The module is folded into the key
    /// for lookup purposes — the cache is flat per locale.
    cache: HashMap<String, HashMap<String, String>>,
}

impl TranslationService {
    /// Load translations from the `translations` table and build
    /// the in-memory cache. Call once during startup.
    pub async fn load(pool: &PgPool) -> VortexResult<Self> {
        let rows: Vec<(String, String, String, String)> = sqlx::query_as(
            "SELECT locale, module, key, value FROM translations ORDER BY locale, module, key",
        )
        .fetch_all(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("load translations: {e}")))?;

        let mut cache: HashMap<String, HashMap<String, String>> = HashMap::new();
        for (locale, module, key, value) in &rows {
            let full_key = if module == "core" {
                key.clone()
            } else {
                format!("{module}.{key}")
            };
            cache
                .entry(locale.clone())
                .or_default()
                .insert(full_key, value.clone());
        }

        info!(
            locales = cache.len() as i64,
            total_keys = rows.len() as i64,
            "translation cache loaded"
        );

        Ok(Self { cache })
    }

    /// Build an empty service. Useful for tests and for startups
    /// before the migration has run.
    pub fn empty() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Look up a translation key using the locale's fallback chain.
    ///
    /// Returns the translated text, or the key itself as the
    /// ultimate fallback (so untranslated strings are visible in
    /// the UI rather than silently empty).
    ///
    /// Returns a `Cow<str>` — borrowed from the cache when a
    /// translation is found, owned (cloned from the key) when
    /// falling back to the key itself. Callers that need `&str`
    /// can `.as_ref()`.
    pub fn t<'a>(&'a self, key: &'a str, locale: &Locale) -> &'a str {
        for candidate in locale.fallback_chain() {
            if let Some(map) = self.cache.get(&candidate) {
                if let Some(value) = map.get(key) {
                    return value.as_str();
                }
            }
        }
        // Ultimate fallback: the key itself. This is deliberately
        // ugly ("menu.dashboard" in the UI) so untranslated strings
        // are immediately obvious to developers and testers.
        key
    }

    /// Number of distinct locales in the cache.
    pub fn locale_count(&self) -> usize {
        self.cache.len()
    }

    /// Total number of translation keys across all locales.
    pub fn key_count(&self) -> usize {
        self.cache.values().map(|m| m.len()).sum()
    }

    /// Insert a batch of translations into the in-memory cache.
    /// Used by the startup path after `load()` to merge plugin-
    /// contributed translations that haven't been persisted yet.
    pub fn merge(&mut self, translations: &[Translation]) {
        for t in translations {
            let full_key = if t.module == "core" {
                t.key.clone()
            } else {
                format!("{}.{}", t.module, t.key)
            };
            self.cache
                .entry(t.locale.clone())
                .or_default()
                .insert(full_key, t.value.clone());
        }
    }
}

impl std::fmt::Debug for TranslationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TranslationService")
            .field("locale_count", &self.locale_count())
            .field("key_count", &self.key_count())
            .finish()
    }
}

/// Bulk-upsert translations into the `translations` table. Existing
/// rows with the same `(locale, module, key)` are updated; new rows
/// are inserted. Called during startup to persist plugin-contributed
/// translations so they survive the next `TranslationService::load`.
pub async fn sync_translations(pool: &PgPool, translations: &[Translation]) -> VortexResult<()> {
    if translations.is_empty() {
        return Ok(());
    }
    for t in translations {
        sqlx::query(
            r#"
            INSERT INTO translations (locale, module, key, value)
            VALUES ($1, $2, $3, $4)
            ON CONFLICT (locale, module, key) DO UPDATE
            SET value = EXCLUDED.value
            "#,
        )
        .bind(&t.locale)
        .bind(&t.module)
        .bind(&t.key)
        .bind(&t.value)
        .execute(pool)
        .await
        .map_err(|e| VortexError::QueryExecution(format!("sync translation: {e}")))?;
    }
    info!(count = translations.len() as i64, "translations synced to DB");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn build_test_service() -> TranslationService {
        let mut svc = TranslationService::empty();
        svc.merge(&[
            Translation::new("en", "core", "menu.dashboard", "Dashboard"),
            Translation::new("en", "core", "btn.save", "Save"),
            Translation::new("ms", "core", "menu.dashboard", "Papan Pemuka"),
            Translation::new("ms", "core", "btn.save", "Simpan"),
            Translation::new("ms-MY", "core", "btn.save", "Simpan (MY)"),
            Translation::new("en", "eam", "menu.assets", "Assets"),
            Translation::new("ms", "eam", "menu.assets", "Aset"),
        ]);
        svc
    }

    #[test]
    fn t_returns_exact_match() {
        let svc = build_test_service();
        let en = Locale::parse("en");
        assert_eq!(svc.t("menu.dashboard", &en), "Dashboard");
        assert_eq!(svc.t("btn.save", &en), "Save");
    }

    #[test]
    fn t_returns_ms_translation() {
        let svc = build_test_service();
        let ms = Locale::parse("ms");
        assert_eq!(svc.t("menu.dashboard", &ms), "Papan Pemuka");
        assert_eq!(svc.t("btn.save", &ms), "Simpan");
    }

    #[test]
    fn t_regional_variant_overrides_base() {
        let svc = build_test_service();
        let ms_my = Locale::parse("ms-MY");
        // ms-MY has its own btn.save → "Simpan (MY)"
        assert_eq!(svc.t("btn.save", &ms_my), "Simpan (MY)");
    }

    #[test]
    fn t_regional_falls_back_to_language() {
        let svc = build_test_service();
        let ms_my = Locale::parse("ms-MY");
        // ms-MY has no dashboard → falls to ms → "Papan Pemuka"
        assert_eq!(svc.t("menu.dashboard", &ms_my), "Papan Pemuka");
    }

    #[test]
    fn t_unknown_locale_falls_back_to_english() {
        let svc = build_test_service();
        let ja = Locale::parse("ja");
        assert_eq!(svc.t("menu.dashboard", &ja), "Dashboard");
    }

    #[test]
    fn t_unknown_key_returns_key_itself() {
        let svc = build_test_service();
        let en = Locale::parse("en");
        assert_eq!(svc.t("nonexistent.key", &en), "nonexistent.key");
    }

    #[test]
    fn t_plugin_keys_are_module_prefixed() {
        let svc = build_test_service();
        let en = Locale::parse("en");
        // EAM's "menu.assets" is stored as "eam.menu.assets"
        assert_eq!(svc.t("eam.menu.assets", &en), "Assets");
        let ms = Locale::parse("ms");
        assert_eq!(svc.t("eam.menu.assets", &ms), "Aset");
    }

    #[test]
    fn empty_service_always_returns_key() {
        let svc = TranslationService::empty();
        let en = Locale::parse("en");
        assert_eq!(svc.t("any.key", &en), "any.key");
    }

    #[test]
    fn merge_adds_to_existing_cache() {
        let mut svc = TranslationService::empty();
        assert_eq!(svc.key_count(), 0);
        svc.merge(&[
            Translation::new("en", "core", "a", "A"),
            Translation::new("en", "core", "b", "B"),
        ]);
        assert_eq!(svc.key_count(), 2);
        assert_eq!(svc.locale_count(), 1);
    }
}
