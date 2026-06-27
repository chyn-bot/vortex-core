-- ============================================================================
-- Migration 120: Platform i18n
-- ============================================================================
--
-- Creates the translations table and adds locale preference columns
-- to users and companies. The TranslationService in
-- vortex_framework::i18n loads this table into an in-memory cache
-- at startup for fast t(key, locale) lookups. Plugins contribute
-- their own translations via Plugin::translations() which are
-- upserted here during startup.

-- ============================================================================
-- 1. TRANSLATIONS TABLE
-- ============================================================================

CREATE TABLE IF NOT EXISTS translations (
    -- BCP 47 locale code: 'en', 'ms', 'ms-MY', 'zh-CN', etc.
    locale      VARCHAR(10)  NOT NULL,
    -- Module / plugin that owns this string. 'core' for platform
    -- strings, plugin technical_name for plugin strings.
    module      VARCHAR(100) NOT NULL,
    -- Dotted key matching the UI location: 'menu.dashboard',
    -- 'btn.save', 'status.active'. Lowercase, dot-separated.
    key         VARCHAR(255) NOT NULL,
    -- The translated text.
    value       TEXT         NOT NULL,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    PRIMARY KEY (locale, module, key)
);

CREATE INDEX IF NOT EXISTS idx_translations_locale ON translations(locale);
CREATE INDEX IF NOT EXISTS idx_translations_module ON translations(module);

COMMENT ON TABLE translations IS
    'Translated UI strings. Keyed by (locale, module, key). Loaded into the in-memory TranslationService at startup. Plugins seed via Plugin::translations(); admins override via SQL or a future settings UI.';

-- ============================================================================
-- 2. USER AND COMPANY LOCALE PREFERENCES
-- ============================================================================

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS locale VARCHAR(10) DEFAULT 'en';

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS locale VARCHAR(10) DEFAULT 'en';

COMMENT ON COLUMN users.locale IS
    'Per-user locale preference (BCP 47). Overrides the company default. Resolved by handlers via Locale::parse(user.locale).';
COMMENT ON COLUMN companies.locale IS
    'Company-wide default locale. Applied when a user has no personal preference set.';

-- ============================================================================
-- 3. SEED: Core English translations
-- ============================================================================
-- These cover the platform UI chrome — menu items, common buttons,
-- status labels, table headers. Plugins add their own translations
-- via Plugin::translations() at startup; admins customize via SQL.

INSERT INTO translations (locale, module, key, value) VALUES
    -- Navigation
    ('en', 'core', 'menu.home',            'Home'),
    ('en', 'core', 'menu.dashboard',       'Dashboard'),
    ('en', 'core', 'menu.contacts',        'Contacts'),
    ('en', 'core', 'menu.settings',        'Settings'),
    ('en', 'core', 'menu.modules',         'Modules'),
    ('en', 'core', 'menu.users',           'Users'),

    -- Common buttons
    ('en', 'core', 'btn.save',             'Save'),
    ('en', 'core', 'btn.cancel',           'Cancel'),
    ('en', 'core', 'btn.delete',           'Delete'),
    ('en', 'core', 'btn.edit',             'Edit'),
    ('en', 'core', 'btn.create',           'Create'),
    ('en', 'core', 'btn.search',           'Search'),
    ('en', 'core', 'btn.export',           'Export'),
    ('en', 'core', 'btn.back',             'Back'),

    -- Status labels
    ('en', 'core', 'status.active',        'Active'),
    ('en', 'core', 'status.inactive',      'Inactive'),
    ('en', 'core', 'status.draft',         'Draft'),
    ('en', 'core', 'status.confirmed',     'Confirmed'),
    ('en', 'core', 'status.done',          'Done'),
    ('en', 'core', 'status.cancelled',     'Cancelled'),

    -- Table / list
    ('en', 'core', 'table.no_records',     'No records found.'),
    ('en', 'core', 'table.showing',        'Showing'),
    ('en', 'core', 'table.of',             'of'),
    ('en', 'core', 'table.actions',        'Actions'),

    -- Auth
    ('en', 'core', 'auth.login',           'Log In'),
    ('en', 'core', 'auth.logout',          'Log Out'),
    ('en', 'core', 'auth.username',        'Username'),
    ('en', 'core', 'auth.password',        'Password'),

    -- Malay translations for the same core keys
    ('ms', 'core', 'menu.home',            'Laman Utama'),
    ('ms', 'core', 'menu.dashboard',       'Papan Pemuka'),
    ('ms', 'core', 'menu.contacts',        'Kenalan'),
    ('ms', 'core', 'menu.settings',        'Tetapan'),
    ('ms', 'core', 'menu.modules',         'Modul'),
    ('ms', 'core', 'menu.users',           'Pengguna'),
    ('ms', 'core', 'btn.save',             'Simpan'),
    ('ms', 'core', 'btn.cancel',           'Batal'),
    ('ms', 'core', 'btn.delete',           'Padam'),
    ('ms', 'core', 'btn.edit',             'Sunting'),
    ('ms', 'core', 'btn.create',           'Cipta'),
    ('ms', 'core', 'btn.search',           'Cari'),
    ('ms', 'core', 'btn.export',           'Eksport'),
    ('ms', 'core', 'btn.back',             'Kembali'),
    ('ms', 'core', 'status.active',        'Aktif'),
    ('ms', 'core', 'status.inactive',      'Tidak Aktif'),
    ('ms', 'core', 'status.draft',         'Draf'),
    ('ms', 'core', 'status.confirmed',     'Disahkan'),
    ('ms', 'core', 'status.done',          'Selesai'),
    ('ms', 'core', 'status.cancelled',     'Dibatalkan'),
    ('ms', 'core', 'table.no_records',     'Tiada rekod dijumpai.'),
    ('ms', 'core', 'table.showing',        'Menunjukkan'),
    ('ms', 'core', 'table.of',             'daripada'),
    ('ms', 'core', 'table.actions',        'Tindakan'),
    ('ms', 'core', 'auth.login',           'Log Masuk'),
    ('ms', 'core', 'auth.logout',          'Log Keluar'),
    ('ms', 'core', 'auth.username',        'Nama Pengguna'),
    ('ms', 'core', 'auth.password',        'Kata Laluan')
ON CONFLICT (locale, module, key) DO NOTHING;
