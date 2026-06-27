-- ============================================================================
-- Migration 119: Commerce Primitives
-- ============================================================================
--
-- Creates the platform-level foundation for any commerce-adjacent
-- vertical: currencies, exchange rates, units of measure, and a
-- minimal tax model. Every future vertical that touches money or
-- physical quantities (Sales, Purchasing, Inventory, Manufacturing,
-- Finance, Services) uses these tables directly rather than
-- reinventing them plugin-by-plugin.
--
-- Rust API lives in `vortex_orm::commerce`.

-- ============================================================================
-- 1. CURRENCIES (ISO 4217)
-- ============================================================================

CREATE TABLE IF NOT EXISTS currencies (
    id              UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    -- Three-letter ISO 4217 code. Custom deployments can insert
    -- non-standard codes but the convention is uppercase alpha-3.
    code            VARCHAR(3)    NOT NULL UNIQUE,
    name            VARCHAR(100)  NOT NULL,
    symbol          VARCHAR(16)   NOT NULL,
    -- 'before' for $100, 'after' for 100 €.
    symbol_position VARCHAR(8)    NOT NULL DEFAULT 'before',
    -- Number of decimal places shown in default formatting.
    -- 2 for most currencies, 0 for JPY/IDR, 3 for some ME currencies.
    decimal_places  SMALLINT      NOT NULL DEFAULT 2,
    -- Smallest representable unit. 0.01 for cent-based, 1 for whole-
    -- unit currencies, 0.05 for Swiss-style nickel rounding.
    rounding        NUMERIC(20,6) NOT NULL DEFAULT 0.01,
    active          BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_currencies_code ON currencies(code);
CREATE INDEX IF NOT EXISTS idx_currencies_active ON currencies(active) WHERE active;

COMMENT ON TABLE currencies IS
    'ISO 4217 currencies. Every monetary amount on a domain table carries a currency_id FK here. Rust API: vortex_orm::commerce::Currency.';
COMMENT ON COLUMN currencies.rounding IS
    'Smallest representable unit. 0.01 = cents, 1 = whole-unit (JPY/IDR), 0.05 = CHF-style nickel rounding.';

-- Seed: common trading currencies. MYR first to match the home-currency
-- convention for the default company. Add more by INSERT or via a
-- seed-data plugin.
INSERT INTO currencies (code, name, symbol, symbol_position, decimal_places, rounding) VALUES
    ('MYR', 'Malaysian Ringgit',  'RM', 'before', 2, 0.01),
    ('USD', 'US Dollar',          '$',  'before', 2, 0.01),
    ('EUR', 'Euro',               '€',  'before', 2, 0.01),
    ('SGD', 'Singapore Dollar',   'S$', 'before', 2, 0.01),
    ('GBP', 'British Pound',      '£',  'before', 2, 0.01),
    ('JPY', 'Japanese Yen',       '¥',  'before', 0, 1),
    ('CNY', 'Chinese Yuan',       '¥',  'before', 2, 0.01),
    ('AUD', 'Australian Dollar',  'A$', 'before', 2, 0.01),
    ('IDR', 'Indonesian Rupiah',  'Rp', 'before', 0, 1),
    ('THB', 'Thai Baht',          '฿',  'before', 2, 0.01)
ON CONFLICT (code) DO NOTHING;

-- ============================================================================
-- 2. CURRENCY RATES
-- ============================================================================
--
-- Time-series of exchange rates. A rate row says "on this date, one
-- unit of `currency_id` equals `rate` units of the platform base
-- currency". The "base" is implicit — whichever currency is pinned
-- at rate 1.0. The seed below pins every currency at 1.0 on the
-- installation date so fresh deployments convert at 1:1 until a
-- rate-provider plugin loads real data.

CREATE TABLE IF NOT EXISTS currency_rates (
    id          UUID           PRIMARY KEY DEFAULT uuid_generate_v4(),
    currency_id UUID           NOT NULL REFERENCES currencies(id) ON DELETE CASCADE,
    rate        NUMERIC(20,10) NOT NULL,
    rate_date   DATE           NOT NULL,
    created_at  TIMESTAMPTZ    NOT NULL DEFAULT NOW(),
    UNIQUE (currency_id, rate_date)
);

-- Descending index on rate_date so the "latest rate on or before D"
-- lookup in `vortex_orm::commerce::get_rate` is a single index-only
-- LIMIT 1.
CREATE INDEX IF NOT EXISTS idx_currency_rates_lookup
    ON currency_rates(currency_id, rate_date DESC);

COMMENT ON TABLE currency_rates IS
    'Exchange-rate time series. Rate = how many base-currency units equal one unit of currency_id. Populated by a rate-provider plugin (future) or by SQL seed.';

-- Baseline seed: rate = 1.0 for every currency on the day of the
-- migration. Lets fresh installs call `convert_amount` without
-- erroring out on "no rate found"; real rates overwrite the same
-- (currency_id, rate_date) key via ON CONFLICT on the upsert path.
INSERT INTO currency_rates (currency_id, rate, rate_date)
SELECT id, 1, CURRENT_DATE FROM currencies
ON CONFLICT (currency_id, rate_date) DO NOTHING;

-- ============================================================================
-- 3. COMPANY HOME CURRENCY
-- ============================================================================

ALTER TABLE companies
    ADD COLUMN IF NOT EXISTS currency_id UUID REFERENCES currencies(id);

-- Backfill the default company to MYR (matches the home-currency
-- convention for the reference deployment). Deployments that need a
-- different default currency update this after the migration runs.
UPDATE companies
SET currency_id = (SELECT id FROM currencies WHERE code = 'MYR')
WHERE currency_id IS NULL;

COMMENT ON COLUMN companies.currency_id IS
    'Home currency for this tenant. Every monetary amount on a tenant-scoped table defaults to this currency unless overridden.';

-- ============================================================================
-- 4. UNITS OF MEASURE
-- ============================================================================
--
-- Category-scoped conversion graph. Each category has one reference
-- unit whose factor = 1; every other unit in the category declares
-- its factor as the multiplier from itself to the reference.
--
--     qty_in_reference = qty_in_this_uom * this_uom.factor
--
-- Rust API: vortex_orm::commerce::convert_uom — pure function.

CREATE TABLE IF NOT EXISTS uom_categories (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       VARCHAR(100) NOT NULL UNIQUE,
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);

COMMENT ON TABLE uom_categories IS
    'Dimensional categories for units of measure (Weight, Length, Volume, Time, Area, Unit). Conversion is only valid within a category.';

CREATE TABLE IF NOT EXISTS uoms (
    id          UUID           PRIMARY KEY DEFAULT uuid_generate_v4(),
    category_id UUID           NOT NULL REFERENCES uom_categories(id) ON DELETE CASCADE,
    name        VARCHAR(100)   NOT NULL,
    code        VARCHAR(20)    NOT NULL UNIQUE,
    -- Multiplier from this unit to the category's reference unit.
    -- 1 kg = 1000 g → if reference is kg, g has factor 0.001.
    factor      NUMERIC(20,10) NOT NULL DEFAULT 1,
    -- 'reference' | 'bigger' | 'smaller' — descriptive; exactly one
    -- 'reference' per category should exist by convention.
    uom_type    VARCHAR(16)    NOT NULL DEFAULT 'reference',
    rounding    NUMERIC(20,6)  NOT NULL DEFAULT 0.01,
    active      BOOLEAN        NOT NULL DEFAULT TRUE,
    created_at  TIMESTAMPTZ    NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_uoms_category ON uoms(category_id);
CREATE INDEX IF NOT EXISTS idx_uoms_code ON uoms(code);

COMMENT ON TABLE uoms IS
    'Units of measure. Each row belongs to a uom_category and carries a factor expressed as multiplier to the category reference unit.';
COMMENT ON COLUMN uoms.factor IS
    'Multiplier from THIS uom to the category reference unit. 1 uom * factor = N reference units.';

-- Seed UoM categories with stable UUIDs so seed migrations for units
-- can reference them by id.
INSERT INTO uom_categories (id, name) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'Unit'),
    ('c0000000-0000-0000-0000-000000000002', 'Weight'),
    ('c0000000-0000-0000-0000-000000000003', 'Length'),
    ('c0000000-0000-0000-0000-000000000004', 'Volume'),
    ('c0000000-0000-0000-0000-000000000005', 'Time'),
    ('c0000000-0000-0000-0000-000000000006', 'Area')
ON CONFLICT (name) DO NOTHING;

-- Unit (reference: unit)
INSERT INTO uoms (category_id, name, code, factor, uom_type) VALUES
    ('c0000000-0000-0000-0000-000000000001', 'Unit',    'unit',    1,   'reference'),
    ('c0000000-0000-0000-0000-000000000001', 'Pair',    'pair',    2,   'bigger'),
    ('c0000000-0000-0000-0000-000000000001', 'Dozen',   'dozen',   12,  'bigger'),
    ('c0000000-0000-0000-0000-000000000001', 'Hundred', 'hundred', 100, 'bigger')
ON CONFLICT (code) DO NOTHING;

-- Weight (reference: kilogram)
INSERT INTO uoms (category_id, name, code, factor, uom_type) VALUES
    ('c0000000-0000-0000-0000-000000000002', 'Kilogram',  'kg', 1,          'reference'),
    ('c0000000-0000-0000-0000-000000000002', 'Gram',      'g',  0.001,      'smaller'),
    ('c0000000-0000-0000-0000-000000000002', 'Milligram', 'mg', 0.000001,   'smaller'),
    ('c0000000-0000-0000-0000-000000000002', 'Tonne',     't',  1000,       'bigger'),
    ('c0000000-0000-0000-0000-000000000002', 'Pound',     'lb', 0.45359237, 'smaller'),
    ('c0000000-0000-0000-0000-000000000002', 'Ounce',     'oz', 0.02834952, 'smaller')
ON CONFLICT (code) DO NOTHING;

-- Length (reference: meter)
INSERT INTO uoms (category_id, name, code, factor, uom_type) VALUES
    ('c0000000-0000-0000-0000-000000000003', 'Meter',      'm',  1,      'reference'),
    ('c0000000-0000-0000-0000-000000000003', 'Centimeter', 'cm', 0.01,   'smaller'),
    ('c0000000-0000-0000-0000-000000000003', 'Millimeter', 'mm', 0.001,  'smaller'),
    ('c0000000-0000-0000-0000-000000000003', 'Kilometer',  'km', 1000,   'bigger'),
    ('c0000000-0000-0000-0000-000000000003', 'Inch',       'in', 0.0254, 'smaller'),
    ('c0000000-0000-0000-0000-000000000003', 'Foot',       'ft', 0.3048, 'smaller'),
    ('c0000000-0000-0000-0000-000000000003', 'Yard',       'yd', 0.9144, 'smaller'),
    ('c0000000-0000-0000-0000-000000000003', 'Mile',       'mi', 1609.344, 'bigger')
ON CONFLICT (code) DO NOTHING;

-- Volume (reference: liter)
INSERT INTO uoms (category_id, name, code, factor, uom_type) VALUES
    ('c0000000-0000-0000-0000-000000000004', 'Liter',       'L',   1,         'reference'),
    ('c0000000-0000-0000-0000-000000000004', 'Milliliter',  'mL',  0.001,     'smaller'),
    ('c0000000-0000-0000-0000-000000000004', 'Cubic Meter', 'm3',  1000,      'bigger'),
    ('c0000000-0000-0000-0000-000000000004', 'Gallon (US)', 'gal', 3.7854118, 'bigger')
ON CONFLICT (code) DO NOTHING;

-- Time (reference: hour)
INSERT INTO uoms (category_id, name, code, factor, uom_type) VALUES
    ('c0000000-0000-0000-0000-000000000005', 'Hour',    'h',    1,              'reference'),
    ('c0000000-0000-0000-0000-000000000005', 'Minute',  'min',  0.01666666667,  'smaller'),
    ('c0000000-0000-0000-0000-000000000005', 'Second',  'sec',  0.00027777778,  'smaller'),
    ('c0000000-0000-0000-0000-000000000005', 'Day',     'day',  24,             'bigger'),
    ('c0000000-0000-0000-0000-000000000005', 'Week',    'week', 168,            'bigger')
ON CONFLICT (code) DO NOTHING;

-- Area (reference: square meter)
INSERT INTO uoms (category_id, name, code, factor, uom_type) VALUES
    ('c0000000-0000-0000-0000-000000000006', 'Square Meter',      'm2',  1,       'reference'),
    ('c0000000-0000-0000-0000-000000000006', 'Square Centimeter', 'cm2', 0.0001,  'smaller'),
    ('c0000000-0000-0000-0000-000000000006', 'Square Kilometer',  'km2', 1000000, 'bigger'),
    ('c0000000-0000-0000-0000-000000000006', 'Hectare',           'ha',  10000,   'bigger'),
    ('c0000000-0000-0000-0000-000000000006', 'Acre',              'acre', 4046.8564, 'bigger')
ON CONFLICT (code) DO NOTHING;

-- ============================================================================
-- 5. TAXES
-- ============================================================================
--
-- Minimal model: percent or fixed, sale/purchase/none, inclusive or
-- exclusive. Compound taxes, tax groups, and tax reports are
-- deliberately out of scope — a Finance plugin extends this later
-- if it needs them.

CREATE TABLE IF NOT EXISTS taxes (
    id            UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    name          VARCHAR(100)  NOT NULL UNIQUE,
    description   TEXT,
    -- 'percent' (amount is a percentage, e.g. 6.0 = 6%)
    -- 'fixed'   (amount is a flat per-line fee in tenant currency)
    amount_type   VARCHAR(16)   NOT NULL DEFAULT 'percent',
    amount        NUMERIC(20,6) NOT NULL DEFAULT 0,
    -- 'sale' | 'purchase' | 'none'
    type_tax_use  VARCHAR(16)   NOT NULL DEFAULT 'sale',
    -- If TRUE, the displayed price already includes this tax and
    -- the base must be backed out; if FALSE, the tax is added on top.
    price_include BOOLEAN       NOT NULL DEFAULT FALSE,
    active        BOOLEAN       NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ   NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_taxes_active_use ON taxes(type_tax_use) WHERE active;

COMMENT ON TABLE taxes IS
    'Minimal tax model (percent/fixed, sale/purchase, inclusive/exclusive). Covers Malaysian SST, GST-style VATs, and flat per-line fees. Compound taxes and tax groups are deferred to a Finance plugin.';

-- Seed: a handful of defaults to make first-time setup useful.
-- Tenants override / extend via SQL or an admin UI.
INSERT INTO taxes (name, description, amount_type, amount, type_tax_use, price_include) VALUES
    ('Exempt',          'Zero-rated / exempt from tax',                'percent', 0,  'sale',     FALSE),
    ('SST 6%',          'Malaysian Sales and Service Tax 6%',          'percent', 6,  'sale',     FALSE),
    ('Service Tax 10%', 'Malaysian Service Tax 10%',                   'percent', 10, 'sale',     FALSE),
    ('Purchase SST 6%', 'Malaysian input SST 6% on purchases',         'percent', 6,  'purchase', FALSE)
ON CONFLICT (name) DO NOTHING;
