-- Countries table (like Odoo's res.country)
CREATE TABLE IF NOT EXISTS countries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(3) NOT NULL UNIQUE,        -- ISO 3166-1 alpha-2 or alpha-3
    name VARCHAR(100) NOT NULL,
    phone_code VARCHAR(10),                  -- International dialing code
    currency_code VARCHAR(3),                -- ISO 4217 currency code
    active BOOLEAN DEFAULT true,
    sequence INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- States/Provinces table (like Odoo's res.country.state)
CREATE TABLE IF NOT EXISTS states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    country_id UUID NOT NULL REFERENCES countries(id) ON DELETE CASCADE,
    code VARCHAR(10) NOT NULL,               -- State/province code
    name VARCHAR(100) NOT NULL,
    active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(country_id, code)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_states_country_id ON states(country_id);
CREATE INDEX IF NOT EXISTS idx_countries_code ON countries(code);
CREATE INDEX IF NOT EXISTS idx_states_code ON states(code);

-- Update contacts table to reference countries and states
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS country_id UUID REFERENCES countries(id);
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS state_id UUID REFERENCES states(id);
ALTER TABLE contacts ADD COLUMN IF NOT EXISTS street2 VARCHAR(255);

-- Seed common countries
INSERT INTO countries (id, code, name, phone_code, currency_code, sequence) VALUES
    ('019323f7-0000-7000-8000-000000000001', 'US', 'United States', '+1', 'USD', 1),
    ('019323f7-0000-7000-8000-000000000002', 'CA', 'Canada', '+1', 'CAD', 2),
    ('019323f7-0000-7000-8000-000000000003', 'MX', 'Mexico', '+52', 'MXN', 3),
    ('019323f7-0000-7000-8000-000000000004', 'GB', 'United Kingdom', '+44', 'GBP', 10),
    ('019323f7-0000-7000-8000-000000000005', 'DE', 'Germany', '+49', 'EUR', 11),
    ('019323f7-0000-7000-8000-000000000006', 'FR', 'France', '+33', 'EUR', 12),
    ('019323f7-0000-7000-8000-000000000007', 'ES', 'Spain', '+34', 'EUR', 13),
    ('019323f7-0000-7000-8000-000000000008', 'IT', 'Italy', '+39', 'EUR', 14),
    ('019323f7-0000-7000-8000-000000000009', 'AU', 'Australia', '+61', 'AUD', 20),
    ('019323f7-0000-7000-8000-000000000010', 'JP', 'Japan', '+81', 'JPY', 21),
    ('019323f7-0000-7000-8000-000000000011', 'CN', 'China', '+86', 'CNY', 22),
    ('019323f7-0000-7000-8000-000000000012', 'IN', 'India', '+91', 'INR', 23),
    ('019323f7-0000-7000-8000-000000000013', 'BR', 'Brazil', '+55', 'BRL', 24),
    ('019323f7-0000-7000-8000-000000000014', 'NL', 'Netherlands', '+31', 'EUR', 15),
    ('019323f7-0000-7000-8000-000000000015', 'BE', 'Belgium', '+32', 'EUR', 16)
ON CONFLICT (code) DO NOTHING;

-- Seed US States
INSERT INTO states (country_id, code, name) VALUES
    ('019323f7-0000-7000-8000-000000000001', 'AL', 'Alabama'),
    ('019323f7-0000-7000-8000-000000000001', 'AK', 'Alaska'),
    ('019323f7-0000-7000-8000-000000000001', 'AZ', 'Arizona'),
    ('019323f7-0000-7000-8000-000000000001', 'AR', 'Arkansas'),
    ('019323f7-0000-7000-8000-000000000001', 'CA', 'California'),
    ('019323f7-0000-7000-8000-000000000001', 'CO', 'Colorado'),
    ('019323f7-0000-7000-8000-000000000001', 'CT', 'Connecticut'),
    ('019323f7-0000-7000-8000-000000000001', 'DE', 'Delaware'),
    ('019323f7-0000-7000-8000-000000000001', 'FL', 'Florida'),
    ('019323f7-0000-7000-8000-000000000001', 'GA', 'Georgia'),
    ('019323f7-0000-7000-8000-000000000001', 'HI', 'Hawaii'),
    ('019323f7-0000-7000-8000-000000000001', 'ID', 'Idaho'),
    ('019323f7-0000-7000-8000-000000000001', 'IL', 'Illinois'),
    ('019323f7-0000-7000-8000-000000000001', 'IN', 'Indiana'),
    ('019323f7-0000-7000-8000-000000000001', 'IA', 'Iowa'),
    ('019323f7-0000-7000-8000-000000000001', 'KS', 'Kansas'),
    ('019323f7-0000-7000-8000-000000000001', 'KY', 'Kentucky'),
    ('019323f7-0000-7000-8000-000000000001', 'LA', 'Louisiana'),
    ('019323f7-0000-7000-8000-000000000001', 'ME', 'Maine'),
    ('019323f7-0000-7000-8000-000000000001', 'MD', 'Maryland'),
    ('019323f7-0000-7000-8000-000000000001', 'MA', 'Massachusetts'),
    ('019323f7-0000-7000-8000-000000000001', 'MI', 'Michigan'),
    ('019323f7-0000-7000-8000-000000000001', 'MN', 'Minnesota'),
    ('019323f7-0000-7000-8000-000000000001', 'MS', 'Mississippi'),
    ('019323f7-0000-7000-8000-000000000001', 'MO', 'Missouri'),
    ('019323f7-0000-7000-8000-000000000001', 'MT', 'Montana'),
    ('019323f7-0000-7000-8000-000000000001', 'NE', 'Nebraska'),
    ('019323f7-0000-7000-8000-000000000001', 'NV', 'Nevada'),
    ('019323f7-0000-7000-8000-000000000001', 'NH', 'New Hampshire'),
    ('019323f7-0000-7000-8000-000000000001', 'NJ', 'New Jersey'),
    ('019323f7-0000-7000-8000-000000000001', 'NM', 'New Mexico'),
    ('019323f7-0000-7000-8000-000000000001', 'NY', 'New York'),
    ('019323f7-0000-7000-8000-000000000001', 'NC', 'North Carolina'),
    ('019323f7-0000-7000-8000-000000000001', 'ND', 'North Dakota'),
    ('019323f7-0000-7000-8000-000000000001', 'OH', 'Ohio'),
    ('019323f7-0000-7000-8000-000000000001', 'OK', 'Oklahoma'),
    ('019323f7-0000-7000-8000-000000000001', 'OR', 'Oregon'),
    ('019323f7-0000-7000-8000-000000000001', 'PA', 'Pennsylvania'),
    ('019323f7-0000-7000-8000-000000000001', 'RI', 'Rhode Island'),
    ('019323f7-0000-7000-8000-000000000001', 'SC', 'South Carolina'),
    ('019323f7-0000-7000-8000-000000000001', 'SD', 'South Dakota'),
    ('019323f7-0000-7000-8000-000000000001', 'TN', 'Tennessee'),
    ('019323f7-0000-7000-8000-000000000001', 'TX', 'Texas'),
    ('019323f7-0000-7000-8000-000000000001', 'UT', 'Utah'),
    ('019323f7-0000-7000-8000-000000000001', 'VT', 'Vermont'),
    ('019323f7-0000-7000-8000-000000000001', 'VA', 'Virginia'),
    ('019323f7-0000-7000-8000-000000000001', 'WA', 'Washington'),
    ('019323f7-0000-7000-8000-000000000001', 'WV', 'West Virginia'),
    ('019323f7-0000-7000-8000-000000000001', 'WI', 'Wisconsin'),
    ('019323f7-0000-7000-8000-000000000001', 'WY', 'Wyoming'),
    ('019323f7-0000-7000-8000-000000000001', 'DC', 'District of Columbia')
ON CONFLICT (country_id, code) DO NOTHING;

-- Seed Canadian Provinces
INSERT INTO states (country_id, code, name) VALUES
    ('019323f7-0000-7000-8000-000000000002', 'AB', 'Alberta'),
    ('019323f7-0000-7000-8000-000000000002', 'BC', 'British Columbia'),
    ('019323f7-0000-7000-8000-000000000002', 'MB', 'Manitoba'),
    ('019323f7-0000-7000-8000-000000000002', 'NB', 'New Brunswick'),
    ('019323f7-0000-7000-8000-000000000002', 'NL', 'Newfoundland and Labrador'),
    ('019323f7-0000-7000-8000-000000000002', 'NS', 'Nova Scotia'),
    ('019323f7-0000-7000-8000-000000000002', 'NT', 'Northwest Territories'),
    ('019323f7-0000-7000-8000-000000000002', 'NU', 'Nunavut'),
    ('019323f7-0000-7000-8000-000000000002', 'ON', 'Ontario'),
    ('019323f7-0000-7000-8000-000000000002', 'PE', 'Prince Edward Island'),
    ('019323f7-0000-7000-8000-000000000002', 'QC', 'Quebec'),
    ('019323f7-0000-7000-8000-000000000002', 'SK', 'Saskatchewan'),
    ('019323f7-0000-7000-8000-000000000002', 'YT', 'Yukon')
ON CONFLICT (country_id, code) DO NOTHING;

-- Seed Mexican States
INSERT INTO states (country_id, code, name) VALUES
    ('019323f7-0000-7000-8000-000000000003', 'AGU', 'Aguascalientes'),
    ('019323f7-0000-7000-8000-000000000003', 'BCN', 'Baja California'),
    ('019323f7-0000-7000-8000-000000000003', 'BCS', 'Baja California Sur'),
    ('019323f7-0000-7000-8000-000000000003', 'CAM', 'Campeche'),
    ('019323f7-0000-7000-8000-000000000003', 'CHP', 'Chiapas'),
    ('019323f7-0000-7000-8000-000000000003', 'CHH', 'Chihuahua'),
    ('019323f7-0000-7000-8000-000000000003', 'CMX', 'Ciudad de Mexico'),
    ('019323f7-0000-7000-8000-000000000003', 'COA', 'Coahuila'),
    ('019323f7-0000-7000-8000-000000000003', 'COL', 'Colima'),
    ('019323f7-0000-7000-8000-000000000003', 'DUR', 'Durango'),
    ('019323f7-0000-7000-8000-000000000003', 'GUA', 'Guanajuato'),
    ('019323f7-0000-7000-8000-000000000003', 'GRO', 'Guerrero'),
    ('019323f7-0000-7000-8000-000000000003', 'HID', 'Hidalgo'),
    ('019323f7-0000-7000-8000-000000000003', 'JAL', 'Jalisco'),
    ('019323f7-0000-7000-8000-000000000003', 'MEX', 'Mexico'),
    ('019323f7-0000-7000-8000-000000000003', 'MIC', 'Michoacan'),
    ('019323f7-0000-7000-8000-000000000003', 'MOR', 'Morelos'),
    ('019323f7-0000-7000-8000-000000000003', 'NAY', 'Nayarit'),
    ('019323f7-0000-7000-8000-000000000003', 'NLE', 'Nuevo Leon'),
    ('019323f7-0000-7000-8000-000000000003', 'OAX', 'Oaxaca'),
    ('019323f7-0000-7000-8000-000000000003', 'PUE', 'Puebla'),
    ('019323f7-0000-7000-8000-000000000003', 'QUE', 'Queretaro'),
    ('019323f7-0000-7000-8000-000000000003', 'ROO', 'Quintana Roo'),
    ('019323f7-0000-7000-8000-000000000003', 'SLP', 'San Luis Potosi'),
    ('019323f7-0000-7000-8000-000000000003', 'SIN', 'Sinaloa'),
    ('019323f7-0000-7000-8000-000000000003', 'SON', 'Sonora'),
    ('019323f7-0000-7000-8000-000000000003', 'TAB', 'Tabasco'),
    ('019323f7-0000-7000-8000-000000000003', 'TAM', 'Tamaulipas'),
    ('019323f7-0000-7000-8000-000000000003', 'TLA', 'Tlaxcala'),
    ('019323f7-0000-7000-8000-000000000003', 'VER', 'Veracruz'),
    ('019323f7-0000-7000-8000-000000000003', 'YUC', 'Yucatan'),
    ('019323f7-0000-7000-8000-000000000003', 'ZAC', 'Zacatecas')
ON CONFLICT (country_id, code) DO NOTHING;

-- Seed Australian States
INSERT INTO states (country_id, code, name) VALUES
    ('019323f7-0000-7000-8000-000000000009', 'NSW', 'New South Wales'),
    ('019323f7-0000-7000-8000-000000000009', 'VIC', 'Victoria'),
    ('019323f7-0000-7000-8000-000000000009', 'QLD', 'Queensland'),
    ('019323f7-0000-7000-8000-000000000009', 'WA', 'Western Australia'),
    ('019323f7-0000-7000-8000-000000000009', 'SA', 'South Australia'),
    ('019323f7-0000-7000-8000-000000000009', 'TAS', 'Tasmania'),
    ('019323f7-0000-7000-8000-000000000009', 'ACT', 'Australian Capital Territory'),
    ('019323f7-0000-7000-8000-000000000009', 'NT', 'Northern Territory')
ON CONFLICT (country_id, code) DO NOTHING;
