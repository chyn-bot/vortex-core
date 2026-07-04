-- Migration 012: bank master
--
-- Banks become a user-configurable reference table instead of free
-- text on partner bank rows — consistent names + SWIFT/BIC defaults,
-- which the future bank-file export (DuitNow/IBG) depends on.
-- Seeded with the Malaysian retail/commercial banks.

CREATE TABLE IF NOT EXISTS acc_bank (
    id         UUID         PRIMARY KEY DEFAULT uuid_generate_v4(),
    name       VARCHAR(120) NOT NULL,
    swift_code VARCHAR(20),
    active     BOOLEAN      NOT NULL DEFAULT TRUE,
    company_id UUID         REFERENCES companies(id),
    created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    -- Tenant = database, so bank names are simply unique (a nullable
    -- company_id in the key would never fire ON CONFLICT).
    CONSTRAINT uq_acc_bank_name UNIQUE (name)
);

INSERT INTO acc_bank (id, name, swift_code) VALUES
    ('accba000-0000-4000-8000-000000000001', 'Maybank',                        'MBBEMYKL'),
    ('accba000-0000-4000-8000-000000000002', 'CIMB Bank',                      'CIBBMYKL'),
    ('accba000-0000-4000-8000-000000000003', 'Public Bank',                    'PBBEMYKL'),
    ('accba000-0000-4000-8000-000000000004', 'RHB Bank',                       'RHBBMYKL'),
    ('accba000-0000-4000-8000-000000000005', 'Hong Leong Bank',                'HLBBMYKL'),
    ('accba000-0000-4000-8000-000000000006', 'AmBank',                         'ARBKMYKL'),
    ('accba000-0000-4000-8000-000000000007', 'Bank Islam Malaysia',            'BIMBMYKL'),
    ('accba000-0000-4000-8000-000000000008', 'Bank Rakyat',                    'BKRMMYKL'),
    ('accba000-0000-4000-8000-000000000009', 'Bank Simpanan Nasional (BSN)',   'BSNAMYK1'),
    ('accba000-0000-4000-8000-00000000000a', 'OCBC Bank (Malaysia)',           'OCBCMYKL'),
    ('accba000-0000-4000-8000-00000000000b', 'UOB Malaysia',                   'UOVBMYKL'),
    ('accba000-0000-4000-8000-00000000000c', 'HSBC Bank Malaysia',             'HBMBMYKL'),
    ('accba000-0000-4000-8000-00000000000d', 'Standard Chartered Malaysia',    'SCBLMYKX'),
    ('accba000-0000-4000-8000-00000000000e', 'Affin Bank',                     'PHBMMYKL'),
    ('accba000-0000-4000-8000-00000000000f', 'Alliance Bank Malaysia',         'MFBBMYKL'),
    ('accba000-0000-4000-8000-000000000010', 'Bank Muamalat Malaysia',         'BMMBMYKL'),
    ('accba000-0000-4000-8000-000000000011', 'Agrobank',                       'AGOBMYKL'),
    ('accba000-0000-4000-8000-000000000012', 'MBSB Bank',                      'MBSBMYKL'),
    ('accba000-0000-4000-8000-000000000013', 'Citibank Malaysia',              'CITIMYKL'),
    ('accba000-0000-4000-8000-000000000014', 'Kuwait Finance House (Malaysia)','KFHOMYKL')
ON CONFLICT (id) DO NOTHING;

-- Partner bank rows reference the master; existing free-text rows are
-- matched by name where possible (bank_name stays as the denormalized
-- display value so nothing downstream breaks).
ALTER TABLE acc_partner_bank
    ADD COLUMN IF NOT EXISTS bank_id UUID REFERENCES acc_bank(id);

UPDATE acc_partner_bank pb SET bank_id = b.id
FROM acc_bank b
WHERE pb.bank_id IS NULL AND lower(pb.bank_name) = lower(b.name);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON acc_bank TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE acc_bank IS
    'Bank master (user-configurable, Malaysian banks seeded) — referenced by partner bank accounts; SWIFT defaults flow from here.';
