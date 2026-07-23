-- Reconciliation — master data.
--
-- Two operator-maintained reference tables. Both are registered models
-- (`#[derive(Model)]`) so they get generic list/form CRUD screens for free;
-- keep columns in sync with the structs in `src/model.rs`.

-- Supplier item code → LSEO SKU + UOM pack factor. The single most important
-- master-data object: it resolves vendor codes and drives UOM conversion.
CREATE TABLE IF NOT EXISTS vendor_item_alias (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    supplier_no    VARCHAR(32)  NOT NULL,
    supplier_sku   VARCHAR(64)  NOT NULL,
    supplier_desc  TEXT,
    lseo_sku       VARCHAR(64)  NOT NULL,
    supplier_uom   VARCHAR(16),
    base_uom       VARCHAR(16),
    pack_factor    NUMERIC(18, 6),
    active         BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_vendor_item_alias UNIQUE (supplier_no, supplier_sku)
);

CREATE INDEX IF NOT EXISTS idx_vendor_item_alias_lseo ON vendor_item_alias(lseo_sku);

-- PV approval routing: supplier (+ division) → ordered chain of up to 3 approvers.
CREATE TABLE IF NOT EXISTS supplier_approval_matrix (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    supplier_no      VARCHAR(32) NOT NULL,
    supplier_name    VARCHAR(255),
    division         VARCHAR(16),
    approver1_name   VARCHAR(255),
    approver1_email  VARCHAR(255),
    approver2_name   VARCHAR(255),
    approver2_email  VARCHAR(255),
    approver3_name   VARCHAR(255),
    approver3_email  VARCHAR(255),
    active           BOOLEAN NOT NULL DEFAULT true,
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_supplier_approval_matrix UNIQUE (supplier_no, division)
);
