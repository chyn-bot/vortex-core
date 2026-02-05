-- Contacts Module Schema
-- Manages customers, suppliers, and other business contacts

CREATE TABLE contacts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    company_id UUID NOT NULL REFERENCES companies(id),
    name VARCHAR(255) NOT NULL,
    display_name VARCHAR(255),
    code VARCHAR(50),
    contact_type VARCHAR(20) NOT NULL DEFAULT 'customer',
    email VARCHAR(255),
    phone VARCHAR(50),
    mobile VARCHAR(50),
    street VARCHAR(255),
    street2 VARCHAR(255),
    city VARCHAR(100),
    state VARCHAR(100),
    zip VARCHAR(20),
    country VARCHAR(100),
    vat_number VARCHAR(50),
    is_company BOOLEAN NOT NULL DEFAULT false,
    parent_id UUID REFERENCES contacts(id),
    credit_limit DECIMAL(15,2) DEFAULT 0,
    notes TEXT,
    active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by UUID REFERENCES users(id),
    updated_by UUID REFERENCES users(id),
    CONSTRAINT uq_contacts_company_code UNIQUE(company_id, code),
    CONSTRAINT chk_contacts_type CHECK (contact_type IN ('customer', 'supplier', 'both', 'other'))
);

-- Indexes for common queries
CREATE INDEX idx_contacts_company ON contacts(company_id);
CREATE INDEX idx_contacts_name ON contacts(company_id, name);
CREATE INDEX idx_contacts_type ON contacts(company_id, contact_type);
CREATE INDEX idx_contacts_active ON contacts(company_id, active);
CREATE INDEX idx_contacts_parent ON contacts(parent_id) WHERE parent_id IS NOT NULL;

-- Auto-update updated_at timestamp
CREATE TRIGGER tr_contacts_updated_at BEFORE UPDATE ON contacts
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
