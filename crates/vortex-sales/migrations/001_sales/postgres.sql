-- Migration 001: sales orders
--
-- Mirrors purchasing on the outbound side: customer (core contact) →
-- sales order → delivery posting stock moves OUT (internal → customer
-- location) via the inventory primitive → customer-invoice bridge
-- into accounting. Lines carry the REAL tax reference and LHDN
-- classification (richer than purchase's tax_percent) because they
-- flow straight into e-invoicing.

CREATE TABLE IF NOT EXISTS sales_order (
    id                        UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    number                    VARCHAR(32)   NOT NULL,
    customer_id               UUID          NOT NULL REFERENCES contacts(id),
    order_date                DATE          NOT NULL DEFAULT CURRENT_DATE,
    expected_date             DATE,
    -- Ship-from (an internal stock location).
    source_location_id        UUID          REFERENCES stock_location(id),
    currency_id               UUID          REFERENCES currencies(id),
    state                     VARCHAR(12)   NOT NULL DEFAULT 'draft',
    note                      TEXT,
    untaxed_amount            NUMERIC(20,2) NOT NULL DEFAULT 0,
    tax_amount                NUMERIC(20,2) NOT NULL DEFAULT 0,
    total_amount              NUMERIC(20,2) NOT NULL DEFAULT 0,
    -- Accounting bridge (registration order guarantees acc_move exists).
    customer_invoice_move_id  UUID          REFERENCES acc_move(id),
    company_id                UUID          REFERENCES companies(id),
    created_by                UUID          REFERENCES users(id),
    updated_by                UUID          REFERENCES users(id),
    created_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    updated_at                TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_so_state CHECK (state IN ('draft', 'confirmed', 'delivered', 'cancelled')),
    CONSTRAINT uq_so_number UNIQUE (company_id, number)
);

CREATE INDEX IF NOT EXISTS idx_so_customer ON sales_order (customer_id, order_date DESC);
CREATE INDEX IF NOT EXISTS idx_so_state ON sales_order (state) WHERE state <> 'cancelled';

CREATE TABLE IF NOT EXISTS sales_order_line (
    id                  UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    order_id            UUID          NOT NULL REFERENCES sales_order(id) ON DELETE CASCADE,
    sequence            INTEGER       NOT NULL DEFAULT 10,
    product_id          UUID          NOT NULL REFERENCES stock_product(id),
    description         VARCHAR(255),
    quantity            NUMERIC(20,4) NOT NULL DEFAULT 1,
    unit_price          NUMERIC(20,4) NOT NULL DEFAULT 0,
    tax_id              UUID          REFERENCES taxes(id),
    classification_code VARCHAR(8),
    qty_delivered       NUMERIC(20,4) NOT NULL DEFAULT 0,
    company_id          UUID          REFERENCES companies(id),
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_sol_qty CHECK (quantity > 0),
    CONSTRAINT chk_sol_delivered CHECK (qty_delivered >= 0)
);

CREATE INDEX IF NOT EXISTS idx_sol_order ON sales_order_line (order_id);

DROP TRIGGER IF EXISTS trg_so_updated_at ON sales_order;
CREATE TRIGGER trg_so_updated_at
    BEFORE UPDATE ON sales_order
    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON sales_order, sales_order_line TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE sales_order IS
    'Sales orders. Customer is a core contact. Delivering a confirmed order posts stock moves out of source_location_id via the inventory primitive; the invoice bridge creates the accounting customer invoice with real taxes and LHDN classifications. number is tenant-scoped (SO/000001).';
