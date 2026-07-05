-- Migration 003: delivery documents + invoiced-quantity tracking
--
-- Partial fulfilment management: every delivery/service-confirmation
-- posting mints a printable document (DO/SC numbers), and lines track
-- qty_invoiced so billing follows delivery (progressive invoicing,
-- backorder = ordered - delivered).

ALTER TABLE sales_order_line
    ADD COLUMN IF NOT EXISTS qty_invoiced NUMERIC(20,4) NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS sales_delivery (
    id                  UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    number              VARCHAR(32)   NOT NULL,
    order_id            UUID          NOT NULL REFERENCES sales_order(id) ON DELETE CASCADE,
    -- 'goods' prints as a Delivery Order, 'service' as a Service
    -- Confirmation.
    kind                VARCHAR(8)    NOT NULL DEFAULT 'goods',
    delivery_date       DATE          NOT NULL DEFAULT CURRENT_DATE,
    source_location_id  UUID          REFERENCES stock_location(id),
    note                TEXT,
    company_id          UUID          REFERENCES companies(id),
    created_by          UUID          REFERENCES users(id),
    created_at          TIMESTAMPTZ   NOT NULL DEFAULT NOW(),

    CONSTRAINT chk_sd_kind CHECK (kind IN ('goods', 'service')),
    CONSTRAINT uq_sd_number UNIQUE (company_id, number)
);

CREATE INDEX IF NOT EXISTS idx_sd_order ON sales_delivery (order_id, created_at DESC);

CREATE TABLE IF NOT EXISTS sales_delivery_line (
    id             UUID          PRIMARY KEY DEFAULT uuid_generate_v4(),
    delivery_id    UUID          NOT NULL REFERENCES sales_delivery(id) ON DELETE CASCADE,
    order_line_id  UUID          NOT NULL REFERENCES sales_order_line(id),
    product_id     UUID          NOT NULL REFERENCES stock_product(id),
    description    VARCHAR(255),
    quantity       NUMERIC(20,4) NOT NULL,
    lot_name       VARCHAR(64),

    CONSTRAINT chk_sdl_qty CHECK (quantity > 0)
);

CREATE INDEX IF NOT EXISTS idx_sdl_delivery ON sales_delivery_line (delivery_id);

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'vortex_runtime') THEN
        EXECUTE 'GRANT SELECT, INSERT, UPDATE, DELETE ON sales_delivery, sales_delivery_line TO vortex_runtime';
    END IF;
END$$;

COMMENT ON TABLE sales_delivery IS
    'Fulfilment documents minted per delivery/service-confirmation posting on a sales order. Printable; goods kind lists what physically shipped (with lots), service kind what work was confirmed.';
