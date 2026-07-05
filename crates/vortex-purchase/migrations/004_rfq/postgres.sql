-- Migration 004: RFQ stage in front of the purchase order
--
-- Mirrors the sales quotation layer on the inbound side: a document
-- is born as a Request for Quotation (RFQ/000001, editable), freezes
-- when sent to the supplier, and only receives its PO number at
-- confirmation. Revisions are immutable sibling rows; the partial
-- unique index guarantees a single live PO per RFQ family.

ALTER TABLE purchase_order ALTER COLUMN number DROP NOT NULL;

ALTER TABLE purchase_order ADD COLUMN IF NOT EXISTS rfq_number    VARCHAR(32);
ALTER TABLE purchase_order ADD COLUMN IF NOT EXISTS revision      INTEGER NOT NULL DEFAULT 1;
ALTER TABLE purchase_order ADD COLUMN IF NOT EXISTS root_rfq_id   UUID REFERENCES purchase_order(id);
-- Reply-by date for the supplier's quote (no auto-expiry; procurement
-- follows up manually).
ALTER TABLE purchase_order ADD COLUMN IF NOT EXISTS respond_by    DATE;

-- State machine: rfq → sent → confirmed → received,
-- exits: superseded (replaced by newer revision), cancelled.
ALTER TABLE purchase_order DROP CONSTRAINT IF EXISTS chk_po_state;
UPDATE purchase_order SET state = 'rfq' WHERE state = 'draft';
ALTER TABLE purchase_order ADD CONSTRAINT chk_po_state CHECK (
    state IN ('rfq', 'sent', 'confirmed', 'received', 'cancelled', 'superseded')
);
ALTER TABLE purchase_order ALTER COLUMN state SET DEFAULT 'rfq';

-- Legacy rows: single-member families with a derived RFQ identity
-- (RFQL prefix stays clear of the real RFQ sequence).
UPDATE purchase_order
   SET rfq_number = regexp_replace(number, '^PO', 'RFQL')
 WHERE rfq_number IS NULL AND number IS NOT NULL;
UPDATE purchase_order SET root_rfq_id = id WHERE root_rfq_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_po_rfq_rev
    ON purchase_order (company_id, rfq_number, revision);
CREATE INDEX IF NOT EXISTS idx_po_root ON purchase_order (root_rfq_id);

-- THE invariant: at most one live purchase order per RFQ family.
CREATE UNIQUE INDEX IF NOT EXISTS uq_po_one_confirmed_per_rfq
    ON purchase_order (root_rfq_id)
    WHERE state NOT IN ('rfq', 'sent', 'superseded', 'cancelled');

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ir_model_field') THEN
        UPDATE ir_model_field
           SET selection_options = '["rfq","sent","confirmed","received","cancelled","superseded"]'::jsonb
         WHERE name = 'state'
           AND model_id = (SELECT id FROM ir_model WHERE name = 'purchase_order');
    END IF;
END$$;

COMMENT ON COLUMN purchase_order.rfq_number IS
    'RFQ number (RFQ/000001), assigned at creation and shared by all revisions of one family. The PO number lands in `number` only at confirmation.';
