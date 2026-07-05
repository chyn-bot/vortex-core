-- Migration 004: quotation stage in front of the sales order
--
-- One document, two identities: a record is born as a quotation
-- (QT/000123, editable), freezes when sent, and only receives its
-- SO number at confirmation. Revisions are immutable sibling rows
-- linked by root_quote_id — a sent quote is what the customer holds,
-- so it must reprint exactly; changes become a new revision. The
-- partial unique index makes "only one confirmed sale per quotation
-- family" a database guarantee, not a UI convention.

-- SO number is now assigned at confirmation.
ALTER TABLE sales_order ALTER COLUMN number DROP NOT NULL;

ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS quote_number  VARCHAR(32);
ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS revision      INTEGER NOT NULL DEFAULT 1;
ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS root_quote_id UUID REFERENCES sales_order(id);
ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS validity_date DATE;
ALTER TABLE sales_order ADD COLUMN IF NOT EXISTS lost_reason   TEXT;

-- Widen the state machine:
--   quotation → sent → confirmed → delivered
--   side exits: superseded (replaced by a newer revision),
--   lost, expired (validity passed), cancelled (confirmed orders).
ALTER TABLE sales_order DROP CONSTRAINT IF EXISTS chk_so_state;
UPDATE sales_order SET state = 'quotation' WHERE state = 'draft';
ALTER TABLE sales_order ADD CONSTRAINT chk_so_state CHECK (
    state IN ('quotation', 'sent', 'confirmed', 'delivered',
              'cancelled', 'superseded', 'lost', 'expired')
);
ALTER TABLE sales_order ALTER COLUMN state SET DEFAULT 'quotation';

-- Legacy rows predate the quotation stage: give each its own
-- single-member family and a derived quote identity.
-- QTL prefix keeps legacy identities clear of the real QT sequence.
UPDATE sales_order
   SET quote_number = regexp_replace(number, '^SO', 'QTL')
 WHERE quote_number IS NULL AND number IS NOT NULL;
UPDATE sales_order SET root_quote_id = id WHERE root_quote_id IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uq_so_quote_rev
    ON sales_order (company_id, quote_number, revision);
CREATE INDEX IF NOT EXISTS idx_so_root ON sales_order (root_quote_id);

-- THE invariant: at most one live sale per quotation family.
CREATE UNIQUE INDEX IF NOT EXISTS uq_so_one_confirmed_per_quote
    ON sales_order (root_quote_id)
    WHERE state NOT IN ('quotation', 'sent', 'superseded', 'lost', 'expired', 'cancelled');

-- Keep the generic list/pivot metadata in step with the new states.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'ir_model_field') THEN
        UPDATE ir_model_field
           SET selection_options = '["quotation","sent","confirmed","delivered","cancelled","superseded","lost","expired"]'::jsonb
         WHERE name = 'state'
           AND model_id = (SELECT id FROM ir_model WHERE name = 'sales_order');
    END IF;
END$$;

COMMENT ON COLUMN sales_order.quote_number IS
    'Quotation number (QT/000001), assigned at creation and shared by all revisions of one family. The SO number lands in `number` only at confirmation.';
COMMENT ON COLUMN sales_order.root_quote_id IS
    'Family root: first revision''s id, self-referencing on the root itself. All revisions of one quotation share it; the partial unique index on it enforces a single confirmed sale per family.';
