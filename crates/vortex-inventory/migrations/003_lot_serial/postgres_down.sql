-- Reverse of 003_lot_serial.
DROP INDEX IF EXISTS uq_stock_quant_lot;
ALTER TABLE stock_quant DROP COLUMN IF EXISTS lot_id;
-- Restore the original (product, location) uniqueness.
ALTER TABLE stock_quant
    ADD CONSTRAINT uq_stock_quant UNIQUE (product_id, location_id);

ALTER TABLE stock_move DROP COLUMN IF EXISTS lot_id;

DROP TABLE IF EXISTS stock_lot;
