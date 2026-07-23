-- Reconciliation — opt-in line-locate for image scans.
--
-- PDFs carry a text layer, so pdf.js gives us per-word coordinates and the
-- "click a line → highlight it on the document" feature works for free. A flat
-- scanned/photographed IMAGE has no text layer, so locating a line requires the
-- vision model to also return each line's vertical position — which costs extra
-- tokens. `image_locate` makes that opt-in per tenant (default off); when on,
-- extraction of an image asks for a normalized vertical band per line, stored
-- here as `doc_y` (top edge, 0..1 of page height) and `doc_h` (height, 0..1).

ALTER TABLE recon_ai_config
    ADD COLUMN IF NOT EXISTS image_locate BOOLEAN NOT NULL DEFAULT false;

ALTER TABLE recon_inv_line ADD COLUMN IF NOT EXISTS doc_y FLOAT8;
ALTER TABLE recon_inv_line ADD COLUMN IF NOT EXISTS doc_h FLOAT8;
