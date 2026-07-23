-- Reconciliation — SKU master (LSEO's own item codes for M3 posting).
--
-- A supplier invoice prints the vendor's item code; M3 posts against LSEO's
-- internal SKU. So the GL entry resolves vendor code → LSEO SKU (via the
-- existing vendor_item_alias, self-learning) and offers this master as the
-- pick-list — mirroring how the GL account is matched.

CREATE TABLE IF NOT EXISTS recon_sku_master (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    sku         VARCHAR(64) NOT NULL UNIQUE,
    description VARCHAR(200),
    active      BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed from items already seen (M3 pool + saved aliases) so it isn't empty.
INSERT INTO recon_sku_master (sku, description)
SELECT lseo_sku, MAX(description)
  FROM recon_m3_line
 WHERE lseo_sku IS NOT NULL AND lseo_sku <> ''
 GROUP BY lseo_sku
ON CONFLICT (sku) DO NOTHING;

INSERT INTO recon_sku_master (sku)
SELECT DISTINCT lseo_sku FROM vendor_item_alias
 WHERE lseo_sku IS NOT NULL AND lseo_sku <> ''
ON CONFLICT (sku) DO NOTHING;
