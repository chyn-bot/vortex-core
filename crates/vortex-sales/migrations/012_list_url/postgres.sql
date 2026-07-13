-- Claim /sales as the canonical list URL for sales_order so /list/sales_order
-- redirects here and the pivot/graph view's back-to-list button lands on our
-- rich custom handler instead of the (empty) generic list.
UPDATE ir_model SET list_url = '/sales' WHERE name = 'sales_order';
