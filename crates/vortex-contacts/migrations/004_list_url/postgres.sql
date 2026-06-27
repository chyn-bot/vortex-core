-- Claim /contacts as the canonical list URL so /list/contacts redirects here
-- and the pivot view's back-to-list button lands on our rich custom handler.
UPDATE ir_model SET list_url = '/contacts' WHERE name = 'contacts';
