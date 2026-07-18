-- Promote the premise (the serviced property) to a first-class field on the
-- account. In utility models the *premise* is where service is delivered; it
-- outlives any single occupant, so a stable `premise_no` lets the same
-- property be identified across move-in/move-out (groundwork — occupancy
-- changes are a later enhancement). `premise_address` is the service address,
-- which may differ from the customer's mailing address on `contacts`.

ALTER TABLE iwk_account
    ADD COLUMN IF NOT EXISTS premise_no      VARCHAR(24),
    ADD COLUMN IF NOT EXISTS premise_address VARCHAR(255);

-- Stable premise identifiers for the existing demo accounts (one premise per
-- account for now). New registrations mint one from the sequence unless the
-- operator links an existing premise.
CREATE SEQUENCE IF NOT EXISTS iwk_premise_seq;
SELECT setval('iwk_premise_seq', GREATEST(400000, (SELECT COUNT(*) FROM iwk_account)));

UPDATE iwk_account
   SET premise_no = 'PR' || lpad(nextval('iwk_premise_seq')::text, 8, '0')
 WHERE premise_no IS NULL;

CREATE INDEX IF NOT EXISTS idx_iwk_account_premise ON iwk_account(premise_no);
