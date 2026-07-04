-- 133_attachments — repair + complete the attachment schema.
--
-- The generic attachment routes (/api/attachments/...) have queried
-- ir_attachment since they shipped, but no migration ever created the
-- table; likewise the chatter handlers reference an is_secure column
-- that never existed. Both features were dead at runtime. This
-- migration makes the schema match the handlers, which now store
-- FileStore keys (backend-portable), never filesystem paths.

CREATE TABLE IF NOT EXISTS ir_attachment (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    res_model VARCHAR(255) NOT NULL,
    res_id UUID NOT NULL,
    -- FileStore key within the tenant's namespace (not a filesystem path)
    store_fname VARCHAR(512),
    file_size BIGINT,
    mimetype VARCHAR(255),
    checksum VARCHAR(64),  -- SHA-256 for audit integrity verification
    created_by UUID REFERENCES users(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ir_attachment_resource
    ON ir_attachment(res_model, res_id);

-- Secure documents: inline preview only, no download. The handlers
-- have set/read this flag since the chatter feature shipped.
ALTER TABLE chatter_attachments
    ADD COLUMN IF NOT EXISTS is_secure BOOLEAN NOT NULL DEFAULT false;
