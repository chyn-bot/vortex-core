-- Generic, multi-step approval workflow. A stage button (record_stage_actions)
-- that has one or more approval_rules requires approval: clicking it creates an
-- approval_request instead of transitioning. Approvers act per ordered step;
-- once the final step's quota is met the stored transition is applied. Reusable
-- by any module — the request carries the status table/column so the
-- approve→apply logic stays fully generic in core.

-- Ordered approval steps for a button. Presence of >=1 row => button needs approval.
CREATE TABLE IF NOT EXISTS approval_rules (
    id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    action_id     UUID NOT NULL REFERENCES record_stage_actions(id) ON DELETE CASCADE,
    step          INTEGER NOT NULL DEFAULT 1,
    label         VARCHAR(100),
    approver_role VARCHAR(100) NOT NULL,
    min_approvals INTEGER NOT NULL DEFAULT 1,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_approval_rules_action_step UNIQUE (action_id, step)
);
CREATE INDEX IF NOT EXISTS idx_approval_rules_action ON approval_rules(action_id, step);

-- An in-progress approval for one record transition.
CREATE TABLE IF NOT EXISTS approval_requests (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    model             VARCHAR(100) NOT NULL,
    record_id         UUID NOT NULL,
    action_id         UUID REFERENCES record_stage_actions(id) ON DELETE SET NULL,
    status_table      VARCHAR(100) NOT NULL,   -- where the status lives (generic apply)
    status_column     VARCHAR(100) NOT NULL,
    from_stage        VARCHAR(50),
    target_stage      VARCHAR(50)  NOT NULL,
    resource_name     VARCHAR(255),
    requested_by      UUID,
    requested_by_name VARCHAR(100),
    current_step      INTEGER NOT NULL DEFAULT 1,
    status            VARCHAR(20) NOT NULL DEFAULT 'pending',  -- pending|approved|rejected|cancelled
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved_at       TIMESTAMPTZ
);
CREATE INDEX IF NOT EXISTS idx_approval_requests_record ON approval_requests(model, record_id);
CREATE INDEX IF NOT EXISTS idx_approval_requests_status ON approval_requests(status, current_step);

-- Individual approve/reject decisions (one per user per step).
CREATE TABLE IF NOT EXISTS approval_decisions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id      UUID NOT NULL REFERENCES approval_requests(id) ON DELETE CASCADE,
    step            INTEGER NOT NULL,
    decided_by      UUID,
    decided_by_name VARCHAR(100),
    decision        VARCHAR(10) NOT NULL,   -- approve|reject
    comment         TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT uq_approval_decision_user_step UNIQUE (request_id, step, decided_by)
);
CREATE INDEX IF NOT EXISTS idx_approval_decisions_request ON approval_decisions(request_id, step);
