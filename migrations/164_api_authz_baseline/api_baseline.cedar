// Core — generic record API authorization baseline (migration 164).
//
// The generic REST API (`/api/v1/{model}`) evaluates this policy on every
// read/create/update/delete. This baseline PERMITS any authenticated principal
// (the bearer-token middleware has already established identity), so that
// turning on enforcement (API_POLICY_ENFORCED=1) does not break existing
// integrations. It is the seam a tenant tightens: add `forbid` rules — e.g.
// forbid `delete` on financial models for non-managers — or replace this
// permit with narrower role-scoped permits.
//
// `resource is Record` confines this permit to the generic record API; it does
// not affect workflow, work-order, blueprint or user-management authorization,
// which use their own resource types.
permit (
    principal,
    action,
    resource
) when {
    resource is Record
};
