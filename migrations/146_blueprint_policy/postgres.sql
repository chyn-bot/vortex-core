-- Governance for Vortex Blueprints.
--
-- Every governed blueprint operation goes through `state.policy.check(...)`
-- against the Cedar engine. Cedar is DENY-BY-DEFAULT: with no matching `permit`,
-- the result is Deny — so without this seed the whole feature would be dead on
-- arrival. This permit grants system administrators the blueprint actions;
-- every other principal stays denied by construction, which is exactly the
-- posture we want for a schema-changing capability.
--
-- A later, finer-grained "data architect" role can be added as an additional
-- permit without touching this one.

INSERT INTO policy_rules (name, description, policy_text, priority) VALUES
(
    'admins_can_manage_blueprints',
    'System administrators can create, alter, and delete Blueprints (runtime user-defined models).',
    $cedar$permit (
    principal in Role::"system_administrator",
    action in [Action::"blueprint.create", Action::"blueprint.alter", Action::"blueprint.delete"],
    resource
);$cedar$,
    100
)
ON CONFLICT (name) DO NOTHING;
