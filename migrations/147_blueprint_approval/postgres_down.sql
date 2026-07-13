DELETE FROM policy_rules WHERE name = 'admins_can_approve_blueprints';
DROP TABLE IF EXISTS blueprint_governance;
DROP TABLE IF EXISTS blueprint_change_request;
