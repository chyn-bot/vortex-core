-- Down: SESB EAM planning & governance
ALTER TABLE eam_maintenance DROP CONSTRAINT IF EXISTS fk_eam_mnt_plan;
ALTER TABLE eam_maintenance DROP CONSTRAINT IF EXISTS fk_eam_mnt_agent_group;
DELETE FROM roles WHERE id IN (
    '5e5b0000-0000-0000-0000-0000000000a1','5e5b0000-0000-0000-0000-0000000000a2',
    '5e5b0000-0000-0000-0000-0000000000a3','5e5b0000-0000-0000-0000-0000000000a4',
    '5e5b0000-0000-0000-0000-0000000000a5','5e5b0000-0000-0000-0000-0000000000a6');
DROP TABLE IF EXISTS eam_approval_line;
DROP TABLE IF EXISTS eam_approval_request;
DROP TABLE IF EXISTS eam_approval_matrix;
DROP TABLE IF EXISTS eam_field_agent_leave;
DROP TABLE IF EXISTS eam_field_agent_group_kawasan_rel;
DROP TABLE IF EXISTS eam_field_agent_kawasan_rel;
DROP TABLE IF EXISTS eam_field_agent_group_rel;
DROP TABLE IF EXISTS eam_field_agent;
DROP TABLE IF EXISTS eam_field_agent_group;
DROP TABLE IF EXISTS eam_maintenance_plan;
