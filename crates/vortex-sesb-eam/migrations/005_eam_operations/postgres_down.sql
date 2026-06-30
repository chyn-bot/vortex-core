-- Down: SESB EAM operations
ALTER TABLE eam_asset_class DROP CONSTRAINT IF EXISTS fk_eam_aclass_checklist;
ALTER TABLE eam_maintenance DROP CONSTRAINT IF EXISTS fk_eam_mnt_repair_defect;
DROP TABLE IF EXISTS eam_troubleshooting_rule;
DROP TABLE IF EXISTS eam_vegetation_section;
DROP TABLE IF EXISTS eam_outage;
DROP TABLE IF EXISTS eam_line_patrol;
DROP TABLE IF EXISTS eam_condition_monitoring;
DROP TABLE IF EXISTS eam_inspection;
DROP TABLE IF EXISTS eam_defect;
DROP TABLE IF EXISTS eam_checklist_line;
DROP TABLE IF EXISTS eam_maintenance_part_line;
DROP TABLE IF EXISTS eam_maintenance;
DROP TABLE IF EXISTS eam_checklist_selection_option;
DROP TABLE IF EXISTS eam_checklist_template_item;
DROP TABLE IF EXISTS eam_checklist_template;
