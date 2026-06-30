-- Down: SESB EAM networks
ALTER TABLE eam_equipment DROP CONSTRAINT IF EXISTS fk_eam_equip_tower;
ALTER TABLE eam_equipment DROP CONSTRAINT IF EXISTS fk_eam_equip_tline;
ALTER TABLE eam_equipment DROP CONSTRAINT IF EXISTS fk_eam_equip_dline;
ALTER TABLE eam_equipment DROP CONSTRAINT IF EXISTS fk_eam_equip_gantry;
ALTER TABLE eam_equipment DROP CONSTRAINT IF EXISTS fk_eam_equip_span;
ALTER TABLE eam_equipment DROP CONSTRAINT IF EXISTS fk_eam_equip_ugc;
DROP TABLE IF EXISTS eam_cable_test;
DROP TABLE IF EXISTS eam_cable_segment;
DROP TABLE IF EXISTS eam_gantry;
DROP TABLE IF EXISTS eam_transmission_span;
DROP TABLE IF EXISTS eam_transmission_tower;
DROP TABLE IF EXISTS eam_transmission_line;
DROP TABLE IF EXISTS eam_ugc_line;
DROP TABLE IF EXISTS eam_distribution_line;
