-- Down: SESB EAM field portal & API support
DROP TABLE IF EXISTS eam_field_agent_location;
ALTER TABLE eam_substation DROP COLUMN IF EXISTS latitude;
ALTER TABLE eam_substation DROP COLUMN IF EXISTS longitude;
