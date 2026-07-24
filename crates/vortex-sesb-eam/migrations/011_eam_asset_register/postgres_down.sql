-- Down migration for 011_eam_asset_register.
DROP TABLE IF EXISTS eam_lifecycle_event;
DROP TABLE IF EXISTS eam_asset_document;
DROP TABLE IF EXISTS eam_asset_movement;
DROP TABLE IF EXISTS eam_asset;
DROP TABLE IF EXISTS eam_asset_location;
DROP TABLE IF EXISTS eam_asset_category;
