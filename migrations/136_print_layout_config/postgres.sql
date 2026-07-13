-- 136_print_layout_config — store the visual (no-code) editor's structured
-- state alongside the compiled QWeb body.
--
-- The "Visual" print-template editor lets non-technical users toggle sections,
-- pick line columns and edit labels; on save it compiles that choice into a
-- normal QWeb `body` (rendered by the existing engine) AND stores the choice
-- itself here as JSON so the form can be re-opened with the same settings.
--
-- A NULL `config` means the template has no visual state to restore — either it
-- has never been customised, or it was hand-edited in the raw-HTML tab (which
-- clears `config` because arbitrary HTML can't be reflected back into the form).

ALTER TABLE doc_print_templates
    ADD COLUMN IF NOT EXISTS config JSONB;
