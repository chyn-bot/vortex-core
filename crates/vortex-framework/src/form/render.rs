//! HTML rendering: FormConfig + values + errors → daisyUI form.

use sqlx::PgPool;

use super::config::{FieldKind, FormConfig, FormField};
use super::lookup::{typeahead_widget, LookupSource};
use super::save::{FieldError, FormValues};
use crate::ui::html_escape;

/// Create or Edit — determines heading, submit target, button label.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FormMode {
    Create,
    /// Edit of the given record id (stringified UUID).
    Edit,
}

/// What a [`FieldKind::Many2One`] needs to render as a typeahead: the signed
/// [`LookupSource`] token the browser echoes to `/api/lookup`, and the current
/// value's display label (empty for a blank field).
struct M2ORender {
    token: String,
    label: String,
}

fn widget(field: &FormField, value: &str, m2o: &Option<M2ORender>) -> String {
    let name = html_escape(&field.name);
    let val = html_escape(value);
    let required = if field.required { " required" } else { "" };
    let readonly = if field.readonly { " readonly disabled" } else { "" };
    let placeholder = field
        .placeholder
        .as_deref()
        .map(|p| format!(" placeholder=\"{}\"", html_escape(p)))
        .unwrap_or_default();

    match &field.kind {
        FieldKind::Text => format!(
            r#"<input type="text" name="{name}" value="{val}" maxlength="255" class="input input-bordered w-full"{placeholder}{required}{readonly}/>"#
        ),
        FieldKind::TextArea => format!(
            r#"<textarea name="{name}" class="textarea textarea-bordered w-full" rows="3"{placeholder}{required}{readonly}>{val}</textarea>"#
        ),
        FieldKind::Number => format!(
            r#"<input type="number" step="any" name="{name}" value="{val}" class="input input-bordered w-full"{placeholder}{required}{readonly}/>"#
        ),
        FieldKind::Json => format!(
            r#"<input type="text" name="{name}" value="{val}" class="input input-bordered w-full font-mono"{placeholder}{required}{readonly}/>"#
        ),
        FieldKind::Datalist(options) => {
            let mut opts = String::new();
            for (v, label) in options {
                opts.push_str(&format!(
                    r#"<option value="{}">{}</option>"#,
                    html_escape(v),
                    html_escape(label)
                ));
            }
            format!(
                r#"<input type="text" name="{name}" value="{val}" list="dl-{name}" class="input input-bordered w-full"{placeholder}{required}{readonly}/><datalist id="dl-{name}">{opts}</datalist>"#
            )
        }
        FieldKind::Date => format!(
            r#"<input type="date" name="{name}" value="{val}" class="input input-bordered w-full"{required}{readonly}/>"#
        ),
        FieldKind::DateTime => {
            // ::text of a timestamptz is "YYYY-MM-DD HH:MM:SS+TZ";
            // datetime-local wants "YYYY-MM-DDTHH:MM".
            let local = value.get(..16).unwrap_or(value).replace(' ', "T");
            format!(
                r#"<input type="datetime-local" name="{name}" value="{}" class="input input-bordered w-full"{required}{readonly}/>"#,
                html_escape(&local)
            )
        }
        FieldKind::Checkbox => {
            let checked = if value == "true" || value == "t" { " checked" } else { "" };
            format!(
                r#"<input type="checkbox" name="{name}" class="toggle toggle-primary"{checked}{readonly}/>"#
            )
        }
        FieldKind::Select(options) => {
            let mut out = format!(r#"<select name="{name}" class="select select-bordered w-full"{required}{readonly}>"#);
            if !field.required {
                out.push_str("<option value=\"\"></option>");
            }
            for (code, label) in options {
                let selected = if code == value { " selected" } else { "" };
                out.push_str(&format!(
                    r#"<option value="{}"{selected}>{}</option>"#,
                    html_escape(code),
                    html_escape(label)
                ));
            }
            out.push_str("</select>");
            out
        }
        FieldKind::Many2One { .. } => match m2o {
            Some(m) => typeahead_widget(
                &field.name,
                &m.token,
                value,
                &m.label,
                field.required,
                field.readonly,
                field.placeholder.as_deref(),
            ),
            // Missing descriptor (e.g. an invalid identifier) — render an
            // inert input rather than an unsearchable, empty select.
            None => format!(
                r#"<input type="text" name="{name}" value="{val}" class="input input-bordered w-full" disabled/>"#
            ),
        },
    }
}

/// Render the full form card. `values` pre-fills fields (submitted
/// values on a validation round-trip, loaded values in Edit mode,
/// empty in Create — field defaults apply then). `errors` render
/// under their fields; `record_id` is required in Edit mode and
/// shapes the submit URL: `{base}/create` vs `{base}/{id}`.
pub async fn render_form(
    db: &PgPool,
    config: &FormConfig,
    mode: FormMode,
    record_id: Option<&str>,
    values: &FormValues,
    errors: &[FieldError],
) -> String {
    let action = match (mode, record_id) {
        (FormMode::Create, _) => format!("{}/create", config.base_url),
        (FormMode::Edit, Some(id)) => format!("{}/{}", config.base_url, html_escape(id)),
        (FormMode::Edit, None) => config.base_url.clone(),
    };
    let heading = match mode {
        FormMode::Create => format!("New {}", config.title),
        FormMode::Edit => format!("Edit {}", config.title),
    };
    let submit = match mode {
        FormMode::Create => "Create",
        FormMode::Edit => "Save",
    };

    let top_errors = if errors.is_empty() {
        String::new()
    } else {
        format!(
            r#"<div class="alert alert-error mb-4"><span>Please correct {} field{}.</span></div>"#,
            errors.len(),
            if errors.len() == 1 { "" } else { "s" }
        )
    };

    let mut body = String::new();
    for section in &config.sections {
        // Fields lay out on a responsive two-column grid inside a flat sheet
        // section (shared primitive); long inputs (textareas) span the full row.
        let mut fields_html = String::new();
        for field in &section.fields {
            let value = values
                .get(&field.name)
                .map(String::as_str)
                .or(match mode {
                    FormMode::Create => field.default.as_deref(),
                    FormMode::Edit => None,
                })
                .unwrap_or("");
            let m2o = match &field.kind {
                FieldKind::Many2One { table, display } => {
                    let src = LookupSource::new(table, display);
                    // Reject illegal identifiers up front: an unsigned/absent
                    // token disables the widget rather than emitting bad SQL.
                    let token = src.encode();
                    let label = if value.is_empty() {
                        String::new()
                    } else {
                        src.label_for(db, value).await.unwrap_or_default()
                    };
                    if LookupSource::decode(&token).is_some() {
                        Some(M2ORender { token, label })
                    } else {
                        None
                    }
                }
                _ => None,
            };
            let error = errors.iter().find(|e| e.field == field.name).map(|e| {
                format!(
                    r#"<span class="label-text-alt text-error">{}</span>"#,
                    html_escape(&e.message)
                )
            });
            let help = field.help.as_deref().map(|h| {
                format!(r#"<span class="label-text-alt opacity-60">{}</span>"#, html_escape(h))
            });
            let star = if field.required { " *" } else { "" };
            let span = if matches!(field.kind, FieldKind::TextArea) {
                " md:col-span-2"
            } else {
                ""
            };
            fields_html.push_str(&format!(
                r#"<label class="form-control mb-3{span}"><div class="label"><span class="label-text">{label}{star}</span>{help}</div>{widget}<div class="label">{error}</div></label>"#,
                span = span,
                label = html_escape(&field.label),
                star = star,
                help = help.unwrap_or_default(),
                widget = widget(field, value, &m2o),
                error = error.unwrap_or_default(),
            ));
            // Custom fields anchored to render right after this one (Initiative
            // #2 placement). Empty unless an admin positioned a field here.
            fields_html.push_str(
                &crate::custom_fields::render_anchor_group(db, &config.table, record_id, &field.name).await,
            );
        }
        body.push_str(&super::form_section(section.title.as_deref().unwrap_or(""), &fields_html));
    }

    // Per-tenant custom fields for this model render as an extra section inside
    // the same form, so they submit and persist with the record. Empty string
    // when the model has none. (Model identity = the form's table name, which
    // is the registry key since Initiative #1.)
    body.push_str(&crate::custom_fields::render_for_form(db, &config.table, record_id).await);

    // Computed / related virtual fields render read-only below the custom
    // fields, evaluated live in Edit mode. Empty string when the model has none.
    body.push_str(&crate::computed_fields::render_for_form(db, &config.table, record_id).await);

    // Wrap in the canonical centered sheet (shared with the generic Blueprint
    // form). Validation errors render just inside the sheet, above the fields.
    let inner = format!("{top_errors}{body}", top_errors = top_errors, body = body);
    let footer = format!(
        r#"<a href="{cancel}" class="btn btn-ghost">Cancel</a><button type="submit" class="btn btn-primary">{submit}</button>"#,
        cancel = html_escape(&config.base_url),
        submit = submit,
    );
    let form_attrs = format!(r#"method="post" action="{}""#, html_escape(&action));
    super::render_form_sheet(&super::FormSheet {
        max_width: super::SHEET_WIDTH,
        back_href: "",
        control_row: "",
        form_attrs: &form_attrs,
        title: &heading,
        inner: &inner,
        footer: &footer,
        below: "",
    })
}

#[cfg(test)]
mod tests {
    use super::super::config::{FormConfig, FormField};
    use super::*;

    fn cfg() -> FormConfig {
        FormConfig::new("Item", "items", "/items")
            .section("Details")
            .field(FormField::text("name", "Name").required().placeholder("e.g. Bay 42"))
            .field(FormField::checkbox("active", "Active"))
            .field(FormField::select("state", "State", &[("draft", "Draft"), ("done", "Done")]))
    }

    fn values(kv: &[(&str, &str)]) -> FormValues {
        kv.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()
    }

    #[test]
    fn widgets_render_and_escape() {
        let c = cfg();
        let name_field = c.fields().next().unwrap();
        let html = widget(name_field, "a<b>&\"quote", &None);
        assert!(html.contains("a&lt;b&gt;&amp;&quot;quote"));
        assert!(html.contains("required"));
        assert!(html.contains("placeholder=\"e.g. Bay 42\""));
    }

    #[test]
    fn select_marks_current_and_offers_empty_when_optional() {
        let c = cfg();
        let state = c.fields().nth(2).unwrap();
        let html = widget(state, "done", &None);
        assert!(html.contains(r#"<option value="done" selected>Done</option>"#));
        assert!(html.contains(r#"<option value=""></option>"#), "optional select offers empty");
    }

    #[test]
    fn checkbox_checked_from_pg_text_bool() {
        let c = cfg();
        let active = c.fields().nth(1).unwrap();
        assert!(widget(active, "t", &None).contains(" checked"));
        assert!(!widget(active, "false", &None).contains(" checked"));
    }

    #[tokio::test]
    async fn form_renders_sections_errors_and_mode() {
        // render_form only touches the DB for Many2One fields; this
        // config has none, so a lazy (never-connected) pool suffices.
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://localhost/unused")
            .unwrap();
        let c = cfg();
        let errs = vec![FieldError { field: "name".into(), message: "Name is required".into() }];
        let html = render_form(&pool, &c, FormMode::Create, None, &values(&[]), &errs).await;
        assert!(html.contains("New Item"));
        assert!(html.contains("Details"));
        assert!(html.contains("action=\"/items/create\""));
        assert!(html.contains("Name is required"));
        // Contract: the config-driven form engine — which every scaffolded
        // plugin routes its create/edit forms through — MUST emit the canonical
        // centered sheet. If this breaks, new plugins silently drift off the
        // core form UI, so pin the sheet's structural markers here.
        assert!(html.contains(crate::form::SHEET_WIDTH), "render_form must use the sheet width");
        assert!(
            html.contains("bg-base-100 rounded-lg shadow-sm border border-base-300"),
            "render_form must wrap fields in the sheet container"
        );
        assert!(!html.contains("card bg-base-100 shadow"), "render_form must not use floating cards");

        let html = render_form(
            &pool, &c, FormMode::Edit, Some("abc-123"),
            &values(&[("name", "Bay 1")]), &[],
        ).await;
        assert!(html.contains("Edit Item"));
        assert!(html.contains("action=\"/items/abc-123\""));
        assert!(html.contains("value=\"Bay 1\""));
    }
}
