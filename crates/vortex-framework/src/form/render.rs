//! HTML rendering: FormConfig + values + errors → daisyUI form.

use sqlx::PgPool;

use super::config::{FieldKind, FormConfig, FormField};
use super::ident;
use super::save::{FieldError, FormValues};
use crate::ui::html_escape;

/// Create or Edit — determines heading, submit target, button label.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FormMode {
    Create,
    /// Edit of the given record id (stringified UUID).
    Edit,
}

/// Options for Many2One selects, loaded once per render.
async fn reference_options(db: &PgPool, table: &str, display: &str) -> Vec<(String, String)> {
    if !ident(table) || !ident(display) {
        return Vec::new();
    }
    let sql = format!(
        "SELECT id::text, {display}::text FROM {table} \
         WHERE COALESCE(active, true) ORDER BY {display} LIMIT 500"
    );
    sqlx::query_as::<_, (String, String)>(&sql)
        .fetch_all(db)
        .await
        .unwrap_or_default()
}

fn widget(field: &FormField, value: &str, m2o_options: &[(String, String)]) -> String {
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
        FieldKind::Many2One { .. } => {
            let mut out = format!(r#"<select name="{name}" class="select select-bordered w-full"{required}{readonly}>"#);
            if !field.required {
                out.push_str("<option value=\"\"></option>");
            }
            for (id, label) in m2o_options {
                let selected = if id == value { " selected" } else { "" };
                out.push_str(&format!(
                    r#"<option value="{}"{selected}>{}</option>"#,
                    html_escape(id),
                    html_escape(label)
                ));
            }
            out.push_str("</select>");
            out
        }
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
        if let Some(title) = &section.title {
            body.push_str(&format!(
                r#"<h2 class="text-sm font-semibold uppercase opacity-60 mt-4 mb-2">{}</h2>"#,
                html_escape(title)
            ));
        }
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
                    reference_options(db, table, display).await
                }
                _ => Vec::new(),
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
            body.push_str(&format!(
                r#"<label class="form-control mb-3"><div class="label"><span class="label-text">{label}{star}</span>{help}</div>{widget}<div class="label">{error}</div></label>"#,
                label = html_escape(&field.label),
                star = star,
                help = help.unwrap_or_default(),
                widget = widget(field, value, &m2o),
                error = error.unwrap_or_default(),
            ));
        }
    }

    format!(
        r##"<div class="max-w-2xl"><h1 class="text-2xl font-bold mb-6">{heading}</h1>{top_errors}
<form method="post" action="{action}" class="card bg-base-100 shadow"><div class="card-body">
{body}
<div class="card-actions justify-end mt-2">
<a href="{cancel}" class="btn btn-ghost">Cancel</a>
<button type="submit" class="btn btn-primary">{submit}</button>
</div></div></form></div>"##,
        heading = html_escape(&heading),
        top_errors = top_errors,
        action = action,
        body = body,
        cancel = config.base_url,
        submit = submit,
    )
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
        let html = widget(name_field, "a<b>&\"quote", &[]);
        assert!(html.contains("a&lt;b&gt;&amp;&quot;quote"));
        assert!(html.contains("required"));
        assert!(html.contains("placeholder=\"e.g. Bay 42\""));
    }

    #[test]
    fn select_marks_current_and_offers_empty_when_optional() {
        let c = cfg();
        let state = c.fields().nth(2).unwrap();
        let html = widget(state, "done", &[]);
        assert!(html.contains(r#"<option value="done" selected>Done</option>"#));
        assert!(html.contains(r#"<option value=""></option>"#), "optional select offers empty");
    }

    #[test]
    fn checkbox_checked_from_pg_text_bool() {
        let c = cfg();
        let active = c.fields().nth(1).unwrap();
        assert!(widget(active, "t", &[]).contains(" checked"));
        assert!(!widget(active, "false", &[]).contains(" checked"));
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

        let html = render_form(
            &pool, &c, FormMode::Edit, Some("abc-123"),
            &values(&[("name", "Bay 1")]), &[],
        ).await;
        assert!(html.contains("Edit Item"));
        assert!(html.contains("action=\"/items/abc-123\""));
        assert!(html.contains("value=\"Bay 1\""));
    }
}
