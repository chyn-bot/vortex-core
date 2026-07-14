//! `vortex scaffold plugin <name>` — generate a working vertical
//! plugin crate and wire it into the workspace and host.
//!
//! The bar: after scaffolding, `cargo build` compiles and the module
//! serves a real list view, create form, and record page (status bar
//! + chatter + audited transitions) as soon as its migration is
//! applied. The generated code is the same shape as
//! `vortex-contacts`, the reference plugin.
//!
//! Wiring performed automatically (each edit is anchored on the
//! vortex-contacts registration lines; if an anchor is missing the
//! step is reported for manual completion instead of guessed at):
//!   1. workspace `members` + `[workspace.dependencies]`
//!   2. vortex-cli dependency
//!   3. plugin registration in `server.rs`
//!   4. migration-registry registration in `db.rs`

use std::fs;
use std::path::Path;

use anyhow::{bail, Context, Result};

const TPL_CARGO: &str = include_str!("../../templates/scaffold/Cargo.toml.tmpl");
const TPL_LIB: &str = include_str!("../../templates/scaffold/lib.rs.tmpl");
const TPL_MODEL: &str = include_str!("../../templates/scaffold/model.rs.tmpl");
const TPL_PLUGIN: &str = include_str!("../../templates/scaffold/plugin.rs.tmpl");
const TPL_HANDLERS: &str = include_str!("../../templates/scaffold/handlers.rs.tmpl");
const TPL_MIGRATION: &str = include_str!("../../templates/scaffold/migration.sql.tmpl");
const TPL_README: &str = include_str!("../../templates/scaffold/README.md.tmpl");

struct Names {
    kebab: String,
    snake: String,
    pascal: String,
    display: String,
    seq: String,
}

impl Names {
    fn derive(raw: &str, display: Option<String>) -> Result<Self> {
        let cleaned = raw.trim().to_lowercase();
        if cleaned.is_empty()
            || !cleaned
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == ' ')
            || !cleaned.chars().next().unwrap().is_ascii_alphabetic()
        {
            bail!("plugin name must start with a letter and contain only letters, digits, '-', '_'");
        }
        let words: Vec<String> = cleaned
            .split(|c| c == '-' || c == '_' || c == ' ')
            .filter(|w| !w.is_empty())
            .map(str::to_string)
            .collect();
        let kebab = words.join("-");
        let snake = words.join("_");
        let pascal = words
            .iter()
            .map(|w| {
                let mut c = w.chars();
                c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
            })
            .collect::<String>();
        let display = display.unwrap_or_else(|| {
            words
                .iter()
                .map(|w| {
                    let mut c = w.chars();
                    c.next().map(|f| f.to_ascii_uppercase().to_string() + c.as_str()).unwrap_or_default()
                })
                .collect::<Vec<_>>()
                .join(" ")
        });
        let seq: String = snake.chars().filter(|c| c.is_ascii_alphabetic()).take(3).collect::<String>().to_uppercase();
        Ok(Self { kebab, snake, pascal, display, seq })
    }

    fn fill(&self, template: &str) -> String {
        template
            .replace("__KEBAB__", &self.kebab)
            .replace("__SNAKE__", &self.snake)
            .replace("__PASCAL__", &self.pascal)
            .replace("__DISPLAY__", &self.display)
            .replace("__SEQ__", &self.seq)
    }
}

/// Insert `addition` directly after the line containing `anchor` in
/// `path`. Returns false (and leaves the file untouched) if the
/// anchor is missing or the addition is already present.
fn wire(path: &str, anchor: &str, addition: &str) -> Result<bool> {
    let src = fs::read_to_string(path).with_context(|| format!("read {path}"))?;
    if src.contains(addition.trim()) {
        return Ok(true); // already wired
    }
    let Some(pos) = src.find(anchor) else {
        return Ok(false);
    };
    let line_end = src[pos..].find('\n').map(|i| pos + i + 1).unwrap_or(src.len());
    let mut out = String::with_capacity(src.len() + addition.len());
    out.push_str(&src[..line_end]);
    out.push_str(addition);
    out.push_str(&src[line_end..]);
    fs::write(path, out).with_context(|| format!("write {path}"))?;
    Ok(true)
}

pub fn run(name: &str, display: Option<String>) -> Result<()> {
    // Must run from the workspace root (same expectation as `db migrate`).
    if !Path::new("Cargo.toml").exists() || !Path::new("crates/vortex-contacts").exists() {
        bail!("run from the vortex-core workspace root");
    }
    let n = Names::derive(name, display)?;
    let crate_dir = format!("crates/vortex-{}", n.kebab);
    if Path::new(&crate_dir).exists() {
        bail!("{crate_dir} already exists");
    }

    // ── generate the crate ───────────────────────────────────────────
    fs::create_dir_all(format!("{crate_dir}/src"))?;
    fs::create_dir_all(format!("{crate_dir}/migrations/001_init"))?;
    fs::write(format!("{crate_dir}/Cargo.toml"), n.fill(TPL_CARGO))?;
    fs::write(format!("{crate_dir}/src/lib.rs"), n.fill(TPL_LIB))?;
    fs::write(format!("{crate_dir}/src/model.rs"), n.fill(TPL_MODEL))?;
    fs::write(format!("{crate_dir}/src/plugin.rs"), n.fill(TPL_PLUGIN))?;
    fs::write(format!("{crate_dir}/src/handlers.rs"), n.fill(TPL_HANDLERS))?;
    fs::write(
        format!("{crate_dir}/migrations/001_init/postgres.sql"),
        n.fill(TPL_MIGRATION),
    )?;
    fs::write(format!("{crate_dir}/README.md"), n.fill(TPL_README))?;
    println!("created {crate_dir}/");

    // ── wire it in ───────────────────────────────────────────────────
    let manual = wire_all(&n)?;

    // ── report ───────────────────────────────────────────────────────
    if manual.is_empty() {
        println!("wired into workspace, host plugin list, and migration registry");
    } else {
        println!("\nfinish wiring manually:");
        for m in &manual {
            println!("  - {m}");
        }
    }
    println!(
        "\nnext:\n  cargo build -p vortex-cli\n  DATABASE_URL=<tenant> ./target/debug/vortex db migrate\n  open /{}  (install the module for the tenant if the sidebar entry is missing)",
        n.kebab
    );
    Ok(())
}

/// Wire a freshly-generated crate into the workspace, host plugin list, and
/// migration registry. Returns the list of steps that need manual completion
/// (empty when everything was anchored automatically). Shared by `run` and
/// `run_from_blueprint`.
fn wire_all(n: &Names) -> Result<Vec<String>> {
    let mut manual: Vec<String> = Vec::new();
    if !wire(
        "Cargo.toml",
        "\"crates/vortex-contacts\",",
        &format!("    \"crates/vortex-{}\",\n", n.kebab),
    )? {
        manual.push(format!("Cargo.toml: add \"crates/vortex-{}\" to [workspace] members", n.kebab));
    }
    if !wire(
        "Cargo.toml",
        "vortex-contacts = { path = \"crates/vortex-contacts\" }",
        &format!("vortex-{} = {{ path = \"crates/vortex-{}\" }}\n", n.kebab, n.kebab),
    )? {
        manual.push(format!("Cargo.toml: add vortex-{} to [workspace.dependencies]", n.kebab));
    }
    if !wire(
        "crates/vortex-cli/Cargo.toml",
        "vortex-contacts = { workspace = true }",
        &format!("vortex-{} = {{ workspace = true }}\n", n.kebab),
    )? {
        manual.push(format!("crates/vortex-cli/Cargo.toml: add vortex-{} = {{ workspace = true }}", n.kebab));
    }
    let register = format!(
        "    plugin_registry.register(Arc::new(vortex_{}::{}Plugin::new()));\n",
        n.snake, n.pascal
    );
    if !wire(
        "crates/vortex-cli/src/commands/server.rs",
        "plugin_registry.register(Arc::new(vortex_contacts::ContactsPlugin::new()));",
        &register,
    )? {
        manual.push(format!("crates/vortex-cli/src/commands/server.rs: {}", register.trim()));
    }
    let register_db = format!(
        "    registry.register(Arc::new(vortex_{}::{}Plugin::new()));\n",
        n.snake, n.pascal
    );
    if !wire(
        "crates/vortex-cli/src/commands/db.rs",
        "registry.register(Arc::new(vortex_contacts::ContactsPlugin::new()));",
        &register_db,
    )? {
        manual.push(format!("crates/vortex-cli/src/commands/db.rs: {}", register_db.trim()));
    }
    Ok(manual)
}

/// A Blueprint field, read from the tenant registry for code generation.
struct BpField {
    name: String,
    label: String,
    field_type: String,
    related_model: Option<String>,
    selection_csv: Option<String>,
}

/// Columns the scaffold skeleton already declares — a Blueprint field with one
/// of these names is skipped (its shape is already provided by the skeleton).
const SKELETON_COLUMNS: &[&str] = &[
    "id", "code", "name", "description", "record_state", "active", "created_by",
    "created_at", "updated_at",
];

/// Map a Blueprint field to `(rust_decl_lines, sql_column_line, needs_chrono)`.
/// Types are constrained to the set the derive macro + `Field` trait support, so
/// the generated crate always compiles; the intended widget is carried in
/// `ui_type`. Relations degrade to a plain `Uuid` with a TODO (no compiled FK).
fn map_field(f: &BpField) -> (String, String, bool) {
    let esc_label = f.label.replace('"', "'");
    let (rust_ty, sql_ty, ui_or_sel, needs_chrono): (&str, &str, String, bool) =
        match f.field_type.as_str() {
            "text" => ("Option<String>", "TEXT", "ui_type = \"text\"".into(), false),
            "integer" => ("Option<i64>", "BIGINT", "ui_type = \"integer\"".into(), false),
            "float" | "number" => ("Option<f64>", "DOUBLE PRECISION", "ui_type = \"number\"".into(), false),
            "decimal" | "monetary" => ("Option<f64>", "DOUBLE PRECISION", "ui_type = \"monetary\"".into(), false),
            "boolean" => ("Option<bool>", "BOOLEAN", "ui_type = \"boolean\"".into(), false),
            "date" => ("Option<DateTime<Utc>>", "TIMESTAMPTZ", "ui_type = \"date\"".into(), true),
            "datetime" => ("Option<DateTime<Utc>>", "TIMESTAMPTZ", "ui_type = \"datetime\"".into(), true),
            "selection" => {
                let csv = f.selection_csv.clone().unwrap_or_default().replace('"', "'");
                ("Option<String>", "VARCHAR(64)", format!("selection = \"{csv}\""), false)
            }
            "many2one" => ("Option<Uuid>", "UUID", "ui_type = \"string\"".into(), false),
            // string / char / anything else
            _ => ("Option<String>", "VARCHAR(255)", "ui_type = \"string\"".into(), false),
        };

    let mut decl = String::new();
    if f.field_type == "many2one" {
        if let Some(rel) = &f.related_model {
            decl.push_str(&format!("    // TODO: relation to `{rel}` — wire a real FK/typeahead if needed.\n"));
        }
    }
    decl.push_str(&format!(
        "    #[vortex(label = \"{esc_label}\", {ui_or_sel})]\n    pub {name}: {rust_ty},\n",
        name = f.name,
    ));
    let sql = format!("    {name} {sql_ty},\n", name = f.name);
    (decl, sql, needs_chrono)
}

/// `vortex scaffold from-blueprint <model>` — generate a compiled plugin crate
/// whose model carries a Blueprint's domain fields on top of the standard
/// skeleton (status bar + chatter + audited transitions). Promotes a Blueprint
/// that has proven itself as runtime data into first-class compiled code.
///
/// Reads the Blueprint from the database named by `DATABASE_URL`. Does NOT adopt
/// the Blueprint's `x_` table or its data — it generates a fresh compiled module
/// with the same field shape, which the developer then refines and migrates.
pub async fn run_from_blueprint(model: &str, name_override: Option<String>) -> Result<()> {
    use sqlx::Row;

    if !Path::new("Cargo.toml").exists() || !Path::new("crates/vortex-contacts").exists() {
        bail!("run from the vortex-core workspace root");
    }
    let url = std::env::var("DATABASE_URL")
        .context("set DATABASE_URL to the tenant database that holds the Blueprint")?;
    let pool = sqlx::postgres::PgPool::connect(&url)
        .await
        .with_context(|| format!("connect to {url}"))?;

    let head = sqlx::query(
        "SELECT id, display_name FROM ir_model WHERE name = $1 AND source = 'blueprint'",
    )
    .bind(model)
    .fetch_optional(&pool)
    .await?
    .with_context(|| format!("Blueprint '{model}' not found in this database"))?;
    let model_id: uuid::Uuid = head.get("id");
    let display_name: String = head.get("display_name");

    let rows = sqlx::query(
        "SELECT name, display_name, field_type, related_model, selection_options
         FROM ir_model_field WHERE model_id = $1 AND source = 'blueprint' ORDER BY sequence, name",
    )
    .bind(model_id)
    .fetch_all(&pool)
    .await?;
    let fields: Vec<BpField> = rows
        .iter()
        .filter_map(|r| {
            let name: String = r.get("name");
            if SKELETON_COLUMNS.contains(&name.as_str()) {
                return None; // provided by the skeleton already
            }
            let selection_csv = r
                .get::<Option<serde_json::Value>, _>("selection_options")
                .and_then(|v| v.as_array().cloned())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|o| o.get("value").and_then(|x| x.as_str()).map(|s| s.replace(',', " ")))
                        .collect::<Vec<_>>()
                        .join(",")
                });
            Some(BpField {
                name,
                label: r.get("display_name"),
                field_type: r.get("field_type"),
                related_model: r.get("related_model"),
                selection_csv,
            })
        })
        .collect();

    // Plugin name: explicit override, else the Blueprint's display name.
    let n = Names::derive(name_override.as_deref().unwrap_or(&display_name), Some(display_name.clone()))?;
    let crate_dir = format!("crates/vortex-{}", n.kebab);
    if Path::new(&crate_dir).exists() {
        bail!("{crate_dir} already exists");
    }

    // Build the custom model + migration by extending the standard templates.
    let mut needs_chrono = false;
    let (mut decls, mut cols) = (String::new(), String::new());
    for f in &fields {
        let (d, c, chrono) = map_field(f);
        decls.push_str(&d);
        cols.push_str(&c);
        needs_chrono |= chrono;
    }

    let mut model_rs = n.fill(TPL_MODEL);
    if needs_chrono {
        model_rs = model_rs.replace(
            "use uuid::Uuid;",
            "use chrono::{DateTime, Utc};\nuse uuid::Uuid;",
        );
    }
    // Insert the promoted fields just before the struct's closing brace.
    let injected = format!(
        "\n    // ── Fields promoted from Blueprint `{model}` ──\n{decls}}}\n",
    );
    model_rs = replace_last(&model_rs, "}\n", &injected);

    let mut migration = n.fill(TPL_MIGRATION);
    // Insert the promoted columns right after the `active` column line.
    let anchor = "    active BOOLEAN NOT NULL DEFAULT true,\n";
    let with_cols = format!(
        "{anchor}    -- Fields promoted from Blueprint `{model}`\n{cols}",
    );
    migration = migration.replacen(anchor, &with_cols, 1);

    // ── write the crate ──────────────────────────────────────────────
    fs::create_dir_all(format!("{crate_dir}/src"))?;
    fs::create_dir_all(format!("{crate_dir}/migrations/001_init"))?;
    let mut cargo = n.fill(TPL_CARGO);
    if needs_chrono {
        // A promoted date/datetime field brings in chrono; add it as a dep.
        cargo = cargo.replace(
            "serde = { workspace = true }",
            "serde = { workspace = true }\nchrono = { workspace = true }",
        );
    }
    fs::write(format!("{crate_dir}/Cargo.toml"), cargo)?;
    fs::write(format!("{crate_dir}/src/lib.rs"), n.fill(TPL_LIB))?;
    fs::write(format!("{crate_dir}/src/model.rs"), model_rs)?;
    fs::write(format!("{crate_dir}/src/plugin.rs"), n.fill(TPL_PLUGIN))?;
    fs::write(format!("{crate_dir}/src/handlers.rs"), n.fill(TPL_HANDLERS))?;
    fs::write(format!("{crate_dir}/migrations/001_init/postgres.sql"), migration)?;
    fs::write(format!("{crate_dir}/README.md"), n.fill(TPL_README))?;
    println!("created {crate_dir}/ from Blueprint `{model}` ({} promoted field(s))", fields.len());

    let manual = wire_all(&n)?;
    if manual.is_empty() {
        println!("wired into workspace, host plugin list, and migration registry");
    } else {
        println!("\nfinish wiring manually:");
        for m in &manual {
            println!("  - {m}");
        }
    }
    println!(
        "\nnotes:\n  - the compiled model is `{}Item` (table `{}_item`); rename to taste.\n  - it does NOT reuse the Blueprint's `x_` table or data — migrate separately if needed.\n  - relation/date fields are approximations (see the TODOs); refine before shipping.\n\nnext:\n  cargo build -p vortex-cli\n  DATABASE_URL=<tenant> ./target/debug/vortex db migrate",
        n.pascal, n.snake
    );
    Ok(())
}

/// Replace the LAST occurrence of `needle` in `s` with `replacement`.
fn replace_last(s: &str, needle: &str, replacement: &str) -> String {
    match s.rfind(needle) {
        Some(pos) => {
            let mut out = String::with_capacity(s.len() - needle.len() + replacement.len());
            out.push_str(&s[..pos]);
            out.push_str(replacement);
            out.push_str(&s[pos + needle.len()..]);
            out
        }
        None => s.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn bp(name: &str, ft: &str, sel: Option<&str>) -> BpField {
        BpField {
            name: name.into(),
            label: name.into(),
            field_type: ft.into(),
            related_model: None,
            selection_csv: sel.map(str::to_string),
        }
    }

    #[test]
    fn map_field_uses_compilable_types_and_flags_chrono() {
        // Scalars map to macro-supported Rust types + matching SQL columns.
        let (d, s, chrono) = map_field(&bp("count", "integer", None));
        assert!(d.contains("pub count: Option<i64>"));
        assert!(s.contains("count BIGINT"));
        assert!(!chrono);

        let (d, s, chrono) = map_field(&bp("value", "monetary", None));
        assert!(d.contains("Option<f64>") && s.contains("DOUBLE PRECISION") && !chrono);

        // A date brings in chrono and uses DateTime<Utc> (NaiveDate has no Field impl).
        let (d, s, chrono) = map_field(&bp("seen", "date", None));
        assert!(d.contains("Option<DateTime<Utc>>") && s.contains("TIMESTAMPTZ") && chrono);

        // Selection carries its options through the `selection` attr.
        let (d, _, _) = map_field(&bp("grade", "selection", Some("A,B,C")));
        assert!(d.contains("selection = \"A,B,C\""));

        // A relation degrades to Uuid with a TODO, never an uncompilable type.
        let (d, s, _) = map_field(&BpField {
            name: "owner".into(), label: "Owner".into(), field_type: "many2one".into(),
            related_model: Some("contacts".into()), selection_csv: None,
        });
        assert!(d.contains("pub owner: Option<Uuid>") && d.contains("TODO") && s.contains("owner UUID"));
    }

    #[test]
    fn replace_last_targets_final_occurrence() {
        assert_eq!(replace_last("a}\nb}\n", "}\n", "X"), "a}\nbX");
    }
}
