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
