//! Governed Blueprint service — the policy + audit layer over the runtime DDL
//! mechanics in [`vortex_orm::blueprint`].
//!
//! This is where the "lead over Odoo/Frappe" lives: every create/alter/delete
//! is **policy-gated** (Cedar, deny-by-default) and **WORM-audited**, and every
//! change writes a `blueprint_version` snapshot for rollback/history. The DDL
//! mechanics know nothing about governance; this module wraps them.
//!
//! Each operation is a single transaction: registry rows (`ir_model` /
//! `ir_model_field`), the physical DDL, and the version snapshot commit
//! together, so a partial failure leaves nothing behind (Postgres DDL is
//! transactional). The audit entry is written after commit.
//!
//! No routes/UI here — that is Phase 1b (the host binary).

use crate::auth::AuthUser;
use crate::state::AppState;
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use vortex_orm::blueprint as ddl;
use vortex_policy::{PolicyPrincipal, PolicyResource};
use vortex_security::{AuditAction, AuditEntry, AuditSeverity};

fn dberr(e: sqlx::Error) -> String {
    format!("database error: {e}")
}

/// Per-tenant quota: the most Blueprints a single tenant may hold. Bounds the
/// generated-schema footprint so a runaway or hostile actor can't schema-bomb
/// the database (design §3/§9). Generous enough not to constrain real use.
pub const MAX_BLUEPRINTS_PER_TENANT: i64 = 100;

/// Per-tenant quota: the most fields a single Blueprint may carry (includes the
/// auto `name` field).
pub const MAX_FIELDS_PER_BLUEPRINT: i64 = 100;

/// A single field-level change between two Blueprint version snapshots, for the
/// schema-history view. `kind` is one of `added` / `removed` / `changed`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldChange {
    pub kind: &'static str,
    pub field: String,
    pub detail: String,
}

fn snapshot_fields(def: &serde_json::Value) -> Vec<serde_json::Value> {
    def.get("fields")
        .and_then(|f| f.as_array())
        .cloned()
        .unwrap_or_default()
}

fn field_str(f: &serde_json::Value, key: &str) -> String {
    f.get(key)
        .map(|v| match v {
            serde_json::Value::String(s) => s.clone(),
            other => other.to_string(),
        })
        .unwrap_or_default()
}

/// Diff two version definitions into a human-readable change list. `prev = None`
/// means the first version (everything is `added`). Compares fields by `name`
/// and reports added/removed fields and changed type/label/list-visibility.
/// Pure and unit-tested — the history handler renders whatever this returns.
pub fn diff_definitions(prev: Option<&serde_json::Value>, cur: &serde_json::Value) -> Vec<FieldChange> {
    let cur_fields = snapshot_fields(cur);
    let prev_fields = prev.map(snapshot_fields).unwrap_or_default();
    let name_of = |f: &serde_json::Value| field_str(f, "name");

    let mut changes = Vec::new();
    // Added / changed.
    for cf in &cur_fields {
        let n = name_of(cf);
        match prev_fields.iter().find(|pf| name_of(pf) == n) {
            None => changes.push(FieldChange {
                kind: "added",
                field: n.clone(),
                detail: format!("{} field", field_str(cf, "type")),
            }),
            Some(pf) => {
                let mut deltas = Vec::new();
                if field_str(pf, "type") != field_str(cf, "type") {
                    deltas.push(format!("type {} → {}", field_str(pf, "type"), field_str(cf, "type")));
                }
                if field_str(pf, "label") != field_str(cf, "label") {
                    deltas.push(format!("renamed “{}” → “{}”", field_str(pf, "label"), field_str(cf, "label")));
                }
                if field_str(pf, "in_list") != field_str(cf, "in_list") {
                    deltas.push(if field_str(cf, "in_list") == "true" {
                        "shown in list".to_string()
                    } else {
                        "hidden from list".to_string()
                    });
                }
                if !deltas.is_empty() {
                    changes.push(FieldChange { kind: "changed", field: n.clone(), detail: deltas.join(", ") });
                }
            }
        }
    }
    // Removed.
    for pf in &prev_fields {
        let n = name_of(pf);
        if !cur_fields.iter().any(|cf| name_of(cf) == n) {
            changes.push(FieldChange { kind: "removed", field: n, detail: String::new() });
        }
    }
    changes
}

/// Turn a human label into a safe `[a-z][a-z0-9_]*` slug: lowercase, non-alnum
/// runs collapse to a single `_`, leading digits/underscores trimmed. The
/// result is still validated by [`ddl::validate_identifier`] before use.
fn slugify(label: &str) -> String {
    let mut out = String::new();
    let mut prev_us = false;
    for ch in label.trim().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_us = false;
        } else if !prev_us && !out.is_empty() {
            out.push('_');
            prev_us = true;
        }
    }
    let trimmed = out.trim_matches('_');
    // Ensure it starts with a letter (validate_identifier requires it).
    match trimmed.chars().next() {
        Some(c) if c.is_ascii_alphabetic() => trimmed.to_string(),
        Some(_) => format!("f_{trimmed}"),
        None => String::new(),
    }
}

fn principal_of(user: &AuthUser) -> PolicyPrincipal {
    PolicyPrincipal {
        user_id: user.id,
        username: user.username.clone(),
        // AuthUser does not carry company_id today (same as the users handler);
        // the seeded blueprint permit is role-based, so the nil company is fine.
        company_id: Uuid::nil(),
        roles: user
            .roles
            .iter()
            .map(|r| r.to_ascii_lowercase().replace(' ', "_"))
            .collect(),
    }
}

fn blueprint_resource(model: &str) -> PolicyResource {
    PolicyResource {
        type_name: "Blueprint".into(),
        id: model.to_string(),
        attributes: serde_json::Value::Null,
    }
}

/// Deny-by-default policy gate. Returns `Err` (which handlers map to 403) unless
/// a `permit` policy allows this action on Blueprints for this principal.
async fn gate(state: &AppState, user: &AuthUser, action: &str, model: &str) -> Result<(), String> {
    match state
        .policy
        .check(&principal_of(user), action, &blueprint_resource(model))
        .await
    {
        Ok(d) if d.is_allow() => Ok(()),
        Ok(_) => Err("Not authorized to manage Blueprints".to_string()),
        Err(e) => Err(format!("policy check failed: {e}")),
    }
}

async fn audit(
    state: &AppState,
    db_name: &str,
    user: &AuthUser,
    code: &str,
    severity: AuditSeverity,
    model: &str,
    details: serde_json::Value,
) {
    let entry = AuditEntry::new(AuditAction::Custom(code.to_string()), severity)
        .with_database(db_name)
        .with_user(vortex_common::UserId(user.id))
        .with_username(&user.username)
        .with_resource("blueprint", model)
        .with_resource_name(model)
        .with_details(details);
    if let Err(e) = state.audit.log(entry).await {
        tracing::error!(model, error = %e, "blueprint audit write failed");
    }
}

/// Resolve a Blueprint model name to (model_id, blueprint_id, table_name).
async fn resolve(db: &PgPool, model: &str) -> Result<(Uuid, Uuid, String), String> {
    let row = sqlx::query(
        "SELECT m.id AS model_id, b.id AS blueprint_id, m.table_name
         FROM ir_model m JOIN blueprint b ON b.model_id = m.id
         WHERE m.name = $1 AND m.source = 'blueprint'",
    )
    .bind(model)
    .fetch_optional(db)
    .await
    .map_err(dberr)?
    .ok_or_else(|| format!("Blueprint '{model}' not found"))?;
    Ok((
        row.get("model_id"),
        row.get("blueprint_id"),
        row.get("table_name"),
    ))
}

/// Snapshot the current blueprint fields as JSON for a version record.
async fn snapshot(tx: &mut Transaction<'_, Postgres>, model_id: Uuid) -> Result<serde_json::Value, String> {
    let rows = sqlx::query(
        "SELECT name, display_name, field_type, sequence, is_visible FROM ir_model_field
         WHERE model_id = $1 AND source = 'blueprint' ORDER BY sequence",
    )
    .bind(model_id)
    .fetch_all(&mut **tx)
    .await
    .map_err(dberr)?;
    let fields: Vec<serde_json::Value> = rows
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.get::<String, _>("name"),
                "label": r.get::<String, _>("display_name"),
                "type": r.get::<String, _>("field_type"),
                "sequence": r.get::<i32, _>("sequence"),
                "in_list": r.get::<bool, _>("is_visible"),
            })
        })
        .collect();
    Ok(serde_json::json!({ "fields": fields }))
}

/// Append a version snapshot of the current definition (called inside the op tx,
/// after the mutation, so the snapshot reflects the new state).
async fn record_version(
    tx: &mut Transaction<'_, Postgres>,
    blueprint_id: Uuid,
    model_id: Uuid,
    user: &AuthUser,
) -> Result<(), String> {
    let version: i32 =
        sqlx::query_scalar("SELECT COALESCE(MAX(version), 0) + 1 FROM blueprint_version WHERE blueprint_id = $1")
            .bind(blueprint_id)
            .fetch_one(&mut **tx)
            .await
            .map_err(dberr)?;
    let definition = snapshot(tx, model_id).await?;
    sqlx::query(
        "INSERT INTO blueprint_version (blueprint_id, version, definition, applied_by)
         VALUES ($1, $2, $3, $4)",
    )
    .bind(blueprint_id)
    .bind(version)
    .bind(definition)
    .bind(user.id)
    .execute(&mut **tx)
    .await
    .map_err(dberr)?;
    Ok(())
}

/// Create a new Blueprint: a governed `ir_model` (source='blueprint') + a real
/// generated `x_<slug>` table. Returns the technical model name.
pub async fn create(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    label: &str,
) -> Result<String, String> {
    let slug = slugify(label);
    ddl::validate_identifier(&slug).map_err(|e| format!("invalid name: {e}"))?;
    let model = format!("{}{}", ddl::TABLE_PREFIX, slug);
    gate(state, user, "blueprint.create", &model).await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blueprint")
        .fetch_one(db)
        .await
        .map_err(dberr)?;
    if count >= MAX_BLUEPRINTS_PER_TENANT {
        return Err(format!(
            "Blueprint limit reached ({MAX_BLUEPRINTS_PER_TENANT} per tenant). Archive an unused Blueprint first."
        ));
    }

    let mut tx = db.begin().await.map_err(dberr)?;

    // No name collision with any existing model (compiled or blueprint).
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1")
        .bind(&model)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dberr)?;
    if exists.is_some() {
        return Err(format!("A model named '{model}' already exists"));
    }

    let model_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ir_model (name, display_name, table_name, module, source, is_virtual)
         VALUES ($1, $2, $1, 'blueprint', 'blueprint', true) RETURNING id",
    )
    .bind(&model)
    .bind(label)
    .fetch_one(&mut *tx)
    .await
    .map_err(dberr)?;

    let blueprint_id: Uuid = sqlx::query_scalar(
        "INSERT INTO blueprint (model_id, status, created_by) VALUES ($1, 'active', $2) RETURNING id",
    )
    .bind(model_id)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(dberr)?;

    ddl::create_model_table(&mut tx, &model, blueprint_id)
        .await
        .map_err(|e| format!("create table failed: {e}"))?;

    // Every Blueprint gets a `name` display field. It gives each record a human
    // label in lists, and — crucially — is the column a many2one to this
    // Blueprint resolves for its picker/JOIN (the generic layer reads `name`).
    // It is a normal, editable field; deleting it is refused while the Blueprint
    // is a relation target (see `remove_field`).
    ddl::add_column(&mut tx, &model, "name", "string", blueprint_id)
        .await
        .map_err(|e| format!("add name column failed: {e}"))?;
    sqlx::query(
        "INSERT INTO ir_model_field
            (model_id, name, display_name, field_type, sequence, source, is_custom, is_visible)
         VALUES ($1, 'name', 'Name', 'string', 10, 'blueprint', false, true)",
    )
    .bind(model_id)
    .execute(&mut *tx)
    .await
    .map_err(dberr)?;

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_created",
        AuditSeverity::Info,
        &model,
        serde_json::json!({ "label": label }),
    )
    .await;
    Ok(model)
}

/// Parse a `selection` field's raw option text (one option per line) into the
/// `[{"value","label"}]` JSON shape the generic form's `<select>` renderer
/// expects. Blank lines are dropped; each option's value and label are the
/// trimmed line (values are data, not identifiers). Values are capped at the
/// column width (64). Returns an error if no options remain.
fn parse_selection_options(raw: &str) -> Result<serde_json::Value, String> {
    let opts: Vec<serde_json::Value> = raw
        .lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty())
        .map(|l| {
            let v: String = l.chars().take(64).collect();
            serde_json::json!({ "value": v, "label": l })
        })
        .collect();
    if opts.is_empty() {
        return Err("A dropdown field needs at least one option".to_string());
    }
    Ok(serde_json::Value::Array(opts))
}

/// Resolve a many2one target: any active model — Blueprint **or** compiled —
/// whose physical table carries a `name` column (the display the generic
/// picker/JOIN reads). Returns the target's table name. Requiring a real `name`
/// column keeps the relation's label resolution robust across both kinds; the
/// generic list/form were hardened (Phase 3b) to resolve the target's real
/// table name and probe for `name`/`active`, so a compiled target whose model
/// name differs from its table name now works too.
async fn resolve_relation_target(db: &PgPool, target_model: &str) -> Result<String, String> {
    sqlx::query_scalar::<_, String>(
        "SELECT m.table_name FROM ir_model m
         WHERE m.name = $1 AND m.is_active = true
           AND EXISTS (
               SELECT 1 FROM information_schema.columns c
               WHERE c.table_schema = 'public' AND c.table_name = m.table_name
                 AND c.column_name = 'name'
           )",
    )
    .bind(target_model)
    .fetch_optional(db)
    .await
    .map_err(dberr)?
    .ok_or_else(|| format!("'{target_model}' is not a valid relation target"))
}

/// Add a field to a Blueprint. Scalars add a typed column; `selection` also
/// stores its options; `many2one` adds a real UUID FK to another Blueprint and
/// stores the target's model name in `related_model` (which the generic layer
/// uses to render the picker and resolve labels).
pub async fn add_field(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    model: &str,
    label: &str,
    field_type: &str,
    related_model: Option<&str>,
    options_raw: Option<&str>,
) -> Result<(), String> {
    let col = slugify(label);
    ddl::validate_identifier(&col).map_err(|e| format!("invalid field name: {e}"))?;
    // Validate the type against the physical-column vocabulary up front.
    ddl::column_type(field_type).map_err(|e| format!("unsupported field type: {e}"))?;
    gate(state, user, "blueprint.alter", model).await?;

    // Type-specific inputs, validated before opening the transaction.
    let selection_options: Option<serde_json::Value> = if field_type == "selection" {
        Some(parse_selection_options(options_raw.unwrap_or(""))?)
    } else {
        None
    };
    let (related, target_table): (Option<String>, Option<String>) = if field_type == "many2one" {
        let target = related_model
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or("Pick a record type this field links to")?;
        let table = resolve_relation_target(db, target).await?;
        (Some(target.to_string()), Some(table))
    } else {
        (None, None)
    };

    let (model_id, blueprint_id, table) = resolve(db, model).await?;

    let fcount: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM ir_model_field WHERE model_id = $1 AND source = 'blueprint'")
            .bind(model_id)
            .fetch_one(db)
            .await
            .map_err(dberr)?;
    if fcount >= MAX_FIELDS_PER_BLUEPRINT {
        return Err(format!("Field limit reached ({MAX_FIELDS_PER_BLUEPRINT} per Blueprint)."));
    }

    let mut tx = db.begin().await.map_err(dberr)?;

    let dup: Option<i32> =
        sqlx::query_scalar("SELECT 1 FROM ir_model_field WHERE model_id = $1 AND name = $2")
            .bind(model_id)
            .bind(&col)
            .fetch_optional(&mut *tx)
            .await
            .map_err(dberr)?;
    if dup.is_some() {
        return Err(format!("A field named '{col}' already exists"));
    }

    match &target_table {
        Some(tt) => ddl::add_reference_column(&mut tx, &table, &col, tt, blueprint_id)
            .await
            .map_err(|e| format!("add relation column failed: {e}"))?,
        None => ddl::add_column(&mut tx, &table, &col, field_type, blueprint_id)
            .await
            .map_err(|e| format!("add column failed: {e}"))?,
    }

    let seq: i32 =
        sqlx::query_scalar("SELECT COALESCE(MAX(sequence), 0) + 10 FROM ir_model_field WHERE model_id = $1")
            .bind(model_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(dberr)?;

    sqlx::query(
        "INSERT INTO ir_model_field
            (model_id, name, display_name, field_type, sequence, source, is_custom, is_visible,
             related_model, selection_options)
         VALUES ($1, $2, $3, $4, $5, 'blueprint', false, true, $6, $7)",
    )
    .bind(model_id)
    .bind(&col)
    .bind(label)
    .bind(field_type)
    .bind(seq)
    .bind(&related)
    .bind(&selection_options)
    .execute(&mut *tx)
    .await
    .map_err(dberr)?;

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_field_added",
        AuditSeverity::Info,
        model,
        serde_json::json!({ "field": col, "type": field_type, "related_model": related }),
    )
    .await;
    Ok(())
}

/// Rename a Blueprint field (column + registry name/label).
pub async fn rename_field(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    model: &str,
    from: &str,
    new_label: &str,
) -> Result<(), String> {
    if from == "name" {
        return Err("The Name field is the record's display field and can't be renamed".to_string());
    }
    let to = slugify(new_label);
    ddl::validate_identifier(&to).map_err(|e| format!("invalid field name: {e}"))?;
    gate(state, user, "blueprint.alter", model).await?;

    let (model_id, blueprint_id, table) = resolve(db, model).await?;
    let mut tx = db.begin().await.map_err(dberr)?;

    ddl::rename_column(&mut tx, &table, from, &to, blueprint_id)
        .await
        .map_err(|e| format!("rename column failed: {e}"))?;

    sqlx::query(
        "UPDATE ir_model_field SET name = $3, display_name = $4
         WHERE model_id = $1 AND name = $2 AND source = 'blueprint'",
    )
    .bind(model_id)
    .bind(from)
    .bind(&to)
    .bind(new_label)
    .execute(&mut *tx)
    .await
    .map_err(dberr)?;

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_field_renamed",
        AuditSeverity::Info,
        model,
        serde_json::json!({ "from": from, "to": to }),
    )
    .await;
    Ok(())
}

/// Remove a Blueprint field (drops the column + registry row).
pub async fn remove_field(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    model: &str,
    name: &str,
) -> Result<(), String> {
    if name == "name" {
        return Err("The Name field is the record's display field and can't be deleted".to_string());
    }
    gate(state, user, "blueprint.alter", model).await?;

    let (model_id, blueprint_id, table) = resolve(db, model).await?;
    let mut tx = db.begin().await.map_err(dberr)?;

    ddl::drop_column(&mut tx, &table, name, blueprint_id)
        .await
        .map_err(|e| format!("drop column failed: {e}"))?;

    sqlx::query("DELETE FROM ir_model_field WHERE model_id = $1 AND name = $2 AND source = 'blueprint'")
        .bind(model_id)
        .bind(name)
        .execute(&mut *tx)
        .await
        .map_err(dberr)?;

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_field_removed",
        AuditSeverity::Warning,
        model,
        serde_json::json!({ "field": name }),
    )
    .await;
    Ok(())
}

/// Compute the normalized layout to apply. `existing` is the blueprint's field
/// names in their current order; `orders` maps a field name to a desired ordinal
/// (lower = earlier); `list_fields` is the set of fields to keep as generic-list
/// columns. Every key in `orders`/`list_fields` must be an existing blueprint
/// field (guards against a tampered form injecting a foreign column name).
/// Returns `(name, sequence, in_list)` with sequences renormalized to clean,
/// gap-spaced values in the requested order.
fn plan_layout(
    existing: &[String],
    orders: &HashMap<String, i32>,
    list_fields: &HashSet<String>,
) -> Result<Vec<(String, i32, bool)>, String> {
    let known: HashSet<&str> = existing.iter().map(|s| s.as_str()).collect();
    for k in orders.keys().chain(list_fields.iter()) {
        if !known.contains(k.as_str()) {
            return Err(format!("Unknown field '{k}'"));
        }
    }
    let mut items: Vec<(usize, &String)> = existing.iter().enumerate().collect();
    items.sort_by(|a, b| {
        let oa = orders.get(a.1).copied().unwrap_or(a.0 as i32);
        let ob = orders.get(b.1).copied().unwrap_or(b.0 as i32);
        oa.cmp(&ob).then_with(|| a.1.cmp(b.1))
    });
    Ok(items
        .into_iter()
        .enumerate()
        .map(|(i, (_, name))| (name.clone(), ((i + 1) * 10) as i32, list_fields.contains(name)))
        .collect())
}

/// Persist a view/layout change for a Blueprint: field order (`sequence`, which
/// drives both the generic form and list) and list-column membership
/// (`is_visible`, which the generic list already honors). Metadata-only — no
/// DDL runs — but still governed (Cedar `blueprint.alter`), version-snapshotted,
/// and WORM-audited, so a layout change is as accountable as a schema change.
pub async fn set_layout(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    model: &str,
    orders: &HashMap<String, i32>,
    list_fields: &HashSet<String>,
    widths: &HashMap<String, i16>,
    sections: &HashMap<String, String>,
) -> Result<(), String> {
    gate(state, user, "blueprint.alter", model).await?;

    let (model_id, blueprint_id, _table) = resolve(db, model).await?;
    let mut tx = db.begin().await.map_err(dberr)?;

    let rows = sqlx::query(
        "SELECT name FROM ir_model_field
         WHERE model_id = $1 AND source = 'blueprint' ORDER BY sequence, name",
    )
    .bind(model_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(dberr)?;
    let existing: Vec<String> = rows.iter().map(|r| r.get::<String, _>("name")).collect();
    if existing.is_empty() {
        return Err("This Blueprint has no fields to lay out yet".to_string());
    }

    let plan = plan_layout(&existing, orders, list_fields)?;
    for (name, seq, in_list) in &plan {
        // Form width: 1 = half column, 2 = full row. Anything else clamps to a
        // full row so a malformed submission can't hide a field. Absent = full.
        let span: i16 = widths.get(name).copied().unwrap_or(2).clamp(1, 2);
        // Section: trimmed, capped, empty → NULL (falls back to "General").
        let section: Option<String> = sections
            .get(name)
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.chars().take(64).collect());
        sqlx::query(
            "UPDATE ir_model_field SET sequence = $3, is_visible = $4, col_span = $5, section = $6
             WHERE model_id = $1 AND name = $2 AND source = 'blueprint'",
        )
        .bind(model_id)
        .bind(name)
        .bind(*seq)
        .bind(*in_list)
        .bind(span)
        .bind(section)
        .execute(&mut *tx)
        .await
        .map_err(dberr)?;
    }

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_layout_changed",
        AuditSeverity::Info,
        model,
        serde_json::json!({ "fields": plan.len() }),
    )
    .await;
    Ok(())
}

/// Enable the stage workflow (status bar) for a Blueprint: add the
/// `record_state` column to its table if missing and, the first time only, seed
/// a starter Draft → In Progress → Done set of stages plus the two transition
/// buttons that move between them — so the bar works immediately. Admins then
/// refine stages/buttons from Settings → Stages (both are generic per-model
/// catalogs). Idempotent; presentation-level metadata + a column add, so it
/// applies directly with no approval gate (like the menu toggle).
pub async fn enable_stages(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    model: &str,
) -> Result<(), String> {
    gate(state, user, "blueprint.alter", model).await?;
    let (model_id, blueprint_id, table) = resolve(db, model).await?;
    if table.is_empty() || !table.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        return Err("Invalid table name".to_string());
    }
    let mut tx = db.begin().await.map_err(dberr)?;

    // 1. record_state column (idempotent — safe to click twice).
    sqlx::query(&format!(
        "ALTER TABLE {table} ADD COLUMN IF NOT EXISTS record_state VARCHAR(64)"
    ))
    .execute(&mut *tx)
    .await
    .map_err(dberr)?;

    // 2. Seed a working starter workflow the first time only. If the admin has
    //    already defined stages for this model, leave them untouched.
    let have: i64 = sqlx::query_scalar("SELECT count(*) FROM record_stages WHERE model = $1")
        .bind(model)
        .fetch_one(&mut *tx)
        .await
        .map_err(dberr)?;
    if have == 0 {
        for (i, (code, label, color)) in [
            ("draft", "Draft", "neutral"),
            ("in_progress", "In Progress", "info"),
            ("done", "Done", "success"),
        ]
        .iter()
        .enumerate()
        {
            sqlx::query(
                "INSERT INTO record_stages (model, code, label, color, sequence, always_visible, locked, active) \
                 VALUES ($1, $2, $3, $4, $5, true, false, true)",
            )
            .bind(model)
            .bind(code)
            .bind(label)
            .bind(color)
            .bind((i as i32 + 1) * 10)
            .execute(&mut *tx)
            .await
            .map_err(dberr)?;
        }
        for (i, (label, from, to, color)) in [
            ("Start", "draft", "in_progress", "info"),
            ("Mark Done", "in_progress", "done", "success"),
        ]
        .iter()
        .enumerate()
        {
            sqlx::query(
                "INSERT INTO record_stage_actions (model, label, target_stage, from_stage, color, sequence, active) \
                 VALUES ($1, $2, $3, $4, $5, $6, true)",
            )
            .bind(model)
            .bind(label)
            .bind(to)
            .bind(from)
            .bind(color)
            .bind((i as i32 + 1) * 10)
            .execute(&mut *tx)
            .await
            .map_err(dberr)?;
        }
    }

    // 3. Give every existing row the first stage so the bar always has a value.
    sqlx::query(&format!(
        "UPDATE {table} SET record_state = 'draft' WHERE record_state IS NULL"
    ))
    .execute(&mut *tx)
    .await
    .map_err(dberr)?;

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_stages_enabled",
        AuditSeverity::Info,
        model,
        serde_json::json!({ "seeded_starter_workflow": have == 0 }),
    )
    .await;
    Ok(())
}

/// Does this Blueprint's table have the `record_state` column (i.e. are stages
/// enabled)? Best-effort — a false is also returned on any query error.
pub async fn stages_enabled(db: &PgPool, model: &str) -> bool {
    let table: Option<String> =
        sqlx::query_scalar("SELECT table_name FROM ir_model WHERE name = $1 AND source = 'blueprint'")
            .bind(model)
            .fetch_optional(db)
            .await
            .ok()
            .flatten();
    let Some(table) = table else { return false };
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM information_schema.columns \
         WHERE table_schema = 'public' AND table_name = $1 AND column_name = 'record_state'",
    )
    .bind(&table)
    .fetch_one(db)
    .await
    .map(|n| n > 0)
    .unwrap_or(false)
}

/// Archive a Blueprint: soft-delete (status='archived', model inactive). The
/// generated table and its data are preserved — a hard drop is a separate,
/// deliberate admin path (Phase 1b/later).
pub async fn archive(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    model: &str,
) -> Result<(), String> {
    gate(state, user, "blueprint.delete", model).await?;

    let (model_id, _blueprint_id, _table) = resolve(db, model).await?;
    let mut tx = db.begin().await.map_err(dberr)?;

    sqlx::query("UPDATE blueprint SET status = 'archived', updated_at = now() WHERE model_id = $1")
        .bind(model_id)
        .execute(&mut *tx)
        .await
        .map_err(dberr)?;
    sqlx::query("UPDATE ir_model SET is_active = false WHERE id = $1")
        .bind(model_id)
        .execute(&mut *tx)
        .await
        .map_err(dberr)?;

    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_archived",
        AuditSeverity::Warning,
        model,
        serde_json::json!({}),
    )
    .await;
    Ok(())
}

// ===========================================================================
// Approval-before-DDL (Phase 4b)
//
// When a tenant enables `require_approval`, a schema-changing operation is not
// executed inline — it is captured as a `BlueprintOp` in `blueprint_change_request`
// and applied only when an approver (never the requester) approves it. The op
// enum IS the serialized payload, so approving simply replays it through the
// same governed service functions above (which re-gate and audit as the original
// requester). Layout/metadata changes are not gated here — only DDL.
// ===========================================================================

/// A schema-changing Blueprint operation, captured for (optional) approval and
/// replayed verbatim on apply. Serialized into `blueprint_change_request.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum BlueprintOp {
    Create { label: String },
    AddField {
        model: String,
        label: String,
        field_type: String,
        related_model: Option<String>,
        options: Option<String>,
    },
    RenameField { model: String, from: String, new_label: String },
    RemoveField { model: String, name: String },
    Archive { model: String },
}

impl BlueprintOp {
    /// The Cedar action that authorizes *requesting* this op.
    fn gate_action(&self) -> &'static str {
        match self {
            BlueprintOp::Create { .. } => "blueprint.create",
            BlueprintOp::AddField { .. }
            | BlueprintOp::RenameField { .. }
            | BlueprintOp::RemoveField { .. } => "blueprint.alter",
            BlueprintOp::Archive { .. } => "blueprint.delete",
        }
    }

    /// The model this op targets, for the policy resource and inbox display.
    /// For a create the model does not exist yet, so we derive its future name.
    fn model_hint(&self) -> String {
        match self {
            BlueprintOp::Create { label } => format!("{}{}", ddl::TABLE_PREFIX, slugify(label)),
            BlueprintOp::AddField { model, .. }
            | BlueprintOp::RenameField { model, .. }
            | BlueprintOp::RemoveField { model, .. }
            | BlueprintOp::Archive { model } => model.clone(),
        }
    }

    fn op_name(&self) -> &'static str {
        match self {
            BlueprintOp::Create { .. } => "create",
            BlueprintOp::AddField { .. } => "add_field",
            BlueprintOp::RenameField { .. } => "rename_field",
            BlueprintOp::RemoveField { .. } => "remove_field",
            BlueprintOp::Archive { .. } => "archive",
        }
    }

    /// One-line human summary for the approval inbox.
    fn summary(&self) -> String {
        match self {
            BlueprintOp::Create { label } => format!("Create Blueprint “{label}”"),
            BlueprintOp::AddField { model, label, field_type, .. } => {
                format!("Add {field_type} field “{label}” to {model}")
            }
            BlueprintOp::RenameField { model, from, new_label } => {
                format!("Rename “{from}” → “{new_label}” on {model}")
            }
            BlueprintOp::RemoveField { model, name } => format!("Delete field “{name}” from {model}"),
            BlueprintOp::Archive { model } => format!("Archive {model}"),
        }
    }
}

/// Outcome of submitting a change: applied immediately, or queued for approval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// Executed now (approval not required). `model` is set for a create.
    Applied { model: Option<String> },
    /// Queued as a pending change request awaiting approval.
    Pending,
}

/// Read the single-row governance switch. Missing table/row ⇒ approval off (the
/// feature is opt-in and must never block the common path on a fresh tenant).
pub async fn approval_required(db: &PgPool) -> bool {
    sqlx::query_scalar::<_, bool>("SELECT require_approval FROM blueprint_governance WHERE id = TRUE")
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .unwrap_or(false)
}

/// Toggle the per-tenant "require approval for schema changes" switch.
pub async fn set_approval_required(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    on: bool,
) -> Result<(), String> {
    // Changing the governance posture is itself a manage-level action.
    gate(state, user, "blueprint.create", "*").await?;
    sqlx::query(
        "INSERT INTO blueprint_governance (id, require_approval) VALUES (TRUE, $1)
         ON CONFLICT (id) DO UPDATE SET require_approval = EXCLUDED.require_approval",
    )
    .bind(on)
    .execute(db)
    .await
    .map_err(dberr)?;
    audit(
        state,
        db_name,
        user,
        "blueprint_approval_toggled",
        AuditSeverity::Warning,
        "*",
        serde_json::json!({ "require_approval": on }),
    )
    .await;
    Ok(())
}

/// Dispatch a `BlueprintOp` to the matching governed service function, acting as
/// `user` (which re-gates and audits as that user). Returns the created model
/// name for a create, `None` otherwise.
async fn execute_op(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    op: &BlueprintOp,
) -> Result<Option<String>, String> {
    match op {
        BlueprintOp::Create { label } => {
            create(state, db, db_name, user, label).await.map(Some)
        }
        BlueprintOp::AddField { model, label, field_type, related_model, options } => add_field(
            state, db, db_name, user, model, label, field_type,
            related_model.as_deref(), options.as_deref(),
        )
        .await
        .map(|_| None),
        BlueprintOp::RenameField { model, from, new_label } => {
            rename_field(state, db, db_name, user, model, from, new_label).await.map(|_| None)
        }
        BlueprintOp::RemoveField { model, name } => {
            remove_field(state, db, db_name, user, model, name).await.map(|_| None)
        }
        BlueprintOp::Archive { model } => {
            archive(state, db, db_name, user, model).await.map(|_| None)
        }
    }
}

/// Submit a schema change. If approval is off, it runs now. If on, the requester
/// is gated (they must be allowed to make the change at all) and the op is queued
/// as a pending request — no DDL runs until an approver applies it.
pub async fn submit(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    op: BlueprintOp,
) -> Result<SubmitOutcome, String> {
    if !approval_required(db).await {
        let model = execute_op(state, db, db_name, user, &op).await?;
        return Ok(SubmitOutcome::Applied { model });
    }

    // Approval required: authorize the *request* (so a non-privileged user can't
    // flood the queue), then enqueue it.
    gate(state, user, op.gate_action(), &op.model_hint()).await?;
    let model_name = match &op {
        BlueprintOp::Create { .. } => None,
        other => Some(other.model_hint()),
    };
    let payload = serde_json::to_value(&op).map_err(|e| format!("serialize op: {e}"))?;
    sqlx::query(
        "INSERT INTO blueprint_change_request (op, payload, model_name, target_label, requested_by)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(op.op_name())
    .bind(&payload)
    .bind(&model_name)
    .bind(op.summary())
    .bind(user.id)
    .execute(db)
    .await
    .map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_change_requested",
        AuditSeverity::Info,
        &op.model_hint(),
        serde_json::json!({ "op": op.op_name(), "summary": op.summary() }),
    )
    .await;
    Ok(SubmitOutcome::Pending)
}

/// Reconstruct a minimal `AuthUser` (id + username + roles) for a stored user,
/// so a queued op can be re-executed and audited as its original requester.
async fn load_requester(db: &PgPool, user_id: Uuid) -> Result<AuthUser, String> {
    let username: String = sqlx::query_scalar("SELECT username FROM users WHERE id = $1")
        .bind(user_id)
        .fetch_optional(db)
        .await
        .map_err(dberr)?
        .ok_or("Original requester no longer exists")?;
    let roles: Vec<String> = sqlx::query_scalar(
        "SELECT r.name FROM roles r JOIN user_roles ur ON ur.role_id = r.id WHERE ur.user_id = $1",
    )
    .bind(user_id)
    .fetch_all(db)
    .await
    .unwrap_or_default();
    Ok(AuthUser {
        id: user_id,
        username,
        full_name: None,
        session_id: Uuid::nil(),
        roles,
        contact_id: None,
        is_portal: false,
    })
}

/// Approve a pending change request: the DDL runs now, attributed to the original
/// requester. The approver must hold `blueprint.approve` and must not be the
/// requester (no self-approval).
pub async fn apply_request(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    approver: &AuthUser,
    request_id: Uuid,
) -> Result<(), String> {
    gate(state, approver, "blueprint.approve", "*").await?;

    let row = sqlx::query(
        "SELECT payload, requested_by, status FROM blueprint_change_request WHERE id = $1",
    )
    .bind(request_id)
    .fetch_optional(db)
    .await
    .map_err(dberr)?
    .ok_or("Change request not found")?;
    let status: String = row.get("status");
    if status != "pending" {
        return Err(format!("This request is already {status}"));
    }
    let requested_by: Uuid = row.get("requested_by");
    if requested_by == approver.id {
        return Err("You can't approve your own change request".to_string());
    }
    let payload: serde_json::Value = row.get("payload");
    let op: BlueprintOp = serde_json::from_value(payload).map_err(|e| format!("bad payload: {e}"))?;

    let requester = load_requester(db, requested_by).await?;
    // Runs the real DDL (transactional, audited as the requester).
    execute_op(state, db, db_name, &requester, &op).await?;

    sqlx::query(
        "UPDATE blueprint_change_request
         SET status = 'approved', decided_by = $2, decided_at = now()
         WHERE id = $1",
    )
    .bind(request_id)
    .bind(approver.id)
    .execute(db)
    .await
    .map_err(dberr)?;

    audit(
        state,
        db_name,
        approver,
        "blueprint_change_approved",
        AuditSeverity::Warning,
        &op.model_hint(),
        serde_json::json!({ "request": request_id, "op": op.op_name() }),
    )
    .await;
    Ok(())
}

/// Reject a pending change request. No DDL runs.
pub async fn reject_request(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    approver: &AuthUser,
    request_id: Uuid,
    reason: &str,
) -> Result<(), String> {
    gate(state, approver, "blueprint.approve", "*").await?;

    let updated = sqlx::query(
        "UPDATE blueprint_change_request
         SET status = 'rejected', decided_by = $2, decided_at = now(), reason = $3
         WHERE id = $1 AND status = 'pending'",
    )
    .bind(request_id)
    .bind(approver.id)
    .bind(reason)
    .execute(db)
    .await
    .map_err(dberr)?;
    if updated.rows_affected() == 0 {
        return Err("Request not found or already decided".to_string());
    }

    audit(
        state,
        db_name,
        approver,
        "blueprint_change_rejected",
        AuditSeverity::Warning,
        "*",
        serde_json::json!({ "request": request_id, "reason": reason }),
    )
    .await;
    Ok(())
}

/// A pending change request for the inbox view.
pub struct PendingRequest {
    pub id: Uuid,
    pub op: String,
    pub summary: String,
    pub requested_by: String,
    pub requested_at: chrono::DateTime<chrono::Utc>,
}

/// List pending change requests, oldest first.
pub async fn pending_requests(db: &PgPool) -> Vec<PendingRequest> {
    sqlx::query(
        "SELECT r.id, r.op, r.target_label, r.requested_at, u.username AS requested_by
         FROM blueprint_change_request r
         LEFT JOIN users u ON u.id = r.requested_by
         WHERE r.status = 'pending'
         ORDER BY r.requested_at ASC",
    )
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .iter()
    .map(|r| PendingRequest {
        id: r.get("id"),
        op: r.get("op"),
        summary: r.get("target_label"),
        requested_by: r.try_get("requested_by").unwrap_or_default(),
        requested_at: r.get("requested_at"),
    })
    .collect()
}

// ===========================================================================
// Portability: signed manifest export / import (Phase 5)
//
// A Blueprint's definition (model + fields + layout) serializes to a JSON
// manifest, HMAC-signed with the instance master key. Exported from dev and
// imported into prod, the signature makes promotion tamper-evident: prod only
// recreates a Blueprint from a manifest produced by an instance sharing the
// secret. Import replays the definition faithfully (exact field names/types),
// governed exactly like a create.
// ===========================================================================

const MANIFEST_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldManifest {
    pub name: String,
    pub label: String,
    pub field_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub related_model: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selection_options: Option<serde_json::Value>,
    pub sequence: i32,
    pub in_list: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlueprintManifest {
    pub manifest_version: u32,
    pub model: String,
    pub display_name: String,
    pub fields: Vec<FieldManifest>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedManifest {
    pub manifest: BlueprintManifest,
    pub signature: String,
}

/// HMAC-SHA256 of the manifest under the instance master key. Deterministic:
/// serde serializes struct fields in declaration order and `serde_json` sorts
/// object keys, so the same definition always yields the same signature.
fn manifest_signature(m: &BlueprintManifest) -> Result<String, String> {
    let bytes = serde_json::to_vec(m).map_err(|e| format!("serialize manifest: {e}"))?;
    Ok(vortex_security::crypto::hmac_sha256_hex(
        &vortex_security::crypto::master_key(),
        &bytes,
    ))
}

/// Constant-time byte compare, so signature verification doesn't leak via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Export a Blueprint as a signed manifest (pretty JSON).
pub async fn export_manifest(db: &PgPool, model: &str) -> Result<String, String> {
    let head = sqlx::query(
        "SELECT id, display_name FROM ir_model WHERE name = $1 AND source = 'blueprint'",
    )
    .bind(model)
    .fetch_optional(db)
    .await
    .map_err(dberr)?
    .ok_or_else(|| format!("Blueprint '{model}' not found"))?;
    let model_id: Uuid = head.get("id");
    let display_name: String = head.get("display_name");

    let rows = sqlx::query(
        "SELECT name, display_name, field_type, related_model, selection_options, sequence, is_visible
         FROM ir_model_field WHERE model_id = $1 AND source = 'blueprint' ORDER BY sequence, name",
    )
    .bind(model_id)
    .fetch_all(db)
    .await
    .map_err(dberr)?;
    let fields: Vec<FieldManifest> = rows
        .iter()
        .map(|r| FieldManifest {
            name: r.get("name"),
            label: r.get("display_name"),
            field_type: r.get("field_type"),
            related_model: r.get("related_model"),
            selection_options: r.get("selection_options"),
            sequence: r.get("sequence"),
            in_list: r.get("is_visible"),
        })
        .collect();

    let manifest = BlueprintManifest {
        manifest_version: MANIFEST_VERSION,
        model: model.to_string(),
        display_name,
        fields,
    };
    let signature = manifest_signature(&manifest)?;
    serde_json::to_string_pretty(&SignedManifest { manifest, signature })
        .map_err(|e| format!("serialize: {e}"))
}

/// Import a signed manifest: verify the signature, then recreate the Blueprint
/// (model + table + every field) exactly as exported. Governed like a create.
pub async fn import_manifest(
    state: &AppState,
    db: &PgPool,
    db_name: &str,
    user: &AuthUser,
    json: &str,
) -> Result<String, String> {
    let signed: SignedManifest =
        serde_json::from_str(json).map_err(|e| format!("Invalid manifest JSON: {e}"))?;
    if signed.manifest.manifest_version != MANIFEST_VERSION {
        return Err(format!(
            "Unsupported manifest version {} (this instance expects {MANIFEST_VERSION})",
            signed.manifest.manifest_version
        ));
    }
    let expected = manifest_signature(&signed.manifest)?;
    if !ct_eq(expected.as_bytes(), signed.signature.as_bytes()) {
        return Err(
            "Manifest signature is invalid — it was not produced by a trusted Vortex instance, or it was modified after export.".to_string(),
        );
    }
    let m = signed.manifest;

    ddl::validate_identifier(&m.model).map_err(|e| format!("invalid model name: {e}"))?;
    if !m.model.starts_with(ddl::TABLE_PREFIX) {
        return Err(format!("model name must start with '{}'", ddl::TABLE_PREFIX));
    }
    gate(state, user, "blueprint.create", &m.model).await?;

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM blueprint")
        .fetch_one(db)
        .await
        .map_err(dberr)?;
    if count >= MAX_BLUEPRINTS_PER_TENANT {
        return Err(format!("Blueprint limit reached ({MAX_BLUEPRINTS_PER_TENANT} per tenant)."));
    }

    // Pre-resolve every many2one target before opening the transaction — a
    // missing target is a clear, actionable error, not a rolled-back DDL.
    let mut resolved_targets: HashMap<String, String> = HashMap::new();
    for f in &m.fields {
        if f.field_type == "many2one" {
            let target = f
                .related_model
                .as_deref()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| format!("Field '{}' is a link but names no target", f.name))?;
            let table = resolve_relation_target(db, target).await.map_err(|_| {
                format!("Relation target '{target}' for field '{}' is not present in this database — import it first", f.name)
            })?;
            resolved_targets.insert(f.name.clone(), table);
        }
    }

    let mut tx = db.begin().await.map_err(dberr)?;
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM ir_model WHERE name = $1")
        .bind(&m.model)
        .fetch_optional(&mut *tx)
        .await
        .map_err(dberr)?;
    if exists.is_some() {
        return Err(format!("A model named '{}' already exists here", m.model));
    }

    let model_id: Uuid = sqlx::query_scalar(
        "INSERT INTO ir_model (name, display_name, table_name, module, source, is_virtual)
         VALUES ($1, $2, $1, 'blueprint', 'blueprint', true) RETURNING id",
    )
    .bind(&m.model)
    .bind(&m.display_name)
    .fetch_one(&mut *tx)
    .await
    .map_err(dberr)?;
    let blueprint_id: Uuid = sqlx::query_scalar(
        "INSERT INTO blueprint (model_id, status, created_by) VALUES ($1, 'active', $2) RETURNING id",
    )
    .bind(model_id)
    .bind(user.id)
    .fetch_one(&mut *tx)
    .await
    .map_err(dberr)?;

    ddl::create_model_table(&mut tx, &m.model, blueprint_id)
        .await
        .map_err(|e| format!("create table failed: {e}"))?;

    for f in &m.fields {
        ddl::validate_identifier(&f.name).map_err(|e| format!("invalid field '{}': {e}", f.name))?;
        ddl::column_type(&f.field_type).map_err(|e| format!("field '{}': {e}", f.name))?;
        match resolved_targets.get(&f.name) {
            Some(tt) => ddl::add_reference_column(&mut tx, &m.model, &f.name, tt, blueprint_id)
                .await
                .map_err(|e| format!("add relation '{}' failed: {e}", f.name))?,
            None => ddl::add_column(&mut tx, &m.model, &f.name, &f.field_type, blueprint_id)
                .await
                .map_err(|e| format!("add field '{}' failed: {e}", f.name))?,
        }
        sqlx::query(
            "INSERT INTO ir_model_field
                (model_id, name, display_name, field_type, sequence, source, is_custom, is_visible,
                 related_model, selection_options)
             VALUES ($1, $2, $3, $4, $5, 'blueprint', false, $6, $7, $8)",
        )
        .bind(model_id)
        .bind(&f.name)
        .bind(&f.label)
        .bind(&f.field_type)
        .bind(f.sequence)
        .bind(f.in_list)
        .bind(&f.related_model)
        .bind(&f.selection_options)
        .execute(&mut *tx)
        .await
        .map_err(dberr)?;
    }

    record_version(&mut tx, blueprint_id, model_id, user).await?;
    tx.commit().await.map_err(dberr)?;

    audit(
        state,
        db_name,
        user,
        "blueprint_imported",
        AuditSeverity::Warning,
        &m.model,
        serde_json::json!({ "fields": m.fields.len(), "display_name": m.display_name }),
    )
    .await;
    Ok(m.model)
}

#[cfg(test)]
mod tests {
    use super::{
        manifest_signature, parse_selection_options, plan_layout, slugify, BlueprintManifest,
        BlueprintOp, FieldManifest,
    };
    use std::collections::{HashMap, HashSet};

    #[test]
    fn parse_selection_options_builds_object_shape() {
        let json = parse_selection_options("Open\n  In Progress \n\nClosed\n").unwrap();
        assert_eq!(
            json,
            serde_json::json!([
                {"value": "Open", "label": "Open"},
                {"value": "In Progress", "label": "In Progress"},
                {"value": "Closed", "label": "Closed"},
            ])
        );
    }

    #[test]
    fn parse_selection_options_rejects_empty() {
        assert!(parse_selection_options("").is_err());
        assert!(parse_selection_options("\n  \n").is_err());
    }

    fn sample_manifest() -> BlueprintManifest {
        BlueprintManifest {
            manifest_version: 1,
            model: "x_widget".into(),
            display_name: "Widget".into(),
            fields: vec![FieldManifest {
                name: "name".into(),
                label: "Name".into(),
                field_type: "string".into(),
                related_model: None,
                selection_options: None,
                sequence: 10,
                in_list: true,
            }],
        }
    }

    #[test]
    fn manifest_signature_is_deterministic_and_tamper_evident() {
        let m = sample_manifest();
        let s1 = manifest_signature(&m).unwrap();
        let s2 = manifest_signature(&m).unwrap();
        assert_eq!(s1, s2, "same manifest must sign identically");

        let mut tampered = sample_manifest();
        tampered.fields[0].label = "Renamed".into();
        let s3 = manifest_signature(&tampered).unwrap();
        assert_ne!(s1, s3, "a modified manifest must not keep the signature");
    }

    #[test]
    fn blueprint_op_round_trips_and_describes() {
        let op = BlueprintOp::AddField {
            model: "x_ticket".into(),
            label: "Amount".into(),
            field_type: "monetary".into(),
            related_model: None,
            options: None,
        };
        // Payload survives a JSON round-trip (how it's stored + replayed).
        let json = serde_json::to_value(&op).unwrap();
        assert_eq!(json["op"], "add_field");
        let back: BlueprintOp = serde_json::from_value(json).unwrap();
        assert_eq!(back.gate_action(), "blueprint.alter");
        assert_eq!(back.op_name(), "add_field");
        assert!(back.summary().contains("Amount"));

        // Create's target model is derived from the label (no model yet).
        let c = BlueprintOp::Create { label: "Site Visit".into() };
        assert_eq!(c.gate_action(), "blueprint.create");
        assert_eq!(c.model_hint(), "x_site_visit");
    }

    #[test]
    fn diff_first_version_is_all_added() {
        let cur = serde_json::json!({"fields": [
            {"name": "name", "label": "Name", "type": "string", "in_list": true},
        ]});
        let d = super::diff_definitions(None, &cur);
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].kind, "added");
        assert_eq!(d[0].field, "name");
    }

    #[test]
    fn diff_detects_add_remove_and_change() {
        let prev = serde_json::json!({"fields": [
            {"name": "name", "label": "Name", "type": "string", "in_list": true},
            {"name": "old", "label": "Old", "type": "integer", "in_list": true},
        ]});
        let cur = serde_json::json!({"fields": [
            {"name": "name", "label": "Title", "type": "string", "in_list": false},
            {"name": "amount", "label": "Amount", "type": "monetary", "in_list": true},
        ]});
        let d = super::diff_definitions(Some(&prev), &cur);
        let changed = d.iter().find(|c| c.field == "name").unwrap();
        assert_eq!(changed.kind, "changed");
        assert!(changed.detail.contains("renamed"));
        assert!(changed.detail.contains("hidden from list"));
        assert!(d.iter().any(|c| c.field == "amount" && c.kind == "added"));
        assert!(d.iter().any(|c| c.field == "old" && c.kind == "removed"));
    }

    #[test]
    fn plan_layout_reorders_and_renormalizes() {
        let existing = vec!["a".to_string(), "b".to_string(), "c".to_string()];
        // Ask for b, a, c via ordinals; keep a and c as list columns.
        let orders = HashMap::from([("a".into(), 2), ("b".into(), 1), ("c".into(), 3)]);
        let list = HashSet::from(["a".to_string(), "c".to_string()]);
        let plan = plan_layout(&existing, &orders, &list).unwrap();
        assert_eq!(
            plan,
            vec![
                ("b".to_string(), 10, false),
                ("a".to_string(), 20, true),
                ("c".to_string(), 30, true),
            ]
        );
    }

    #[test]
    fn plan_layout_rejects_unknown_field() {
        let existing = vec!["a".to_string()];
        let orders = HashMap::from([("ghost".to_string(), 1)]);
        let list = HashSet::new();
        assert!(plan_layout(&existing, &orders, &list).is_err());
    }

    #[test]
    fn plan_layout_ties_break_by_name() {
        let existing = vec!["zeta".to_string(), "alpha".to_string()];
        // Same ordinal for both -> deterministic name order.
        let orders = HashMap::from([("zeta".into(), 5), ("alpha".into(), 5)]);
        let list = HashSet::new();
        let plan = plan_layout(&existing, &orders, &list).unwrap();
        assert_eq!(plan[0].0, "alpha");
        assert_eq!(plan[1].0, "zeta");
    }

    #[test]
    fn slugify_makes_safe_identifiers() {
        assert_eq!(slugify("Purchase Widget"), "purchase_widget");
        assert_eq!(slugify("  Trailing / Slashes  "), "trailing_slashes");
        assert_eq!(slugify("Amount ($)"), "amount");
        assert_eq!(slugify("multi   space"), "multi_space");
        // Leading digit gets an `f_` guard so it starts with a letter.
        assert_eq!(slugify("3rd Party"), "f_3rd_party");
        assert_eq!(slugify("client-name"), "client_name");
    }
}
