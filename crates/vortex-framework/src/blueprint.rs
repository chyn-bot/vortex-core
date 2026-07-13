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
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;
use vortex_orm::blueprint as ddl;
use vortex_policy::{PolicyPrincipal, PolicyResource};
use vortex_security::{AuditAction, AuditEntry, AuditSeverity};

fn dberr(e: sqlx::Error) -> String {
    format!("database error: {e}")
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

/// Resolve a many2one target: it must be an active Blueprint that carries a
/// `name` field (the display column the generic picker/JOIN reads). Returns the
/// target's physical table name. Restricting targets to name-bearing Blueprints
/// keeps the relation robust — a target without `name` would break the generic
/// list of the owning model. (Blueprint→compiled targets are a later phase that
/// hardens the generic JOIN to resolve arbitrary display columns.)
async fn resolve_relation_target(db: &PgPool, target_model: &str) -> Result<String, String> {
    sqlx::query_scalar::<_, String>(
        "SELECT m.table_name FROM ir_model m
         WHERE m.name = $1 AND m.source = 'blueprint' AND m.is_active = true
           AND EXISTS (SELECT 1 FROM ir_model_field f WHERE f.model_id = m.id AND f.name = 'name')",
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
        sqlx::query(
            "UPDATE ir_model_field SET sequence = $3, is_visible = $4
             WHERE model_id = $1 AND name = $2 AND source = 'blueprint'",
        )
        .bind(model_id)
        .bind(name)
        .bind(*seq)
        .bind(*in_list)
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

#[cfg(test)]
mod tests {
    use super::{parse_selection_options, plan_layout, slugify};
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
