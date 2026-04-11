//! `vortex workflow` — inspect workflow instances and history.
//!
//! Read-only CLI for walking `workflow_instances` and
//! `workflow_transitions`. Mirrors the `vortex audit verify/head/
//! export` pattern: the server binary owns the transition-writing
//! paths; the CLI only reads. Mutating a workflow via the CLI is
//! intentionally NOT exposed here — transitions should flow through
//! the HTTP handlers so the full policy + audit + hook chain runs.
//!
//! Subcommands:
//! - `list` — print instances filtered by workflow type / state /
//!   company. Defaults: 50 most-recently-updated instances across
//!   all types.
//! - `show <id>` — print the full instance record including
//!   state_data, timestamps, and the registered workflow type.
//! - `history <id>` — walk `workflow_transitions` in chronological
//!   order and print each transition with its audit_entry_id so
//!   the operator can cross-reference with `vortex audit`.

use std::str::FromStr;

use anyhow::{Context as _, Result};
use chrono::{DateTime, Utc};
use clap::Subcommand;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

#[derive(Subcommand)]
pub enum WorkflowCommands {
    /// List workflow instances with optional filters.
    List {
        /// Filter to a specific workflow type (e.g. "change_request").
        #[arg(long)]
        workflow_type: Option<String>,
        /// Filter to a specific state (e.g. "submitted").
        #[arg(long)]
        state: Option<String>,
        /// Filter to a single company UUID.
        #[arg(long)]
        company: Option<Uuid>,
        /// Maximum rows to return.
        #[arg(long, default_value_t = 50)]
        limit: i64,
    },
    /// Print the full record for a single instance.
    Show {
        /// Workflow instance UUID.
        id: Uuid,
    },
    /// Walk the transition history for an instance.
    History {
        /// Workflow instance UUID.
        id: Uuid,
    },
}

pub async fn run(command: WorkflowCommands) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://remicle:remicle_dev_2026@localhost/remicle".to_string());
    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("failed to connect to DATABASE_URL for workflow CLI")?;

    match command {
        WorkflowCommands::List {
            workflow_type,
            state,
            company,
            limit,
        } => list_cmd(&pool, workflow_type, state, company, limit).await,
        WorkflowCommands::Show { id } => show_cmd(&pool, id).await,
        WorkflowCommands::History { id } => history_cmd(&pool, id).await,
    }
}

async fn list_cmd(
    pool: &sqlx::PgPool,
    workflow_type: Option<String>,
    state: Option<String>,
    company: Option<Uuid>,
    limit: i64,
) -> Result<()> {
    let mut sql = String::from(
        "SELECT id, workflow_type, current_state, company_id, created_by, updated_at
         FROM workflow_instances WHERE 1=1",
    );
    let mut args: Vec<String> = Vec::new();
    if let Some(w) = &workflow_type {
        args.push(format!("workflow_type = '{}'", w.replace('\'', "''")));
    }
    if let Some(s) = &state {
        args.push(format!("current_state = '{}'", s.replace('\'', "''")));
    }
    if let Some(c) = company {
        args.push(format!("company_id = '{c}'"));
    }
    for a in &args {
        sql.push_str(" AND ");
        sql.push_str(a);
    }
    sql.push_str(&format!(" ORDER BY updated_at DESC LIMIT {limit}"));

    let rows = sqlx::query(&sql)
        .fetch_all(pool)
        .await
        .context("workflow_instances list")?;

    if rows.is_empty() {
        println!("No workflow instances match the filters.");
        return Ok(());
    }

    println!(
        "{:<38}  {:<20}  {:<18}  {:<26}  updated_at",
        "id", "type", "state", "company"
    );
    println!("{}", "-".repeat(120));
    for row in rows {
        let id: Uuid = row.get("id");
        let wt: String = row.get("workflow_type");
        let st: String = row.get("current_state");
        let company: Uuid = row.get("company_id");
        let updated: DateTime<Utc> = row.get("updated_at");
        println!(
            "{}  {:<20}  {:<18}  {}  {}",
            id,
            truncate(&wt, 20),
            truncate(&st, 18),
            company,
            updated.to_rfc3339()
        );
    }
    Ok(())
}

async fn show_cmd(pool: &sqlx::PgPool, id: Uuid) -> Result<()> {
    let row = sqlx::query(
        "SELECT id, workflow_type, current_state, state_data,
                company_id, created_by, created_at, updated_at
         FROM workflow_instances WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await
    .context("workflow_instances select")?;

    let Some(row) = row else {
        println!("No workflow instance with id {id}");
        std::process::exit(1);
    };

    let wt: String = row.get("workflow_type");
    let st: String = row.get("current_state");
    let data: Option<serde_json::Value> = row.try_get("state_data").ok();
    let company: Uuid = row.get("company_id");
    let created_by: Uuid = row.get("created_by");
    let created_at: DateTime<Utc> = row.get("created_at");
    let updated_at: DateTime<Utc> = row.get("updated_at");

    println!("── Workflow instance {id} ──");
    println!("  workflow_type:  {wt}");
    println!("  current_state:  {st}");
    println!("  company_id:     {company}");
    println!("  created_by:     {created_by}");
    println!("  created_at:     {}", created_at.to_rfc3339());
    println!("  updated_at:     {}", updated_at.to_rfc3339());
    println!();
    println!("  state_data:");
    let data_str = match data {
        Some(v) => serde_json::to_string_pretty(&v).unwrap_or_else(|_| v.to_string()),
        None => "(null)".to_string(),
    };
    for line in data_str.lines() {
        println!("    {line}");
    }

    // Also print a short summary of transitions applied to this
    // instance so `show` is a one-stop inspection command.
    let count: Option<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM workflow_transitions WHERE instance_id = $1",
    )
    .bind(id)
    .fetch_one(pool)
    .await
    .ok();
    println!();
    println!(
        "  transitions recorded: {}",
        count.unwrap_or(0)
    );
    println!("  (use `vortex workflow history {id}` to walk them)");

    Ok(())
}

async fn history_cmd(pool: &sqlx::PgPool, id: Uuid) -> Result<()> {
    let rows = sqlx::query(
        "SELECT id, transition_name, from_state, to_state,
                actor_user_id, audit_entry_id, occurred_at, context
         FROM workflow_transitions
         WHERE instance_id = $1
         ORDER BY occurred_at ASC",
    )
    .bind(id)
    .fetch_all(pool)
    .await
    .context("workflow_transitions select")?;

    if rows.is_empty() {
        println!("No transitions recorded for instance {id}");
        return Ok(());
    }

    println!("── Transition history for {id} ──");
    println!();
    for (i, row) in rows.iter().enumerate() {
        let trec_id: Uuid = row.get("id");
        let name: String = row.get("transition_name");
        let from: String = row.get("from_state");
        let to: String = row.get("to_state");
        let actor: Option<Uuid> = row.try_get("actor_user_id").ok();
        let audit_id: Option<Uuid> = row.try_get("audit_entry_id").ok();
        let when: DateTime<Utc> = row.get("occurred_at");
        let context: Option<serde_json::Value> = row.try_get("context").ok();

        println!(
            "  [{:>2}]  {:<20}  {:<15} → {:<15}  {}",
            i + 1,
            name,
            from,
            to,
            when.to_rfc3339()
        );
        println!("        transition_id: {trec_id}");
        if let Some(a) = actor {
            println!("        actor:         {a}");
        }
        if let Some(a) = audit_id {
            println!("        audit_entry:   {a}");
        }
        if let Some(c) = &context {
            if !c.is_null() {
                println!("        context:       {}", serde_json::to_string(c).unwrap_or_default());
            }
        }
        println!();
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

#[allow(unused)]
fn _unused() -> Result<()> {
    let _ = Uuid::from_str("");
    Ok(())
}
