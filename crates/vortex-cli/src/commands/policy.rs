//! `vortex policy` — inspect and dry-run the Cedar policy engine.
//!
//! Subcommands:
//! - `list` — print every row in `policy_rules` with active flag and
//!   priority. Useful during migration review and for auditors.
//! - `test` — perform a single authorization check without starting the
//!   server. Takes principal/action/resource on the CLI, loads policies
//!   from `DATABASE_URL`, runs Cedar, prints Allow/Deny with determining
//!   policy names. Exit code mirrors the decision: 0 on Allow, 1 on
//!   Deny, 2 on infra error.
//! - `validate` — parse every row in `policy_rules` and report any
//!   syntax errors without hitting the authorizer. Safe to run in CI.

use std::sync::Arc;

use anyhow::{Context as _, Result};
use clap::Subcommand;
use sqlx::postgres::PgPoolOptions;
use sqlx::Row;
use uuid::Uuid;

use vortex_policy::{
    Decision, PgPolicyStore, PolicyPrincipal, PolicyResource, PolicyService,
};

#[derive(Subcommand)]
pub enum PolicyCommands {
    /// List every policy in the `policy_rules` table.
    List {
        /// Show inactive policies too.
        #[arg(long)]
        all: bool,
    },
    /// Parse every policy and report syntax errors without evaluating.
    Validate,
    /// Dry-run an authorization decision.
    Test {
        /// Principal user UUID.
        #[arg(long)]
        principal: Uuid,
        /// Comma-separated list of role names the principal holds.
        #[arg(long, default_value = "")]
        roles: String,
        /// Action name (e.g. `update`, `delete`, `approve`).
        #[arg(long)]
        action: String,
        /// Resource type (e.g. `User`, `WorkOrder`).
        #[arg(long, default_value = "User")]
        resource_type: String,
        /// Resource id (UUID string or free-form string).
        #[arg(long)]
        resource_id: String,
        /// Optional username for the principal entity. Defaults to
        /// `cli-tester`.
        #[arg(long, default_value = "cli-tester")]
        username: String,
        /// Optional company/tenant UUID for the principal. Defaults to
        /// the seeded system company.
        #[arg(long, default_value = "00000000-0000-0000-0000-000000000001")]
        company: Uuid,
    },
}

pub async fn run(command: PolicyCommands) -> Result<()> {
    let database_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://remicle:remicle_dev_2026@localhost/remicle".to_string());

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .connect(&database_url)
        .await
        .context("failed to connect to DATABASE_URL for policy CLI")?;

    match command {
        PolicyCommands::List { all } => list_cmd(&pool, all).await,
        PolicyCommands::Validate => validate_cmd(&pool).await,
        PolicyCommands::Test {
            principal,
            roles,
            action,
            resource_type,
            resource_id,
            username,
            company,
        } => {
            test_cmd(
                &pool,
                principal,
                &roles,
                &action,
                &resource_type,
                &resource_id,
                &username,
                company,
            )
            .await
        }
    }
}

async fn list_cmd(pool: &sqlx::PgPool, show_all: bool) -> Result<()> {
    let sql = if show_all {
        "SELECT id, name, active, priority, description \
         FROM policy_rules ORDER BY priority ASC, name ASC"
    } else {
        "SELECT id, name, active, priority, description \
         FROM policy_rules WHERE active = true ORDER BY priority ASC, name ASC"
    };
    let rows = sqlx::query(sql)
        .fetch_all(pool)
        .await
        .context("policy_rules select")?;

    if rows.is_empty() {
        println!("No policies found.");
        return Ok(());
    }

    println!(
        "{:>4}  {:<8}  {:<40}  {}",
        "prio", "active", "name", "description"
    );
    println!("{}", "-".repeat(100));
    for row in rows {
        let id: Uuid = row.get("id");
        let name: String = row.get("name");
        let active: bool = row.get("active");
        let priority: i32 = row.get("priority");
        let description: Option<String> = row.try_get("description").ok();
        println!(
            "{:>4}  {:<8}  {:<40}  {}  [{}]",
            priority,
            if active { "active" } else { "inactive" },
            truncate(&name, 40),
            description.as_deref().unwrap_or("").chars().take(40).collect::<String>(),
            &id.to_string()[..8]
        );
    }

    Ok(())
}

async fn validate_cmd(pool: &sqlx::PgPool) -> Result<()> {
    let store = Arc::new(PgPolicyStore::new(pool.clone()));
    let svc = PolicyService::load(store)
        .await
        .context("PolicyService::load")?;
    let errors = svc.parse_errors().await;
    if errors.is_empty() {
        println!("All active policies parsed successfully.");
        return Ok(());
    }
    println!("Parse errors ({}):", errors.len());
    for err in &errors {
        println!();
        println!("  policy_id: {}", err.policy_db_id);
        println!("  name:      {}", err.policy_name);
        println!("  error:     {}", err.error);
    }
    std::process::exit(1);
}

#[allow(clippy::too_many_arguments)]
async fn test_cmd(
    pool: &sqlx::PgPool,
    principal_id: Uuid,
    roles_csv: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    username: &str,
    company: Uuid,
) -> Result<()> {
    let store = Arc::new(PgPolicyStore::new(pool.clone()));
    let svc = PolicyService::load(store)
        .await
        .context("PolicyService::load")?;

    let roles: Vec<String> = roles_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let principal = PolicyPrincipal {
        user_id: principal_id,
        username: username.to_string(),
        company_id: company,
        roles,
    };
    let resource = PolicyResource {
        type_name: resource_type.to_string(),
        id: resource_id.to_string(),
        attributes: serde_json::Value::Null,
    };

    println!("── Cedar Policy Dry-Run ──");
    println!("  principal:     User::\"{}\"", principal.user_id);
    println!("  principal.username:   {}", principal.username);
    println!("  principal.company:    {}", principal.company_id);
    println!("  principal.roles:      {:?}", principal.roles);
    println!("  action:        Action::\"{}\"", action);
    println!("  resource:      {}::\"{}\"", resource.type_name, resource.id);
    println!();

    let decision = svc
        .check(&principal, action, &resource)
        .await
        .context("policy check")?;

    match decision {
        Decision::Allow { determining_policies } => {
            println!("DECISION: \x1b[32mALLOW\x1b[0m");
            println!("  determining policies:");
            for p in determining_policies {
                println!("    - {}", p);
            }
        }
        Decision::Deny {
            determining_policies,
            reason,
        } => {
            println!("DECISION: \x1b[31mDENY\x1b[0m");
            println!("  reason: {:?}", reason);
            if determining_policies.is_empty() {
                println!("  (no permit policy matched; this is the default-deny path)");
            } else {
                println!("  determining policies:");
                for p in determining_policies {
                    println!("    - {}", p);
                }
            }
            std::process::exit(1);
        }
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
