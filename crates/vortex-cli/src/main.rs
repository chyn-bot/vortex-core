//! Vortex CLI - Command Line Interface
//!
//! Main entry point for the Vortex application.

use anyhow::Result;
use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

mod commands;

/// Vortex - Zero-Trust Enterprise Core
#[derive(Parser)]
#[command(name = "vortex")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, default_value = "vortex.toml")]
    config: String,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start the Vortex server
    Server {
        /// Host to bind to
        #[arg(short = 'H', long, default_value = "0.0.0.0")]
        host: String,

        /// Port to listen on
        #[arg(short, long, default_value = "8080")]
        port: u16,

        /// Number of worker threads
        #[arg(short, long)]
        workers: Option<usize>,
    },

    /// Scaffold a new plugin crate (generates code + wires it in)
    Scaffold {
        #[command(subcommand)]
        what: ScaffoldCommands,
    },

    /// Database management commands
    Db {
        #[command(subcommand)]
        command: DbCommands,
    },

    /// Module management commands
    Module {
        #[command(subcommand)]
        command: ModuleCommands,
    },

    /// User management commands
    User {
        #[command(subcommand)]
        command: UserCommands,
    },

    /// WORM audit ledger verification and inspection
    Audit {
        #[command(subcommand)]
        command: commands::audit::AuditCommands,
    },

    /// Secure data erasure — crypto-shred a subject's PII or decommission a
    /// tenant database, with WORM-audited events and signed certificates.
    Erase {
        #[command(subcommand)]
        command: commands::erase::EraseCommands,
    },

    /// Cedar policy engine inspection and dry-run
    Policy {
        #[command(subcommand)]
        command: commands::policy::PolicyCommands,
    },

    /// Workflow engine inspection — list instances, show state, walk history
    Workflow {
        #[command(subcommand)]
        command: commands::workflow::WorkflowCommands,
    },

    /// Generate shell completions
    Completions {
        /// Shell to generate completions for
        shell: clap_complete::Shell,
    },

    /// Show system information
    Info,
}

#[derive(Subcommand)]
enum DbCommands {
    /// Initialize the database
    Init {
        /// Drop existing tables first
        #[arg(long)]
        drop: bool,
    },

    /// Run pending migrations
    Migrate {
        /// Target version (default: latest)
        #[arg(short, long)]
        target: Option<String>,

        /// Run on all managed databases
        #[arg(long)]
        all: bool,
    },

    /// Rollback migrations
    Rollback {
        /// Number of migrations to rollback
        #[arg(short, long, default_value = "1")]
        steps: u32,
    },

    /// Show migration status
    Status,

    /// Create a new migration
    CreateMigration {
        /// Migration name
        name: String,

        /// Module for the migration
        #[arg(short, long, default_value = "core")]
        module: String,
    },

    /// Create a new database
    Create {
        /// Database name
        name: String,

        /// Seed with demo data
        #[arg(long)]
        demo: bool,
    },

    /// List managed databases
    List,

    /// Delete a managed database
    Delete {
        /// Database name
        name: String,

        /// Skip confirmation
        #[arg(long)]
        force: bool,
    },

    /// Backup a database to a file
    Backup {
        /// Database name
        name: String,

        /// Output file path
        #[arg(short, long)]
        output: Option<String>,
    },

    /// Restore a database from a backup file
    Restore {
        /// Backup file path
        file: String,

        /// Database name (defaults to name in backup)
        #[arg(short, long)]
        name: Option<String>,
    },

    /// Duplicate a database
    Duplicate {
        /// Source database name
        source: String,

        /// Target database name
        target: String,
    },
}

#[derive(Subcommand)]
enum ModuleCommands {
    /// List all modules
    List {
        /// Show only installed modules
        #[arg(long)]
        installed: bool,
    },

    /// Install a module
    Install {
        /// Module ID
        module_id: String,

        /// Skip dependency check
        #[arg(long)]
        no_deps: bool,
    },

    /// Uninstall a module
    Uninstall {
        /// Module ID
        module_id: String,
    },

    /// Upgrade a module
    Upgrade {
        /// Module ID (or "all" for all modules)
        module_id: String,
    },

    /// Show module information
    Info {
        /// Module ID
        module_id: String,
    },
}

#[derive(Subcommand)]
enum UserCommands {
    /// Create a new user
    Create {
        /// Username
        username: String,

        /// Email
        email: String,

        /// Make admin user
        #[arg(long)]
        admin: bool,
    },

    /// Reset user password (connects via DATABASE_URL)
    ResetPassword {
        /// Username
        username: String,

        /// New password. If omitted, a strong one is generated and printed.
        #[arg(long)]
        password: Option<String>,
    },

    /// Lock a user account
    Lock {
        /// Username
        username: String,
    },

    /// Unlock a user account
    Unlock {
        /// Username
        username: String,
    },

    /// List users
    List {
        /// Filter by role
        #[arg(short, long)]
        role: Option<String>,
    },
}

#[derive(Subcommand)]
enum ScaffoldCommands {
    /// Generate a working vertical plugin (list + form + record page)
    Plugin {
        /// Technical name, e.g. "parking" or "highway-ops"
        name: String,
        /// Display name shown in menus (default: title-cased name)
        #[arg(long)]
        display: Option<String>,
    },
    /// Generate a plugin crate from an existing Blueprint (reads DATABASE_URL)
    FromBlueprint {
        /// Blueprint technical model name, e.g. "x_vendor_audit"
        model: String,
        /// Plugin crate name (default: derived from the Blueprint's display name)
        #[arg(long)]
        name: Option<String>,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    // Parse CLI arguments
    let cli = Cli::parse();

    // Setup logging
    let log_level = if cli.verbose { Level::DEBUG } else { Level::INFO };
    let subscriber = FmtSubscriber::builder()
        .with_max_level(log_level)
        .with_target(false)
        .finish();
    tracing::subscriber::set_global_default(subscriber)?;

    // Execute command
    match cli.command {
        Commands::Server { host, port, workers } => {
            commands::server::run(host, port, workers).await
        }
        Commands::Db { command } => {
            commands::db::run(command).await
        }
        Commands::Module { command } => {
            commands::module::run(command).await
        }
        Commands::User { command } => {
            commands::user::run(command).await
        }
        Commands::Audit { command } => {
            commands::audit::run(command).await
        }
        Commands::Erase { command } => {
            commands::erase::run(command).await
        }
        Commands::Policy { command } => {
            commands::policy::run(command).await
        }
        Commands::Workflow { command } => {
            commands::workflow::run(command).await
        }
        Commands::Completions { shell } => {
            commands::completions::run(shell)
        }
        Commands::Scaffold { what } => {
            match what {
                ScaffoldCommands::Plugin { name, display } => {
                    commands::scaffold::run(&name, display)
                }
                ScaffoldCommands::FromBlueprint { model, name } => {
                    commands::scaffold::run_from_blueprint(&model, name).await
                }
            }
        }
        Commands::Info => {
            commands::info::run().await
        }
    }
}
