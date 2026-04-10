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

    /// Reset user password
    ResetPassword {
        /// Username
        username: String,
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
        Commands::Completions { shell } => {
            commands::completions::run(shell)
        }
        Commands::Info => {
            commands::info::run().await
        }
    }
}
