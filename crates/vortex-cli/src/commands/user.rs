//! User commands

use anyhow::{Context, Result};
use crate::UserCommands;

/// Connect to the database named by `DATABASE_URL` (the same convention the
/// `db` subcommands use). Pick the target tenant by pointing `DATABASE_URL`
/// at it, e.g. `DATABASE_URL=postgres://…/vortex vortex user reset-password …`.
async fn connect() -> Result<sqlx::PgPool> {
    let url = std::env::var("DATABASE_URL")
        .context("DATABASE_URL not set — point it at the target database, e.g. postgres://vortex:vortex@localhost:5432/vortex")?;
    sqlx::postgres::PgPoolOptions::new()
        .max_connections(2)
        .connect(&url)
        .await
        .context("failed to connect to database")
}

/// Hash a password exactly the way the running server does, so the stored
/// hash verifies under the app's `Argon2::default().verify_password` (see
/// `server.rs::verify_password`).
fn hash_password(password: &str) -> Result<String> {
    use argon2::{password_hash::SaltString, Argon2, PasswordHasher};
    let salt = SaltString::generate(&mut rand::thread_rng());
    Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|h| h.to_string())
        .map_err(|e| anyhow::anyhow!("failed to hash password: {e}"))
}

/// Generate a readable-but-strong random password for the no-`--password` path.
///
/// The fixed `Vx-` prefix guarantees an uppercase, a lowercase and a symbol;
/// the appended digit guarantees the fourth class — so the result always
/// satisfies [`password_policy::validate`] regardless of the random body
/// (the body's charset excludes ambiguous 0/O/1/l and has no symbols, so a
/// digit is not otherwise guaranteed).
fn generate_password() -> String {
    use rand::Rng;
    const CHARS: &[u8] = b"ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
    let mut rng = rand::thread_rng();
    let body: String = (0..12).map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char).collect();
    let digit = rng.gen_range(2..=9);
    format!("Vx-{body}{digit}")
}

pub async fn run(command: UserCommands) -> Result<()> {
    match command {
        UserCommands::Create { username, email, admin } => {
            println!("Creating user '{}'...", username);
            println!("Email: {}", email);
            if admin {
                println!("Admin privileges: Yes");
            }
            // TODO: Create user
            println!("User '{}' created successfully", username);
            println!("Temporary password: [generated]");
        }
        UserCommands::ResetPassword { username, password } => {
            let pool = connect().await?;
            let new_password = password.unwrap_or_else(generate_password);
            // Enforce the same complexity policy the web set/reset paths use.
            // A generated password always satisfies it (see `generate_password`),
            // so this only ever rejects a weak operator-supplied `--password`.
            if let Err(reason) = crate::commands::password_policy::validate(&new_password) {
                anyhow::bail!("{reason}");
            }
            let hash = hash_password(&new_password)?;

            let rows = sqlx::query(
                "UPDATE users \
                 SET password_hash = $1, locked = false, failed_login_attempts = 0, \
                     must_change_password = false, password_changed_at = now(), updated_at = now() \
                 WHERE username = $2",
            )
            .bind(&hash)
            .bind(&username)
            .execute(&pool)
            .await
            .context("failed to update password")?
            .rows_affected();

            if rows == 0 {
                anyhow::bail!("no user named '{username}' in this database (is DATABASE_URL pointing at the right tenant?)");
            }
            println!("Password reset for '{username}'.");
            println!("New password: {new_password}");
        }
        UserCommands::Lock { username } => {
            println!("Locking user '{}'...", username);
            // TODO: Lock user
            println!("User '{}' locked", username);
        }
        UserCommands::Unlock { username } => {
            println!("Unlocking user '{}'...", username);
            // TODO: Unlock user
            println!("User '{}' unlocked", username);
        }
        UserCommands::List { role } => {
            if let Some(role) = role {
                println!("Users with role '{}':", role);
            } else {
                println!("All Users:");
            }
            println!("─────────────────────────────────────────");
            // TODO: List users
            println!("No users found");
        }
    }
    Ok(())
}
