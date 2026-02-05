//! User commands

use anyhow::Result;
use crate::UserCommands;

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
        UserCommands::ResetPassword { username } => {
            println!("Resetting password for '{}'...", username);
            // TODO: Reset password
            println!("Password reset. New password: [generated]");
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
