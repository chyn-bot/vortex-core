//! Database seeding for core data
//!
//! Seeds essential data like roles on application startup.

use sqlx::Row;
use tracing::info;
use uuid::Uuid;
use vortex_common::VortexResult;
use vortex_orm::ConnectionPool;

/// Seed the database with core data
pub async fn seed_core_data(pool: &ConnectionPool) -> VortexResult<()> {
    seed_roles(pool).await?;
    Ok(())
}

/// Seed default roles if they don't exist
async fn seed_roles(pool: &ConnectionPool) -> VortexResult<()> {
    let roles = [
        ("System Administrator", "Full system access - all companies, audit logs, system settings"),
        ("Administrator", "Company administrator - manage users and data within company"),
        ("User", "Standard user - basic read access to allowed resources"),
    ];

    for (name, description) in roles {
        // Check if role exists
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM roles WHERE name = $1)"
        )
        .bind(name)
        .fetch_one(pool.pool())
        .await
        .unwrap_or(false);

        if !exists {
            let id = Uuid::now_v7();
            let result = sqlx::query(
                r#"
                INSERT INTO roles (id, name, description, is_system, created_at, updated_at)
                VALUES ($1, $2, $3, true, NOW(), NOW())
                "#
            )
            .bind(id)
            .bind(name)
            .bind(description)
            .execute(pool.pool())
            .await;

            match result {
                Ok(_) => info!("Created role: {}", name),
                Err(e) => tracing::warn!("Failed to create role {}: {}", name, e),
            }
        }
    }

    info!("Core roles seeded");
    Ok(())
}

/// Seed a default admin user if no users exist
pub async fn seed_default_admin(pool: &ConnectionPool) -> VortexResult<()> {
    // Check if any users exist
    let user_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
        .fetch_one(pool.pool())
        .await
        .unwrap_or(0);

    if user_count == 0 {
        // Create default admin user
        let user_id = Uuid::now_v7();
        let password_hash = vortex_security::PasswordHasher::new()
            .hash("Admin@123!")
            .unwrap_or_else(|_| "invalid".to_string());

        let result = sqlx::query(
            r#"
            INSERT INTO users (id, username, name, email, password_hash, active, created_at, updated_at, password_changed_at)
            VALUES ($1, 'admin', 'System Administrator', 'admin@example.com', $2, true, NOW(), NOW(), NOW())
            "#
        )
        .bind(user_id)
        .bind(&password_hash)
        .execute(pool.pool())
        .await;

        if let Ok(_) = result {
            // Assign System Administrator role
            let role_id: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM roles WHERE name = 'System Administrator'"
            )
            .fetch_optional(pool.pool())
            .await
            .ok()
            .flatten();

            if let Some(role_id) = role_id {
                let _ = sqlx::query(
                    "INSERT INTO user_roles (user_id, role_id) VALUES ($1, $2)"
                )
                .bind(user_id)
                .bind(role_id)
                .execute(pool.pool())
                .await;
            }

            info!("Created default admin user (username: admin, password: Admin@123!)");
        }
    }

    Ok(())
}
