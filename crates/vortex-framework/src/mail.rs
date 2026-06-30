//! Outbound email — a core service over SMTP, usable by any module.
//!
//! Configuration is per-tenant: each tenant DB has a `mail_servers` table
//! holding one or more SMTP servers (Gmail, Office 365, or any generic host),
//! one marked default. Passwords are encrypted at rest with
//! [`vortex_security::crypto`] (AES-256-GCM). Sends are recorded in `mail_log`.
//!
//! ```ignore
//! mail::send_default(&db, &EmailMessage::text("a@b.com", "Hi", "body"), "welcome").await?;
//! ```
//!
//! The transport uses rustls (no system openssl) on the tokio runtime.

use lettre::message::{Mailbox, MultiPart};
use lettre::transport::smtp::authentication::Credentials;
use lettre::{Address, AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor};
use sqlx::{PgPool, Row};
use uuid::Uuid;
use vortex_security::crypto;

/// How the SMTP connection is secured.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MailSecurity {
    /// Plain connection upgraded with STARTTLS (typically port 587).
    Starttls,
    /// Implicit TLS from connect (typically port 465).
    Tls,
    /// No transport security (port 25, internal relays only).
    None,
}

impl MailSecurity {
    pub fn as_str(&self) -> &'static str {
        match self {
            MailSecurity::Starttls => "starttls",
            MailSecurity::Tls => "tls",
            MailSecurity::None => "none",
        }
    }
    pub fn parse(s: &str) -> Self {
        match s {
            "tls" => MailSecurity::Tls,
            "none" => MailSecurity::None,
            _ => MailSecurity::Starttls,
        }
    }
}

/// A known provider preset: host, port, and security pre-filled in the UI.
/// `generic` lets the operator type their own.
pub fn provider_preset(provider: &str) -> Option<(&'static str, i32, MailSecurity)> {
    match provider {
        "gmail" => Some(("smtp.gmail.com", 587, MailSecurity::Starttls)),
        "office365" => Some(("smtp.office365.com", 587, MailSecurity::Starttls)),
        "sendgrid" => Some(("smtp.sendgrid.net", 587, MailSecurity::Starttls)),
        "mailgun" => Some(("smtp.mailgun.org", 587, MailSecurity::Starttls)),
        _ => None,
    }
}

/// The known providers, for a settings dropdown: (value, label).
pub const PROVIDERS: &[(&str, &str)] = &[
    ("generic", "Generic SMTP"),
    ("gmail", "Gmail / Google Workspace"),
    ("office365", "Microsoft 365 / Outlook"),
    ("sendgrid", "SendGrid"),
    ("mailgun", "Mailgun"),
];

/// A configured SMTP server (password still encrypted).
#[derive(Debug, Clone)]
pub struct MailServer {
    pub id: Uuid,
    pub name: String,
    pub provider: String,
    pub host: String,
    pub port: i32,
    pub security: MailSecurity,
    pub username: Option<String>,
    pub password_enc: Option<Vec<u8>>,
    pub from_address: String,
    pub from_name: Option<String>,
    pub is_default: bool,
}

/// One email to send.
#[derive(Debug, Clone)]
pub struct EmailMessage {
    pub to: String,
    pub subject: String,
    pub text: String,
    pub html: Option<String>,
}

impl EmailMessage {
    pub fn text(to: impl Into<String>, subject: impl Into<String>, text: impl Into<String>) -> Self {
        Self { to: to.into(), subject: subject.into(), text: text.into(), html: None }
    }
    pub fn with_html(mut self, html: impl Into<String>) -> Self {
        self.html = Some(html.into());
        self
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("no mail server configured")]
    NotConfigured,
    #[error("invalid address: {0}")]
    Address(String),
    #[error("could not decrypt the stored password")]
    Decrypt,
    #[error("build error: {0}")]
    Build(String),
    #[error("smtp error: {0}")]
    Smtp(String),
}

const SERVER_COLS: &str = "id, name, provider, host, port, security, username, \
    password_enc, from_address, from_name, is_default";

fn map_server(r: &sqlx::postgres::PgRow) -> MailServer {
    MailServer {
        id: r.get("id"),
        name: r.get("name"),
        provider: r.get("provider"),
        host: r.get("host"),
        port: r.get("port"),
        security: MailSecurity::parse(&r.get::<String, _>("security")),
        username: r.try_get("username").ok().flatten(),
        password_enc: r.try_get("password_enc").ok().flatten(),
        from_address: r.get("from_address"),
        from_name: r.try_get("from_name").ok().flatten(),
        is_default: r.get("is_default"),
    }
}

/// Load the tenant's default active mail server (highest `is_default`, oldest).
pub async fn default_server(db: &PgPool) -> Option<MailServer> {
    let sql = format!(
        "SELECT {SERVER_COLS} FROM mail_servers WHERE active = true \
         ORDER BY is_default DESC, created_at LIMIT 1"
    );
    sqlx::query(&sql)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|r| map_server(&r))
}

/// Load one mail server by id (any active flag).
pub async fn server_by_id(db: &PgPool, id: Uuid) -> Option<MailServer> {
    let sql = format!("SELECT {SERVER_COLS} FROM mail_servers WHERE id = $1");
    sqlx::query(&sql)
        .bind(id)
        .fetch_optional(db)
        .await
        .ok()
        .flatten()
        .map(|r| map_server(&r))
}

/// Send `msg` via a specific server. Records the attempt in `mail_log`.
pub async fn send_with(
    db: &PgPool,
    server: &MailServer,
    msg: &EmailMessage,
    context: &str,
) -> Result<(), MailError> {
    let result = deliver(server, msg).await;
    let (status, err) = match &result {
        Ok(()) => ("sent", None),
        Err(e) => ("failed", Some(e.to_string())),
    };
    let _ = sqlx::query(
        "INSERT INTO mail_log (server_id, to_address, subject, status, error, context) \
         VALUES ($1,$2,$3,$4,$5,$6)",
    )
    .bind(server.id)
    .bind(&msg.to)
    .bind(&msg.subject)
    .bind(status)
    .bind(err)
    .bind(context)
    .execute(db)
    .await;
    result
}

/// Send via the tenant's default server. Errors if none is configured.
pub async fn send_default(db: &PgPool, msg: &EmailMessage, context: &str) -> Result<(), MailError> {
    let server = default_server(db).await.ok_or(MailError::NotConfigured)?;
    send_with(db, &server, msg, context).await
}

/// Build the transport and actually deliver (no logging here).
async fn deliver(server: &MailServer, msg: &EmailMessage) -> Result<(), MailError> {
    let from_addr: Address = server
        .from_address
        .parse()
        .map_err(|_| MailError::Address(server.from_address.clone()))?;
    let from = Mailbox::new(server.from_name.clone(), from_addr);
    let to: Mailbox = msg
        .to
        .parse()
        .map_err(|_| MailError::Address(msg.to.clone()))?;

    let builder = Message::builder().from(from).to(to).subject(&msg.subject);
    let email = match &msg.html {
        Some(html) => builder
            .multipart(MultiPart::alternative_plain_html(msg.text.clone(), html.clone()))
            .map_err(|e| MailError::Build(e.to_string()))?,
        None => builder
            .body(msg.text.clone())
            .map_err(|e| MailError::Build(e.to_string()))?,
    };

    let mut tb = match server.security {
        MailSecurity::Tls => AsyncSmtpTransport::<Tokio1Executor>::relay(&server.host)
            .map_err(|e| MailError::Smtp(e.to_string()))?,
        MailSecurity::Starttls => AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&server.host)
            .map_err(|e| MailError::Smtp(e.to_string()))?,
        MailSecurity::None => AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&server.host),
    };
    tb = tb.port(server.port as u16);

    if let Some(user) = &server.username {
        if let Some(enc) = &server.password_enc {
            let key = crypto::master_key();
            let pass = crypto::decrypt_str(enc, &key).map_err(|_| MailError::Decrypt)?;
            tb = tb.credentials(Credentials::new(user.clone(), pass));
        }
    }

    let transport = tb.build();
    transport.send(email).await.map_err(|e| MailError::Smtp(e.to_string()))?;
    Ok(())
}
