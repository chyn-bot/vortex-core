//! Remote invoice pickup — pulls PDFs from a vendor drop folder.
//!
//! Two transports, both pure-Rust: **SFTP** over SSH (`russh` + `russh-sftp`,
//! async/tokio) and **FTP / FTPS** (`suppaftp`'s sync client run inside
//! `spawn_blocking`, since its async client is async-std-based). Both expose the
//! same two-phase API so the caller (handlers) can do the DB import in between:
//!
//!   1. [`fetch_files`] — connect, list files matching the pattern, download them.
//!   2. caller imports each file into a `recon_batch`.
//!   3. [`move_to_processed`] — connect, move the imported files to the archive
//!      subfolder so they are never picked up again.

use std::sync::Arc;

/// Decrypted, in-memory connection config for one remote source. The API key /
/// password live here only for the duration of a poll (AES-256-GCM at rest).
#[derive(Clone)]
pub struct RemoteConfig {
    pub protocol: String, // sftp | ftp | ftps
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>, // PEM, SFTP key auth
    pub remote_dir: String,
    pub processed_dir: String,
    pub pattern: String, // e.g. "*.pdf"
}

/// One downloaded file.
pub struct Fetched {
    pub name: String,
    pub data: Vec<u8>,
}

/// Minimal glob: `*` / `*.*` match everything, `*.ext` matches by extension,
/// anything else is an exact (case-insensitive) filename. Enough for drop folders.
fn matches(pattern: &str, name: &str) -> bool {
    let p = pattern.trim();
    if p.is_empty() || p == "*" || p == "*.*" {
        return true;
    }
    if let Some(ext) = p.strip_prefix("*.") {
        return name.to_ascii_lowercase().ends_with(&format!(".{}", ext.to_ascii_lowercase()));
    }
    name.eq_ignore_ascii_case(p)
}

fn join(dir: &str, name: &str) -> String {
    if dir.ends_with('/') {
        format!("{dir}{name}")
    } else {
        format!("{dir}/{name}")
    }
}

/// Download every matching file from the source's remote directory.
pub async fn fetch_files(cfg: &RemoteConfig) -> Result<Vec<Fetched>, String> {
    match cfg.protocol.as_str() {
        "sftp" => sftp_fetch(cfg).await,
        "ftp" | "ftps" => {
            let c = cfg.clone();
            tokio::task::spawn_blocking(move || ftp_fetch_blocking(&c))
                .await
                .map_err(|e| format!("join error: {e}"))?
        }
        other => Err(format!("unknown protocol '{other}'")),
    }
}

/// Move the named files from the remote dir into the processed/archive subfolder.
pub async fn move_to_processed(cfg: &RemoteConfig, names: &[String]) -> Result<(), String> {
    if names.is_empty() {
        return Ok(());
    }
    match cfg.protocol.as_str() {
        "sftp" => sftp_move(cfg, names).await,
        "ftp" | "ftps" => {
            let c = cfg.clone();
            let n = names.to_vec();
            tokio::task::spawn_blocking(move || ftp_move_blocking(&c, &n))
                .await
                .map_err(|e| format!("join error: {e}"))?
        }
        other => Err(format!("unknown protocol '{other}'")),
    }
}

// ── SFTP (russh) ─────────────────────────────────────────────────────────────

struct AcceptAll;

#[vortex_plugin_sdk::async_trait::async_trait]
impl russh::client::Handler for AcceptAll {
    type Error = russh::Error;
    // NOTE: accept any host key. Host-key pinning is a hardening follow-up;
    // the transport is still SSH-encrypted.
    async fn check_server_key(
        &mut self,
        _server_public_key: &russh::keys::key::PublicKey,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

async fn sftp_connect(cfg: &RemoteConfig) -> Result<russh_sftp::client::SftpSession, String> {
    let config = Arc::new(russh::client::Config::default());
    let mut handle = russh::client::connect(config, (cfg.host.as_str(), cfg.port), AcceptAll)
        .await
        .map_err(|e| format!("SSH connect failed: {e}"))?;

    let authed = if let Some(pem) = cfg.private_key.as_ref().filter(|s| !s.trim().is_empty()) {
        let kp = russh::keys::decode_secret_key(pem, None)
            .map_err(|e| format!("private key parse failed: {e}"))?;
        handle
            .authenticate_publickey(&cfg.username, Arc::new(kp))
            .await
            .map_err(|e| format!("SSH key auth failed: {e}"))?
    } else {
        handle
            .authenticate_password(&cfg.username, cfg.password.clone().unwrap_or_default())
            .await
            .map_err(|e| format!("SSH password auth failed: {e}"))?
    };
    if !authed {
        return Err("SFTP authentication rejected (check username / password / key)".into());
    }

    let channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("SSH channel open failed: {e}"))?;
    channel
        .request_subsystem(true, "sftp")
        .await
        .map_err(|e| format!("SFTP subsystem failed: {e}"))?;
    russh_sftp::client::SftpSession::new(channel.into_stream())
        .await
        .map_err(|e| format!("SFTP handshake failed: {e}"))
}

async fn sftp_fetch(cfg: &RemoteConfig) -> Result<Vec<Fetched>, String> {
    let sftp = sftp_connect(cfg).await?;
    let entries = sftp
        .read_dir(cfg.remote_dir.clone())
        .await
        .map_err(|e| format!("list {} failed: {e}", cfg.remote_dir))?;
    let mut out = Vec::new();
    for entry in entries {
        let name = entry.file_name();
        if !matches(&cfg.pattern, &name) {
            continue;
        }
        let data = sftp
            .read(join(&cfg.remote_dir, &name))
            .await
            .map_err(|e| format!("read {name} failed: {e}"))?;
        out.push(Fetched { name, data });
    }
    Ok(out)
}

async fn sftp_move(cfg: &RemoteConfig, names: &[String]) -> Result<(), String> {
    let sftp = sftp_connect(cfg).await?;
    let _ = sftp.create_dir(cfg.processed_dir.clone()).await; // ok if it already exists
    for n in names {
        let _ = sftp
            .rename(join(&cfg.remote_dir, n), join(&cfg.processed_dir, n))
            .await;
    }
    Ok(())
}

// ── FTP / FTPS (suppaftp, sync in spawn_blocking) ────────────────────────────

fn ftp_rustls_connector() -> Result<suppaftp::RustlsConnector, String> {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|e| format!("TLS config failed: {e}"))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config).into())
}

fn ftp_open(cfg: &RemoteConfig) -> Result<suppaftp::RustlsFtpStream, String> {
    // Use the rustls-capable stream type for both; only upgrade to TLS for ftps.
    let mut ftp = suppaftp::RustlsFtpStream::connect((cfg.host.as_str(), cfg.port))
        .map_err(|e| format!("FTP connect failed: {e}"))?;
    if cfg.protocol == "ftps" {
        ftp = ftp
            .into_secure(ftp_rustls_connector()?, &cfg.host)
            .map_err(|e| format!("FTPS TLS failed: {e}"))?;
    }
    ftp.login(cfg.username.as_str(), cfg.password.as_deref().unwrap_or(""))
        .map_err(|e| format!("FTP login failed: {e}"))?;
    ftp.cwd(&cfg.remote_dir)
        .map_err(|e| format!("FTP cwd {} failed: {e}", cfg.remote_dir))?;
    Ok(ftp)
}

fn ftp_fetch_blocking(cfg: &RemoteConfig) -> Result<Vec<Fetched>, String> {
    let mut ftp = ftp_open(cfg)?;
    let names = ftp.nlst(None).map_err(|e| format!("FTP list failed: {e}"))?;
    let mut out = Vec::new();
    for full in names {
        // nlst may return full paths; keep the basename for matching + storage.
        let name = full.rsplit('/').next().unwrap_or(&full).to_string();
        if !matches(&cfg.pattern, &name) {
            continue;
        }
        let cur = ftp
            .retr_as_buffer(&name)
            .map_err(|e| format!("FTP download {name} failed: {e}"))?;
        out.push(Fetched { name, data: cur.into_inner() });
    }
    let _ = ftp.quit();
    Ok(out)
}

fn ftp_move_blocking(cfg: &RemoteConfig, names: &[String]) -> Result<(), String> {
    let mut ftp = ftp_open(cfg)?;
    // Best-effort create the processed dir (ignore "already exists").
    let _ = ftp.mkdir(&cfg.processed_dir);
    for n in names {
        let _ = ftp.rename(n, &join(&cfg.processed_dir, n));
    }
    let _ = ftp.quit();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pattern_matching() {
        assert!(matches("*.pdf", "INV123.PDF"));
        assert!(matches("*.pdf", "a.pdf"));
        assert!(!matches("*.pdf", "a.csv"));
        assert!(matches("*", "anything.xyz"));
        assert!(matches("exact.pdf", "EXACT.pdf"));
    }
    #[test]
    fn joins_paths() {
        assert_eq!(join("/in", "a.pdf"), "/in/a.pdf");
        assert_eq!(join("/in/", "a.pdf"), "/in/a.pdf");
    }
}
