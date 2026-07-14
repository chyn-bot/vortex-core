//! Pluggable anti-virus scanning for uploaded content.
//!
//! Intake (and any other upload path) can screen a blob *before* it is stored
//! or linked to a record. Scanning is a **hook**: the default backend is a
//! no-op that accepts everything (so an install that hasn't configured AV
//! behaves exactly as before), and a real scanner is wired in from
//! `[antivirus]` in `vortex.toml`. The built-in real backend speaks the ClamAV
//! `clamd` `INSTREAM` protocol over TCP — no new dependency, no external CDN,
//! air-gap friendly (point it at a `clamd` on the private network).
//!
//! Fail policy lives with the backend: a `clamd` that is unreachable either
//! fails **closed** (reject the upload — the default when you bothered to turn
//! AV on) or **open** (accept and log) per `fail_open`.

use async_trait::async_trait;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// The result of scanning one blob.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AvVerdict {
    /// No threat found.
    Clean,
    /// A threat was found; carries the scanner's signature name.
    Infected(String),
}

/// A scan could not be completed (transport, protocol, or size problem). A
/// backend that is configured `fail_open` converts these into `Clean` itself,
/// so a caller that receives `Err` should treat the upload as un-scannable and
/// fail closed.
#[derive(Debug, thiserror::Error)]
pub enum AvError {
    #[error("scanner unreachable: {0}")]
    Unreachable(String),
    #[error("scan protocol error: {0}")]
    Protocol(String),
    #[error("payload too large to scan ({0} bytes)")]
    TooLarge(usize),
}

/// A pluggable virus scanner. Implementations must be safe for concurrent use.
#[async_trait]
pub trait AvScanner: Send + Sync {
    /// Scan `data`. `Ok(Clean)`/`Ok(Infected(..))` are definite verdicts;
    /// `Err` means the scan itself failed (callers should fail closed).
    async fn scan(&self, data: &[u8]) -> Result<AvVerdict, AvError>;

    /// Short backend name for startup logs and health output.
    fn backend_name(&self) -> &'static str;

    /// `true` when this backend actually inspects content (a real scanner),
    /// `false` for the no-op default. Lets the UI/logs say whether uploads are
    /// really being screened.
    fn is_active(&self) -> bool {
        true
    }
}

/// The default: accept everything. Used when `[antivirus]` is absent/`none`.
pub struct NoopScanner;

#[async_trait]
impl AvScanner for NoopScanner {
    async fn scan(&self, _data: &[u8]) -> Result<AvVerdict, AvError> {
        Ok(AvVerdict::Clean)
    }
    fn backend_name(&self) -> &'static str {
        "none"
    }
    fn is_active(&self) -> bool {
        false
    }
}

/// ClamAV `clamd` scanner over TCP, using the `INSTREAM` command.
pub struct ClamdScanner {
    address: String,
    timeout: Duration,
    max_bytes: usize,
    fail_open: bool,
}

impl ClamdScanner {
    pub fn new(address: impl Into<String>, timeout: Duration, max_bytes: usize, fail_open: bool) -> Self {
        Self { address: address.into(), timeout, max_bytes, fail_open }
    }

    /// Run the INSTREAM exchange; returns the raw response bytes.
    async fn instream(&self, data: &[u8]) -> Result<Vec<u8>, AvError> {
        let mut stream = TcpStream::connect(&self.address)
            .await
            .map_err(|e| AvError::Unreachable(e.to_string()))?;
        stream
            .write_all(b"zINSTREAM\0")
            .await
            .map_err(|e| AvError::Protocol(e.to_string()))?;
        // Send the payload in <=64 KiB frames: 4-byte big-endian length + bytes.
        for chunk in data.chunks(65536) {
            let len = (chunk.len() as u32).to_be_bytes();
            stream.write_all(&len).await.map_err(|e| AvError::Protocol(e.to_string()))?;
            stream.write_all(chunk).await.map_err(|e| AvError::Protocol(e.to_string()))?;
        }
        // Zero-length frame terminates the stream.
        stream.write_all(&0u32.to_be_bytes()).await.map_err(|e| AvError::Protocol(e.to_string()))?;
        let mut resp = Vec::new();
        stream.read_to_end(&mut resp).await.map_err(|e| AvError::Protocol(e.to_string()))?;
        Ok(resp)
    }
}

/// Parse a `clamd` INSTREAM response into a verdict.
///
/// `stream: OK` → clean; `stream: <sig> FOUND` → infected; a size-limit or
/// other error line → `Err`.
pub fn parse_clamd_response(resp: &[u8]) -> Result<AvVerdict, AvError> {
    let text = String::from_utf8_lossy(resp);
    let line = text.trim().trim_end_matches('\0').trim();
    if line.ends_with("OK") {
        Ok(AvVerdict::Clean)
    } else if let Some(idx) = line.find("FOUND") {
        // Format: "stream: <signature> FOUND"
        let sig = line[..idx]
            .trim()
            .strip_prefix("stream:")
            .unwrap_or(&line[..idx])
            .trim()
            .to_string();
        Ok(AvVerdict::Infected(if sig.is_empty() { "unknown".into() } else { sig }))
    } else {
        Err(AvError::Protocol(format!("unexpected clamd response: {line:?}")))
    }
}

#[async_trait]
impl AvScanner for ClamdScanner {
    async fn scan(&self, data: &[u8]) -> Result<AvVerdict, AvError> {
        if data.len() > self.max_bytes {
            let e = AvError::TooLarge(data.len());
            return if self.fail_open {
                tracing::warn!(bytes = data.len(), "clamd: payload over scan limit, failing open");
                Ok(AvVerdict::Clean)
            } else {
                Err(e)
            };
        }
        let outcome = tokio::time::timeout(self.timeout, self.instream(data))
            .await
            .map_err(|_| AvError::Unreachable("clamd timed out".into()))
            .and_then(|r| r)
            .and_then(|resp| parse_clamd_response(&resp));
        match outcome {
            Ok(v) => Ok(v),
            Err(e) if self.fail_open => {
                tracing::warn!(error = %e, "clamd scan failed, failing open");
                Ok(AvVerdict::Clean)
            }
            Err(e) => Err(e),
        }
    }
    fn backend_name(&self) -> &'static str {
        "clamd"
    }
}

/// Configuration parsed from `[antivirus]` in vortex.toml by the host.
#[derive(Debug, Clone)]
pub enum AvConfig {
    /// No scanning — uploads are accepted as-is (default).
    Disabled,
    Clamd {
        address: String,
        timeout: Duration,
        max_bytes: usize,
        fail_open: bool,
    },
}

/// Build the configured scanner. Never fails — a bad address surfaces at scan
/// time (subject to `fail_open`), so a misconfigured scanner can't stop the
/// server from starting.
pub fn from_config(config: &AvConfig) -> Arc<dyn AvScanner> {
    match config {
        AvConfig::Disabled => Arc::new(NoopScanner),
        AvConfig::Clamd { address, timeout, max_bytes, fail_open } => {
            Arc::new(ClamdScanner::new(address.clone(), *timeout, *max_bytes, *fail_open))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_clean_infected_and_errors() {
        assert_eq!(parse_clamd_response(b"stream: OK\0").unwrap(), AvVerdict::Clean);
        assert_eq!(
            parse_clamd_response(b"stream: Eicar-Test-Signature FOUND\0").unwrap(),
            AvVerdict::Infected("Eicar-Test-Signature".into())
        );
        // Real clamd emits the full path label before FOUND; still extract the sig.
        assert!(matches!(
            parse_clamd_response(b"stream: Win.Test.EICAR_HDB-1 FOUND").unwrap(),
            AvVerdict::Infected(s) if s == "Win.Test.EICAR_HDB-1"
        ));
        assert!(parse_clamd_response(b"INSTREAM size limit exceeded\0").is_err());
    }

    #[tokio::test]
    async fn noop_scanner_accepts_everything() {
        let s = NoopScanner;
        assert_eq!(s.scan(b"anything").await.unwrap(), AvVerdict::Clean);
        assert!(!s.is_active());
    }

    #[tokio::test]
    async fn clamd_unreachable_fails_open_or_closed() {
        // Nothing is listening on this port in tests.
        let closed = ClamdScanner::new("127.0.0.1:1", Duration::from_millis(200), 1024, false);
        assert!(closed.scan(b"x").await.is_err(), "fail-closed surfaces the error");
        let open = ClamdScanner::new("127.0.0.1:1", Duration::from_millis(200), 1024, true);
        assert_eq!(open.scan(b"x").await.unwrap(), AvVerdict::Clean, "fail-open accepts");
    }

    #[tokio::test]
    async fn over_size_limit_respects_fail_policy() {
        let closed = ClamdScanner::new("127.0.0.1:1", Duration::from_millis(200), 4, false);
        assert!(matches!(closed.scan(b"toolong").await, Err(AvError::TooLarge(_))));
        let open = ClamdScanner::new("127.0.0.1:1", Duration::from_millis(200), 4, true);
        assert_eq!(open.scan(b"toolong").await.unwrap(), AvVerdict::Clean);
    }
}
