//! # FileStore — pluggable binary/attachment storage
//!
//! Core primitive for anything that persists user files (record
//! attachments, chatter uploads, future document verticals). Handlers
//! and plugins talk to `state.files` (an `Arc<dyn FileStore>`) and
//! store only the returned *key* in their tables — never a filesystem
//! path — so the same rows work under every backend.
//!
//! Two backends, selected by `[files]` in vortex.toml:
//!
//! - **`local`** (default) — files under `<path>/<tenant>/<key>` on the
//!   app server's disk. Zero infrastructure; the single-tier deploy
//!   shape. Point `path` at an NFS mount to share across app servers
//!   without switching backends.
//! - **`s3`** — any S3-compatible object store: AWS S3 for SaaS,
//!   MinIO / Ceph / enterprise arrays for on-prem and air-gapped.
//!   Objects are keyed `<tenant>/<key>`. Requests are signed with AWS
//!   Signature V4 implemented here on top of `reqwest` + `ring` — no
//!   AWS SDK dependency tree, auditable in one file. Credentials come
//!   from `VORTEX_S3_ACCESS_KEY` / `VORTEX_S3_SECRET_KEY`, never from
//!   config files.
//!
//! Tenant isolation is structural: every operation takes the tenant
//! (database) name and the backends namespace storage by it, so one
//! tenant's keys cannot address another tenant's blobs.

use std::path::PathBuf;

use async_trait::async_trait;
use vortex_common::{VortexError, VortexResult};

/// Hex SHA-256 of an empty body — SigV4's hash for payloadless requests.
const EMPTY_PAYLOAD_SHA256: &str =
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// Pluggable file storage. Implementations must be safe for concurrent
/// use from many request handlers.
#[async_trait]
pub trait FileStore: Send + Sync {
    /// Store `data` under `key` in `tenant`'s namespace, overwriting.
    async fn put(
        &self,
        tenant: &str,
        key: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> VortexResult<()>;

    /// Fetch a blob. `Ok(None)` when the key doesn't exist.
    async fn get(&self, tenant: &str, key: &str) -> VortexResult<Option<Vec<u8>>>;

    /// Delete a blob. Deleting a missing key is not an error.
    async fn delete(&self, tenant: &str, key: &str) -> VortexResult<()>;

    /// Short backend name for startup logs and health output.
    fn backend_name(&self) -> &'static str;
}

/// Configuration parsed from `[files]` in vortex.toml by the host.
#[derive(Debug, Clone)]
pub enum FilesConfig {
    Local { path: String },
    S3(S3Config),
}

#[derive(Debug, Clone)]
pub struct S3Config {
    /// Scheme + host(:port), e.g. `https://s3.ap-southeast-1.amazonaws.com`
    /// or `http://minio.internal:9000`.
    pub endpoint: String,
    pub region: String,
    pub bucket: String,
    /// `true` (MinIO/on-prem default): `endpoint/bucket/key`.
    /// `false`: virtual-hosted style, `bucket.host/key`.
    pub path_style: bool,
    pub access_key: String,
    pub secret_key: String,
}

/// Build the configured backend. Fails fast on bad config — a server
/// that silently stored files somewhere unexpected would be worse.
pub fn from_config(config: &FilesConfig) -> VortexResult<std::sync::Arc<dyn FileStore>> {
    match config {
        FilesConfig::Local { path } => Ok(std::sync::Arc::new(LocalDirStore::new(path)?)),
        FilesConfig::S3(s3) => Ok(std::sync::Arc::new(S3Store::new(s3.clone())?)),
    }
}

/// Tenant names follow database-name rules.
fn validate_tenant(tenant: &str) -> VortexResult<()> {
    if !tenant.is_empty() && tenant.chars().all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Ok(())
    } else {
        Err(VortexError::ValidationFailed(format!(
            "invalid tenant name for file storage: {tenant:?}"
        )))
    }
}

/// Keys are server-generated (`chatter/<uuid>.<ext>`), but validate
/// defensively: `/`-separated segments of `[A-Za-z0-9._-]`, no empty
/// or dot-only segments, so a key can never traverse out of its
/// tenant directory.
fn validate_key(key: &str) -> VortexResult<()> {
    let valid = !key.is_empty()
        && key.len() <= 512
        && key.split('/').all(|seg| {
            !seg.is_empty()
                && seg.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
                && seg.chars().any(|c| c != '.')
        });
    if valid {
        Ok(())
    } else {
        Err(VortexError::ValidationFailed(format!(
            "invalid file storage key: {key:?}"
        )))
    }
}

// ─── Local directory backend ────────────────────────────────────────

pub struct LocalDirStore {
    base: PathBuf,
}

impl LocalDirStore {
    pub fn new(path: &str) -> VortexResult<Self> {
        if path.trim().is_empty() {
            return Err(VortexError::ConfigurationError(
                "[files] local path must not be empty".into(),
            ));
        }
        Ok(Self { base: PathBuf::from(path) })
    }

    fn blob_path(&self, tenant: &str, key: &str) -> VortexResult<PathBuf> {
        validate_tenant(tenant)?;
        validate_key(key)?;
        Ok(self.base.join(tenant).join(key))
    }
}

#[async_trait]
impl FileStore for LocalDirStore {
    async fn put(
        &self,
        tenant: &str,
        key: &str,
        data: &[u8],
        _content_type: Option<&str>,
    ) -> VortexResult<()> {
        let path = self.blob_path(tenant, key)?;
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, data).await?;
        Ok(())
    }

    async fn get(&self, tenant: &str, key: &str) -> VortexResult<Option<Vec<u8>>> {
        let path = self.blob_path(tenant, key)?;
        match tokio::fs::read(&path).await {
            Ok(data) => Ok(Some(data)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn delete(&self, tenant: &str, key: &str) -> VortexResult<()> {
        let path = self.blob_path(tenant, key)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }

    fn backend_name(&self) -> &'static str {
        "local"
    }
}

// ─── S3-compatible backend (AWS Signature V4) ───────────────────────

pub struct S3Store {
    config: S3Config,
    /// Host header value derived from endpoint (+ bucket when
    /// virtual-hosted), computed once.
    host: String,
    /// URL prefix up to (not including) the object key.
    url_prefix: String,
    client: reqwest::Client,
}

impl S3Store {
    pub fn new(config: S3Config) -> VortexResult<Self> {
        let url = reqwest::Url::parse(&config.endpoint).map_err(|e| {
            VortexError::ConfigurationError(format!("[files.s3] bad endpoint: {e}"))
        })?;
        let scheme = url.scheme().to_string();
        let bare_host = url
            .host_str()
            .ok_or_else(|| {
                VortexError::ConfigurationError("[files.s3] endpoint has no host".into())
            })?
            .to_string();
        let port = url.port().map(|p| format!(":{p}")).unwrap_or_default();

        let (host, url_prefix) = if config.path_style {
            let host = format!("{bare_host}{port}");
            let prefix = format!("{scheme}://{host}/{}", config.bucket);
            (host, prefix)
        } else {
            let host = format!("{}.{bare_host}{port}", config.bucket);
            let prefix = format!("{scheme}://{host}");
            (host, prefix)
        };

        if config.bucket.is_empty() || config.region.is_empty() {
            return Err(VortexError::ConfigurationError(
                "[files.s3] bucket and region are required".into(),
            ));
        }
        if config.access_key.is_empty() || config.secret_key.is_empty() {
            return Err(VortexError::ConfigurationError(
                "[files.s3] credentials missing — set VORTEX_S3_ACCESS_KEY and VORTEX_S3_SECRET_KEY".into(),
            ));
        }

        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .map_err(|e| VortexError::Internal(format!("http client: {e}")))?;

        Ok(Self { config, host, url_prefix, client })
    }

    /// Canonical URI path for the object (always path the request URL
    /// actually uses: `/bucket/key` in path style, `/key` otherwise).
    fn object_uri(&self, object_key: &str) -> String {
        let encoded = uri_encode(object_key, false);
        if self.config.path_style {
            format!("/{}/{}", self.config.bucket, encoded)
        } else {
            format!("/{encoded}")
        }
    }

    fn object_url(&self, object_key: &str) -> String {
        format!("{}/{}", self.url_prefix, uri_encode(object_key, false))
    }

    async fn request(
        &self,
        method: reqwest::Method,
        object_key: &str,
        body: Option<(&[u8], Option<&str>)>,
    ) -> VortexResult<reqwest::Response> {
        let now = chrono::Utc::now();
        let amz_date = now.format("%Y%m%dT%H%M%SZ").to_string();
        let payload_hash = match body {
            Some((data, _)) => sha256_hex(data),
            None => EMPTY_PAYLOAD_SHA256.to_string(),
        };

        let signed = sign_v4(&SigningInput {
            method: method.as_str(),
            canonical_uri: &self.object_uri(object_key),
            canonical_query: "",
            headers: &[
                ("host", &self.host),
                ("x-amz-content-sha256", &payload_hash),
                ("x-amz-date", &amz_date),
            ],
            payload_hash: &payload_hash,
            amz_date: &amz_date,
            region: &self.config.region,
            service: "s3",
            access_key: &self.config.access_key,
            secret_key: &self.config.secret_key,
        });

        let mut req = self
            .client
            .request(method, self.object_url(object_key))
            .header("x-amz-date", &amz_date)
            .header("x-amz-content-sha256", &payload_hash)
            .header(reqwest::header::AUTHORIZATION, signed);
        if let Some((data, content_type)) = body {
            if let Some(ct) = content_type {
                req = req.header(reqwest::header::CONTENT_TYPE, ct);
            }
            req = req.body(data.to_vec());
        }
        req.send()
            .await
            .map_err(|e| VortexError::Internal(format!("s3 request failed: {e}")))
    }
}

#[async_trait]
impl FileStore for S3Store {
    async fn put(
        &self,
        tenant: &str,
        key: &str,
        data: &[u8],
        content_type: Option<&str>,
    ) -> VortexResult<()> {
        validate_tenant(tenant)?;
        validate_key(key)?;
        let object = format!("{tenant}/{key}");
        let resp = self
            .request(reqwest::Method::PUT, &object, Some((data, content_type)))
            .await?;
        if resp.status().is_success() {
            Ok(())
        } else {
            Err(VortexError::Internal(format!(
                "s3 put '{object}' failed: {}",
                resp.status()
            )))
        }
    }

    async fn get(&self, tenant: &str, key: &str) -> VortexResult<Option<Vec<u8>>> {
        validate_tenant(tenant)?;
        validate_key(key)?;
        let object = format!("{tenant}/{key}");
        let resp = self.request(reqwest::Method::GET, &object, None).await?;
        if resp.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !resp.status().is_success() {
            return Err(VortexError::Internal(format!(
                "s3 get '{object}' failed: {}",
                resp.status()
            )));
        }
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| VortexError::Internal(format!("s3 get body: {e}")))?;
        Ok(Some(bytes.to_vec()))
    }

    async fn delete(&self, tenant: &str, key: &str) -> VortexResult<()> {
        validate_tenant(tenant)?;
        validate_key(key)?;
        let object = format!("{tenant}/{key}");
        let resp = self.request(reqwest::Method::DELETE, &object, None).await?;
        // S3 DELETE returns 204 even for missing keys; treat 404 the same.
        if resp.status().is_success() || resp.status() == reqwest::StatusCode::NOT_FOUND {
            Ok(())
        } else {
            Err(VortexError::Internal(format!(
                "s3 delete '{object}' failed: {}",
                resp.status()
            )))
        }
    }

    fn backend_name(&self) -> &'static str {
        "s3"
    }
}

// ─── AWS Signature V4 ────────────────────────────────────────────────
//
// Implemented directly (RFC-style, one screen of code) instead of
// pulling the AWS SDK: the only S3 operations Vortex needs are object
// GET/PUT/DELETE, and a dependency tree we can read end-to-end is
// worth more to regulated deployments than SDK coverage we don't use.
// Verified against the worked example in the AWS SigV4 documentation
// (see tests).

struct SigningInput<'a> {
    method: &'a str,
    canonical_uri: &'a str,
    canonical_query: &'a str,
    /// (lowercase-name, value) pairs, pre-sorted by name.
    headers: &'a [(&'a str, &'a str)],
    payload_hash: &'a str,
    amz_date: &'a str,
    region: &'a str,
    service: &'a str,
    access_key: &'a str,
    secret_key: &'a str,
}

/// Produce the `Authorization` header value for a SigV4 request.
fn sign_v4(input: &SigningInput<'_>) -> String {
    use vortex_security::crypto::hmac_sha256;

    let canonical_headers: String = input
        .headers
        .iter()
        .map(|(name, value)| format!("{name}:{}\n", value.trim()))
        .collect();
    let signed_headers: Vec<&str> = input.headers.iter().map(|(name, _)| *name).collect();
    let signed_headers = signed_headers.join(";");

    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        input.method,
        input.canonical_uri,
        input.canonical_query,
        canonical_headers,
        signed_headers,
        input.payload_hash,
    );

    let date = &input.amz_date[..8];
    let scope = format!("{date}/{}/{}/aws4_request", input.region, input.service);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{}\n{}\n{}",
        input.amz_date,
        scope,
        sha256_hex(canonical_request.as_bytes()),
    );

    let k_date = hmac_sha256(format!("AWS4{}", input.secret_key).as_bytes(), date.as_bytes());
    let k_region = hmac_sha256(&k_date, input.region.as_bytes());
    let k_service = hmac_sha256(&k_region, input.service.as_bytes());
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let signature = hex::encode(hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed_headers}, Signature={signature}",
        input.access_key,
    )
}

fn sha256_hex(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

/// AWS-style URI encoding: unreserved characters (`A-Za-z0-9-._~`)
/// pass through; everything else becomes uppercase `%XX`. `/` is kept
/// when encoding an object path.
fn uri_encode(s: &str, encode_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            b'/' if !encode_slash => out.push('/'),
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // The worked GET-object example from the AWS Signature V4 docs:
    // known credentials, fixed date, expected signature. If this
    // passes, the canonical request, string-to-sign, key derivation
    // and final MAC all match AWS's reference.
    #[test]
    fn sigv4_matches_aws_reference_vector() {
        let signed = sign_v4(&SigningInput {
            method: "GET",
            canonical_uri: "/test.txt",
            canonical_query: "",
            headers: &[
                ("host", "examplebucket.s3.amazonaws.com"),
                ("range", "bytes=0-9"),
                ("x-amz-content-sha256", EMPTY_PAYLOAD_SHA256),
                ("x-amz-date", "20130524T000000Z"),
            ],
            payload_hash: EMPTY_PAYLOAD_SHA256,
            amz_date: "20130524T000000Z",
            region: "us-east-1",
            service: "s3",
            access_key: "AKIAIOSFODNN7EXAMPLE",
            secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        });
        assert_eq!(
            signed,
            "AWS4-HMAC-SHA256 \
             Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, \
             SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, \
             Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"
        );
    }

    #[test]
    fn keys_cannot_traverse() {
        assert!(validate_key("chatter/abc-123.pdf").is_ok());
        assert!(validate_key("9b2e1c4a.bin").is_ok());
        assert!(validate_key("../secrets").is_err());
        assert!(validate_key("a/../../etc/passwd").is_err());
        assert!(validate_key("/absolute").is_err());
        assert!(validate_key("trailing/").is_err());
        assert!(validate_key("").is_err());
        assert!(validate_key("nul\0byte").is_err());
    }

    #[test]
    fn tenants_follow_db_name_rules() {
        assert!(validate_tenant("gaia").is_ok());
        assert!(validate_tenant("vortex_acme").is_ok());
        assert!(validate_tenant("").is_err());
        assert!(validate_tenant("a/b").is_err());
        assert!(validate_tenant("a;drop").is_err());
    }

    #[test]
    fn uri_encoding_is_aws_style() {
        assert_eq!(uri_encode("chatter/a b+c.pdf", false), "chatter/a%20b%2Bc.pdf");
        assert_eq!(uri_encode("a/b", true), "a%2Fb");
        assert_eq!(uri_encode("safe-._~", true), "safe-._~");
    }

    #[test]
    fn path_style_and_virtual_hosted_urls() {
        let base = S3Config {
            endpoint: "http://minio.internal:9000".into(),
            region: "us-east-1".into(),
            bucket: "vortex".into(),
            path_style: true,
            access_key: "k".into(),
            secret_key: "s".into(),
        };
        let s3 = S3Store::new(base.clone()).unwrap();
        assert_eq!(s3.host, "minio.internal:9000");
        assert_eq!(s3.object_url("gaia/a.pdf"), "http://minio.internal:9000/vortex/gaia/a.pdf");
        assert_eq!(s3.object_uri("gaia/a.pdf"), "/vortex/gaia/a.pdf");

        let aws = S3Store::new(S3Config {
            endpoint: "https://s3.ap-southeast-1.amazonaws.com".into(),
            path_style: false,
            ..base
        })
        .unwrap();
        assert_eq!(aws.host, "vortex.s3.ap-southeast-1.amazonaws.com");
        assert_eq!(aws.object_url("gaia/a.pdf"), "https://vortex.s3.ap-southeast-1.amazonaws.com/gaia/a.pdf");
        assert_eq!(aws.object_uri("gaia/a.pdf"), "/gaia/a.pdf");
    }
}
