//! PKCS#11 signing backend — the production path for regulated
//! deployments (banks, healthcare, critical infrastructure).
//!
//! Delegates every `sign()` call to a hardware security module
//! via the OASIS PKCS#11 v3.0 standard API. The private key
//! material **never enters the Vortex process heap** — sign
//! operations happen inside the HSM and only the signature bytes
//! come back across the boundary.
//!
//! ## Supported devices
//!
//! This backend works with any PKCS#11 v2.40+ device, which in
//! practice means every serious HSM on the market:
//!
//! - **SoftHSM2** — open-source software-only PKCS#11, for dev and
//!   CI. Not FIPS-validated; not acceptable as a production root
//!   of trust. Use it to exercise the code path without owning
//!   hardware, then swap the `library_path` at deployment.
//! - **YubiHSM 2** / **YubiHSM 2 FIPS** — USB HSM, cheap, good
//!   for smaller deployments or staging.
//! - **Thales Luna Network HSM** — industry standard for banks,
//!   FIPS 140-2 Level 3, rack-mounted, fully offline.
//! - **Entrust nShield Connect** — Luna's main competitor, same
//!   FIPS level, also bank-standard.
//! - **Utimaco CryptoServer / SecurityServer** — popular with EU
//!   regulators, especially in DACH banking.
//!
//! Because all of them speak the same standard API, Vortex binary
//! is vendor-neutral: point it at the HSM's PKCS#11 `.so` path via
//! `vortex.toml` and everything else is identical.
//!
//! ## Operational preconditions
//!
//! This backend does NOT generate keys. The key ceremony is an
//! out-of-band procedure run by bank operators with dual control
//! (typically two custodians holding separate PIN halves, per the
//! HSM vendor's procedure). Vortex **opens an existing key by
//! label** — if the label does not exist, startup fails with a
//! clear error. Never run an auto-bootstrap path for money-center
//! signing keys; auditors will flag it.
//!
//! The expected operational flow:
//!
//! 1. Bank ops runs a key ceremony on the HSM, creating an
//!    Ed25519 keypair with label `vortex-audit` (or whatever
//!    `key_label` is configured).
//! 2. The public half of the keypair is extracted and stored by
//!    the HSM alongside the private half.
//! 3. `vortex.toml` is configured with the library path, slot /
//!    token label, key label, and the environment variable name
//!    that holds the User PIN.
//! 4. Vortex starts, opens the key by label, reads the public
//!    half to register in `audit_signing_keys`, and is ready.
//! 5. Every audit write calls `session.sign()`; no private key
//!    material ever leaves the HSM.
//!
//! ## Concurrency model
//!
//! PKCS#11 sessions are not thread-safe by design — the standard
//! requires serialized access to a session handle, and `cryptoki`
//! reflects that by marking [`cryptoki::session::Session`] as
//! `Send` but not `Sync`. This impl wraps the session in a
//! [`std::sync::Mutex`] so [`SigningKey::sign`] can take `&self`
//! and still be thread-safe.
//!
//! Every audit write acquires the mutex, signs synchronously
//! (blocking the current tokio worker for the duration of the
//! HSM round-trip), and releases. In practice a modern HSM signs
//! Ed25519 in under 10ms, and Vortex audit write rates are low
//! enough (a few per second at steady state) that this is fine.
//! If audit write throughput becomes a problem, wrap the sign
//! call in `tokio::task::spawn_blocking`; the trait signature is
//! compatible.
//!
//! ## Public key extraction
//!
//! On open, this backend looks up the public key object matching
//! `key_label + CKO_PUBLIC_KEY` and reads the `CKA_EC_POINT`
//! attribute. For Ed25519 specifically, PKCS#11 v3.0 specifies
//! `CKA_EC_POINT` as a DER-encoded `OCTET STRING` containing the
//! raw 32-byte public key — tag `04`, length `20`, then the
//! bytes. Some vendor implementations omit the DER wrap and
//! return the raw 32 bytes directly; we handle both.

use std::sync::{Arc, Mutex};

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::eddsa::{EddsaParams, EddsaSignatureScheme};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, AttributeType, ObjectClass, ObjectHandle};
use cryptoki::session::{Session, UserType};
use cryptoki::slot::Slot;
use cryptoki::types::AuthPin;

use super::config::Pkcs11Config;
use super::{SigningError, SigningKey, ALG_ED25519};

/// PKCS#11-backed Ed25519 signing key.
pub struct Pkcs11SigningKey {
    /// The library context. Kept in the struct so the `Session`
    /// it owns stays alive for the process lifetime.
    _context: Arc<Pkcs11>,
    /// The logged-in session, wrapped in a mutex because PKCS#11
    /// sessions are not `Sync`.
    session: Mutex<Session>,
    /// Object handle of the private key inside the HSM. Stable
    /// for the lifetime of the session.
    private_key: ObjectHandle,
    /// Cached public key bytes (32 for Ed25519). Read once at
    /// open so `public_key()` is cheap.
    public_key_bytes: Vec<u8>,
    /// Stable key identifier exposed via [`SigningKey::key_id`].
    /// Matches the `key_label` from config so the identifier
    /// in `audit_signing_keys` is meaningful.
    key_id: String,
}

impl Pkcs11SigningKey {
    /// Open the PKCS#11 library, select the token, log in with
    /// the PIN from `config.pin_env`, find the keypair by label,
    /// and cache the public key bytes. Fails fast with a clear
    /// error on any step — startup should not proceed with a
    /// misconfigured HSM.
    pub fn open(config: &Pkcs11Config) -> Result<Self, SigningError> {
        // 1. Load the PKCS#11 library. This dlopens the .so and
        //    resolves the C_GetFunctionList entry point. A bad
        //    path or a corrupt library surfaces here.
        let pkcs11 = Pkcs11::new(&config.library_path).map_err(|e| {
            SigningError::Pkcs11(format!(
                "failed to load PKCS#11 library at '{}': {e}",
                config.library_path
            ))
        })?;
        pkcs11
            .initialize(CInitializeArgs::OsThreads)
            .map_err(|e| SigningError::Pkcs11(format!("C_Initialize failed: {e}")))?;

        // 2. Find the slot. Prefer lookup by token label (stable
        //    across reboots and reslots), fall back to numeric
        //    slot index only if no label is configured.
        let slot = Self::find_slot(&pkcs11, config)?;

        // 3. Read the PIN from the named env var. Missing PIN is
        //    a configuration error the operator must fix before
        //    the server can start.
        let pin_string = std::env::var(&config.pin_env).map_err(|_| {
            SigningError::Config(format!(
                "PKCS#11 PIN environment variable '{}' is not set",
                config.pin_env
            ))
        })?;
        let pin = AuthPin::new(pin_string);

        // 4. Open a read-write session and log in as User. RW is
        //    needed so Vortex could (in a future admin path) create
        //    key rotation records; for steady-state signing, RO
        //    would be enough. The overhead is negligible.
        let session = pkcs11
            .open_rw_session(slot)
            .map_err(|e| SigningError::Pkcs11(format!("open_rw_session failed: {e}")))?;
        session
            .login(UserType::User, Some(&pin))
            .map_err(|e| SigningError::Pkcs11(format!("login failed: {e}")))?;

        // 5. Find the private key object by label. PKCS#11 object
        //    lookups match on the attribute template; we narrow
        //    by CKO_PRIVATE_KEY + label so the query returns
        //    exactly the one key we care about.
        let private_key = Self::find_key_by_label(
            &session,
            ObjectClass::PRIVATE_KEY,
            &config.key_label,
        )?;

        // 6. Find the matching public key object and extract the
        //    raw public key bytes. Ed25519 stores the key as
        //    CKA_EC_POINT — a DER OCTET STRING containing the 32
        //    raw bytes on spec-compliant devices, or the raw 32
        //    bytes directly on some vendor implementations.
        let public_handle = Self::find_key_by_label(
            &session,
            ObjectClass::PUBLIC_KEY,
            &config.key_label,
        )?;
        let public_key_bytes = Self::read_ed25519_public_key(&session, public_handle)?;

        Ok(Self {
            _context: Arc::new(pkcs11),
            session: Mutex::new(session),
            private_key,
            public_key_bytes,
            key_id: config.key_label.clone(),
        })
    }

    /// Find a slot matching the config. If `token_label` is set,
    /// walk every slot with a token and match on
    /// `TokenInfo::label()`. Otherwise, use the numeric `slot`
    /// index as a fallback.
    fn find_slot(pkcs11: &Pkcs11, config: &Pkcs11Config) -> Result<Slot, SigningError> {
        if let Some(label) = config.token_label.as_deref() {
            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| SigningError::Pkcs11(format!("get_slots_with_token: {e}")))?;
            for slot in slots {
                let info = pkcs11.get_token_info(slot).map_err(|e| {
                    SigningError::Pkcs11(format!("get_token_info: {e}"))
                })?;
                if info.label().trim() == label {
                    return Ok(slot);
                }
            }
            return Err(SigningError::Config(format!(
                "no PKCS#11 token with label '{label}' was found"
            )));
        }

        if let Some(slot_num) = config.slot {
            let slots = pkcs11
                .get_slots_with_token()
                .map_err(|e| SigningError::Pkcs11(format!("get_slots_with_token: {e}")))?;
            let target = slot_num;
            for slot in slots {
                if u64::from(slot.id()) == target {
                    return Ok(slot);
                }
            }
            return Err(SigningError::Config(format!(
                "no PKCS#11 token found at slot index {slot_num}"
            )));
        }

        Err(SigningError::Config(
            "PKCS#11 config specifies neither token_label nor slot".to_string(),
        ))
    }

    /// Find a single key object by `(class, label)`. Errors if
    /// zero or more than one object matches — both conditions
    /// indicate a misconfigured token and should be surfaced to
    /// the operator.
    fn find_key_by_label(
        session: &Session,
        class: ObjectClass,
        label: &str,
    ) -> Result<ObjectHandle, SigningError> {
        let template = [
            Attribute::Class(class),
            Attribute::Label(label.as_bytes().to_vec()),
        ];
        let handles = session
            .find_objects(&template)
            .map_err(|e| SigningError::Pkcs11(format!("find_objects({label}): {e}")))?;
        match handles.len() {
            0 => Err(SigningError::Config(format!(
                "no PKCS#11 object found with label '{label}' and class {:?}",
                class
            ))),
            1 => Ok(handles[0]),
            n => Err(SigningError::Config(format!(
                "expected exactly 1 PKCS#11 object for '{label}' / {:?}, found {n}",
                class
            ))),
        }
    }

    /// Read the public key bytes for an Ed25519 public key object.
    /// Handles both the spec-compliant DER `OCTET STRING` wrapping
    /// and the raw-32-bytes form some vendor firmwares emit.
    fn read_ed25519_public_key(
        session: &Session,
        handle: ObjectHandle,
    ) -> Result<Vec<u8>, SigningError> {
        let attrs = session
            .get_attributes(handle, &[AttributeType::EcPoint])
            .map_err(|e| {
                SigningError::Pkcs11(format!("get_attributes(CKA_EC_POINT): {e}"))
            })?;
        let raw = attrs
            .into_iter()
            .find_map(|a| match a {
                Attribute::EcPoint(bytes) => Some(bytes),
                _ => None,
            })
            .ok_or_else(|| {
                SigningError::Pkcs11(
                    "public key object has no CKA_EC_POINT attribute".to_string(),
                )
            })?;

        // Unwrap the DER OCTET STRING envelope if present. For a
        // 32-byte key the full DER is 34 bytes: [0x04, 0x20, ...32 bytes].
        // Some vendors emit the raw 32 bytes directly.
        match raw.as_slice() {
            [0x04, 0x20, rest @ ..] if rest.len() == 32 => Ok(rest.to_vec()),
            bytes if bytes.len() == 32 => Ok(bytes.to_vec()),
            other => Err(SigningError::Pkcs11(format!(
                "unexpected Ed25519 public key length {} (expected 32 raw or 34 DER-wrapped)",
                other.len()
            ))),
        }
    }
}

impl SigningKey for Pkcs11SigningKey {
    fn key_id(&self) -> &str {
        &self.key_id
    }

    fn algorithm(&self) -> &'static str {
        ALG_ED25519
    }

    fn sign(&self, bytes: &[u8]) -> Vec<u8> {
        // Serialize access to the session — PKCS#11 is not thread-safe
        // per-session. Holding the mutex across the HSM round trip is
        // fine: Vortex audit write throughput is low, HSM latency is
        // typically <10ms, and the alternative (opening a session per
        // sign) would be slower AND burn the HSM's session pool.
        let session = self
            .session
            .lock()
            .expect("PKCS#11 session mutex poisoned");
        let mechanism = Mechanism::Eddsa(EddsaParams::new(EddsaSignatureScheme::Pure));
        match session.sign(&mechanism, self.private_key, bytes) {
            Ok(sig) => sig,
            Err(e) => {
                // `SigningKey::sign` is infallible by contract (matches
                // the Ed25519 backend). An HSM error here is a serious
                // incident — the audit write about to happen will fail
                // chain verification because the signature is empty.
                // We log loudly and return an empty vec, which the
                // verifier will detect as a verification failure.
                tracing::error!(
                    error = %e,
                    key_id = %self.key_id,
                    "PKCS#11 sign operation failed — audit entry will be unsigned"
                );
                Vec::new()
            }
        }
    }

    fn public_key(&self) -> Vec<u8> {
        self.public_key_bytes.clone()
    }
}
