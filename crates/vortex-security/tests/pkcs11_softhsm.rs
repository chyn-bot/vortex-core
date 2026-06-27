//! Integration test: `Pkcs11SigningKey` end-to-end against SoftHSM2.
//!
//! Proves the full Vortex ↔ PKCS#11 ↔ HSM path works without
//! needing real hardware:
//!
//! 1. Create a tempdir and write a SoftHSM2 config pointing at it
//! 2. Initialize a token programmatically via `cryptoki` (no
//!    `softhsm2-util` subprocess required — keeps the test
//!    self-contained)
//! 3. Generate a fresh Ed25519 keypair in the token
//! 4. Open `Pkcs11SigningKey` against the token, sign a message
//! 5. Verify the signature with `verify_ed25519`
//!
//! Guarded on SoftHSM2 being installed. If the library is not
//! found at a standard path and `VORTEX_SOFTHSM_LIB` is not set,
//! the test prints a skip message and passes — same pattern as
//! the audit_worm tests that skip when `DATABASE_URL` is unset.
//!
//! ## Running this test
//!
//! On Ubuntu / Debian:
//!
//! ```sh
//! apt install softhsm2
//! cargo test -p vortex-security --test pkcs11_softhsm
//! ```
//!
//! On RHEL / Fedora:
//!
//! ```sh
//! dnf install softhsm
//! VORTEX_SOFTHSM_LIB=/usr/lib64/pkcs11/libsofthsm2.so \
//!   cargo test -p vortex-security --test pkcs11_softhsm
//! ```
//!
//! ## Important: single-process constraint
//!
//! SoftHSM2 reads its configuration from the `SOFTHSM2_CONF` env
//! var **once per process**. This test cannot be parallelized
//! with other tests that also touch SoftHSM2 in the same test
//! binary. Because it lives in its own integration-test file
//! (`tests/pkcs11_softhsm.rs`), cargo runs it in a dedicated
//! process — no collision possible.

use std::path::PathBuf;

use cryptoki::context::{CInitializeArgs, Pkcs11};
use cryptoki::mechanism::Mechanism;
use cryptoki::object::{Attribute, ObjectClass};
use cryptoki::session::UserType;
use cryptoki::types::AuthPin;

use vortex_security::signing::{
    verify_ed25519, Pkcs11Config, Pkcs11SigningKey, SigningKey,
};

/// Standard SoftHSM2 library locations across major distros, plus
/// an override from the `VORTEX_SOFTHSM_LIB` environment variable
/// for custom installs.
fn locate_softhsm2_library() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("VORTEX_SOFTHSM_LIB") {
        let path = PathBuf::from(p);
        if path.exists() {
            return Some(path);
        }
    }
    for candidate in &[
        "/usr/lib/softhsm/libsofthsm2.so",
        "/usr/lib64/pkcs11/libsofthsm2.so",
        "/usr/lib/x86_64-linux-gnu/softhsm/libsofthsm2.so",
        "/usr/local/lib/softhsm/libsofthsm2.so",
        "/opt/homebrew/lib/softhsm/libsofthsm2.so", // macOS via brew
    ] {
        let p = PathBuf::from(candidate);
        if p.exists() {
            return Some(p);
        }
    }
    None
}

/// OID-encoded curve identifier for Ed25519 (RFC 8410):
///   OBJECT IDENTIFIER 1.3.101.112
/// DER encoding: 06 03 2B 65 70
const ED25519_OID_DER: &[u8] = &[0x06, 0x03, 0x2B, 0x65, 0x70];

/// Test-only constants — PINs have no security implications here,
/// the SoftHSM2 instance lives in a tempdir that's wiped at exit.
const SO_PIN: &str = "12345678";
const USER_PIN: &str = "fedcba";
const TOKEN_LABEL: &str = "vortex-test";
const KEY_LABEL: &str = "vortex-audit-test";
const PIN_ENV_VAR: &str = "VORTEX_TEST_HSM_PIN";

/// Set up a throwaway SoftHSM2 token directory, initialize a
/// token in it, and generate an Ed25519 keypair with the expected
/// label. Returns the path to the library for reuse by the test.
fn setup_softhsm_with_key(library_path: &std::path::Path) -> tempfile::TempDir {
    // Tempdir holds the SoftHSM2 tokens directory and its config.
    let tmp = tempfile::Builder::new()
        .prefix("vortex-softhsm-")
        .tempdir()
        .expect("create tempdir");

    let tokendir = tmp.path().join("tokens");
    std::fs::create_dir_all(&tokendir).expect("create tokens dir");
    let conf_path = tmp.path().join("softhsm2.conf");
    let conf = format!(
        "directories.tokendir = {}\nobjectstore.backend = file\nlog.level = ERROR\n",
        tokendir.display()
    );
    std::fs::write(&conf_path, conf).expect("write softhsm2.conf");

    // SOFTHSM2_CONF is read by libsofthsm2 on first init; setting
    // it here means the Pkcs11::new call below (and the one inside
    // Pkcs11SigningKey::open later) both see the same config.
    //
    // Safety: this test's own process is the only place that reads
    // SOFTHSM2_CONF within this binary. No parallel test sets it.
    unsafe {
        std::env::set_var("SOFTHSM2_CONF", &conf_path);
    }

    // Load the library and initialize a token.
    let pkcs11 = Pkcs11::new(library_path).expect("load SoftHSM2 library");
    pkcs11
        .initialize(CInitializeArgs::OsThreads)
        .expect("C_Initialize");

    // A freshly-configured tokendir presents an uninitialized
    // slot at index 0. init_token configures it with the given
    // SO PIN and label.
    let slots = pkcs11.get_all_slots().expect("get_all_slots");
    assert!(!slots.is_empty(), "SoftHSM2 presents no slots");
    let slot = slots[0];

    pkcs11
        .init_token(slot, &AuthPin::new(SO_PIN.to_string()), TOKEN_LABEL)
        .expect("init_token");

    // Login as SO to set the User PIN, then log out and in as User
    // to generate the keypair.
    let session = pkcs11.open_rw_session(slot).expect("open_rw_session");
    session
        .login(UserType::So, Some(&AuthPin::new(SO_PIN.to_string())))
        .expect("SO login");
    session
        .init_pin(&AuthPin::new(USER_PIN.to_string()))
        .expect("init_pin");
    session.logout().expect("SO logout");
    session
        .login(UserType::User, Some(&AuthPin::new(USER_PIN.to_string())))
        .expect("User login");

    // Generate the Ed25519 keypair. PKCS#11 Ed25519 key generation
    // uses the same CKM_EC_EDWARDS_KEY_PAIR_GEN mechanism with an
    // EcParams attribute containing the DER-encoded OID of curve25519.
    let mech = Mechanism::EccEdwardsKeyPairGen;
    let pub_template = [
        Attribute::Class(ObjectClass::PUBLIC_KEY),
        Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
        Attribute::Token(true),
        Attribute::Private(false),
        Attribute::Verify(true),
        Attribute::EcParams(ED25519_OID_DER.to_vec()),
    ];
    let priv_template = [
        Attribute::Class(ObjectClass::PRIVATE_KEY),
        Attribute::Label(KEY_LABEL.as_bytes().to_vec()),
        Attribute::Token(true),
        Attribute::Private(true),
        Attribute::Sensitive(true),
        Attribute::Sign(true),
    ];
    session
        .generate_key_pair(&mech, &pub_template, &priv_template)
        .expect("generate_key_pair");
    session.logout().expect("User logout");
    drop(session);
    drop(pkcs11);

    tmp
}

#[test]
fn pkcs11_sign_verify_roundtrip_against_softhsm2() {
    let Some(lib) = locate_softhsm2_library() else {
        eprintln!(
            "SKIP: SoftHSM2 library not found. \
             Install softhsm2 (apt/dnf) or set VORTEX_SOFTHSM_LIB \
             to the libsofthsm2.so path to run this test."
        );
        return;
    };
    eprintln!("Using SoftHSM2 library: {}", lib.display());

    // Setup: creates tempdir, initializes token, generates key.
    // Keep the tempdir alive for the duration of the test so
    // SoftHSM2 can still find the tokens.
    let _tmp = setup_softhsm_with_key(&lib);

    // Provide the PIN via the env var the Pkcs11Config will read.
    //
    // Safety: only this integration test touches VORTEX_TEST_HSM_PIN
    // and it runs in its own process per cargo's one-binary-per-
    // integration-test model.
    unsafe {
        std::env::set_var(PIN_ENV_VAR, USER_PIN);
    }

    let config = Pkcs11Config {
        library_path: lib.to_string_lossy().into_owned(),
        token_label: Some(TOKEN_LABEL.to_string()),
        slot: None,
        key_label: KEY_LABEL.to_string(),
        pin_env: PIN_ENV_VAR.to_string(),
    };

    // Open the signing key through the exact same code path the
    // Vortex server uses at startup.
    let signer = Pkcs11SigningKey::open(&config).expect("open Pkcs11SigningKey");

    assert_eq!(signer.key_id(), KEY_LABEL);
    assert_eq!(signer.algorithm(), "ed25519");
    assert_eq!(
        signer.public_key().len(),
        32,
        "Ed25519 public key must be 32 bytes"
    );

    // Sign a message through the HSM.
    let message = b"vortex audit chain entry: pkcs11 softhsm2 roundtrip";
    let signature = signer.sign(message);
    assert_eq!(signature.len(), 64, "Ed25519 signature must be 64 bytes");

    // Verify via the same helper `vortex audit verify` uses.
    verify_ed25519(&signer.public_key(), message, &signature)
        .expect("signature should verify against the HSM-extracted public key");

    // Tampered message should fail verification.
    let tampered = b"vortex audit chain entry: pkcs11 softhsm2 roundtripX";
    assert!(
        verify_ed25519(&signer.public_key(), tampered, &signature).is_err(),
        "tampered message must not verify"
    );
}
