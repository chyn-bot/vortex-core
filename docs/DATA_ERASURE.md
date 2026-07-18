# Secure Data Erasure

How Vortex erases data on request or at end-of-life, and the proof it leaves
behind. Covers subject erasure (GDPR/PDPA right-to-erasure) and full-tenant
decommission (POC teardown, contract exit). Satisfies CSRA control 18b.

The tooling is `vortex erase` (see `crates/vortex-cli/src/commands/erase.rs`).
Every erasure is recorded through the WORM audit ledger **and** emits a signed
erasure certificate to `$VORTEX_ERASURE_DIR` (default `./erasure-certificates`)
as tamper-evident proof of what was erased, when, and by whom.

## The immutability tension (read first)

Vortex's audit ledger is **WORM** — append-only, hash-chained, and the
`audit_log` table holds a foreign key to `users.id`. That is deliberate: it is
what makes the audit trail trustworthy. It also means a data subject's row
**cannot be hard-deleted** without breaking the chain and destroying the
evidentiary value of the whole ledger.

The resolution is the industry-standard one: **crypto-shred the PII in the
operational tables, retain the audit trail under a separate legal basis.**
Operational PII (name, email, credentials in `users`) is irreversibly
overwritten. The immutable ledger is *not* rewritten: audit entries recorded
**before** the erasure still contain whatever identifiers they captured at the
time (e.g. the then-current username in a login event), and the `users` row is
retained so its `audit_log` foreign keys stay valid. That retained data lives
under the *audit / security-necessity* basis (GDPR Art. 17(3)(b)/(e),
Art. 6(1)(c)), which exempts it from the erasure right. To keep that retained
footprint minimal, Vortex records identifiers (username, `users.id`), not
broader PII, in audit payloads. The erasure certificate is scoped precisely:
it attests that no original PII remains in the **operational tables**, not that
the immutable ledger was altered.

## Subject erasure

```
DATABASE_URL=postgres://…/<tenant> vortex erase subject <username> --yes --by <operator>
```

Without `--yes` it is a **dry run** that prints the tombstones it would write.
With `--yes` it, in one transaction-per-step:

1. Overwrites every PII field on the `users` row — `username` →
   `erased_<id>`, `email` → `erased+<id>@erased.invalid`, `full_name` →
   `[erased]`, `password_hash` → `!` (unloginnable), `mfa_secret` → NULL — and
   disables + locks the account (`locked_reason = 'DATA_ERASED'`). The row is
   **kept** (WORM FK); the tombstones satisfy the `(company_id, username)` /
   `(company_id, email)` uniqueness constraints.
2. Records a `record_deleted` / `secure_subject_erasure` entry in the WORM
   ledger, including a **SHA-256 fingerprint of the original PII** — enough to
   later prove *which* record was erased without retaining the cleartext.
3. Re-reads the row and **verifies** no original PII remains (fails loudly if
   any does).
4. Writes a sealed erasure certificate.

**Scope:** this erases PII in the core `users` table. PII that a vertical
plugin stores in its own tables (contacts, custom records) is outside core's
knowledge — a plugin that holds subject PII should expose its own erasure
handler and be run alongside this command. Track those per deployment.

## Tenant decommission

```
DATABASE_URL=postgres://…/<primary> vortex erase database <tenant> --yes --by <operator>
```

Point `DATABASE_URL` at the **primary/master**; name the tenant to erase as the
argument (the command refuses to erase the database the URL itself points at).
Without `--yes`, a dry run. With `--yes`:

1. **Attests the tenant's WORM chain first** — runs the full chain
   verification and captures the final chain head(s) into the certificate. If
   the chain does not verify, the command **refuses to erase** — you never
   destroy a tenant whose audit trail can't be shown to have been intact at
   teardown. Investigate first.
2. Terminates other backends on the target, `DROP DATABASE`, and deregisters
   it from `managed_databases` (primary and `vortex_master`).
3. **Verifies** the database no longer exists.
4. Records a `record_deleted` / `secure_database_decommission` entry on the
   **primary** chain (which survives), and writes a sealed certificate
   carrying the pre-erasure attestation.

### Media sanitisation (residual data)

A logical `DROP DATABASE` frees blocks but does not purge them from disk —
NIST SP 800-88 *Purge* is a media-level control, not a SQL one. For POC
teardown / decommission where residual-data recovery is in scope, the deployed
control is **crypto-erase**: run PostgreSQL and the FileStore on encrypted
volumes (LUKS, or the cloud provider's encrypted disks / KMS-backed buckets)
and **destroy the key** at decommission. The dumps and FileStore blobs then
become unrecoverable ciphertext regardless of block residue. Backups of the
tenant must be pruned / crypto-erased too (see `docs/DISASTER_RECOVERY.md`).

### FileStore blobs

Decommission does **not** auto-delete FileStore blobs, because the local
backend is a shared directory across tenants and blind deletion risks other
tenants' data. Remove the decommissioned tenant's blobs deliberately (local
dir: delete + overwrite the tenant's files, or rely on volume crypto-erase; S3:
delete the tenant prefix / destroy the bucket key).

## Certificates

Each run writes `erasure-<kind>-<target>-<stamp>.json` to
`$VORTEX_ERASURE_DIR`, wrapping the certificate body in an `integrity_sha256`
seal so later tampering with the file is detectable. Retain certificates in
your compliance record. A subject certificate carries the PII fingerprint; a
decommission certificate carries the attested pre-erasure chain heads.

## Verification checklist

- Subject: certificate `verification` = passed; the `users` row shows
  tombstones; `vortex audit verify` on the tenant still returns 0 failures
  (the erasure event chained in cleanly).
- Decommission: certificate `verification` = passed; the database is absent
  from `pg_database`; the primary `vortex audit verify` still returns 0
  failures; the tenant is gone from `managed_databases`; backups pruned; volume
  key destroyed where residual-purge is in scope.
