# Audit & Log Retention

Vortex keeps two distinct streams. They have different retention rules because
they have different trust properties.

## 1. The WORM audit ledger — retained, never rotated

`audit_log` is append-only, hash-chained, and (in production) Ed25519/HSM
signed. It is the evidentiary record, so it is **not** pruned or rotated
locally — deleting entries would break the chain and `vortex audit verify`
would fail. It is retained in Postgres for the full compliance retention
period, and durability is provided by the backup tier (see
`docs/DISASTER_RECOVERY.md`), not by log rotation.

**Off-box retention (SIEM):** stream the ledger to the SIEM continuously so the
authoritative copy also lives outside the box:

```
# incremental export since the last run (cron/systemd timer), CEF or LEEF:
DATABASE_URL=… vortex audit export --from "$LAST_RUN" --format cef  >> /var/log/vortex/audit.cef
# or pipe straight to the collector / forwarder
```

`vortex audit export` supports `jsonl`, `cef`, and `leef`. Ship these to the
SIEM's retention tier; that system owns long-term archival and legal hold.

**Integrity monitoring:** schedule `vortex audit verify` (the nightly built-in
check already does this) so any tampering is detected, and the verification
result is itself written back to the ledger.

## 2. Local operational logs — capped and rotated (~4 GB)

The server's diagnostic log (stdout → journald under systemd) is bounded so it
can't fill the disk. Install the drop-in:

```
sudo cp deploy/journald-vortex.conf /etc/systemd/journald.conf.d/vortex.conf
sudo systemctl restart systemd-journald
```

Caps: `SystemMaxUse=4G`, `SystemMaxFileSize=256M`, `MaxRetentionSec=90day`,
persistent storage. This is the operational log only — it is not the audit
record, so size-based rotation of it loses no compliance data.

## Summary

| Stream | Store | Retention | Rotation |
|---|---|---|---|
| WORM audit ledger | Postgres `audit_log` | full compliance period | **never** (immutable); exported to SIEM + backed up |
| Operational / diagnostic log | journald | ≤ 90 days / ≤ 4 GB | size + age capped (journald drop-in) |
