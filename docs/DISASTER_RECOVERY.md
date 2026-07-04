# Disaster Recovery

How Vortex deployments are backed up, how they come back, and the
proof that the procedure works. Complements `docs/ARCHITECTURE.md` §5
(deployment shapes) — everything here applies to both the SaaS and
on-prem shapes.

## What a deployment consists of

| State | Where | Covered by |
|---|---|---|
| Tenant databases + master registry + primary | PostgreSQL | `scripts/backup.sh` (pg_dump per DB) |
| FileStore blobs (attachments, chatter, report artifacts) | `uploads/` (local backend) or S3 bucket | `scripts/backup.sh` tarball / bucket versioning+replication |
| Master password hash | `/etc/vortex/vortex.env` | **secrets channel — NOT in backup sets** |
| `VORTEX_SECRET_KEY` | systemd env / secrets manager | **secrets channel — NOT in backup sets.** Without it, AES-GCM-encrypted values in the dumps (SMTP passwords, webhook secrets) are unrecoverable |
| Audit signing key | env (dev) / HSM (prod) | HSM material never leaves the device; a restore re-attaches to the same HSM. Env-key deployments: secrets channel |
| Config | `vortex.toml` (in git) | git |

## Backup

`scripts/backup.sh` produces one timestamped set under `$BACKUP_DIR`:
every managed database as a custom-format `pg_dump`, the FileStore as
a tarball, a `MANIFEST` (what, when, from which git revision), and
`SHA256SUMS`. Retention-pruned after `RETENTION_DAYS` (default 14).

Nightly scheduling: `deploy/vortex-backup.{service,timer}` —

```
cp deploy/vortex-backup.{service,timer} /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vortex-backup.timer
```

**Off-site:** a backup on the same disk as the database protects
against mistakes, not disasters. Sync `$BACKUP_DIR` off the machine —
`rsync` to another host, or `aws s3 sync` / MinIO `mc mirror` to
object storage. Backup sets contain business data and password
hashes: the transport and the destination must be encrypted and
access-controlled.

## Restore

```
DATABASE_URL=postgres://user:pass@host:5432/vortex \
  bash scripts/restore.sh /var/backups/vortex/backup-<stamp> [prefix]
```

- Checksums are verified before anything is touched.
- With a `prefix` (e.g. `drill_`) everything restores side by side —
  this is how drills run, and how you inspect a backup without
  committing to it.
- Without a prefix, databases restore under their original names;
  the script refuses to overwrite an existing database — drop
  manually first if you really are replacing a broken instance.
- FileStore: unpack `uploads.tar.gz` into the server's working
  directory (or restore the S3 bucket by its own mechanism).
- Re-provision secrets from the secrets channel
  (`/etc/vortex/vortex.env`, `VORTEX_SECRET_KEY`), then start the
  service.

**Post-restore verification is not optional:**

1. `DATABASE_URL=<base>/<tenant> vortex audit verify` for every
   tenant — proves the WORM chain is byte-identical to what was
   backed up. A chain failure means the backup or the restore path
   corrupted data; do not go live on it.
2. Run `scripts/smoke.sh` against a server booted on the restored
   data — proves the application actually works, not just that
   tables exist.

## Objectives (current tier)

| Metric | Value | Determined by |
|---|---|---|
| RPO | ≤ 24 h | nightly timer — data since the last dump is lost |
| RTO | ≈ minutes–1 h | restore is `pg_restore` + untar + service start |

### Upgrade path: PITR (RPO → minutes)

When a customer contract demands a tighter RPO, add WAL archiving on
the Postgres side — no Vortex changes required:

```
# postgresql.conf
archive_mode = on
archive_command = 'test ! -f /var/backups/vortex/wal/%f && cp %p /var/backups/vortex/wal/%f'
```

plus a periodic `pg_basebackup`. Restore then replays WAL to any
point in time. The logical-dump sets in this document remain useful
as the portable, per-tenant, integrity-checked tier on top.

## Drill log

Drills are rehearsed on a copy (`drill_` prefix), never on the live
system. Every drill: full backup → prefixed restore → WORM
verification on every tenant → smoke suite against a server booted on
the restored copy.

| Date | Set | Result |
|---|---|---|
| 2026-07-04 | backup-20260704-033243 (5 DBs + FileStore, 12 MB) | ✅ checksums OK; WORM chains verified on vortex/gaia/remicle (126 entries, 0 failures); restored server booted; full smoke suite passed (200 pages crawled, all lifecycles green) |

Schedule: rerun the drill after any migration touching `audit_log`,
`sessions`, or the FileStore, and at minimum quarterly.
