#!/usr/bin/env bash
# Vortex full-deployment backup.
#
# Produces one timestamped, self-describing backup set containing:
#   - a pg_dump (custom format) of every managed tenant database,
#     the master registry, and the primary database
#   - a tarball of the FileStore local directory (attachments,
#     chatter uploads, generated report artifacts)
#   - MANIFEST + SHA256SUMS so a restore can prove integrity first
#
# What this deliberately does NOT contain (back these up separately,
# through your secrets channel, not alongside the data):
#   - /etc/vortex/vortex.env        (master-password hash)
#   - VORTEX_SECRET_KEY             (without it, AES-encrypted SMTP/
#                                    webhook secrets in the dumps are
#                                    UNRECOVERABLE after restore)
#   - HSM material                  (never leaves the device by design)
#
# Usage (defaults suit the systemd timer in deploy/):
#   DATABASE_URL=postgres://user:pass@host:5432/vortex \
#   BACKUP_DIR=/var/backups/vortex \
#   UPLOADS_DIR=/home/vortex/vortex-core/uploads \
#   RETENTION_DAYS=14 \
#     bash scripts/backup.sh
set -euo pipefail

DB_URL="${DATABASE_URL:?DATABASE_URL is required}"
BACKUP_DIR="${BACKUP_DIR:-/var/backups/vortex}"
UPLOADS_DIR="${UPLOADS_DIR:-uploads}"
RETENTION_DAYS="${RETENTION_DAYS:-14}"

BASE_URL="${DB_URL%/*}"
PRIMARY_DB="${DB_URL##*/}"
STAMP=$(date -u +%Y%m%d-%H%M%S)
SET_DIR="$BACKUP_DIR/backup-$STAMP"
mkdir -p "$SET_DIR"
umask 027

# ── enumerate databases: primary + master + active tenants ──────────
# The master registry DB name defaults to `vortex_master` but can be
# overridden (multi-deployment hosts, or an isolated restore drill).
MASTER_DB_NAME="${VORTEX_MASTER_DB:-vortex_master}"
DBS="$PRIMARY_DB"
MASTER_DB=$(psql "$DB_URL" -tAc \
  "SELECT '$MASTER_DB_NAME' WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname='$MASTER_DB_NAME')" \
  2>/dev/null || true)
if [ -n "$MASTER_DB" ]; then
  DBS="$DBS $MASTER_DB"
  TENANTS=$(psql "$BASE_URL/$MASTER_DB" -tAc \
    "SELECT name FROM managed_databases WHERE state = 'active'" 2>/dev/null || true)
  DBS="$DBS $TENANTS"
fi
DBS=$(echo "$DBS" | tr ' ' '\n' | grep -v '^$' | sort -u)

# ── validate existence ───────────────────────────────────────────────
# A tenant dropped but not deregistered leaves a stale `state='active'`
# row in managed_databases. Dumping it fails, and under `set -e` that
# used to abort the ENTIRE run — so a single bit of registry drift meant
# no backup at all that night. Partition the list first: back up every
# database that actually exists, and treat a registered-but-absent one as
# a loud warning (nothing to back up), never a fatal error.
EXISTING=""
MISSING=""
for db in $DBS; do
  # Defence in depth: names come from managed_databases / env, not end users,
  # but never interpolate an unexpected string into psql. Skip anything that
  # isn't a plain identifier.
  if ! [[ "$db" =~ ^[A-Za-z0-9_]+$ ]]; then
    echo "  WARNING: skipping database with unexpected name characters: '$db'"
    continue
  fi
  if psql "$DB_URL" -tAc "SELECT 1 FROM pg_database WHERE datname='$db'" 2>/dev/null | grep -q 1; then
    EXISTING="$EXISTING $db"
  else
    MISSING="$MISSING $db"
    echo "  WARNING: '$db' is registered active but does not exist — skipping (deregister it in managed_databases)"
  fi
done
EXISTING=$(echo "$EXISTING" | tr ' ' '\n' | grep -v '^$' | sort -u)
MISSING=$(echo "$MISSING" | tr ' ' '\n' | grep -v '^$' | sort -u)

# ── dump each database ───────────────────────────────────────────────
# A dump that fails on a database that DOES exist is a real backup
# failure: record it, drop the partial (junk that would still checksum),
# keep going so the other tenants are still captured, and fail the run at
# the end so the systemd unit reports failure and someone investigates.
echo "Backup set: $SET_DIR"
FAILED=""
for db in $EXISTING; do
  echo "  dumping $db"
  if ! pg_dump --format=custom --file "$SET_DIR/$db.dump" "$BASE_URL/$db"; then
    echo "  ERROR: pg_dump failed for '$db'"
    rm -f "$SET_DIR/$db.dump"
    FAILED="$FAILED $db"
  fi
done

# ── FileStore blobs ──────────────────────────────────────────────────
if [ -d "$UPLOADS_DIR" ]; then
  echo "  archiving FileStore ($UPLOADS_DIR)"
  tar -czf "$SET_DIR/uploads.tar.gz" -C "$(dirname "$UPLOADS_DIR")" "$(basename "$UPLOADS_DIR")"
else
  echo "  (no local FileStore dir at $UPLOADS_DIR — s3 backend or empty; skipping)"
fi

# ── manifest + integrity ─────────────────────────────────────────────
GIT_REV=$(git -C "$(dirname "$0")/.." rev-parse --short HEAD 2>/dev/null || echo "unknown")
{
  echo "created_utc: $(date -u +%FT%TZ)"
  echo "host: $(hostname)"
  echo "vortex_git: $GIT_REV"
  echo "postgres: $(psql "$DB_URL" -tAc 'SHOW server_version')"
  echo "databases:"
  for db in $EXISTING; do
    [ -f "$SET_DIR/$db.dump" ] && echo "  - $db ($(du -h "$SET_DIR/$db.dump" | cut -f1))"
  done
  [ -f "$SET_DIR/uploads.tar.gz" ] && echo "filestore: uploads.tar.gz ($(du -h "$SET_DIR/uploads.tar.gz" | cut -f1))"
  [ -n "$MISSING" ] && echo "stale_registry_entries:$(echo "$MISSING" | tr '\n' ' ' | sed 's/ *$//' | sed 's/^/ /')"
  [ -n "$FAILED" ]  && echo "dump_failures:$FAILED"
  echo "restore_with: scripts/restore.sh $SET_DIR"
} > "$SET_DIR/MANIFEST"
(cd "$SET_DIR" && sha256sum ./*.dump ./*.tar.gz 2>/dev/null > SHA256SUMS) || true

# ── retention ────────────────────────────────────────────────────────
PRUNED=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup-*' -mtime "+$RETENTION_DAYS" | wc -l)
find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup-*' -mtime "+$RETENTION_DAYS" -exec rm -rf {} +
[ "$PRUNED" -gt 0 ] && echo "  pruned $PRUNED set(s) older than ${RETENTION_DAYS}d"

echo "Done: $(du -sh "$SET_DIR" | cut -f1) — $(ls "$SET_DIR" | wc -l) files"

# A registered-but-absent tenant is drift, not a backup failure — the run
# still produced a complete backup of everything that exists, so exit 0 and
# let the WARNING lines above (and the MANIFEST note) flag the cleanup. A
# dump that failed on a database that DOES exist is a real failure: exit
# non-zero so the systemd unit is marked failed and the drift gets noticed.
if [ -n "$FAILED" ]; then
  echo "BACKUP INCOMPLETE — pg_dump failed for:$FAILED" >&2
  exit 1
fi
