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
DBS="$PRIMARY_DB"
MASTER_DB=$(psql "$DB_URL" -tAc \
  "SELECT 'vortex_master' WHERE EXISTS (SELECT 1 FROM pg_database WHERE datname='vortex_master')" \
  2>/dev/null || true)
if [ -n "$MASTER_DB" ]; then
  DBS="$DBS $MASTER_DB"
  TENANTS=$(psql "$BASE_URL/$MASTER_DB" -tAc \
    "SELECT name FROM managed_databases WHERE state = 'active'" 2>/dev/null || true)
  DBS="$DBS $TENANTS"
fi
DBS=$(echo "$DBS" | tr ' ' '\n' | grep -v '^$' | sort -u)

# ── dump each database ───────────────────────────────────────────────
echo "Backup set: $SET_DIR"
for db in $DBS; do
  echo "  dumping $db"
  pg_dump --format=custom --file "$SET_DIR/$db.dump" "$BASE_URL/$db"
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
  for db in $DBS; do
    echo "  - $db ($(du -h "$SET_DIR/$db.dump" | cut -f1))"
  done
  [ -f "$SET_DIR/uploads.tar.gz" ] && echo "filestore: uploads.tar.gz ($(du -h "$SET_DIR/uploads.tar.gz" | cut -f1))"
  echo "restore_with: scripts/restore.sh $SET_DIR"
} > "$SET_DIR/MANIFEST"
(cd "$SET_DIR" && sha256sum ./*.dump ./*.tar.gz 2>/dev/null > SHA256SUMS) || true

# ── retention ────────────────────────────────────────────────────────
PRUNED=$(find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup-*' -mtime "+$RETENTION_DAYS" | wc -l)
find "$BACKUP_DIR" -maxdepth 1 -type d -name 'backup-*' -mtime "+$RETENTION_DAYS" -exec rm -rf {} +
[ "$PRUNED" -gt 0 ] && echo "  pruned $PRUNED set(s) older than ${RETENTION_DAYS}d"

echo "Done: $(du -sh "$SET_DIR" | cut -f1) — $(ls "$SET_DIR" | wc -l) files"
