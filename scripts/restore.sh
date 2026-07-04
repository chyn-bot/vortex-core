#!/usr/bin/env bash
# Vortex restore — bring a backup set produced by scripts/backup.sh
# back to life, either in place or under a prefix for drills.
#
#   DATABASE_URL=postgres://user:pass@host:5432/vortex \
#     bash scripts/restore.sh <backup-set-dir> [db-prefix]
#
# With a prefix (e.g. "drill_"), every database restores side by side
# as <prefix><name> and the FileStore unpacks into
# <set-dir>/restored-uploads/ — the live system is untouched. That is
# how DR drills run. Without a prefix, databases are restored under
# their original names (they must not already exist — this script
# never drops anything; drop manually first if you mean it).
#
# After restoring, ALWAYS:
#   1. DATABASE_URL=<base>/<db> vortex audit verify   (per tenant —
#      proves the WORM chain survived intact)
#   2. point a server at the restored primary + FileStore dir and run
#      scripts/smoke.sh against it
set -euo pipefail

SET_DIR="${1:?usage: restore.sh <backup-set-dir> [db-prefix]}"
PREFIX="${2:-}"
DB_URL="${DATABASE_URL:?DATABASE_URL is required}"
BASE_URL="${DB_URL%/*}"

[ -f "$SET_DIR/MANIFEST" ] || { echo "no MANIFEST in $SET_DIR"; exit 1; }

# ── integrity first ──────────────────────────────────────────────────
echo "── verifying checksums"
(cd "$SET_DIR" && sha256sum -c SHA256SUMS)

# ── databases ────────────────────────────────────────────────────────
for dump in "$SET_DIR"/*.dump; do
  db="$(basename "$dump" .dump)"
  target="${PREFIX}${db}"
  echo "── restoring $db → $target"
  if ! psql "$BASE_URL/postgres" -tAc "SELECT 1 FROM pg_database WHERE datname='$target'" | grep -q 1; then
    psql "$BASE_URL/postgres" -c "CREATE DATABASE \"$target\"" >/dev/null
  else
    echo "   database '$target' already exists — refusing to overwrite"; exit 1
  fi
  # exit code 1 = completed with ignorable warnings (ownership etc.)
  pg_restore --no-owner --no-acl -d "$BASE_URL/$target" "$dump" || [ $? -eq 1 ]
done

# ── FileStore ────────────────────────────────────────────────────────
if [ -f "$SET_DIR/uploads.tar.gz" ]; then
  if [ -n "$PREFIX" ]; then
    DEST="$SET_DIR/restored-uploads"
  else
    DEST="${UPLOADS_RESTORE_DIR:-$(pwd)}"
  fi
  mkdir -p "$DEST"
  echo "── unpacking FileStore → $DEST"
  tar -xzf "$SET_DIR/uploads.tar.gz" -C "$DEST"
fi

echo
echo "Restored. Post-restore checklist:"
echo "  1. per tenant:  DATABASE_URL=$BASE_URL/${PREFIX}<db> vortex audit verify"
if [ -n "$PREFIX" ]; then
  echo "  2. boot a server against the drill copies and run scripts/smoke.sh"
else
  echo "  2. boot a server against the restored DBs and run scripts/smoke.sh"
fi
echo "  3. restore /etc/vortex/vortex.env + VORTEX_SECRET_KEY from your secrets channel"
