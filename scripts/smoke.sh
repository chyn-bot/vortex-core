#!/usr/bin/env bash
# Vortex integration smoke test.
#
# Contract: against a freshly provisioned tenant, no reachable page or
# endpoint may 500, and the core record lifecycles (attachment upload/
# download/delete, chatter upload, async report queue→render→download)
# must work end to end. This is the platform's route-level regression
# net — it exists because unit tests cannot catch schema/handler drift
# (two shipped features were dead at runtime before this suite).
#
# Requirements: a running server (SMOKE_BASE_URL), its database
# (DATABASE_URL) reachable via psql, and the `argon2` CLI.
#
# Usage:
#   DATABASE_URL=postgres://... SMOKE_BASE_URL=http://127.0.0.1:3003 \
#     bash scripts/smoke.sh
set -uo pipefail

BASE="${SMOKE_BASE_URL:-http://127.0.0.1:3003}"
DB_URL="${DATABASE_URL:?DATABASE_URL is required}"
SMOKE_USER="${SMOKE_USER:-smokeadmin}"
SMOKE_PASS="${SMOKE_PASS:-Smoke-$(openssl rand -hex 6)}"
WORK="$(mktemp -d)"
JAR="$WORK/cookies.txt"
MAX_PAGES=200
FAIL=0

note()  { printf '  %s\n' "$*"; }
pass()  { printf '\033[32m✓\033[0m %s\n' "$*"; }
fail()  { printf '\033[31m✗ %s\033[0m\n' "$*"; FAIL=1; }

sql() { psql "$DB_URL" -tAc "$1"; }

# ── 1. Seed an admin user ────────────────────────────────────────────
echo "── seeding admin user"
HASH=$(printf '%s' "$SMOKE_PASS" | argon2 "$(openssl rand -hex 8)" -id -e)
COMPANY=$(sql "SELECT id FROM companies LIMIT 1")
if [ -z "$COMPANY" ]; then fail "no company row — db not provisioned?"; exit 1; fi
sql "INSERT INTO users (username, email, password_hash, full_name, active, company_id)
     VALUES ('$SMOKE_USER', '$SMOKE_USER@smoke.test', '$HASH', 'Smoke Admin', true, '$COMPANY')
     ON CONFLICT (company_id, username) DO UPDATE SET password_hash = EXCLUDED.password_hash
     RETURNING id" > "$WORK/uid" || { fail "user seed failed"; exit 1; }
UID_=$(head -1 "$WORK/uid")
ROLE=$(sql "SELECT id FROM roles WHERE name IN ('System Administrator','Administrator') ORDER BY name DESC LIMIT 1")
sql "INSERT INTO user_roles (user_id, role_id) VALUES ('$UID_', '$ROLE') ON CONFLICT DO NOTHING" >/dev/null
pass "admin '$SMOKE_USER' ready"

# ── 2. Login ─────────────────────────────────────────────────────────
echo "── login"
LOGIN_STATUS=$(curl -s -o "$WORK/login.out" -w '%{http_code}' -c "$JAR" \
  -d "username=$SMOKE_USER&password=$SMOKE_PASS" "$BASE/auth/login")
if [ "$LOGIN_STATUS" != "200" ] || ! grep -q "session" "$JAR"; then
  fail "login failed (status $LOGIN_STATUS)"; cat "$WORK/login.out"; exit 1
fi
pass "session established"
CURL=(curl -s -b "$JAR")

# ── 3. Crawl every reachable page — nothing may 500 ─────────────────
echo "── crawling pages (bound: $MAX_PAGES)"
printf '%s\n' /home /reports /reports/runs /login > "$WORK/queue"
: > "$WORK/visited"
i=1
while :; do
  path=$(sed -n "${i}p" "$WORK/queue")
  [ -z "$path" ] && break
  i=$((i+1))
  grep -qxF "$path" "$WORK/visited" && continue
  [ "$(wc -l < "$WORK/visited")" -ge "$MAX_PAGES" ] && break
  echo "$path" >> "$WORK/visited"

  STATUS=$("${CURL[@]}" -o "$WORK/page.html" -w '%{http_code}' "$BASE$path")
  if [ "$STATUS" -ge 500 ] 2>/dev/null; then
    fail "$path → $STATUS"
  fi
  # harvest same-origin navigation links; skip logout/static/raw
  # downloads and export links (GET with side-effect-free content only)
  grep -oE 'href="/[^"]*"' "$WORK/page.html" 2>/dev/null \
    | sed 's/^href="//; s/"$//; s/&amp;/\&/g' \
    | grep -vE '^/(logout|static/|attachments/|auth/)' \
    | grep -vE '[?&]format=' \
    >> "$WORK/queue" || true
done
pass "crawled $(wc -l < "$WORK/visited") unique pages, no 5xx"

# curated API endpoints not linked from pages
for path in /health /api/notifications; do
  STATUS=$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$BASE$path")
  if [ "$STATUS" -ge 500 ] 2>/dev/null; then fail "$path → $STATUS"; else note "$path → $STATUS"; fi
done

# ── 4. Attachment lifecycle ──────────────────────────────────────────
echo "── attachment lifecycle"
REC=$(sql "SELECT gen_random_uuid()")
echo "smoke-payload-$(date +%s)" > "$WORK/upload.txt"
UP=$("${CURL[@]}" -F "file=@$WORK/upload.txt;type=text/plain" "$BASE/api/attachments/smoke.test/$REC")
ATT_ID=$(echo "$UP" | grep -o '"id":"[^"]*"' | head -1 | cut -d'"' -f4)
if [ -z "$ATT_ID" ]; then fail "attachment upload: $UP"; else
  DL="$WORK/download.txt"
  "${CURL[@]}" -o "$DL" "$BASE/attachments/$ATT_ID"
  if cmp -s "$WORK/upload.txt" "$DL"; then pass "upload → download byte-exact"; else fail "downloaded bytes differ"; fi
  DEL=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X DELETE "$BASE/attachments/$ATT_ID")
  [ "$DEL" = "200" ] && pass "delete → $DEL" || fail "delete → $DEL"
fi

# ── 5. Chatter upload ────────────────────────────────────────────────
echo "── chatter upload"
CH=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -F "file=@$WORK/upload.txt;type=text/plain" \
  "$BASE/api/chatter/smoke.test/$REC/attachments")
[ "$CH" = "200" ] && pass "chatter upload → 200" || fail "chatter upload → $CH"

# ── 6. Async report pipeline (skipped if no model is registered) ────
echo "── async report pipeline"
MODEL=$(sql "SELECT m.name FROM ir_model m JOIN ir_model_field f ON f.model_id = m.id
             WHERE m.is_active = true GROUP BY m.name LIMIT 1")
if [ -z "$MODEL" ]; then
  note "no registered models — skipping report cycle"
else
  FIELD=$(sql "SELECT f.name FROM ir_model_field f JOIN ir_model m ON m.id = f.model_id
               WHERE m.name = '$MODEL' AND f.field_type NOT IN ('many2one') LIMIT 1")
  RID=$(sql "INSERT INTO ir_report (code, name, model_name, report_type, sort_dir, paper_size, orientation, row_limit)
             VALUES ('smoke_report', 'Smoke Report', '$MODEL', 'tabular', 'asc', 'a4', 'portrait', 10)
             ON CONFLICT (code) DO UPDATE SET model_name = EXCLUDED.model_name RETURNING id" | head -1)
  sql "DELETE FROM ir_report_column WHERE report_id = '$RID';
       INSERT INTO ir_report_column (report_id, field, label, sequence) VALUES ('$RID', '$FIELD', 'Field', 1)" >/dev/null
  Q=$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$BASE/reports/queue/$RID?format=csv")
  if [ "$Q" != "303" ] && [ "$Q" != "200" ]; then fail "report queue → $Q"; else
    STATUS=""
    for _ in $(seq 1 30); do
      STATUS=$(sql "SELECT status FROM report_runs WHERE report_id = '$RID' ORDER BY created_at DESC LIMIT 1")
      [ "$STATUS" = "done" ] || [ "$STATUS" = "failed" ] && break
      sleep 2
    done
    if [ "$STATUS" = "done" ]; then
      RUN=$(sql "SELECT id FROM report_runs WHERE report_id = '$RID' ORDER BY created_at DESC LIMIT 1")
      DLS=$("${CURL[@]}" -o "$WORK/report.csv" -w '%{http_code}' "$BASE/reports/runs/$RUN/download")
      if [ "$DLS" = "200" ] && [ -s "$WORK/report.csv" ]; then
        pass "report queued → rendered → downloaded ($(wc -c < "$WORK/report.csv")B csv over model '$MODEL')"
      else fail "report download → $DLS"; fi
    else
      fail "report run ended '$STATUS': $(sql "SELECT error FROM report_runs WHERE report_id = '$RID' ORDER BY created_at DESC LIMIT 1")"
    fi
  fi
fi

# ── result ───────────────────────────────────────────────────────────
echo
if [ "$FAIL" = "0" ]; then
  pass "SMOKE SUITE PASSED"
else
  fail "SMOKE SUITE FAILED"
fi
rm -rf "$WORK"
exit "$FAIL"
