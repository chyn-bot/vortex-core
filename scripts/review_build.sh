#!/usr/bin/env bash
#
# review_build.sh — verify the governed-low-code work (Initiatives #1–#5 + the
# #4 saved-views tail).
#
# What it checks, end to end:
#   Build   — the whole workspace compiles.
#   Unit    — the pure-logic unit tests (registry sync, custom fields, automation).
#   #1      — #[derive(Model)] is the single registry source of truth:
#             a fresh migrate registers all 12 models / 74 fields, and the
#             derive-sync ALONE (hand-seeds are tombstoned) restores them.
#   #2      — per-tenant custom fields: migration 137 objects + a real
#             add→render→save→load→delete round-trip against Postgres.
#   #3      — no-code automation rules: migration 138 + a real rule that
#             fires on a match, skips on a non-match, and applies its action.
#   #4      — saveable dashboards: migration 140 + a real KPI + bars board
#             computing aggregates over a registered model.
#   #5      — computed / related fields: migration 139 + a real formula field
#             that evaluates, stores read-only, and renders disabled.
#
# It is NON-DESTRUCTIVE: it creates a throwaway database, uses only that,
# and drops it at the end. No shared database is touched.
#
# Usage:
#   scripts/review_build.sh                 # build + all checks
#   SKIP_BUILD=1 scripts/review_build.sh    # skip the slow cargo build
#   PGHOST=... PGUSER=... PGPASSWORD=... PGPORT=... scripts/review_build.sh
#
# Env (defaults match the dev setup in vortex.toml):
#   PGHOST=localhost PGPORT=5432 PGUSER=vortex PGPASSWORD=vortex
#   TESTDB=review_build_$$   (auto throwaway name)

set -u

# ── config ───────────────────────────────────────────────────────────────────
export PGHOST="${PGHOST:-localhost}"
export PGPORT="${PGPORT:-5432}"
export PGUSER="${PGUSER:-vortex}"
export PGPASSWORD="${PGPASSWORD:-vortex}"
TESTDB="${TESTDB:-review_build_$$}"
DBURL="postgres://${PGUSER}:${PGPASSWORD}@${PGHOST}:${PGPORT}/${TESTDB}"

# Run from the repo root (this script lives in scripts/).
cd "$(dirname "$0")/.." || exit 1
REPO="$(pwd)"

PASS=0; FAIL=0
c_grn=$'\033[32m'; c_red=$'\033[31m'; c_dim=$'\033[2m'; c_bold=$'\033[1m'; c_rst=$'\033[0m'
pass() { PASS=$((PASS+1)); echo "  ${c_grn}✓${c_rst} $1"; }
fail() { FAIL=$((FAIL+1)); echo "  ${c_red}✗ $1${c_rst}"; }
hdr()  { echo; echo "${c_bold}== $1 ==${c_rst}"; }
# check "<label>" <actual> <expected>
check() { if [ "$2" = "$3" ]; then pass "$1 ($2)"; else fail "$1 — got '$2', expected '$3'"; fi; }
q() { psql -tAqX -d "$TESTDB" -c "$1" 2>/dev/null; }  # scalar query on the test DB

cleanup() {
  psql -tAqX -d postgres -c "DROP DATABASE IF EXISTS \"$TESTDB\";" >/dev/null 2>&1
}
trap cleanup EXIT

echo "${c_bold}Vortex build review${c_rst}  ${c_dim}(repo: $REPO)${c_rst}"
echo "${c_dim}throwaway DB: $TESTDB @ $PGHOST:$PGPORT as $PGUSER${c_rst}"

# ── 0. preflight ─────────────────────────────────────────────────────────────
hdr "Preflight"
command -v cargo >/dev/null && pass "cargo present" || { fail "cargo missing"; exit 1; }
if psql -tAqX -d postgres -c "SELECT 1" >/dev/null 2>&1; then
  pass "postgres reachable"
else
  fail "cannot connect to postgres as $PGUSER@$PGHOST:$PGPORT — set PGUSER/PGPASSWORD/PGHOST"; exit 1
fi

# ── 1. build ─────────────────────────────────────────────────────────────────
hdr "Build (cargo build --workspace)"
if [ "${SKIP_BUILD:-0}" = "1" ]; then
  echo "  ${c_dim}skipped (SKIP_BUILD=1)${c_rst}"
else
  echo "  ${c_dim}compiling… (a few minutes cold)${c_rst}"
  if cargo build --workspace >/tmp/rb_build.log 2>&1; then
    pass "workspace compiles"
  else
    fail "workspace build FAILED — see /tmp/rb_build.log"; tail -20 /tmp/rb_build.log
  fi
fi
BIN="$REPO/target/debug/vortex"
[ -x "$BIN" ] && pass "vortex binary built" || { fail "vortex binary missing (build first)"; }

# ── 2. unit tests (pure logic) ───────────────────────────────────────────────
hdr "Unit tests"
run_unit() { # <crate> <filter> <label>
  if cargo test -p "$1" "$2" >/tmp/rb_test.log 2>&1; then
    local r; r=$(grep -oE '[0-9]+ passed' /tmp/rb_test.log | head -1)
    pass "$3 — $r"
  else
    fail "$3 — see /tmp/rb_test.log"; grep -E 'FAILED|panicked' /tmp/rb_test.log | head -5
  fi
}
run_unit vortex-orm       registry_sync   "ORM registry-sync mapping"
run_unit vortex-framework custom_fields   "custom-fields logic"
run_unit vortex-framework automation      "automation logic"
run_unit vortex-framework computed_fields "computed-fields logic"
run_unit vortex-framework dashboards      "dashboards logic"
run_unit vortex-framework saved_views     "saved-views logic"

# ── 3. provision throwaway DB ────────────────────────────────────────────────
hdr "Provision throwaway DB (applies all migrations + derive-sync)"
psql -tAqX -d postgres -c "DROP DATABASE IF EXISTS \"$TESTDB\";" >/dev/null 2>&1
if psql -tAqX -d postgres -c "CREATE DATABASE \"$TESTDB\";" >/dev/null 2>&1; then
  pass "created $TESTDB"
else
  fail "could not create $TESTDB"; exit 1
fi
if DATABASE_URL="$DBURL" "$BIN" db migrate >/tmp/rb_migrate.log 2>&1; then
  synced=$(grep -oE 'Model registry synced: [0-9]+' /tmp/rb_migrate.log | grep -oE '[0-9]+' | head -1)
  check "migrate ran, models synced" "${synced:-0}" "12"
else
  fail "db migrate FAILED — see /tmp/rb_migrate.log"; tail -20 /tmp/rb_migrate.log; exit 1
fi

# ── 4. Initiative #1 — registry is derive-sourced ────────────────────────────
hdr "#1  derive(Model) is the registry source of truth"
MODELS="'contacts','stock_product','stock_location','stock_move','stock_lot','acc_move','acc_account','purchase_order','sales_order','maint_asset','maint_work_order','maint_plan'"
check "models registered"        "$(q "SELECT count(*) FROM ir_model WHERE name IN ($MODELS);")" "12"
check "fields registered"        "$(q "SELECT count(*) FROM ir_model_field f JOIN ir_model m ON m.id=f.model_id WHERE m.name IN ($MODELS);")" "74"
check "hand-seed INSERTs gone"   "$(grep -rl 'INSERT INTO ir_model' "$REPO"/crates/*/migrations/*/postgres.sql 2>/dev/null | wc -l | tr -d ' ')" "0"

# Isolation: wipe the registry, re-migrate. Seeds are tombstones, so ONLY the
# derive-sync can restore the rows. Counts must return to 74.
BEFORE="$(q "SELECT count(*) FROM ir_model_field f JOIN ir_model m ON m.id=f.model_id WHERE m.name IN ($MODELS);")"
q "DELETE FROM ir_model WHERE name IN ($MODELS);" >/dev/null
WIPED="$(q "SELECT count(*) FROM ir_model_field f JOIN ir_model m ON m.id=f.model_id WHERE m.name IN ($MODELS);")"
DATABASE_URL="$DBURL" "$BIN" db migrate >/tmp/rb_remigrate.log 2>&1
AFTER="$(q "SELECT count(*) FROM ir_model_field f JOIN ir_model m ON m.id=f.model_id WHERE m.name IN ($MODELS);")"
check "registry wiped"                    "$WIPED"  "0"
check "derive-sync restored it (isolated)" "$AFTER" "$BEFORE"

# ── 5. Initiative #2 — per-tenant custom fields ──────────────────────────────
hdr "#2  per-tenant custom fields"
check "migration 137: is_custom column" "$(q "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='ir_model_field' AND column_name='is_custom');")" "t"
check "migration 137: ir_custom_value"  "$(q "SELECT to_regclass('ir_custom_value') IS NOT NULL;")" "t"
# Real add→render→save→load→delete round-trip (the crate's DB-gated test).
if VORTEX_TEST_DB="$DBURL" cargo test -p vortex-framework end_to_end_against_db -- --nocapture >/tmp/rb_cf.log 2>&1 \
   && grep -q "1 passed" /tmp/rb_cf.log; then
  pass "add→render→save→load→delete round-trip"
else
  fail "custom-field round-trip — see /tmp/rb_cf.log"; grep -E 'panicked|assert|FAILED' /tmp/rb_cf.log | head
fi

# ── 6. Initiative #3 — no-code automation rules ──────────────────────────────
hdr "#3  no-code automation rules"
check "migration 138: automation_rule" "$(q "SELECT to_regclass('automation_rule') IS NOT NULL;")" "t"
# Real rule: matching rule fires + applies action; non-matching rule skipped.
if VORTEX_TEST_DB="$DBURL" cargo test -p vortex-framework run_rules_against_db -- --nocapture >/tmp/rb_auto.log 2>&1 \
   && grep -q "1 passed" /tmp/rb_auto.log; then
  pass "rule fires on match, skips on non-match, action applied"
else
  fail "automation run_rules — see /tmp/rb_auto.log"; grep -E 'panicked|assert|FAILED' /tmp/rb_auto.log | head
fi

# ── 7. Initiative #5 — computed / related fields ─────────────────────────────
hdr "#5  computed / related fields"
check "migration 139: is_computed column" "$(q "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='ir_model_field' AND column_name='is_computed');")" "t"
check "migration 139: compute_expr column" "$(q "SELECT EXISTS(SELECT 1 FROM information_schema.columns WHERE table_name='ir_model_field' AND column_name='compute_expr');")" "t"
# Real formula: define x_ = credit_limit*2, save a record, evaluate + store read-only.
if VORTEX_TEST_DB="$DBURL" cargo test -p vortex-framework evaluate_against_db -- --nocapture >/tmp/rb_comp.log 2>&1 \
   && grep -q "1 passed" /tmp/rb_comp.log; then
  pass "formula evaluates, stores read-only, renders disabled"
else
  fail "computed-field evaluate — see /tmp/rb_comp.log"; grep -E 'panicked|assert|FAILED' /tmp/rb_comp.log | head
fi

# ── 8. Initiative #4 — saveable dashboards ───────────────────────────────────
hdr "#4  saveable dashboards"
check "migration 140: dashboard table"        "$(q "SELECT to_regclass('dashboard') IS NOT NULL;")" "t"
check "migration 140: dashboard_widget table" "$(q "SELECT to_regclass('dashboard_widget') IS NOT NULL;")" "t"
# Real board: KPI count + bars breakdown over contacts, computed from the registry.
if VORTEX_TEST_DB="$DBURL" cargo test -p vortex-framework widget_compute_against_db -- --nocapture >/tmp/rb_dash.log 2>&1 \
   && grep -q "1 passed" /tmp/rb_dash.log; then
  pass "KPI + bars widgets compute against a registered model"
else
  fail "dashboard widget compute — see /tmp/rb_dash.log"; grep -E 'panicked|assert|FAILED' /tmp/rb_dash.log | head
fi

# ── 9. Initiative #4 tail — saveable analytic views ──────────────────────────
hdr "#4-tail  saveable analytic views (pivot/graph/kanban/calendar)"
check "migration 141: saved_view table" "$(q "SELECT to_regclass('saved_view') IS NOT NULL;")" "t"
check "one shared default per (model,view_type)" \
      "$(q "SELECT COUNT(*) FROM pg_indexes WHERE indexname = 'uq_saved_view_default';")" "1"
check "no phantom ir_ui_view tables remain referenced" \
      "$(q "SELECT to_regclass('ir_ui_view') IS NULL;")" "t"
# Real round-trip: validate a config against the registry, persist, load, default.
if VORTEX_TEST_DB="$DBURL" cargo test -p vortex-framework saved_view_roundtrip_against_db -- --nocapture >/tmp/rb_views.log 2>&1 \
   && grep -q "1 passed" /tmp/rb_views.log; then
  pass "config validate → save → load → default over a registered model"
else
  fail "saved-view round-trip — see /tmp/rb_views.log"; grep -E 'panicked|assert|FAILED' /tmp/rb_views.log | head
fi

# ── summary ──────────────────────────────────────────────────────────────────
hdr "Summary"
echo "  ${c_grn}passed: $PASS${c_rst}    $([ "$FAIL" -gt 0 ] && echo "${c_red}failed: $FAIL${c_rst}" || echo "failed: 0")"
echo
if [ "$FAIL" -eq 0 ]; then
  echo "${c_grn}${c_bold}ALL CHECKS PASSED${c_rst}"
  exit 0
else
  echo "${c_red}${c_bold}$FAIL CHECK(S) FAILED${c_rst} — logs in /tmp/rb_*.log"
  exit 1
fi
