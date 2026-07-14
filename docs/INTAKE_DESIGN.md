# Vortex Intake — Public Web-Forms & Interactive Portal — Design Plan

**Status:** Draft / proposal · **Author:** design session 2026-07-14 · **Depends on:** Blueprints (shipped, `f4f1e2c`), the model registry, `public_context_middleware` / `Plugin::public_routes`, the generic write path (`dynamic_form_create`), `vortex_security::crypto`, the in-memory rate limiter.

---

## 1. What this is

**Intake** is a governed way to capture data from *outside* the trust boundary. Two related surfaces on one engine:

- **Public web-forms** (anonymous): an admin publishes a form at a public URL that writes a real record into any model — a Blueprint or a compiled one. Contact-us, support-ticket intake, job applications, event registration, vendor onboarding, RMA requests.
- **Interactive portal** (authenticated): today the `/portal/*` surface is **read-only** (a partner can view their invoices/orders/statement). Intake lets a logged-in portal user *submit and track* records — the same form engine, scoped to their own `contact_id`.

Today Vortex can present data to external parties but cannot **accept** it: there is no public form surface in core, and the one generic write path (`dynamic_form_create`) is inside the authed tree and does no attribution, validation, or audit. Intake closes the standing "read-only portal / no web-forms" gap — the next-biggest hole after Blueprints.

### The thesis: parity by leverage, lead by governance

- **Parity is mostly plumbing we already have.** `public_context_middleware` already resolves the tenant from the Host header and injects a pool with **no** `AuthUser`; `Plugin::public_routes` already mounts a no-auth, module-gated surface; `dynamic_form_create` already writes to any `ir_model` table by name (Blueprint `x_` tables included) with catalog-whitelisted, type-cast columns; the rate limiter and CSP/security headers already exist. A web-form is "render a subset of a model's fields, then write through a hardened version of the path we already have."
- **The lead is the governance.** Odoo Website Forms and Frappe Web Forms accept external input with thin controls. Vortex treats every public write as hostile by construction: an explicit **field allow-list** (not "any real column"), a **signed form nonce** + origin check + honeypot + rate limit, **server-side tenant/owner stamping**, a **WORM audit entry per submission**, optional **spam quarantine** and **approval-before-commit**. We don't out-feature them on form widgets; we make external intake **tamper-evident and policy-bounded** — the thing a regulated buyer actually needs.

## 2. Goals / Non-goals

**Goals**
- Publish a public form bound to a model, exposing a chosen subset of fields, at a stable public URL — no deploy, per tenant.
- Every public submission writes a first-class record through a hardened path: field-allow-listed, tenant/owner-stamped, required-field-validated, WORM-audited.
- Hardened against the public-internet threat model: CSRF/replay, spam/automation, mass-assignment, model-target tampering, oversized payloads.
- Let authenticated portal users submit/track records scoped to their own partner.
- Works over Blueprint models out of the box (Intake + Blueprints = "design a model and a public form for it, both no-code").

**Non-goals (explicitly deferred)**
- **A website/CMS/page builder.** Intake renders *forms*, not marketing pages. A form can be embedded (iframe/snippet) into whatever site the customer already runs.
- **File uploads** in v1 (a real attachment path with AV/size/type policy is its own effort; see Phase 4).
- **Payment collection** on the form (integrations are a separate track).
- **Arbitrary client scripting** on the form (declarative fields only — same discipline as Blueprints).

## 3. Central decisions

### 3.1 A core public sub-router, not a plugin

The existing public surface is `Plugin::public_routes()` at `/p/<plugin>`. Intake is a **core** capability (every vertical wants intake), so it gets a core public sub-router — call it `intake_public` — mounted at the outer no-auth layer next to `portal_public`, wrapped in:
- `public_context_middleware` (tenant from Host, injects `DatabaseContext`, **no** `AuthUser`),
- the in-memory **rate limiter** (as the login routes do), keyed per-IP,
- `security_headers_middleware` (already global).

Routes:
- `GET  /i/{slug}` — render the form (issues a signed nonce).
- `POST /i/{slug}` — validate + write the record.
- `GET  /i/{slug}/thanks` — post-submit confirmation (or inline).

`/i/` (short, public) keeps public URLs clean and distinct from the authed `/form/{model}` tree.

### 3.2 A Form is a stored definition, field allow-list is the security seam

A **web_form** row binds a `slug` → a `model` (any `ir_model.name`), plus the **explicit list of exposed fields**, labels/help/required overrides, and settings. The submit handler writes **only** the fields named in the form definition — never the raw "any real column" whitelist `dynamic_form_create` uses. This is the load-bearing security decision: it closes mass-assignment (a submitter cannot set `record_state`, `company_id`, an internal price, or any column the form didn't publish) and makes the writable surface auditable and intentional.

The target model is resolved **server-side from the slug** — the client never names a model, so a request can't retarget the write.

### 3.3 Server stamps identity; the client never does

`dynamic_form_create` today stamps neither `company_id` nor `created_by`. The Intake write path stamps them **server-side**: `company_id` from the resolved tenant/form, `created_by` = a per-tenant **system "Anonymous Intake" user** (a real `users` row so FKs and audit attribution hold), and the model's **default `record_stage`** if it has stages. None of these are ever read from the request body.

### 3.4 Tenant trust is Host + `db_filter` + trusted proxy

Anonymous tenant resolution is Host-header based (`resolve_database`). It is only safe with `db_filter` configured and a **trusted reverse proxy** setting the Host and `X-Forwarded-For`. Intake documents this as a hard deployment requirement and refuses to serve a public form when `db_filter` is unset and more than the default DB exists (fail closed rather than leak cross-tenant).

## 4. Security model (the hard part — this is where we beat them)

Every public POST must clear all of:

1. **Signed form nonce (CSRF/replay).** `GET /i/{slug}` embeds a hidden token = `HMAC(master_key, slug | tenant | issued_at)` (reuse `crypto::hmac_sha256`). `POST` recomputes and checks it, and rejects tokens older than N minutes. Stateless, no server session needed. (Fixes the *"no CSRF anywhere in the real router"* finding for this surface.)
2. **Origin/Referer allowlist.** The form's settings hold allowed origins (for embedded forms); the POST's `Origin`/`Referer` must match. Same-origin (hosted `/i/`) is always allowed.
3. **Honeypot + min-fill-time.** A hidden field that must stay empty, and a rejected-if-submitted-too-fast check — cheap, effective bot filters. (Captcha is a pluggable Phase 3 add-on; no third-party call in v1 core.)
4. **Rate limit.** Per-IP via the existing limiter; per-form daily cap in settings.
5. **Field allow-list (§3.2)** — only published fields are written.
6. **Payload bounds.** Max field count/size; reject unknown keys loudly (don't silently drop, unlike the current whitelist-skip).
7. **Required + type validation** from `ir_model_field` (the generic path skips this today) before the insert.
8. **Fail-closed tenant** (§3.4).

A submission that passes is written in one transaction and **WORM-audited** (`intake.submitted`, with form slug, model, resolved tenant, source IP). Governance options per form: **quarantine** (write with an `intake_pending` stage for human triage), **approval** (reuse the Blueprints approval primitive's shape), and **notify** (assignee/email via the existing mail/notification bus).

## 5. Data model (new tables)

```
-- Migration 148_intake (core)

CREATE TABLE web_form (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug         VARCHAR(64) NOT NULL UNIQUE,        -- public URL segment
    model        VARCHAR(128) NOT NULL,              -- ir_model.name (target)
    title        VARCHAR(255) NOT NULL,
    description  TEXT,
    fields       JSONB NOT NULL DEFAULT '[]',        -- ordered allow-list: [{name,label,help,required}]
    settings     JSONB NOT NULL DEFAULT '{}',        -- origins[], success_msg, quarantine, approval, notify_to, daily_cap
    company_id   UUID,                               -- owning tenant company
    active       BOOLEAN NOT NULL DEFAULT true,
    created_by   UUID,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Lightweight submission ledger (spam triage, rate/analytics; the real record
-- lives in the target model's table).
CREATE TABLE web_form_submission (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    form_id      UUID NOT NULL REFERENCES web_form(id) ON DELETE CASCADE,
    record_id    UUID,                               -- the row created in the target model
    status       VARCHAR(16) NOT NULL DEFAULT 'accepted', -- accepted|quarantined|rejected
    source_ip    INET,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Per-tenant system user for anonymous attribution (seeded, is_portal=false,
-- a locked login). created_by on intake rows points here.
```

`fields`/`settings` field names are validated against `ir_model_field` at **save** time (same discipline as saved-views/Blueprints), so a published form can only expose real, registered columns.

## 6. Reuse the generic write path — hardened

`submit_web_form` composes over `dynamic_form_create`'s proven SQL builder (catalog `udt_name` casts, parameterized binds), but wraps it:
- intersect submitted keys with the **form's field allow-list** (not all real columns);
- validate required/typed against `ir_model_field`;
- stamp `company_id` / `created_by` / default stage server-side;
- run inside one tx; write `web_form_submission`; `state.audit.log(intake.submitted)`;
- fire optional chatter/notification.

Refactor: extract the pure "build typed INSERT from (table, allowed cols, values)" core out of `dynamic_form_create` so both the authed form and Intake share exactly one write builder (and fix the current path to stamp owner/tenant while we're there — a strict improvement for authed creates too).

## 7. Phase plan

**Phase 0 — Anonymous write path + safety core (no UI).** Extract the shared typed-INSERT builder; add server-side stamping (company/owner/stage) and `ir_model_field` required/type validation; the signed-nonce + honeypot + rate-limit + origin primitives; the `intake` audit action; migration 148 (`web_form`, `web_form_submission`, system user). Unit-test the nonce, the allow-list intersection, and the validator.

**Phase 1 — Public form engine (the "aha").** `web_form` CRUD in the admin (`/settings/forms` or a Blueprint-adjacent builder), a public `GET/POST /i/{slug}` that renders the allow-listed fields and writes a governed record. Demo: publish a form for a Blueprint, submit it logged-out, watch an audited row appear. Fail-closed tenant guard.

**Phase 2 — Governance depth.** Per-form quarantine + a triage inbox; approval-before-commit (reuse the Blueprints approval shape); assignee/notification on submit; per-form daily cap + spam metrics; the submission ledger UI.

**Phase 3 — Interactive portal.** Let authenticated portal users submit/track records via the same engine, scoped to `contact_id` (e.g. "raise a ticket", "request a quote", then see its status). Extends `/portal/*` from read-only to read-write, reusing the form definitions and the stamping/validation path (owner = the portal partner, not the anon user). Optional captcha adapter.

**Phase 4 — Attachments & embedding.** A policy-bounded file field (size/type/AV, FileStore-backed) and a documented embed snippet (iframe + origin allowlist) so a form drops into an external site.

**Post-Phase-4 follow-ups (shipped).**
- *AV scanning hook* — pluggable `AvScanner` (no-op default, `clamd` INSTREAM backend) screening every upload before it is stored; wired on `AppState.av`, configured from `[antivirus]`.
- *CAPTCHA adapter* — pluggable `CaptchaVerifier` (no-op default; one `SiteverifyVerifier` covers Cloudflare Turnstile, hCaptcha, and reCAPTCHA v2 — same `siteverify` shape). Wired on `AppState.captcha`, configured from `[captcha]` (provider + public sitekey + private secret + `fail_open`); forms opt in per-form via a `captcha` setting. Public `GET /i/{slug}` renders the widget div + external provider script (no inline JS) and widens the page CSP (`script-/frame-/connect-src`) to the provider's hosts; `POST` verifies the solved token server-side (the provider response field is consumed as a control field, never reaching the allow-list) before any write. The signed nonce + honeypot + fill-time gate still run — CAPTCHA is the human-verification escalation, not a replacement. Scoped to the anonymous public path; the cookie-authed portal is unaffected.
- *Portal record-stage tracking* — `/portal/requests` now shows a partner where their accepted request actually is, not just "Received". `list_partner_submissions` resolves each accepted record's live `record_state` against the model's `record_stages` catalogue (batched one query per distinct model, so no N+1 across forms) into a `StageInfo{code,label,color,index,total}`; the portal renders a coloured stage badge + a "step {index} of {total}" progress bar. Models without a status bar (no stages / no `record_state` column) and non-accepted submissions fall back to the plain status badge. Read-only — the portal never mutates a stage.
- *Orphaned-blob sweep* — a rejected quarantine never creates a record, so its stored blobs are never linked to an `ir_attachment`. A daily `system.intake_blob_sweep` scheduled action (`intake::sweep_orphaned_attachments`, per-tenant, `VORTEX_INTAKE_BLOB_GRACE_DAYS` grace window) reclaims those blobs — skipping any key still referenced by a live record — and clears the stale pointers. `delete_form` proactively purges held quarantine/rejected blobs before its cascade drops the rows that hold the keys. DB-driven (no `FileStore::list`); a blob stranded by a store-then-DB-failure is the accepted out-of-reach case.

## 8. What we reuse (net-new surface is small)

| Capability | Source | Status |
|---|---|---|
| No-auth, tenant-resolved surface | `public_context_middleware`, outer router | reuse (new core sub-router) |
| Tenant from Host | `resolve_database` / `db_filter` | reuse |
| Generic typed write | `dynamic_form_create` builder | reuse (extract + harden) |
| Field metadata / validation | `ir_model_field` registry | reuse |
| Signing (nonce) | `vortex_security::crypto::hmac_sha256` | reuse |
| Rate limit | `vortex_server::middleware::rate_limit` | reuse |
| Audit / approval / notify | `state.audit`, approval primitive, mail bus | reuse |
| Blueprint targets | `ir_model` (source='blueprint') | reuse (works by name) |
| **Net-new** | `web_form`/submission tables + builder UI, `/i/{slug}` engine, nonce/honeypot/origin guards, server-side stamping, portal write | **build** |

## 9. Risks & open questions

- **CSRF is absent app-wide** (a real finding): the signed nonce fixes it for `/i/`, but authed forms still rely on SameSite=Strict only. In-scope hardening of the *public* path; a broader CSRF pass on authed forms is a separate ticket to note.
- **Anonymous tenant trust**: Host-only resolution is safe *only* behind a trusted proxy with `db_filter`. Fail-closed default + explicit docs; consider a per-form pinned tenant as belt-and-suspenders.
- **Spam / abuse** at internet scale: honeypot + rate-limit + daily-cap in v1; a captcha adapter interface in Phase 3; quarantine keeps junk out of clean tables.
- **Mass-assignment** is the classic web-form bug — the field allow-list (§3.2) is the mitigation and must be the *only* writable surface; add a test that a POST with an extra column is rejected, not silently dropped.
- **Ownerless rows today**: extracting/stamping in `dynamic_form_create` changes behavior for authed creates too (they'd start stamping owner/tenant) — a strict improvement, but verify no handler depended on the old NULLs.
- **Naming**: "Intake" (recommended — describes governed external capture without the CMS baggage of "Website"). Alternates: "Front Desk", "Gateway", "Public Forms".

## 10. Recommendation

Build **Phases 0–1** first as one milestone: a governed public web-form that writes an audited, field-allow-listed, tenant-stamped record into any model — including a Blueprint — from a logged-out browser. That alone closes the biggest post-Blueprints gap and demos the pairing ("no-code model + no-code public form, both governed"). Phase 2 adds the governance depth that is the lead; Phase 3 turns the read-only portal interactive on the same engine.
