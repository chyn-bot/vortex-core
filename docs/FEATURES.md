# Vortex Core — Platform Overview & Capability Catalog

*The zero-trust, multi-tenant application **foundation** for regulated enterprise software. Persistence, identity, audit, policy, workflow, and integration are solved once in the core — so developers ship domain **modules** on the Vortex SDK instead of rebuilding plumbing.*

Last updated: 2026-06-28 · Core platform (kernel build, no domain modules).

---

## 1. The thesis

Serious enterprise software keeps re-solving the same hard, unglamorous problems: multi-tenant data isolation, identity, tamper-proof audit, access policy, workflow, reporting, and integration. In regulated industries those have to be **provably** correct — and that is exactly where teams burn years before writing a line of domain logic.

**Vortex Core solves that substrate once.** It is a horizontal application platform — a runtime, data layer, security model, and extension contract — on which any number of business **modules** are built. The core never knows what industry it serves; domain capability is added as plugin crates through a stable SDK.

- **Foundation, not a product.** The core ships the kernel and shared services; it carries zero industry assumptions and builds standalone with no domain tables.
- **Built to be built on.** A documented `Plugin` contract + SDK lets our team, partners, and customers add modules (and whole verticals) without forking or touching the core.
- **Zero-trust by construction.** Every state change is policy-gated and written to a cryptographically chained, tamper-evident ledger — the compliance posture regulated buyers demand, inherited free by every module.
- **Rust + PostgreSQL.** Memory-safe, high-performance, on-prem and air-gap friendly — a fit for finance, healthcare, energy, and public-sector deployments.

> The objective: make Vortex Core the dependable base that an ecosystem of applications is built upon, with the SDK as the front door for developers.

---

## 2. Why zero-trust — and why now

The corporate perimeter has dissolved. Cloud, remote work, third-party integrations, and software supply chains mean there is no longer an "inside" to trust — yet most enterprise systems still assume there is, and attackers exploit exactly that assumption.

- **The threat curve is going the wrong way.** Ransomware, credential theft, insider misuse, and supply-chain compromises keep rising in both frequency and cost; breach-cost studies consistently measure the average incident in the millions, and a single stolen credential or poisoned dependency can move laterally through a "trusted" network unchecked. AI is now accelerating both the volume and the sophistication of attacks.
- **Regulators have made it non-optional.** Zero-trust has moved from best practice to mandate — NIST SP 800-207, US Executive Order 14028, the EU's NIS2 directive, and DORA for financial services all push continuous verification, least privilege, and tamper-evident audit. Regulated buyers increasingly *require* these controls to be demonstrable, not merely asserted.
- **The model that replaces the perimeter is zero-trust:** *never trust, always verify; assume breach.* Every request is authenticated, authorized to the minimum necessary, and recorded — regardless of where it originates.

**The problem with most enterprise software:** it was built perimeter-first and bolts security on afterward — implicit trust between modules, mutable logs, coarse roles, secrets in config files. When (not if) something inside is compromised, there is little to contain it and little to prove what happened.

**Vortex inverts that.** Zero-trust is not a feature we added; it is the architecture of the kernel — so every module built on Vortex is born with it:

| Zero-trust principle | How Vortex enforces it, in the core |
|---|---|
| **Verify explicitly** | Every action is authenticated (sessions / scoped API tokens) and authorized by the Cedar policy engine before it runs — default-deny. |
| **Least privilege** | Attribute-based access control, per-request and per-field; API tokens are narrowly scoped; nothing is trusted by default. |
| **Assume breach — prove everything** | A WORM, hash-chained audit ledger (optionally HSM-signed) makes every state change tamper-evident and independently verifiable. |
| **Contain the blast radius** | Per-tenant database isolation — a compromise in one tenant cannot reach another tenant's data. |
| **Protect data everywhere** | Secrets encrypted at rest, modern TLS on all outbound calls, parameterized queries, no implicit trust between modules. |
| **Continuous, exportable evidence** | Policy decisions and state changes stream to SIEM formats (CEF / LEEF) for monitoring and forensics. |

**Why this is the thesis, not just a feature.** Security has crossed over from a compliance checkbox to a primary purchase driver — especially in the regulated, high-value industries Vortex targets. A platform that is **provably zero-trust by construction** lowers a buyer's breach risk and audit burden in one stroke: it shortens security reviews, commands premium pricing, and raises switching costs. And because every module inherits this posture for free, the advantage **compounds across the entire ecosystem** — one foundation, defended once, that protects every app built on top.

> In a world where breaches are inevitable, the platforms that win won't be the ones promising to keep attackers out — they'll be the ones that assume attackers are already in, and are built to verify, contain, and prove at every step. That is Vortex.

---
## 3. Architecture & platform stack

### The platform stack

<!-- STACK_DIAGRAM -->

The core (bottom) is what we own and harden. The **SDK** is the contract. Everything above it — modules, apps, and full verticals — is the ecosystem developers build, each one inheriting tenancy, security, audit, workflow, and integration for free.

### System architecture

Every request crosses a zero-trust boundary, is authenticated and authorized **before any handler runs**, and acts only on its own tenant's data — while audit, policy, and cryptography wrap the entire path. Core services and plugin modules run side by side on the same kernel; outbound integration (email, webhooks) is brokered through the durable job queue.

<!-- ARCH_DIAGRAM -->

---

## 4. Platform at a glance

| Aspect | Detail |
|---|---|
| Language / runtime | Rust, async (Tokio), Axum HTTP shell |
| Database | PostgreSQL — per-tenant databases + a primary registry DB |
| Frontend | Server-rendered HTML, progressive enhancement, no build step for core pages |
| Extensibility | `Plugin` trait — modules contribute routes, menus, migrations, reports, scheduled actions, translations |
| Deployment | On-prem first-class (incl. air-gapped); multi-tenant; core builds standalone with zero domain tables |
| Footprint | Core-only build carries no modules and no browser dependency; optional PDF backend behind a feature flag |

---

## 5. Zero-Trust Foundation

### 5.1 WORM cryptographic audit ledger
- Append-only audit log with a **SHA-256 hash chain** (each entry chains to the prior) — tamper-evident; optional **Ed25519 / HSM signatures**; dual-clock entries; canonical serialization so hashes/signatures are stable.
- Per-tenant scoping; database triggers + a restricted runtime role block out-of-band writes.
- CLI verification and export to standard SIEM formats (**JSONL / CEF / LEEF**); nightly automated chain verification.

### 5.2 Policy engine (attribute-based access control)
- **Cedar**-based ABAC. Database-backed policies loaded at startup; a single `check(principal, action, resource)` gate returns allow/deny with the determining policies. Default-deny.
- Admin Access Control UI for models, rules, and field-level access.

### 5.3 Key management & signing
- Pluggable signing backends: software keys for dev, **PKCS#11 HSM** (SoftHSM2, Thales Luna, Entrust nShield, YubiHSM 2, Utimaco) for production — private keys never enter the process.

---

## 6. Workflow & Approvals

- **Generic workflow engine** — a reusable state machine (states, transitions, guards) any module adopts.
- **Record stages & status bar** — user-managed stages and role-gated stage-button transitions over any model.
- **Approval workflow** — generic, multi-step sign-off attached to stage buttons: ordered steps, per-step approver role, quotas, no self-approval; applies the transition only on final approval. Inbox + on-record panel; approvers notified by email through the durable job queue.

---

## 7. Data, Persistence & Multi-Tenancy

- **ORM** with a connection pool, model trait, and a derive macro.
- **Multi-tenant pool manager** — per-tenant databases resolved at request time; a primary database holds cross-tenant registries and the job queue.
- **Database manager** (master-password protected) — create and migrate tenant databases.
- **Model registry** — runtime introspection of tables, fields, types, and relations; powers generic views, reports, and the REST API.
- **Universal sequence service** — configurable prefixes/padding/reset, available to any module.
- **Migration contract** — core migrations in the core; module migrations ship inside the module crate and are tracked independently, so modules install and upgrade cleanly.

---

## 8. Identity & Access

- Session-based authentication, **Argon2** password hashing, rate-limited login, `Secure` + `SameSite=Strict` cookies.
- Users, companies/tenants, roles; Users and Access Control admin UIs.
- Coarse role helpers plus fine-grained Cedar policy gating; the full identity lifecycle (login, role change, lock/unlock) is audited.

---

## 9. Records & Experience Primitives

These give a module a complete CRUD/UX surface for a model with minimal code:

- **Generic views** over any registered model — **List, Kanban, Graph, Calendar, Pivot** — with a hardened filter framework (saved filters, pagination).
- **Dynamic forms** — create/edit any registered model.
- **Chatter** — per-record message log, **@mentions**, scheduled activities, and an audit bridge: the collaboration/notification surface attachable to any record.
- **Field tracking** — records old→new changes into the record's history.
- **Audit-trail & attachments** — per-record history widget; file upload/download attached to any record (with checksum and size).

---

## 10. Shared Business Primitives

Generic building blocks every module reuses — not a finance product, just the math and metadata domain apps need:

- **Currency & exchange rates** — ISO-4217 seeds, time-series rates, conversion and rounding helpers.
- **Taxes & units of measure** — percent/fixed tax computation; category-scoped UoM conversion graph.
- **Internationalization** — locale model with fallback chain, database-backed translations, locale-aware date/number formatting, and a per-module translation hook.

---

## 11. Automation & Jobs

- **Scheduled actions / cron** — a supervisor runs database-defined scheduled actions; modules contribute their own; admin run-now/toggle UI. (Backs the nightly audit-chain verification.)
- **Durable background-job queue** — retryable, audited work. A central queue resolves the right tenant per job, claims work safely under concurrency, retries with **exponential backoff**, and **dead-letters** after a cap. Modules register their own job types; admin retry/cancel UI.

---

## 12. Reporting & Documents

- **Report engine** — module-declared reports delivered as **HTML / CSV / JSON**, every render audited.
- **No-code report builder** — non-developers compose reports from the model registry: pick a model, columns, filters, group-by, and aggregates, or author a sandboxed template; safe SQL generated from the registry. Dedicated author role and a reports hub.
- **PDF engine** — server-side HTML→PDF via headless Chromium (behind an optional feature flag); fully offline and deterministic with a self-hosted stylesheet (no external assets).

---

## 13. Integration Fabric

The surfaces that let Vortex participate in a customer's wider system landscape:

- **Outbound email / SMTP** — per-tenant mail servers with provider presets, secrets encrypted at rest, append-only send log, one-line send for any module.
- **Public REST API + tokens** — a bearer-authenticated `/api/v1` for machine-to-machine integration. Tokens act *as a user* (inherit roles), are hashed at rest, scoped (read vs write), per-tenant, revocable, shown once. Generic record CRUD over the model registry with strict allow-listing and full audit.
- **Outbound webhooks / event bus** — external systems **subscribe** to events instead of polling. Deliveries ride the durable job queue (retries, backoff, dead-letter) and are **HMAC-signed**; per-endpoint delivery log and a test-ping. Record changes emit events today; modules emit their own.

---

## 14. Security & Compliance Posture

- **Audit everything that changes state** — through the WORM ledger, never raw inserts; the hash chain makes tampering detectable.
- **Policy-gate user-facing actions** via Cedar; parameterized SQL throughout; identifier validation for any dynamic SQL; output escaping in templates.
- **Secrets** encrypted at rest (AES-256-GCM); session and token secrets stored only as hashes.
- **Hardening** — security-headers middleware, rate-limited auth, strict cookies; modern TLS without system OpenSSL for all outbound calls; dependency auditing; no unjustified `unsafe`.
- **Designed for regulated industries** — vertical compliance *profiles* (e.g. SOX, HIPAA, PCI-DSS, GDPR shapes) layer on top of these core primitives as modules, never baked into the core.

---

## 15. Build on Vortex — the SDK & module model

The core's reason for existing is to be built on. A module is a Rust crate that implements one trait and is dropped into the workspace — **no core changes required**.

- **One dependency, one contract.** The SDK re-exports the entire core surface plus pinned framework versions. A module declares its `routes`, menu entries, `migrations`, `reports`, `scheduled_actions`, `translations`, and a startup hook.
- **Everything is inherited.** A new module immediately gets multi-tenancy, identity, Cedar policy, the WORM audit ledger, workflow, generic views, the job queue, reporting, the REST API, and webhooks — for free.
- **Stable platform ABI.** Shared state is treated as a contract (additive only), so modules keep working across core releases.
- **Reference modules in-tree** demonstrate the pattern end-to-end (a CRM-style contacts module and a change-request module), and double as a developer starting point.

This is the wedge: the cost of building a compliant, multi-tenant enterprise app on Vortex is a fraction of building it from scratch — and the developer experience is a documented SDK, not a framework archaeology dig.

---

## 16. What can be built on Vortex

The core is domain-agnostic, but its primitives — tenant isolation, the WORM audit ledger, policy, workflow, approvals, the job queue, and the REST/webhook fabric — make it a particularly strong base for **asset-intensive, process-heavy, and regulated** applications. Illustrative modules and suites, each tied to the core capabilities it would build on:

### Enterprise & business operations

| Module | What it does | Builds on |
|---|---|---|
| **ERP** — Enterprise Resource Planning | Finance, procurement, inventory, sales, HR as one integrated suite | Multi-tenancy, ORM, sequences, commerce primitives, reporting |
| **CRM** — Customer Relationship Mgmt | Leads, opportunities, pipeline, activities | Records & chatter, generic views, workflow |
| **HRMS / HCM** — Human Capital | Employees, leave, payroll, org structure | Identity, approvals, workflow, documents |
| **PSA** — Professional Services Automation | Projects, timesheets, billing | Workflow, reporting, REST API |
| **S2P** — Source-to-Pay / Procurement | Requisitions, POs, supplier management, approvals | Approval workflow, sequences, email & webhooks |

### Asset, manufacturing & supply chain

| Module | What it does | Builds on |
|---|---|---|
| **EAM** — Enterprise Asset Management | Asset register, maintenance, work orders, spares — *a natural Vortex flagship* | Records, workflow, scheduler, audit |
| **CMMS** — Maintenance Management | Preventive & corrective maintenance scheduling | Scheduler, job queue, work-order workflow |
| **MRP** — Material Requirements Planning | Demand/supply planning, BOM explosion | Commerce/UoM, jobs (planning runs), reporting |
| **MES** — Manufacturing Execution | Shop-floor execution, traceability, machine data | Job queue, webhooks (machine/IoT), audit trail |
| **PLM** — Product Lifecycle Management | Engineering BOMs, change/ECO control | Workflow, approvals, audit |
| **WMS / SCM** — Warehouse & Supply Chain | Warehouse ops, logistics, supplier networks | Multi-tenancy, ORM, REST API integrations |

### Regulated & compliance-intensive — Vortex's sweet spot

| Module | What it does | Builds on |
|---|---|---|
| **QMS** — Quality Management | NCRs, CAPA, audits, document control | WORM audit, approvals, e-signature, workflow |
| **GRC** — Governance, Risk & Compliance | Controls, risk register, attestations | Policy engine, audit ledger, approvals |
| **LIMS** — Lab Information Management | Sample tracking, results, instrument data | Audit trail, workflow, webhooks |
| **EHS / HSE** — Environment, Health & Safety | Incidents, permits-to-work, safety audits | Workflow, approvals, scheduler |
| **GxP / 21 CFR Part 11** — Validated records | Tamper-proof e-records & e-signatures for FDA/GxP | WORM ledger + cryptographic signing + approvals |

### What's possible next

Because the foundation is already solved, more ambitious applications become straightforward to build:

- **IoT & predictive maintenance** — stream telemetry in via webhooks/REST, score asset health on the job queue, and route alerts through approvals and email; a natural extension of EAM/MES.
- **AI copilots over governed data** — every action is policy-gated and written to a tamper-proof ledger, so LLM-driven assistants can *read and act* through the REST API safely, with a complete audit trail — a differentiator few platforms can offer.
- **Low-code app composition** — the model registry already turns a data model into List/Kanban/Calendar/Pivot screens; a studio layer would let business analysts assemble apps with no code.
- **Partner-built vertical suites & a module marketplace** — third parties package and monetize domain modules and compliance profiles on top of the SDK.
- **Embedded / white-label** — ISVs ship Vortex-powered products under their own brand.

> Each of these is a **module on the same core** — so one investment in tenancy, security, and audit serves the entire portfolio, and every new module makes the platform more valuable to the next builder.

---

## 17. Roadmap & ecosystem pipeline

### Core platform roadmap

| Now — shipped | Next — in build | Horizon |
|---|---|---|
| Zero-trust kernel (audit, policy, signing) | Scheduled report delivery | Module marketplace & registry |
| Workflow + approvals | Object-store attachments backend | Entitlement / licensing for paid modules |
| Multi-tenant data + model registry | Per-tenant configuration UI | Packaged compliance profiles |
| Reporting, no-code builder, PDF | Settings-driven UI (low-code) | Multi-region + KMS-backed unseal |
| Durable job queue | API descriptor (OpenAPI) + per-model policies | Managed cloud offering |
| REST API + tokens, webhooks, email | SDK developer guide & templates | Partner certification program |

### The ecosystem opportunity

Domain capability is deliberately **outside** the core — that boundary is the platform's leverage. The example modules in §16 (ERP, EAM, MRP, MES, QMS, GRC and more), regulated verticals (healthcare, energy & utilities, financial services, public sector), and SDK-built integrations are all revenue surfaces that we, partners, and customers can build and monetize. Each reaches market faster *because* the foundation is solved — and each strengthens the platform's pull for the next builder.

---

## 18. Appendix — Request lifecycle

A concrete trace of a single governed write: an external system creates a record through the REST API, and the change cascades through authorization, persistence, audit, and event delivery — every step isolated to one tenant and recorded. This is the zero-trust architecture (§2–§3) in motion.

<!-- FLOW_DIAGRAM -->

Notable properties: authorization happens **before** any business logic; the data write and its audit entry are part of the same governed path; and outbound delivery is decoupled through the durable queue, so a slow or failing subscriber never blocks — or loses — the event.

---

*Confidential. Prepared for stakeholders and investors. The core platform builds standalone today; the items above describe the trajectory, not current shipping state where marked "Next" or "Horizon."*
