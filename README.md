# Vortex Core

[![CI](https://github.com/chyn-bot/vortex-core/actions/workflows/ci.yml/badge.svg)](https://github.com/chyn-bot/vortex-core/actions/workflows/ci.yml)

**Vortex is a horizontal, multi-tenant, zero-trust ERP platform written in Rust.**
The core ships the kernel — persistence, identity, audit, policy, workflow,
multi-tenancy, plugin loading, and the HTTP shell — and every domain-specific
capability ships as a **plugin crate**. It is designed for regulated-industry
deployments: compliance profiles layer on top of generic core primitives, never
baked into the core.

- **Backend:** Rust (Axum) + PostgreSQL
- **Frontend:** vanilla-JS micro-framework served as static files — no npm, no
  build step, fully auditable
- **Auth:** session-based, LDAP federation
- **Audit:** WORM ledger with SHA-256 hash chaining and optional Ed25519 signatures

## Architecture

Verticals ship as plugin crates; the in-tree examples are Change Request
(`vortex-change`) and the Contacts reference plugin (`vortex-contacts`). Anything
that assumes a specific industry, regulator, or geography lives in a plugin, not
the core.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full platform contract:
what the core guarantees, what plugins provide, the `Plugin` trait, migration
ownership, and deployment shapes. Working guidance for contributors is in
[`CLAUDE.md`](CLAUDE.md).

```
vortex-core/
├── crates/
│   ├── vortex-common/   vortex-macros/   vortex-orm/
│   ├── vortex-security/ vortex-policy/   vortex-workflow/
│   ├── vortex-module/   vortex-framework/ vortex-chatter/
│   ├── vortex-server/   vortex-cli/      vortex-plugin-sdk/
│   ├── vortex-change/   # vertical plugin — change requests
│   └── vortex-contacts/ # reference plugin — contacts / CRM
├── migrations/          # core migrations only
└── docs/                # architecture + feature/design docs
```

## Documentation

| Doc | What it covers |
|---|---|
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Platform vs. vertical contract; the `Plugin` trait |
| [CORE_FEATURES.md](docs/CORE_FEATURES.md) | Core primitives available to every vertical |
| [FEATURES.md](docs/FEATURES.md) | Feature catalogue |
| [ODOO_PARITY.md](docs/ODOO_PARITY.md) | Capability mapping against Odoo |
| [BLUEPRINTS_DESIGN.md](docs/BLUEPRINTS_DESIGN.md) | Governed runtime no-code app builder |
| [INTAKE_DESIGN.md](docs/INTAKE_DESIGN.md) | Governed public web-forms + interactive portal (✅ shipped) |
| [mobile-field-auth.md](docs/mobile-field-auth.md) | Mobile / field-app authentication |
| [DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md) | Backup & recovery procedures |

## Build & test

Each crate compiles independently. Plugins depend on `vortex-framework` and the
core crates they need — never on `vortex-cli` or `vortex-server`.

```sh
cargo build                                   # full workspace
cargo build -p vortex-cli --no-default-features   # core-only (no plugins)
cargo test                                    # unit + integration tests
```

## Continuous integration

[`ci.yml`](.github/workflows/ci.yml) runs on every push and pull request:

- **test** — `cargo build` + `cargo test` across the workspace.
- **smoke** — provisions a fresh tenant against a real Postgres, boots the
  server, crawls every reachable page (nothing may 5xx), and exercises the
  attachment / chatter / report lifecycles end to end.
- **audit** — `cargo audit` supply-chain check.

The badge above reflects the latest run on the default branch.
