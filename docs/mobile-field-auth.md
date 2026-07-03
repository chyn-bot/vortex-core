# Vortex Mobile Field API — Authentication & Sync Guide

**Audience:** the app development team building the SESB field-technician app (or
any first-party mobile client).
**Status:** implemented in Vortex core (migration `132_mobile_auth`,
`vortex_framework::mobile_auth`, `/api/v1/auth/*`). Verified end-to-end.

---

## 1. The model in one picture

A field technician is offline for most of a shift. So we split responsibility:

```
 ┌─────────────────────────────┐        ┌──────────────────────────────┐
 │  APP (offline)              │        │  VORTEX (only reached on sync)│
 │  • device unlock (biometric)│        │  • access token → every call  │
 │    guards the local data    │        │  • refresh token → mint the   │
 │  • work is written to an     │  sync  │    next access token          │
 │    encrypted local queue     │◀──────▶│  • Cedar policy gates each    │
 │  • no server token needed    │        │    call; audit is WORM-logged │
 └─────────────────────────────┘        └──────────────────────────────┘
```

- **Access token** — short-lived (default **1 hour**). Sent as
  `Authorization: Bearer` on *every* API call.
- **Refresh token** — long-lived (default **30 days**). Used *only* to mint the
  next access token when connectivity returns. Size it to your worst realistic
  offline gap; it is the thing that survives an offline shift.
- Tokens are **opaque and server-side** (not JWTs). That means a lost device is
  killed instantly server-side — one revoke, and the token is dead. There is no
  "valid until expiry" window you can't close.

**Golden rule for the client:** never block the technician's work on a token.
Only *sync* needs a live token. If the access token expired while offline, the
app silently refreshes on reconnect and replays its queue.

---

## 2. Conventions

- **Base URL:** `https://<host>` (TLS is mandatory — never send tokens over
  plain HTTP).
- **Tenant selection:** every request names its database. Two equivalent ways:
  - header `X-Vortex-Database: <db>` (use this for all calls), **or**
  - `"database": "<db>"` in the JSON body of `login` / `refresh`.
  For SESB this is the SESB tenant DB name (e.g. `gaia` in the test
  environment). Ask ops for the production value.
- **Content types:** auth endpoints take/return **JSON**. Some work-order
  endpoints take **form-encoded** bodies (called out below — read carefully).
- **Auth header:** `Authorization: Bearer <access_token>`.
- **Error envelope:** `{ "error": { "code": "...", "message": "..." } }` with a
  matching HTTP status.

---

## 3. Auth flow

```
  login(username, password, device)
        │
        ▼
  { access_token, refresh_token, expires_in, refresh_expires_in, user }
        │
        │  use access_token on every API call ─────────────► 200 / data
        │
        │  access_token expired? (401) ──► refresh(refresh_token)
        │                                       │
        │                                       ▼
        │                          { new access_token, new refresh_token }
        │                          (old access + old refresh now dead)
        │
  logout(access_token)  ──►  whole device session revoked
```

**Refresh rotation:** every refresh returns a **new** refresh token and
invalidates the one you presented. Always store the newest. If a refresh token
is presented twice (theft signal), the **entire device session is revoked** and
everyone must log in again — see `refresh_reuse_detected` below.

---

## 4. Endpoints

### 4.1 `POST /api/v1/auth/login` — exchange credentials for tokens

Public, rate-limited (10 requests / 60 s per IP).

**Request**
```json
{
  "username": "fa001",
  "password": "········",
  "database": "gaia",
  "device_id": "a3f1c9-installation-uuid",
  "device_name": "Ahmad — Galaxy A54"
}
```
- `device_id` (recommended): a stable, app-generated identifier for the install.
  Powers the "your devices" list and per-device revocation.
- `device_name` (optional): human label for that list.
- `database` may be omitted if you send `X-Vortex-Database`.
- `scopes` (optional): defaults to `["write"]` so a technician can complete
  work orders. Policy still governs what the user may actually do.
- `mfa_code` (optional): a 6-digit authenticator code — **required only when
  logging in a *new* device for an MFA-enabled user** (see §4a). Omit on a
  device that has logged in before.

**Response `200`**
```json
{
  "access_token":  "vtxa_…",
  "refresh_token": "vtxr_…",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_expires_in": 5184000,
  "database": "gaia",
  "user": { "id": "…uuid…", "username": "fa001", "full_name": "…", "roles": ["…"] }
}
```
`expires_in` / `refresh_expires_in` are seconds. `401 invalid_credentials` on a
bad username/password/disabled/locked account.

```bash
curl -X POST https://<host>/api/v1/auth/login \
  -H 'Content-Type: application/json' -H 'X-Vortex-Database: gaia' \
  -d '{"username":"fa001","password":"secret","device_id":"dev-1","device_name":"Ahmad A54"}'
```

### 4a. Multi-factor authentication (enroll-time MFA)

MFA is enforced **once, when a new device is enrolled** — never on every login,
and never mid-shift (that would be unworkable offline). A device that has logged
in before is trusted and skips the code; silent refresh is never challenged.

There are two situations the client must handle after a *correct password* on a
new device:

**A) The user has never set up MFA** → `login` returns `401` with a provisioning
secret. Show it as a QR code (`otpauth_uri`) or the `secret` string, have the
user add it to their authenticator, then confirm via `/api/v1/auth/mfa/enroll`.
```json
{ "error": { "code": "mfa_enrollment_required", "message": "…" },
  "mfa": {
    "secret": "2RAZ4U66O2MGGHFYBBW7RNCIYTD3POFF",
    "otpauth_uri": "otpauth://totp/Vortex:fa001?secret=…&issuer=Vortex&algorithm=SHA1&digits=6&period=30",
    "issuer": "Vortex", "account": "fa001" } }
```

**B) The user already has MFA** → `login` on a new device returns `401`
`{"error":{"code":"mfa_required"}}`. Re-submit `login` with the `mfa_code`
field set to the current 6-digit code.

#### `POST /api/v1/auth/mfa/enroll` — confirm first-time setup

Public, rate-limited. Verifies password + the first code against the pending
secret from case (A), enables MFA, and returns the first token pair (same shape
as a successful login).
```json
{ "username": "fa001", "password": "········", "code": "946104",
  "device_id": "phone-1", "device_name": "Ahmad — Galaxy A54" }
```
Errors: `401 mfa_invalid_code` (wrong/expired code), `400 no_pending_enrollment`
(call `login` first to get a secret), `401 invalid_credentials`.

**Client rule of thumb:** on `login` → if `mfa_enrollment_required`, run the
QR-setup screen then call `/mfa/enroll`; if `mfa_required`, prompt for the code
and re-call `login` with `mfa_code`. Codes tolerate ±30 s of clock skew, so keep
the device clock roughly correct.

### 4.2 `POST /api/v1/auth/refresh` — rotate for a fresh pair

Public, rate-limited. Present the **latest** refresh token.

**Request**
```json
{ "refresh_token": "vtxr_…", "database": "gaia" }
```
**Response `200`** — same token shape as login (no `user` block). **Store the
new `refresh_token`; the old one is now dead.**

Error codes (all HTTP `401`) — **the app must branch on these:**

| `error.code`             | Meaning                                        | App action |
|--------------------------|------------------------------------------------|------------|
| `refresh_expired`        | Refresh token past its lifetime                | Prompt re-login. **Keep the offline queue.** |
| `refresh_reuse_detected` | A consumed refresh was replayed → session revoked | Force re-login. Treat as a possible compromise. |
| `invalid_refresh`        | Unknown / malformed / revoked token            | Force re-login. |

### 4.3 `POST /api/v1/auth/logout` — end this device session

Bearer-authenticated. Revokes the whole family (this device's access **and**
refresh tokens). Idempotent.
```bash
curl -X POST https://<host>/api/v1/auth/logout \
  -H 'Authorization: Bearer vtxa_…' -H 'X-Vortex-Database: gaia'
```

### 4.4 `GET /api/v1/auth/me` — current identity

Bearer-authenticated.
```json
{ "user": { "id":"…","username":"fa001","full_name":"…","roles":["…"] },
  "scopes": ["write"], "database": "gaia" }
```

### 4.5 `GET /api/v1/auth/devices` — active sessions for this user

Bearer-authenticated. One entry per live device login.
```json
{ "devices": [
  { "family_id":"…uuid…", "device_id":"dev-1", "device_name":"Ahmad A54",
    "last_used_at":"…", "created_at":"…", "expires_at":"…" }
]}
```

### 4.6 `POST /api/v1/auth/devices/{family_id}/revoke` — kill a device

Bearer-authenticated. Revokes one of the current user's device sessions (lost or
decommissioned phone). `404 not_found` if the `family_id` isn't an active
session of this user. `200 { "ok": true, "revoked": <n> }` on success.

---

## 5. Calling the work-order API

Once logged in, the access token authenticates **every** Vortex API surface —
both `/api/v1/*` and the SESB EAM plugin routes under `/sesb-eam/api/v1/*`. Send
the same two headers on all of them:

```
Authorization: Bearer <access_token>
X-Vortex-Database: gaia
```

The token *acts as the technician* and inherits their roles; Cedar policy gates
every call, so a technician only sees/does what they're permitted to.

Key technician endpoints (all JSON responses unless noted):

| Method & path | Purpose |
|---|---|
| `GET  /sesb-eam/api/v1/ping` | Connectivity probe (also works unauthenticated-cheap). |
| `GET  /sesb-eam/api/v1/me` | Technician profile + active-job count. |
| `GET  /sesb-eam/api/v1/maintenance?assigned_to_me=1` | **The technician's assigned work orders.** Supports `state=`, `limit=`, `offset=`. |
| `GET  /sesb-eam/api/v1/maintenance/{id}` | One work order + its checklist. |
| `POST /sesb-eam/api/v1/maintenance/{id}/action` | Advance the work order. **Form-encoded.** |
| `POST /sesb-eam/api/v1/maintenance/{id}/checklist/line/{line_id}` | Record a checklist result. Form-encoded. |
| `GET/POST /sesb-eam/api/v1/defects` | List / raise defects. |
| `GET/POST /sesb-eam/api/v1/location` | Read / push GPS pings. |

**Always pull the technician's own queue with `?assigned_to_me=1`** — that
filter scopes the list to work orders where `assigned_to = <this user>`.

**List envelope** (all list endpoints):
```json
{ "total": 12, "count": 12, "offset": 0, "limit": 50, "results": [ … ] }
```

**Work-order state machine** (`POST …/action`, body `action=<verb>`,
`Content-Type: application/x-www-form-urlencoded`):

| verb | allowed from | → new state | notes |
|---|---|---|---|
| `accept` / `start` | `scheduled`, `assigned` | `in_progress` | stamps acceptance + start |
| `reject` | `scheduled`, `assigned` | `scheduled` (unassigned) | send `reason=…` |
| `hold` | `in_progress` | `on_hold` | |
| `resume` | `on_hold` | `in_progress` | |
| `complete` | `in_progress`, `on_hold` | `completed` | **all required checklist items must be filled** or you get `409` |

```bash
# accept a work order
curl -X POST https://<host>/sesb-eam/api/v1/maintenance/<id>/action \
  -H 'Authorization: Bearer vtxa_…' -H 'X-Vortex-Database: gaia' \
  -H 'Content-Type: application/x-www-form-urlencoded' -d 'action=accept'
```

Every action is WORM-audited against the technician's identity, so completing a
work order offline and syncing it later still attributes the change correctly.

---

## 6. Offline sync — how the client should behave

The server gives you the primitives; the offline UX is the client's job. Build
it like this:

1. **On (re)login while online:** pull assigned work orders
   (`?assigned_to_me=1`) and their detail/checklists into local storage.
2. **Offline:** gate the app with **device unlock (biometric/PIN)**. The
   technician accepts, fills checklists, completes, raises defects, captures GPS
   — all written to a **local mutation queue**, each entry carrying an
   **idempotency key** you generate.
3. **On reconnect:**
   - If the access token is still valid, replay the queue.
   - If a call returns `401`, call **refresh** once, then retry. On
     `refresh_expired` / `invalid_refresh` / `refresh_reuse_detected`, prompt
     re-login **without discarding the queue** — replay after the user
     re-authenticates.
4. **Idempotency:** the same queued mutation may be retried after a flaky
   connection. Because a `complete` on an already-completed WO is an *illegal
   transition* (rejected), and actions are state-guarded, retries are safe — but
   still de-duplicate client-side by idempotency key so you don't double-submit
   checklist values or GPS rows.
5. **Conflict:** if the server state moved (e.g. the WO was reassigned), an
   action returns `409`/illegal-transition. Surface it and re-pull that WO.

**Silent-refresh pseudocode (the token manager):**
```
async function apiCall(req):
    res = send(req, bearer=accessToken)
    if res.status == 401 and not req.isRetry:
        pair = POST /api/v1/auth/refresh { refresh_token: refreshToken }
        if pair.ok:
            accessToken  = pair.access_token
            refreshToken = pair.refresh_token          # rotate — store the new one
            return apiCall(req.markRetry())
        else:
            enqueueForLater(req); requireLogin(pair.error.code)   # keep the queue
    return res
```

---

## 7. Security requirements for the client

These are not optional for a regulated utility deployment:

- **TLS only**, and pin the server certificate.
- **Encrypt the local store**; bind the key to device unlock (biometric/PIN).
  Work-order and asset data is sensitive.
- **Never log tokens** or write them to plaintext files/analytics.
- Store tokens in the platform keystore (iOS Keychain / Android Keystore), not
  in shared prefs.
- On logout or detected compromise, wipe the local store and call
  `/api/v1/auth/logout`.
- **MFA is enforced at device enrollment** (see §4a) — a new device is
  challenged once, then trusted; reconnect/refresh is never challenged. Render
  the `otpauth_uri` as a QR code and store the `secret` only transiently in
  memory during setup.

---

## 8. Rate limits & tuning

- `login` and `refresh`: **10 requests / 60 s per IP** → `429 Too Many Requests`.
  Back off; don't hammer.
- Token lifetimes are server-configured (env), so ops can tune per deployment:
  - `VORTEX_MOBILE_ACCESS_TTL_SECS` (default `3600`)
  - `VORTEX_MOBILE_REFRESH_TTL_DAYS` (default `30`)
  Use `expires_in` / `refresh_expires_in` from the responses — **don't hardcode
  lifetimes** in the client.

---

## 9. Quick reference

| Action | Call |
|---|---|
| Log in | `POST /api/v1/auth/login` |
| Enroll MFA (first setup) | `POST /api/v1/auth/mfa/enroll` |
| Refresh tokens | `POST /api/v1/auth/refresh` |
| Log out (this device) | `POST /api/v1/auth/logout` |
| Who am I | `GET /api/v1/auth/me` |
| My devices | `GET /api/v1/auth/devices` |
| Revoke a device | `POST /api/v1/auth/devices/{family_id}/revoke` |
| My work orders | `GET /sesb-eam/api/v1/maintenance?assigned_to_me=1` |
| Work-order detail | `GET /sesb-eam/api/v1/maintenance/{id}` |
| Advance a work order | `POST /sesb-eam/api/v1/maintenance/{id}/action` (form) |
| Record checklist line | `POST /sesb-eam/api/v1/maintenance/{id}/checklist/line/{line_id}` (form) |

All calls except `login` / `refresh` require
`Authorization: Bearer <access_token>` and `X-Vortex-Database: <db>`.
