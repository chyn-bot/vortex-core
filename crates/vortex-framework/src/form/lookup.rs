//! Signed lookup descriptors for the many2one **typeahead** widget.
//!
//! A reference field used to render as a `<select>` with every candidate row
//! materialised as an `<option>` — fine for a handful of records, unusable
//! when a table holds thousands of partners. The typeahead replaces that with
//! a search-as-you-type input backed by `GET /api/lookup`.
//!
//! The security problem this module solves: the browser must tell the endpoint
//! *what to search*, but it must not be able to point the endpoint at an
//! arbitrary table/column (an authenticated user asking for
//! `users.password_hash` would be a data breach). So the server never trusts a
//! table/column name from the client. Instead it authors a [`LookupSource`],
//! **HMAC-signs** it into an opaque token ([`LookupSource::encode`]), and embeds
//! that token in the widget. The browser echoes the token back verbatim; the
//! endpoint [`decode`](LookupSource::decode)s it and only runs the query if the
//! signature verifies. A tampered or forged descriptor is rejected before any
//! SQL is built. Because the whole descriptor is signed, an optional
//! server-authored `filter` predicate is safe to interpolate — the client
//! cannot alter it without invalidating the signature.

use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use vortex_security::crypto;

use super::ident;
use crate::ui::html_escape;

/// Max rows a single suggestion query returns. Enough to fill the dropdown;
/// the user narrows further by typing.
const SUGGEST_LIMIT: i64 = 20;

/// What a typeahead searches. Authored server-side, never accepted from the
/// client except as a signed [token](LookupSource::encode).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LookupSource {
    /// Table to search (validated as a SQL identifier before use).
    pub table: String,
    /// Column shown to the user and matched with `ILIKE` (default `name`).
    pub display: String,
    /// Optional server-authored SQL predicate ANDed into the `WHERE`, e.g.
    /// `contact_type IN ('customer','both')`. Safe to interpolate **only**
    /// because the descriptor is signed; never build this from client input.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter: Option<String>,
}

impl LookupSource {
    /// Search `table.display` (display column defaults to `name`).
    pub fn new(table: &str, display: &str) -> Self {
        Self { table: table.to_string(), display: display.to_string(), filter: None }
    }

    /// Search with a server-authored `WHERE` predicate (e.g. only customers).
    pub fn with_filter(table: &str, display: &str, filter: &str) -> Self {
        Self {
            table: table.to_string(),
            display: display.to_string(),
            filter: Some(filter.to_string()),
        }
    }

    /// Sign this descriptor into an opaque `"{hex(json)}.{hmac}"` token. The
    /// payload is not secret (it authorises reading exactly the rows the form
    /// already shows); the signature is what stops a client forging a
    /// different table/column/filter.
    pub fn encode(&self) -> String {
        let json = serde_json::to_vec(self).unwrap_or_default();
        let payload = hex::encode(json);
        let sig = crypto::hmac_sha256_hex(&crypto::master_key(), payload.as_bytes());
        format!("{payload}.{sig}")
    }

    /// Verify and parse a token produced by [`encode`](Self::encode). Returns
    /// `None` for any malformed, tampered, or unsigned token — the caller must
    /// treat that as "refuse to search", never as an empty descriptor.
    pub fn decode(token: &str) -> Option<Self> {
        let (payload, sig) = token.split_once('.')?;
        let expected = crypto::hmac_sha256_hex(&crypto::master_key(), payload.as_bytes());
        if !ct_eq(sig.as_bytes(), expected.as_bytes()) {
            return None;
        }
        let json = hex::decode(payload).ok()?;
        let src: LookupSource = serde_json::from_slice(&json).ok()?;
        // Defence in depth: even a validly-signed descriptor must name legal
        // identifiers before it reaches a query string.
        if !ident(&src.table) || !ident(&src.display) {
            return None;
        }
        Some(src)
    }

    /// Run the suggestion query: rows whose `display` matches `q` (substring,
    /// case-insensitive), newest-relevant first, capped at [`SUGGEST_LIMIT`].
    /// Returns `(id, label)` pairs. `table`/`display` are identifier-validated
    /// here too so this is safe to call on a decoded descriptor.
    pub async fn search(&self, db: &PgPool, q: &str) -> Vec<(String, String)> {
        if !ident(&self.table) || !ident(&self.display) {
            return Vec::new();
        }
        let table = &self.table;
        let display = &self.display;
        let filter = self
            .filter
            .as_deref()
            .map(|f| format!(" AND ({f})"))
            .unwrap_or_default();
        let sql = format!(
            "SELECT id::text, {display}::text FROM {table} \
             WHERE COALESCE(active, true){filter} AND {display} ILIKE $1 \
             ORDER BY {display} LIMIT {SUGGEST_LIMIT}"
        );
        sqlx::query_as::<_, (String, String)>(&sql)
            .bind(ilike_pattern(q))
            .fetch_all(db)
            .await
            .unwrap_or_default()
    }

    /// Resolve a single id to its display label — used to pre-fill the visible
    /// input in Edit mode without loading the whole candidate list.
    pub async fn label_for(&self, db: &PgPool, id: &str) -> Option<String> {
        if id.is_empty() || !ident(&self.table) || !ident(&self.display) {
            return None;
        }
        let sql = format!(
            "SELECT {}::text FROM {} WHERE id::text = $1",
            self.display, self.table
        );
        sqlx::query_scalar::<_, String>(&sql)
            .bind(id)
            .fetch_optional(db)
            .await
            .ok()
            .flatten()
    }
}

/// Wrap a user query as a safe `ILIKE` pattern: the LIKE metacharacters
/// `%` `_` `\` are escaped so a search for `50%` matches literally rather than
/// "anything". The value is still bound as a parameter — this only stops the
/// *pattern* from being abused, not SQL injection (which binding already
/// prevents).
fn ilike_pattern(q: &str) -> String {
    let escaped = q.replace('\\', "\\\\").replace('%', "\\%").replace('_', "\\_");
    format!("%{escaped}%")
}

/// Constant-time byte comparison, so signature verification does not leak how
/// many leading bytes matched via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

/// Render a reference field as a typeahead: a visible search input carrying the
/// current *label*, a hidden input carrying the id that actually submits under
/// `name`, and an empty menu the client script fills as the user types.
///
/// `token` is a signed [`LookupSource`]. `value_id`/`value_label` pre-fill the
/// field in Edit mode (pass empty strings for a blank Create field). Server-side
/// validation still enforces `required`; the marker here drives the client's
/// "you must pick from the list" guard and dirty-tracking.
pub fn typeahead_widget(
    name: &str,
    token: &str,
    value_id: &str,
    value_label: &str,
    required: bool,
    readonly: bool,
    placeholder: Option<&str>,
) -> String {
    let name = html_escape(name);
    let token = html_escape(token);
    let id = html_escape(value_id);
    let label = html_escape(value_label);
    let ph = html_escape(placeholder.unwrap_or("Type to search…"));
    let req = if required { " data-ta-required" } else { "" };
    let hidden_req = if required { " required" } else { "" };
    let disabled = if readonly { " disabled" } else { "" };
    format!(
        r#"<div class="vortex-ta" data-vortex-typeahead>
<input type="text" class="input input-bordered w-full" value="{label}" data-ta-src="{token}"{req} placeholder="{ph}" autocomplete="off" role="combobox" aria-autocomplete="list" aria-expanded="false"{disabled}/>
<input type="hidden" name="{name}" value="{id}" data-vortex-dirty{hidden_req}/>
<ul class="vortex-ta-menu menu" role="listbox" hidden></ul>
</div>"#
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_descriptor() {
        let src = LookupSource::new("contacts", "name");
        let token = src.encode();
        assert_eq!(LookupSource::decode(&token), Some(src));
    }

    #[test]
    fn round_trips_a_filtered_descriptor() {
        let src = LookupSource::with_filter("contacts", "name", "contact_type IN ('customer')");
        let token = src.encode();
        assert_eq!(LookupSource::decode(&token), Some(src));
    }

    #[test]
    fn rejects_a_tampered_payload() {
        let token = LookupSource::new("contacts", "name").encode();
        let (payload, sig) = token.split_once('.').unwrap();
        // Flip the descriptor to point at another table, keep the old sig.
        let forged_payload = hex::encode(br#"{"table":"users","display":"password_hash"}"#);
        let forged = format!("{forged_payload}.{sig}");
        assert_eq!(LookupSource::decode(&forged), None);
        // A signature that isn't ours is rejected too.
        assert_eq!(LookupSource::decode(&format!("{payload}.deadbeef")), None);
    }

    #[test]
    fn rejects_signed_but_illegal_identifiers() {
        // Even correctly signed, an injection-shaped table name is refused.
        let src = LookupSource::new("users; DROP TABLE x", "name");
        assert_eq!(LookupSource::decode(&src.encode()), None);
    }

    #[test]
    fn escapes_like_metacharacters() {
        assert_eq!(ilike_pattern("50%"), "%50\\%%");
        assert_eq!(ilike_pattern("a_b"), "%a\\_b%");
        assert_eq!(ilike_pattern("plain"), "%plain%");
    }

    #[test]
    fn widget_wires_hidden_name_and_signed_src() {
        let html = typeahead_widget("partner_id", "tok.sig", "abc", "Acme Bhd", true, false, None);
        assert!(html.contains(r#"name="partner_id""#));
        assert!(html.contains(r#"data-ta-src="tok.sig""#));
        assert!(html.contains(r#"value="abc""#)); // hidden id
        assert!(html.contains("Acme Bhd")); // visible label
        assert!(html.contains("data-ta-required"));
    }
}
