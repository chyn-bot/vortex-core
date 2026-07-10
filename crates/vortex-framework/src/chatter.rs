//! On-record **activity stream** (chatter) embed — a reusable SDK primitive.
//!
//! The panel itself (Messages feed, **Activities** with schedule / assign-to-
//! another-user / due-date / mark-complete, and Attachments) is rendered by the
//! host's generic `GET /partials/chatter/{model}/{id}` handler and its sibling
//! `POST /api/chatter/...` routes. All of that already exists and is model-
//! agnostic; what was missing is a uniform way for every plugin record page to
//! *embed* it, next to [`crate::audit_trail::render_audit_trail`] and
//! [`crate::approval::render_for_record`].
//!
//! [`render_chatter_panel`] returns that embed: a lazily-loaded `#activity-
//! stream` container. Because plugin page shells don't ship htmx (the panel's
//! forms are htmx-driven), the embed is **self-contained** — it ensures htmx is
//! loaded, then fetches the panel and wires it up. A plugin only has to drop the
//! returned string into its record page's side column; no shell changes needed.
//!
//! Usage from a plugin record page (mirrors `render_audit_trail`):
//! ```ignore
//! let activity_panel =
//!     vortex_plugin_sdk::framework::render_chatter_panel("contacts", id);
//! // …then place `{activity_panel}` in the page's right-hand column.
//! ```

use uuid::Uuid;

/// Emit the record's activity-stream panel.
///
/// `model` is the record's canonical model key (e.g. `"contacts"`,
/// `"maint_asset"`, `"acc_move"`). It scopes messages and activities to this
/// entity and must stay **stable** for the record. Only identifier-safe keys
/// are accepted — anything else returns an empty string rather than emit a
/// broken URL or risk markup injection.
///
/// The returned markup lazy-loads `/partials/chatter/{model}/{record_id}` into
/// `#activity-stream`; the panel's own forms/buttons target `#activity-stream`
/// so posting a message, scheduling an activity, or marking one done re-renders
/// the panel in place. There is one activity stream per record page (the id is
/// fixed), which is exactly the one-record-per-page shape of a detail view.
pub fn render_chatter_panel(model: &str, record_id: Uuid) -> String {
    let ident_ok = !model.is_empty()
        && model.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !ident_ok {
        return String::new();
    }

    // The loader boots the panel once the DOM is ready. It reuses htmx when the
    // host page already ships it (CLI-rendered pages do) and otherwise loads it
    // on demand — so this works identically on plugin pages, which don't.
    format!(
        r#"<div id="activity-stream" class="sticky top-4">
  <div class="card bg-base-100 shadow"><div class="card-body">
    <div class="flex items-center justify-center py-8"><span class="loading loading-spinner loading-md"></span></div>
  </div></div>
</div>
<script>
(function () {{
  var url = '/partials/chatter/{model}/{id}';
  function boot() {{
    fetch(url, {{ credentials: 'same-origin' }})
      .then(function (r) {{ return r.text(); }})
      .then(function (html) {{
        var panel = document.getElementById('activity-stream');
        if (!panel) return;
        panel.innerHTML = html;
        if (window.htmx) window.htmx.process(panel);
      }})
      .catch(function () {{
        var panel = document.getElementById('activity-stream');
        if (panel) panel.innerHTML =
          '<div class="card bg-base-100 shadow"><div class="card-body text-center text-base-content/60">Activity stream unavailable</div></div>';
      }});
  }}
  function ensureHtmxThenBoot() {{
    if (window.htmx) {{ boot(); return; }}
    var existing = document.getElementById('vortex-htmx');
    if (existing) {{ existing.addEventListener('load', boot); return; }}
    var s = document.createElement('script');
    s.id = 'vortex-htmx';
    s.src = '/static/vendor/htmx.min.js';
    s.onload = boot;
    s.onerror = boot; // still show the panel (read-only) even if htmx fails
    document.head.appendChild(s);
  }}
  if (document.readyState === 'loading') {{
    document.addEventListener('DOMContentLoaded', ensureHtmxThenBoot);
  }} else {{
    ensureHtmxThenBoot();
  }}
}})();
</script>"#,
        model = model,
        id = record_id,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn emits_container_and_loader_for_valid_model() {
        let html = render_chatter_panel("contacts", Uuid::nil());
        assert!(html.contains(r#"id="activity-stream""#));
        assert!(html.contains("/partials/chatter/contacts/00000000-0000-0000-0000-000000000000"));
        assert!(html.contains("htmx.min.js"));
    }

    #[test]
    fn rejects_unsafe_model_key() {
        assert_eq!(render_chatter_panel("../etc", Uuid::nil()), "");
        assert_eq!(render_chatter_panel("a b", Uuid::nil()), "");
        assert_eq!(render_chatter_panel("", Uuid::nil()), "");
    }

    #[test]
    fn accepts_underscore_and_alnum() {
        assert!(!render_chatter_panel("maint_asset", Uuid::nil()).is_empty());
        assert!(!render_chatter_panel("acc_move", Uuid::nil()).is_empty());
    }
}
