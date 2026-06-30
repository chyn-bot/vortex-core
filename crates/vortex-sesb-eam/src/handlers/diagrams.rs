//! Asset hierarchy diagram (§9.2) — a navigable Region → Zon → Kawasan → Site
//! → Substation → Bay → Equipment tree rendered server-side with collapsible
//! `<details>` (no external JS). The Leaflet maps (§9.3) and SVG single-line
//! diagrams (§9.2) consume the REST/location API and are layered on the client.

use std::collections::HashMap;
use std::sync::Arc;

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::sqlx::Row;
use vortex_plugin_sdk::uuid::Uuid;

use super::*;

pub fn routes() -> Router<Arc<AppState>> {
    Router::new().route("/sesb-eam/hierarchy", get(asset_hierarchy))
}

fn node(label: &str, count: i64, children: &str, open: bool) -> String {
    let badge = if count > 0 { format!(r#" <span class="badge badge-sm badge-ghost">{}</span>"#, count) } else { String::new() };
    if children.is_empty() {
        format!(r#"<div class="pl-4 py-0.5 text-sm">{}{}</div>"#, esc(label), badge)
    } else {
        format!(r#"<details {o} class="pl-2"><summary class="cursor-pointer py-0.5 text-sm font-medium">{l}{b}</summary><div class="border-l border-base-300 ml-2">{c}</div></details>"#,
            o = if open { "open" } else { "" }, l = esc(label), b = badge, c = children)
    }
}

async fn asset_hierarchy(
    State(state): State<Arc<AppState>>, Db(db): Db,
    Extension(user): Extension<AuthUser>, Extension(db_ctx): Extension<DatabaseContext>,
    Query(_q): Query<HashMap<String, String>>,
) -> Response {
    let sidebar = render_sidebar_active(&state, &user, &db_ctx, "sesb_eam.hierarchy");
    // Walk Region → Site → Substation → Bay → Equipment (zon/kawasan shown as
    // attributes of sites; we group the engineering tree by region for clarity).
    let regions = vortex_plugin_sdk::sqlx::query("SELECT id, code, name FROM eam_region WHERE active ORDER BY sequence, name").fetch_all(&db).await.unwrap_or_default();
    let mut tree = String::new();
    for r in &regions {
        let rid: Uuid = r.get("id");
        let rname = format!("{} · {}", r.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default(), r.get::<String,_>("name"));
        let sites = vortex_plugin_sdk::sqlx::query("SELECT id, code, name FROM eam_site WHERE region_id=$1 AND active ORDER BY code").bind(rid).fetch_all(&db).await.unwrap_or_default();
        let mut site_nodes = String::new();
        let mut region_equip = 0i64;
        for si in &sites {
            let sid: Uuid = si.get("id");
            let sname = format!("{} · {}", si.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default(), si.get::<String,_>("name"));
            let subs = vortex_plugin_sdk::sqlx::query("SELECT id, code, name FROM eam_substation WHERE site_id=$1 AND active ORDER BY code").bind(sid).fetch_all(&db).await.unwrap_or_default();
            let mut sub_nodes = String::new();
            for su in &subs {
                let suid: Uuid = su.get("id");
                let suname = format!("{} · {}", su.get::<String,_>("code"), su.get::<String,_>("name"));
                let bays = vortex_plugin_sdk::sqlx::query("SELECT id, code, name FROM eam_bay WHERE substation_id=$1 ORDER BY code").bind(suid).fetch_all(&db).await.unwrap_or_default();
                let mut bay_nodes = String::new();
                for b in &bays {
                    let bid: Uuid = b.get("id");
                    let bname = format!("{} · {}", b.get::<String,_>("code"), b.get::<String,_>("name"));
                    let eq = vortex_plugin_sdk::sqlx::query("SELECT code, name FROM eam_equipment WHERE bay_id=$1 ORDER BY code").bind(bid).fetch_all(&db).await.unwrap_or_default();
                    region_equip += eq.len() as i64;
                    let eq_nodes: String = eq.iter().map(|e| node(&format!("{} · {}", e.try_get::<Option<String>,_>("code").ok().flatten().unwrap_or_default(), e.get::<String,_>("name")), 0, "", false)).collect();
                    bay_nodes.push_str(&node(&bname, eq.len() as i64, &eq_nodes, false));
                }
                sub_nodes.push_str(&node(&suname, bays.len() as i64, &bay_nodes, false));
            }
            site_nodes.push_str(&node(&sname, subs.len() as i64, &sub_nodes, false));
        }
        tree.push_str(&node(&rname, region_equip, &site_nodes, false));
    }
    if tree.is_empty() { tree = "<p class=\"opacity-60\">No hierarchy yet.</p>".into(); }
    let content = format!(
        r#"<h1 class="text-2xl font-bold mb-1">Asset Hierarchy</h1>
<p class="opacity-60 text-sm mb-3">Region → Site → Substation → Bay → Equipment. Counts show equipment per branch.</p>
<div class="card bg-base-100 shadow"><div class="card-body p-3">{tree}</div></div>"#, tree = tree);
    Html(page_shell(&sidebar, "Asset Hierarchy", &content)).into_response()
}
