//! Scheduled jobs (§10.1): escalate overdue maintenance, expire stale
//! field-agent locations, and derive positions for agents without a fresh GPS
//! fix. Registered from the plugin's `scheduled_actions()`.

use vortex_plugin_sdk::prelude::*;
use vortex_plugin_sdk::common::VortexResult;
use vortex_plugin_sdk::tracing::info;

/// Daily: escalate work orders overdue by 3 / 7 / 14 days to escalation level
/// 1 / 2 / 3. Only bumps when the threshold level exceeds the current one, and
/// stamps `last_escalated_on`. (§5.2)
pub async fn escalate_overdue(state: &AppState) -> VortexResult<()> {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_maintenance SET \
            escalation_level = lvl.target, last_escalated_on = NOW() \
         FROM ( \
            SELECT id, CASE \
                WHEN (CURRENT_DATE - scheduled_date) >= 14 THEN 3 \
                WHEN (CURRENT_DATE - scheduled_date) >= 7  THEN 2 \
                WHEN (CURRENT_DATE - scheduled_date) >= 3  THEN 1 \
                ELSE 0 END AS target \
            FROM eam_maintenance \
            WHERE state IN ('draft','scheduled','assigned','in_progress','on_hold') \
              AND scheduled_date IS NOT NULL AND scheduled_date < CURRENT_DATE \
         ) lvl \
         WHERE eam_maintenance.id = lvl.id AND lvl.target > eam_maintenance.escalation_level")
        .execute(&state.db).await.map_err(|e| vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string()))?;
    if res.rows_affected() > 0 {
        info!(escalated = res.rows_affected(), "sesb_eam: escalated overdue work orders");
    }
    Ok(())
}

/// Every 15 min: mark agent locations inactive after 30 min without an update.
pub async fn expire_stale_locations(state: &AppState) -> VortexResult<()> {
    let res = vortex_plugin_sdk::sqlx::query(
        "UPDATE eam_field_agent_location SET is_active = FALSE \
         WHERE is_active AND last_seen < NOW() - INTERVAL '30 minutes'")
        .execute(&state.db).await.map_err(|e| vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string()))?;
    if res.rows_affected() > 0 {
        info!(expired = res.rows_affected(), "sesb_eam: expired stale agent locations");
    }
    Ok(())
}

/// Every 10 min: for agents on an active order without a fresh device fix,
/// derive a position from the order's substation coordinates.
pub async fn refresh_derived_locations(state: &AppState) -> VortexResult<()> {
    let res = vortex_plugin_sdk::sqlx::query(
        "INSERT INTO eam_field_agent_location (user_id, agent_id, name, lat, lng, status, source, maintenance_id, region_id, last_seen, is_active) \
         SELECT DISTINCT ON (m.assigned_to) m.assigned_to, a.id, a.name, s.latitude, s.longitude, \
                CASE WHEN m.state='in_progress' THEN 'on_site' ELSE 'en_route' END, 'derived', m.id, m.region_id, NOW(), TRUE \
         FROM eam_maintenance m \
         JOIN eam_substation s ON s.id = m.substation_id \
         LEFT JOIN eam_field_agent a ON a.user_id = m.assigned_to \
         WHERE m.assigned_to IS NOT NULL AND m.state IN ('assigned','in_progress') \
           AND s.latitude IS NOT NULL AND s.longitude IS NOT NULL \
           AND NOT EXISTS ( \
               SELECT 1 FROM eam_field_agent_location l \
               WHERE l.user_id = m.assigned_to AND l.source = 'device' AND l.last_seen > NOW() - INTERVAL '10 minutes') \
         ORDER BY m.assigned_to, m.scheduled_date NULLS LAST \
         ON CONFLICT (user_id) DO UPDATE SET \
            lat = EXCLUDED.lat, lng = EXCLUDED.lng, status = EXCLUDED.status, source = 'derived', \
            maintenance_id = EXCLUDED.maintenance_id, region_id = EXCLUDED.region_id, last_seen = NOW(), is_active = TRUE \
         WHERE eam_field_agent_location.source <> 'device' OR eam_field_agent_location.last_seen <= NOW() - INTERVAL '10 minutes'")
        .execute(&state.db).await.map_err(|e| vortex_plugin_sdk::common::VortexError::QueryExecution(e.to_string()))?;
    if res.rows_affected() > 0 {
        info!(derived = res.rows_affected(), "sesb_eam: refreshed job-derived locations");
    }
    Ok(())
}
