//! MNEC asset-ID composition (spec §4.9).
//!
//! Asset IDs are built hierarchically from a parent's ID plus an acronym. These
//! are the **pure** grammar functions — string composition only, no DB — so the
//! contract is unit-tested against real IDs from the live system (see the
//! `DISTRIBUTION_ASSET_SCHEMA` sample records). The DB-backed resolvers that
//! fetch the parts (acronyms, location codes, route numbers) live in the create
//! handlers and call these.
//!
//! Grammar:
//! ```text
//! Substation       = SE-{TS|DS}-{kv}-{location}[-{seq:03}]   TS if kv>=66 else DS
//! TransmissionLine = SE-TL-LOC-{from}-{to}
//! Tower            = {line.asset_id}-T{tower:03}
//! UgcLine          = SE-TU-{kv}-{from}-{to}
//! DistributionLine = SE-DF-{kv}-{source_location}-F{route:05}   (an L1 root)
//! Equipment        = {parent.asset_id}-{acronym}[-{seq:02}]
//!                    parent = bay | tower | gantry | span | ugc_line | distribution_line
//! Component        = {equipment.asset_id}-[circuit-][acronym-][seq:02-]phase[-side]
//! ```
//! Real examples reproduced by the tests: `SE-DS-33-KK-MI-001`,
//! `SE-TS-132-ELOP-001-E01-DS-01`, `SE-TS-132-ELOP-001-E01-CT-R`,
//! `SE-TU-132-KPYN-LKWI`, `SE-DF-11-EASTERN-F00009`, `SE-TL-LOC-MGRS-KDAT-T001`.

/// `TS` (transmission) if the primary voltage is ≥ 66 kV, else `DS` (distribution).
pub fn substation_class_code(kv: i32) -> &'static str {
    if kv >= 66 { "TS" } else { "DS" }
}

/// `SE-{TS|DS}-{kv}-{location}[-{seq:03}]`. `location` is the substation's
/// four-letter acronym (caller falls back to its code). `seq` disambiguates
/// several substations sharing a location; omitted when `None`.
pub fn substation_asset_id(kv: i32, location: &str, seq: Option<i32>) -> String {
    let base = format!("SE-{}-{}-{}", substation_class_code(kv), kv, location.trim());
    match seq {
        Some(n) => format!("{base}-{n:03}"),
        None => base,
    }
}

/// `SE-TL-LOC-{from}-{to}` — the transmission line's own prefix, from its two
/// endpoint substations' location codes. Towers extend this.
pub fn transmission_line_asset_id(from_loc: &str, to_loc: &str) -> String {
    format!("SE-TL-LOC-{}-{}", from_loc.trim(), to_loc.trim())
}

/// `{line.asset_id}-T{tower:03}`.
pub fn tower_asset_id(line_asset_id: &str, tower_number: i32) -> String {
    format!("{}-T{tower_number:03}", line_asset_id.trim_end_matches('-'))
}

/// `SE-TU-{kv}-{from}-{to}` — underground transmission cable, from its two
/// endpoint substations' location codes.
pub fn ugc_line_asset_id(kv: i32, from_loc: &str, to_loc: &str) -> String {
    format!("SE-TU-{}-{}-{}", kv, from_loc.trim(), to_loc.trim())
}

/// `SE-DF-{kv}-{source_location}-F{route:05}` — a distribution feeder. An L1
/// root: the composed ID is unique by construction (the route number is
/// unique), so it can safely carry a uniqueness constraint.
pub fn distribution_line_asset_id(kv: i32, source_location: &str, route_number: i32) -> String {
    format!("SE-DF-{}-{}-F{route_number:05}", kv, source_location.trim())
}

/// `{parent.asset_id}-{acronym}[-{seq:02}]`. The parent is whichever asset the
/// equipment hangs off (bay, tower, gantry, span, ugc line or feeder); the
/// caller resolves its `asset_id`. `seq` disambiguates several of the same
/// acronym under one parent; omitted for a lone asset of its type.
pub fn equipment_asset_id(parent_asset_id: &str, acronym: &str, seq: Option<i32>) -> String {
    let base = format!("{}-{}", parent_asset_id.trim_end_matches('-'), acronym.trim());
    match seq.filter(|n| *n > 0) {
        Some(n) => format!("{base}-{n:02}"),
        None => base,
    }
}

/// `{equipment.asset_id}-[circuit-][acronym-][seq:02-]phase[-side]`. Only
/// `phase` is required; the optional parts are prepended in grammar order.
pub fn component_asset_id(
    equipment_asset_id: &str,
    circuit: Option<&str>,
    acronym: Option<&str>,
    seq: Option<i32>,
    phase: &str,
    side: Option<&str>,
) -> String {
    let mut parts: Vec<String> = vec![equipment_asset_id.trim_end_matches('-').to_string()];
    if let Some(c) = circuit.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(c.to_string());
    }
    if let Some(a) = acronym.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(a.to_string());
    }
    if let Some(n) = seq.filter(|n| *n > 0) {
        parts.push(format!("{n:02}"));
    }
    parts.push(phase.trim().to_string());
    if let Some(s) = side.map(str::trim).filter(|s| !s.is_empty()) {
        parts.push(s.to_string());
    }
    parts.join("-")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substation_matches_live_ids() {
        assert_eq!(substation_asset_id(33, "KK-MI", Some(1)), "SE-DS-33-KK-MI-001");
        assert_eq!(substation_asset_id(132, "ELOP", Some(1)), "SE-TS-132-ELOP-001");
        assert_eq!(substation_asset_id(132, "ELOP", None), "SE-TS-132-ELOP");
        // 66 kV is the TS/DS boundary (>= 66 → TS).
        assert_eq!(substation_class_code(66), "TS");
        assert_eq!(substation_class_code(33), "DS");
    }

    #[test]
    fn equipment_matches_live_ids() {
        // No seq: bare acronym.
        assert_eq!(
            equipment_asset_id("SE-TS-132-ELOP-001-E01", "CT", None),
            "SE-TS-132-ELOP-001-E01-CT"
        );
        // With seq: two-digit zero pad.
        assert_eq!(
            equipment_asset_id("SE-TS-132-ELOP-001-E01", "DS", Some(1)),
            "SE-TS-132-ELOP-001-E01-DS-01"
        );
        // seq 0 is treated as "no seq".
        assert_eq!(
            equipment_asset_id("SE-DS-33-KK-MI-001-B01", "TX", Some(0)),
            "SE-DS-33-KK-MI-001-B01-TX"
        );
    }

    #[test]
    fn component_matches_live_ids() {
        // Just a phase suffix.
        assert_eq!(
            component_asset_id("SE-TS-132-ELOP-001-E01-CT", None, None, None, "R", None),
            "SE-TS-132-ELOP-001-E01-CT-R"
        );
        // All optional parts present, in grammar order.
        assert_eq!(
            component_asset_id("SE-EQ", Some("C1"), Some("BSH"), Some(2), "Y", Some("HV")),
            "SE-EQ-C1-BSH-02-Y-HV"
        );
    }

    #[test]
    fn linear_assets_match_grammar() {
        assert_eq!(ugc_line_asset_id(132, "KPYN", "LKWI"), "SE-TU-132-KPYN-LKWI");
        assert_eq!(distribution_line_asset_id(11, "EASTERN", 9), "SE-DF-11-EASTERN-F00009");
        let line = transmission_line_asset_id("MGRS", "KDAT");
        assert_eq!(line, "SE-TL-LOC-MGRS-KDAT");
        assert_eq!(tower_asset_id(&line, 1), "SE-TL-LOC-MGRS-KDAT-T001");
    }
}
