//! Data-driven equipment-specialization detail forms (§3.3).
//!
//! Rather than hand-code 11 near-identical CRUD flows, each specialization
//! is described as a list of [`SpecField`]s over its 1-to-1 detail table.
//! [`render_spec`] builds the form section and [`save_spec`] performs a
//! typed UPSERT keyed by `equipment_id`. Column names are compile-time
//! constants (never user input), so the dynamic SQL is safe.

use std::collections::HashMap;

use vortex_plugin_sdk::sqlx::{PgPool, Row};
use vortex_plugin_sdk::uuid::Uuid;

use super::{date_field, enum_options, esc, num_field, select_field, text_field};

#[derive(Clone, Copy)]
pub enum Kind {
    Text,
    Num,
    Int,
    Date,
    Bool,
    Enum(&'static [(&'static str, &'static str)]),
}

#[derive(Clone, Copy)]
pub struct SpecField {
    pub col: &'static str,
    pub label: &'static str,
    pub kind: Kind,
}

const fn f(col: &'static str, label: &'static str, kind: Kind) -> SpecField {
    SpecField { col, label, kind }
}

pub struct Spec {
    pub table: &'static str,
    pub title: &'static str,
    pub fields: &'static [SpecField],
}

// ── shared enum option sets ──
const YN: &[(&str, &str)] = &[("", "—"), ("yes", "Yes"), ("no", "No"), ("na", "N/A")];

/// Return the detail spec for an equipment category, if it has one.
pub fn spec_for(category: &str) -> Option<&'static Spec> {
    Some(match category {
        "transformer" => &TRANSFORMER,
        "switchgear" => &SWITCHGEAR,
        "rmu" | "motorised_rmu" => &RMU,
        "protection" => &PROTECTION,
        "scada" | "rtu" => &SCADA,
        "battery" => &BATTERY,
        "feeder_pillar" => &FEEDER_PILLAR,
        "capacitor" => &CAPACITOR,
        "ner" => &NER,
        "elb" => &ELB,
        "cable" => &UGC_CABLE,
        _ => return None,
    })
}

/// Render the specialization section: a titled card with all fields,
/// pre-filled from the existing detail row (if any).
pub async fn render_spec(db: &PgPool, spec: &Spec, equipment_id: Option<Uuid>) -> String {
    // Load current values into a name→string map.
    let mut vals: HashMap<String, String> = HashMap::new();
    if let Some(eid) = equipment_id {
        let cols: Vec<String> = spec.fields.iter().map(|fld| match fld.kind {
            Kind::Num | Kind::Int => format!("{}::text AS {}", fld.col, fld.col),
            Kind::Date => format!("{}::text AS {}", fld.col, fld.col),
            Kind::Bool => format!("{}::text AS {}", fld.col, fld.col),
            _ => fld.col.to_string(),
        }).collect();
        let sql = format!("SELECT {} FROM {} WHERE equipment_id = $1", cols.join(", "), spec.table);
        if let Ok(Some(row)) = vortex_plugin_sdk::sqlx::query(&sql).bind(eid).fetch_optional(db).await {
            for fld in spec.fields {
                if let Ok(Some(v)) = row.try_get::<Option<String>, _>(fld.col) {
                    vals.insert(fld.col.to_string(), v);
                }
            }
        }
    }
    let mut body = String::new();
    for fld in spec.fields {
        let cur = vals.get(fld.col).map(|s| s.as_str()).unwrap_or("");
        let name = format!("spec__{}", fld.col);
        body.push_str(&match fld.kind {
            Kind::Text => text_field(fld.label, &name, cur, false),
            Kind::Num => num_field(fld.label, &name, cur, "0.0001"),
            Kind::Int => num_field(fld.label, &name, cur, "1"),
            Kind::Date => date_field(fld.label, &name, cur),
            Kind::Bool => format!(
                r#"<div class="form-control mb-3"><label class="cursor-pointer label justify-start gap-3"><input type="checkbox" name="{name}" class="checkbox checkbox-sm" {c}/><span class="label-text">{label}</span></label></div>"#,
                name = name, label = fld.label, c = if cur == "true" { "checked" } else { "" }),
            Kind::Enum(opts) => select_field(fld.label, &name, &enum_options(opts, cur)),
        });
    }
    format!(
        r#"<h2 class="font-semibold text-sm uppercase opacity-60 mt-4 mb-2">{title}</h2>
<div class="grid grid-cols-1 md:grid-cols-3 gap-x-4">{body}</div>"#,
        title = esc(spec.title), body = body,
    )
}

/// UPSERT the specialization detail row from the submitted form. Values
/// arrive under `spec__<col>` keys; types are cast in SQL.
pub async fn save_spec(
    db: &PgPool,
    spec: &Spec,
    equipment_id: Uuid,
    form: &HashMap<String, String>,
) -> Result<(), vortex_plugin_sdk::sqlx::Error> {
    let mut cols: Vec<String> = vec!["equipment_id".into()];
    let mut placeholders: Vec<String> = vec!["$1".into()];
    let mut updates: Vec<String> = Vec::new();
    let mut binds: Vec<Option<String>> = Vec::new();
    let mut n = 2;
    for fld in spec.fields {
        let key = format!("spec__{}", fld.col);
        let raw = form.get(&key);
        let val: Option<String> = match fld.kind {
            Kind::Bool => Some(if raw.is_some() { "true".into() } else { "false".into() }),
            _ => raw.filter(|s| !s.trim().is_empty()).cloned(),
        };
        let cast = match fld.kind {
            Kind::Num => "::numeric",
            Kind::Int => "::int",
            Kind::Date => "::date",
            Kind::Bool => "::boolean",
            _ => "",
        };
        cols.push(fld.col.to_string());
        placeholders.push(format!("${n}{cast}", n = n, cast = cast));
        updates.push(format!("{col} = ${n}{cast}", col = fld.col, n = n, cast = cast));
        binds.push(val);
        n += 1;
    }
    let sql = format!(
        "INSERT INTO {table} ({cols}) VALUES ({ph}) ON CONFLICT (equipment_id) DO UPDATE SET {upd}",
        table = spec.table, cols = cols.join(", "), ph = placeholders.join(", "), upd = updates.join(", "),
    );
    let mut q = vortex_plugin_sdk::sqlx::query(&sql).bind(equipment_id);
    for b in binds {
        q = q.bind(b);
    }
    q.execute(db).await.map(|_| ())
}

// ════════════════════════════════════════════════════════════════════════
// Specialization field catalogues (§3.3)
// ════════════════════════════════════════════════════════════════════════

static TRANSFORMER: Spec = Spec {
    table: "eam_equipment_transformer",
    title: "Transformer Details",
    fields: &[
        f("tx_no", "Transformer No", Kind::Text),
        f("bil_tx", "BIL TX No", Kind::Int),
        f("nameplate_voltage_kv", "Nameplate Voltage", Kind::Text),
        f("make_country", "Make Country", Kind::Text),
        f("mva_rating", "MVA Rating", Kind::Num),
        f("kva_rating", "kVA Rating", Kind::Num),
        f("primary_voltage_kv", "Primary kV", Kind::Num),
        f("secondary_voltage_kv", "Secondary kV", Kind::Num),
        f("tertiary_voltage_kv", "Tertiary kV", Kind::Num),
        f("transformer_type", "Type", Kind::Enum(&[("","—"),("power","Power"),("distribution","Distribution"),("auto","Auto"),("grounding","Grounding"),("auxiliary","Auxiliary")])),
        f("vector_group", "Vector Group", Kind::Text),
        f("winding_material", "Winding Material", Kind::Enum(&[("","—"),("copper","Copper"),("aluminum","Aluminum")])),
        f("phase_count", "Phase Count", Kind::Enum(&[("","—"),("1","1"),("3","3")])),
        f("cooling_type", "Cooling Type", Kind::Enum(&[("","—"),("onan","ONAN"),("onaf","ONAF"),("ofaf","OFAF"),("ofwf","OFWF"),("dry","Dry")])),
        f("tap_changer_type", "Tap Changer", Kind::Enum(&[("","—"),("none","None"),("oltc","OLTC"),("offload","Off-load")])),
        f("tap_position_min", "Tap Min", Kind::Int),
        f("tap_position_max", "Tap Max", Kind::Int),
        f("tap_position_current", "Tap Current", Kind::Int),
        f("tap_step_voltage", "Tap Step V", Kind::Num),
        f("oltc_make", "OLTC Make", Kind::Text),
        f("oltc_types", "OLTC Type", Kind::Text),
        f("oltc_year", "OLTC Year", Kind::Int),
        f("oltc_serial_no", "OLTC Serial", Kind::Text),
        f("max_tapping", "Max Tapping", Kind::Int),
        f("nominal_tapping", "Nominal Tapping", Kind::Int),
        f("lowest_voltage_kv", "Lowest V (kV)", Kind::Num),
        f("highest_voltage_kv", "Highest V (kV)", Kind::Num),
        f("oltc_motor_voltage_v", "OLTC Motor V", Kind::Num),
        f("oltc_motor_capacity_kw", "OLTC Motor kW", Kind::Num),
        f("oltc_operation_counter", "OLTC Op Counter", Kind::Int),
        f("oltc_asset_number", "OLTC Asset No", Kind::Text),
        f("oil_type", "Oil Type", Kind::Enum(&[("","—"),("mineral","Mineral"),("silicone","Silicone"),("synthetic","Synthetic"),("natural","Natural")])),
        f("oil_volume_liters", "Oil Volume (L)", Kind::Num),
        f("oil_weight_kg", "Oil Weight (kg)", Kind::Num),
        f("total_weight_kg", "Total Weight (kg)", Kind::Num),
        f("impedance_percent", "Impedance %", Kind::Num),
        f("no_load_loss_kw", "No-load Loss (kW)", Kind::Num),
        f("load_loss_kw", "Load Loss (kW)", Kind::Num),
        f("max_ambient_temp_c", "Max Ambient °C", Kind::Num),
        f("max_winding_temp_rise_c", "Max Winding Rise °C", Kind::Num),
        f("max_oil_temp_rise_c", "Max Oil Rise °C", Kind::Num),
        f("has_buchholz_relay", "Buchholz Relay", Kind::Bool),
        f("has_pressure_relief", "Pressure Relief", Kind::Bool),
        f("has_wti", "WTI", Kind::Bool),
        f("has_oti", "OTI", Kind::Bool),
        f("has_mog", "MOG", Kind::Bool),
        f("last_dga_date", "Last DGA Date", Kind::Date),
        f("dga_status", "DGA Status", Kind::Enum(&[("","—"),("normal","Normal"),("caution","Caution"),("warning","Warning"),("critical","Critical")])),
    ],
};

static SWITCHGEAR: Spec = Spec {
    table: "eam_equipment_switchgear",
    title: "Switchgear Details",
    fields: &[
        f("switchgear_type", "Switchgear Type", Kind::Enum(&[("gis_33kv","GIS 33kV"),("gis_11kv","GIS 11kV"),("ais_33kv","AIS 33kV"),("ais_11kv","AIS 11kV"),("vcb_33kv","VCB 33kV"),("vcb_11kv","VCB 11kV")])),
        f("rated_breaking_current_ka", "Breaking Current (kA)", Kind::Num),
        f("rated_making_current_ka", "Making Current (kA)", Kind::Num),
        f("short_time_current_ka", "Short-time Current (kA)", Kind::Num),
        f("short_time_duration_s", "Short-time Duration (s)", Kind::Num),
        f("insulation_type", "Insulation", Kind::Enum(&[("","—"),("sf6","SF6"),("vacuum","Vacuum"),("air","Air"),("oil","Oil")])),
        f("sf6_pressure_bar", "SF6 Pressure (bar)", Kind::Num),
        f("sf6_pressure_alarm", "SF6 Alarm (bar)", Kind::Num),
        f("sf6_pressure_lockout", "SF6 Lockout (bar)", Kind::Num),
        f("sf6_volume_kg", "SF6 Volume (kg)", Kind::Num),
        f("last_sf6_refill_date", "Last SF6 Refill", Kind::Date),
        f("mechanism_type", "Mechanism", Kind::Enum(&[("","—"),("spring","Spring"),("motor","Motor"),("pneumatic","Pneumatic"),("hydraulic","Hydraulic"),("manual","Manual")])),
        f("operation_count", "Operation Count", Kind::Int),
        f("max_operations", "Max Operations", Kind::Int),
        f("control_voltage_vdc", "Control Voltage (Vdc)", Kind::Num),
        f("motor_voltage_vac", "Motor Voltage (Vac)", Kind::Num),
        f("closing_time_ms", "Closing Time (ms)", Kind::Num),
        f("opening_time_ms", "Opening Time (ms)", Kind::Num),
        f("close_open_time_ms", "Close-Open Time (ms)", Kind::Num),
        f("position", "Position", Kind::Enum(&[("","—"),("open","Open"),("closed","Closed"),("trip","Trip"),("unknown","Unknown")])),
        f("contact_wear_percent", "Contact Wear %", Kind::Num),
        f("last_overhaul_date", "Last Overhaul", Kind::Date),
        f("next_overhaul_date", "Next Overhaul", Kind::Date),
    ],
};

static RMU: Spec = Spec {
    table: "eam_equipment_rmu",
    title: "Ring Main Unit Details",
    fields: &[
        f("rmu_spec", "RMU Spec", Kind::Enum(&[("2+1","2+1"),("3+0","3+0"),("3+1","3+1"),("4+0","4+0"),("2+2","2+2"),("custom","Custom")])),
        f("custom_config", "Custom Config", Kind::Text),
        f("rated_fault_current_ka", "Fault Current (kA)", Kind::Num),
        f("insulation_medium", "Insulation Medium", Kind::Enum(&[("","—"),("sf6","SF6"),("solid","Solid"),("air","Air")])),
        f("sf6_pressure_bar", "SF6 Pressure (bar)", Kind::Num),
        f("sf6_filled_date", "SF6 Filled Date", Kind::Date),
        f("protection_type", "Protection", Kind::Enum(&[("","—"),("fuse","Fuse"),("relay","Relay"),("combined","Combined")])),
        f("cable_box_type", "Cable Box", Kind::Enum(&[("","—"),("type_a","Type A"),("type_b","Type B"),("type_c","Type C")])),
        f("enclosure_type", "Enclosure", Kind::Enum(&[("","—"),("indoor","Indoor"),("outdoor","Outdoor"),("padmount","Padmount"),("pole_mount","Pole-mount")])),
        f("ip_rating", "IP Rating", Kind::Text),
        f("width_mm", "Width (mm)", Kind::Num),
        f("depth_mm", "Depth (mm)", Kind::Num),
        f("height_mm", "Height (mm)", Kind::Num),
        f("weight_kg", "Weight (kg)", Kind::Num),
        f("unit_1_type", "Unit 1 Type", Kind::Enum(&[("","—"),("ring","Ring"),("teeoff","Tee-off"),("vcb","VCB"),("fuse","Fuse")])),
        f("unit_1_position", "Unit 1 Position", Kind::Enum(&[("","—"),("open","Open"),("closed","Closed")])),
        f("unit_2_type", "Unit 2 Type", Kind::Enum(&[("","—"),("ring","Ring"),("teeoff","Tee-off"),("vcb","VCB"),("fuse","Fuse")])),
        f("unit_2_position", "Unit 2 Position", Kind::Enum(&[("","—"),("open","Open"),("closed","Closed")])),
        f("unit_3_type", "Unit 3 Type", Kind::Enum(&[("","—"),("ring","Ring"),("teeoff","Tee-off"),("vcb","VCB"),("fuse","Fuse")])),
        f("unit_3_position", "Unit 3 Position", Kind::Enum(&[("","—"),("open","Open"),("closed","Closed")])),
        f("unit_4_type", "Unit 4 Type", Kind::Enum(&[("","—"),("ring","Ring"),("teeoff","Tee-off"),("vcb","VCB"),("fuse","Fuse")])),
        f("unit_4_position", "Unit 4 Position", Kind::Enum(&[("","—"),("open","Open"),("closed","Closed")])),
    ],
};

static PROTECTION: Spec = Spec {
    table: "eam_equipment_protection",
    title: "Protection Relay Details",
    fields: &[
        f("relay_model", "Relay Model", Kind::Text),
        f("relay_function", "Function (e.g. 50/51)", Kind::Text),
        f("relay_type", "Relay Type", Kind::Enum(&[("","—"),("overcurrent","Overcurrent"),("earth_fault","Earth Fault"),("differential","Differential"),("distance","Distance"),("directional","Directional"),("under_voltage","Under-voltage")])),
        f("pickup_current_a", "Pickup Current (A)", Kind::Num),
        f("time_dial", "Time Dial", Kind::Num),
        f("curve_type", "Curve Type", Kind::Enum(&[("","—"),("standard_inverse","Standard Inverse"),("very_inverse","Very Inverse"),("extremely_inverse","Extremely Inverse"),("long_time_inverse","Long-time Inverse"),("definite_time","Definite Time")])),
        f("instantaneous_setting_a", "Instantaneous (A)", Kind::Num),
        f("instantaneous_time_ms", "Instantaneous (ms)", Kind::Num),
        f("ct_primary_a", "CT Primary (A)", Kind::Num),
        f("ct_secondary_a", "CT Secondary (A)", Kind::Num),
        f("vt_primary_v", "VT Primary (V)", Kind::Num),
        f("vt_secondary_v", "VT Secondary (V)", Kind::Num),
        f("communication_protocol", "Protocol", Kind::Enum(&[("","—"),("iec61850","IEC 61850"),("dnp3","DNP3"),("modbus","Modbus"),("iec103","IEC 103"),("iec101","IEC 101"),("none","None")])),
        f("ip_address", "IP Address", Kind::Text),
        f("port_number", "Port", Kind::Int),
        f("auxiliary_voltage_vdc", "Aux Voltage (Vdc)", Kind::Num),
        f("last_test_date", "Last Test", Kind::Date),
        f("next_test_date", "Next Test", Kind::Date),
        f("test_result", "Test Result", Kind::Enum(&[("","—"),("pass","Pass"),("fail","Fail"),("pending","Pending")])),
        f("trip_count", "Trip Count", Kind::Int),
        f("firmware_version", "Firmware Version", Kind::Text),
        f("firmware_date", "Firmware Date", Kind::Date),
    ],
};

static SCADA: Spec = Spec {
    table: "eam_equipment_scada",
    title: "SCADA / RTU Details",
    fields: &[
        f("device_type", "Device Type", Kind::Enum(&[("rtu","RTU"),("gateway","Gateway"),("protocol_converter","Protocol Converter"),("data_concentrator","Data Concentrator"),("hmi","HMI"),("server","Server")])),
        f("ip_address", "IP Address", Kind::Text),
        f("subnet_mask", "Subnet Mask", Kind::Text),
        f("gateway_address", "Gateway", Kind::Text),
        f("mac_address", "MAC Address", Kind::Text),
        f("protocol_master", "Master Protocol", Kind::Enum(&[("","—"),("iec61850","IEC 61850"),("dnp3","DNP3"),("iec104","IEC 104"),("iec101","IEC 101"),("modbus_tcp","Modbus TCP"),("modbus_rtu","Modbus RTU")])),
        f("protocol_slave", "Slave Protocol", Kind::Enum(&[("","—"),("iec61850","IEC 61850"),("dnp3","DNP3"),("iec104","IEC 104"),("iec101","IEC 101"),("modbus_tcp","Modbus TCP"),("modbus_rtu","Modbus RTU")])),
        f("rtu_address", "RTU Address", Kind::Int),
        f("station_address", "Station Address", Kind::Int),
        f("digital_input_count", "Digital Inputs", Kind::Int),
        f("digital_output_count", "Digital Outputs", Kind::Int),
        f("analog_input_count", "Analog Inputs", Kind::Int),
        f("analog_output_count", "Analog Outputs", Kind::Int),
        f("pulse_counter_count", "Pulse Counters", Kind::Int),
        f("connection_status", "Connection", Kind::Enum(&[("","—"),("online","Online"),("offline","Offline"),("degraded","Degraded")])),
        f("communication_quality", "Comm Quality %", Kind::Num),
        f("power_supply_vdc", "Power Supply (Vdc)", Kind::Enum(&[("","—"),("110","110"),("48","48"),("24","24"),("12","12")])),
        f("firmware_version", "Firmware Version", Kind::Text),
        f("software_version", "Software Version", Kind::Text),
        f("last_firmware_update", "Last Firmware Update", Kind::Date),
        f("encrypted_communication", "Encrypted Comm", Kind::Bool),
        f("security_level", "Security Level", Kind::Enum(&[("","—"),("low","Low"),("medium","Medium"),("high","High")])),
    ],
};

static BATTERY: Spec = Spec {
    table: "eam_equipment_battery",
    title: "Battery Bank Details",
    fields: &[
        f("dc_voltage", "DC Voltage", Kind::Enum(&[("110vdc","110 Vdc"),("48vdc","48 Vdc"),("30vdc","30 Vdc"),("24vdc","24 Vdc")])),
        f("battery_type", "Battery Type", Kind::Enum(&[("vrla","VRLA"),("nicd","NiCd"),("lion","Li-ion"),("flooded","Flooded")])),
        f("ampere_hour", "Ampere-Hour", Kind::Num),
        f("autonomy_hours", "Autonomy (h)", Kind::Num),
        f("cell_count", "Cell Count", Kind::Int),
        f("cells_per_string", "Cells / String", Kind::Int),
        f("string_count", "String Count", Kind::Int),
        f("cell_voltage", "Cell Voltage", Kind::Num),
        f("charger_type", "Charger Type", Kind::Enum(&[("","—"),("float","Float"),("boost_float","Boost-Float"),("smart","Smart")])),
        f("charger_rating_a", "Charger Rating (A)", Kind::Num),
        f("float_voltage_v", "Float Voltage", Kind::Num),
        f("boost_voltage_v", "Boost Voltage", Kind::Num),
        f("current_voltage_v", "Current Voltage", Kind::Num),
        f("current_mode", "Current Mode", Kind::Enum(&[("","—"),("float","Float"),("boost","Boost"),("discharge","Discharge"),("standby","Standby")])),
        f("temperature_c", "Temperature °C", Kind::Num),
        f("specific_gravity", "Specific Gravity", Kind::Num),
        f("state_of_health", "State of Health %", Kind::Num),
        f("state_of_charge", "State of Charge %", Kind::Num),
        f("last_discharge_test_date", "Last Discharge Test", Kind::Date),
        f("last_discharge_test_result", "Discharge Result", Kind::Enum(&[("","—"),("pass","Pass"),("fail","Fail"),("marginal","Marginal")])),
        f("last_capacity_measured_ah", "Last Capacity (Ah)", Kind::Num),
        f("last_equalizing_charge_date", "Last Equalizing Charge", Kind::Date),
        f("last_water_top_up_date", "Last Water Top-up", Kind::Date),
        f("lowest_cell_voltage", "Lowest Cell V", Kind::Num),
        f("highest_cell_voltage", "Highest Cell V", Kind::Num),
    ],
};

static FEEDER_PILLAR: Spec = Spec {
    table: "eam_equipment_feeder_pillar",
    title: "Feeder Pillar Details",
    fields: &[
        f("pillar_type", "Pillar Type", Kind::Enum(&[("distribution","Distribution"),("sub_feeder","Sub-feeder"),("metering","Metering"),("link_box","Link Box"),("service_pillar","Service Pillar"),("street_lighting","Street Lighting")])),
        f("rated_voltage_v", "Rated Voltage (V)", Kind::Num),
        f("rated_fault_current_ka", "Fault Current (kA)", Kind::Num),
        f("incoming_ways", "Incoming Ways", Kind::Int),
        f("outgoing_ways", "Outgoing Ways", Kind::Int),
        f("spare_ways", "Spare Ways", Kind::Int),
        f("protection_type", "Protection", Kind::Enum(&[("","—"),("fuse","Fuse"),("mccb","MCCB"),("mcb","MCB"),("combined","Combined")])),
        f("incoming_fuse_rating_a", "Incoming Fuse (A)", Kind::Num),
        f("outgoing_fuse_rating_a", "Outgoing Fuse (A)", Kind::Num),
        f("enclosure_material", "Enclosure Material", Kind::Enum(&[("","—"),("steel","Steel"),("stainless","Stainless"),("grp","GRP"),("aluminum","Aluminum")])),
        f("ip_rating", "IP Rating", Kind::Text),
        f("installation_type", "Installation", Kind::Enum(&[("","—"),("ground","Ground"),("wall","Wall"),("pole","Pole")])),
        f("width_mm", "Width (mm)", Kind::Num),
        f("depth_mm", "Depth (mm)", Kind::Num),
        f("height_mm", "Height (mm)", Kind::Num),
        f("gps_latitude", "GPS Latitude", Kind::Num),
        f("gps_longitude", "GPS Longitude", Kind::Num),
        f("location_description", "Location Description", Kind::Text),
        f("supplied_customers", "Supplied Customers", Kind::Int),
        f("has_metering", "Has Metering", Kind::Bool),
        f("meter_count", "Meter Count", Kind::Int),
        f("ct_ratio", "CT Ratio", Kind::Text),
        f("door_status", "Door Status", Kind::Enum(&[("","—"),("secured","Secured"),("damaged","Damaged"),("missing","Missing")])),
        f("condition_rating", "Condition Rating", Kind::Enum(&[("","—"),("good","Good"),("fair","Fair"),("poor","Poor"),("needs_replacement","Needs Replacement")])),
    ],
};

static CAPACITOR: Spec = Spec {
    table: "eam_equipment_capacitor",
    title: "Capacitor Bank Details",
    fields: &[
        f("capacitance_uf", "Capacitance (µF)", Kind::Num),
        f("rated_power_kvar", "Rated Power (kVAr)", Kind::Num),
        f("phase_connection", "Phase Connection", Kind::Enum(&[("","—"),("star","Star"),("delta","Delta"),("single","Single"),("double_star","Double Star")])),
        f("bank_configuration", "Bank Configuration", Kind::Enum(&[("","—"),("single","Single"),("double","Double"),("switched","Switched"),("fixed","Fixed")])),
        f("number_of_steps", "Number of Steps", Kind::Int),
        f("number_of_units", "Number of Units", Kind::Int),
        f("units_per_phase", "Units per Phase", Kind::Int),
        f("series_groups", "Series Groups", Kind::Int),
        f("parallel_units", "Parallel Units", Kind::Int),
        f("protection_type", "Protection", Kind::Enum(&[("","—"),("fuse","Fuse"),("relay","Relay"),("combined","Combined")])),
        f("has_discharge_resistor", "Discharge Resistor", Kind::Bool),
        f("has_unbalance_protection", "Unbalance Protection", Kind::Bool),
        f("switching_device", "Switching Device", Kind::Enum(&[("","—"),("vcb","VCB"),("contactor","Contactor"),("thyristor","Thyristor")])),
    ],
};

static NER: Spec = Spec {
    table: "eam_equipment_ner",
    title: "Neutral Earthing Resistor Details",
    fields: &[
        f("resistance_ohm", "Resistance (Ω)", Kind::Num),
        f("rated_time_s", "Rated Time (s)", Kind::Num),
        f("system_voltage_kv", "System Voltage (kV)", Kind::Num),
        f("ner_voltage_kv", "NER Voltage (kV)", Kind::Num),
        f("ner_type", "NER Type", Kind::Enum(&[("","—"),("low_resistance","Low Resistance"),("high_resistance","High Resistance"),("reactance","Reactance")])),
        f("resistor_material", "Resistor Material", Kind::Enum(&[("","—"),("stainless_steel","Stainless Steel"),("cast_iron","Cast Iron"),("nickel_chrome","Nickel-Chrome")])),
        f("enclosure_type", "Enclosure", Kind::Enum(&[("","—"),("indoor","Indoor"),("outdoor","Outdoor")])),
        f("ip_rating", "IP Rating", Kind::Text),
        f("last_resistance_test_date", "Last Resistance Test", Kind::Date),
        f("last_measured_resistance_ohm", "Last Measured (Ω)", Kind::Num),
    ],
};

static ELB: Spec = Spec {
    table: "eam_equipment_elb",
    title: "Earth Link Box + Wayleave",
    fields: &[
        f("elb_no", "ELB No", Kind::Text),
        f("distance_m", "Chainage Distance (m)", Kind::Num),
        f("gps_latitude", "GPS Latitude", Kind::Num),
        f("gps_longitude", "GPS Longitude", Kind::Num),
        f("elevation_m", "Elevation (m)", Kind::Num),
        f("crossbond_joint_type", "Crossbond Joint Type", Kind::Text),
        f("crossbond_joint_count", "Crossbond Joints (CBJ)", Kind::Int),
        f("slipon_joint_type", "Slip-on Joint Type", Kind::Text),
        f("slipon_joint_count", "Slip-on Joints (STJ)", Kind::Int),
        f("span_rata", "Span Rata (flat)", Kind::Enum(YN)),
        f("span_bukit", "Span Bukit (hill)", Kind::Enum(YN)),
        f("span_gaung", "Span Gaung (ravine)", Kind::Enum(YN)),
        f("road_crossing", "Road Crossing", Kind::Text),
        f("river_crossing", "River Crossing", Kind::Text),
        f("locality", "Locality", Kind::Text),
        f("landowner", "Landowner", Kind::Text),
        f("activity", "Land Activity", Kind::Text),
        f("danger_tree", "Danger Tree", Kind::Enum(YN)),
        f("occupational_permit", "Occupational Permit (OP)", Kind::Text),
        f("safety_signage", "Safety Signage", Kind::Enum(YN)),
    ],
};

static UGC_CABLE: Spec = Spec {
    table: "eam_equipment_ugc_cable",
    title: "Underground Cable Details",
    fields: &[
        f("cable_material", "Cable Material", Kind::Enum(&[("","—"),("copper","Copper"),("aluminium","Aluminium"),("xlpe","XLPE"),("oil_filled","Oil-filled"),("other","Other")])),
        f("cable_size_mm2", "Cable Size (mm²)", Kind::Num),
        f("current_rating_a", "Current Rating @80°C (A)", Kind::Num),
        f("cable_brand", "Cable Brand", Kind::Text),
        f("make_country", "Make / Origin", Kind::Text),
    ],
};
