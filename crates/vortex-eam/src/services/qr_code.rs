//! QR Code Generation Service
//!
//! Generates QR codes for equipment identification per SESB spec
//! Format: SESB://EQP/000001

use vortex_common::{VortexResult, VortexError};

/// QR Code prefix for SESB equipment
pub const SESB_QR_PREFIX: &str = "SESB://";

/// Entity type codes
#[derive(Debug, Clone, Copy)]
pub enum EntityType {
    /// Equipment/Asset
    Equipment,
    /// Component
    Component,
    /// Part
    Part,
    /// Bay
    Bay,
    /// Substation
    Substation,
    /// Site
    Site,
    /// Work Order
    WorkOrder,
    /// Inspection
    Inspection,
}

impl EntityType {
    pub fn code(&self) -> &'static str {
        match self {
            EntityType::Equipment => "EQP",
            EntityType::Component => "CMP",
            EntityType::Part => "PRT",
            EntityType::Bay => "BAY",
            EntityType::Substation => "SUB",
            EntityType::Site => "STE",
            EntityType::WorkOrder => "WO",
            EntityType::Inspection => "INS",
        }
    }

    pub fn from_code(code: &str) -> Option<Self> {
        match code.to_uppercase().as_str() {
            "EQP" => Some(EntityType::Equipment),
            "CMP" => Some(EntityType::Component),
            "PRT" => Some(EntityType::Part),
            "BAY" => Some(EntityType::Bay),
            "SUB" => Some(EntityType::Substation),
            "STE" => Some(EntityType::Site),
            "WO" => Some(EntityType::WorkOrder),
            "INS" => Some(EntityType::Inspection),
            _ => None,
        }
    }
}

/// Generates a QR code string for an entity
///
/// Format: SESB://{ENTITY_TYPE}/{CODE}
///
/// # Arguments
/// * `entity_type` - Type of entity
/// * `code` - Entity code (e.g., "000001", "EQP/000001")
///
/// # Returns
/// QR code string (e.g., "SESB://EQP/000001")
///
/// # Examples
/// ```
/// use vortex_eam::services::qr_code::{generate_code_string, EntityType};
///
/// let qr = generate_code_string(EntityType::Equipment, "000001");
/// assert_eq!(qr, "SESB://EQP/000001");
/// ```
pub fn generate_code_string(entity_type: EntityType, code: &str) -> String {
    format!("{}{}/{}", SESB_QR_PREFIX, entity_type.code(), code)
}

/// Generates a QR code string from an existing equipment code
///
/// If the code already has a prefix (e.g., "EQP/000001"), it will be used directly.
/// Otherwise, it will be prefixed with the entity type.
///
/// # Arguments
/// * `equipment_code` - Equipment code (e.g., "000001" or "EQP/000001")
///
/// # Returns
/// QR code string
pub fn generate_equipment_qr(equipment_code: &str) -> String {
    if equipment_code.starts_with("EQP/") {
        format!("{}{}", SESB_QR_PREFIX, equipment_code)
    } else {
        generate_code_string(EntityType::Equipment, equipment_code)
    }
}

/// Parses a QR code string to extract entity type and code
///
/// # Arguments
/// * `qr_string` - QR code string (e.g., "SESB://EQP/000001")
///
/// # Returns
/// Tuple of (EntityType, code) if valid
pub fn parse_code_string(qr_string: &str) -> Option<(EntityType, String)> {
    // Remove prefix
    let rest = qr_string.strip_prefix(SESB_QR_PREFIX)?;

    // Split by first /
    let mut parts = rest.splitn(2, '/');
    let entity_code = parts.next()?;
    let code = parts.next()?;

    let entity_type = EntityType::from_code(entity_code)?;
    Some((entity_type, code.to_string()))
}

/// Generates a QR code image as PNG bytes
///
/// # Arguments
/// * `code_string` - The QR code content string
///
/// # Returns
/// PNG image data as bytes, or error if generation fails
pub fn generate_image(code_string: &str) -> VortexResult<Vec<u8>> {
    // Note: In a real implementation, this would use a QR code library
    // like `qrcode` crate to generate the actual image.
    // For now, we return a placeholder that indicates the content.

    // Validate input
    if code_string.is_empty() {
        return Err(VortexError::ValidationFailed("QR code content cannot be empty".to_string()));
    }

    if code_string.len() > 2048 {
        return Err(VortexError::ValidationFailed("QR code content too long".to_string()));
    }

    // In production, this would generate actual QR code PNG
    // For now, return a simple placeholder with the content embedded
    // This allows the function signature to be correct for future implementation

    // Placeholder: return content as UTF-8 bytes prefixed with a marker
    let mut result = Vec::new();
    result.extend_from_slice(b"QRCODE:");
    result.extend_from_slice(code_string.as_bytes());

    Ok(result)
}

/// Generates a QR code image as base64 string
///
/// # Arguments
/// * `code_string` - The QR code content string
///
/// # Returns
/// Base64 encoded PNG image data
pub fn generate_image_base64(code_string: &str) -> VortexResult<String> {
    let image_bytes = generate_image(code_string)?;

    // In production, use base64 crate
    // For now, simple encoding
    use std::io::Write;
    let mut output = Vec::new();
    for byte in image_bytes {
        write!(output, "{:02x}", byte).ok();
    }

    Ok(String::from_utf8(output).unwrap_or_default())
}

/// Generates a QR code data URL for embedding in HTML/SVG
///
/// # Arguments
/// * `code_string` - The QR code content string
///
/// # Returns
/// Data URL string (data:image/png;base64,...)
pub fn generate_data_url(code_string: &str) -> VortexResult<String> {
    let base64_data = generate_image_base64(code_string)?;
    Ok(format!("data:image/png;base64,{}", base64_data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_code_string() {
        let qr = generate_code_string(EntityType::Equipment, "000001");
        assert_eq!(qr, "SESB://EQP/000001");

        let qr = generate_code_string(EntityType::Component, "CMP-001");
        assert_eq!(qr, "SESB://CMP/CMP-001");

        let qr = generate_code_string(EntityType::WorkOrder, "2026/00001");
        assert_eq!(qr, "SESB://WO/2026/00001");
    }

    #[test]
    fn test_parse_code_string() {
        let (entity, code) = parse_code_string("SESB://EQP/000001").unwrap();
        assert!(matches!(entity, EntityType::Equipment));
        assert_eq!(code, "000001");

        let (entity, code) = parse_code_string("SESB://CMP/CMP-001").unwrap();
        assert!(matches!(entity, EntityType::Component));
        assert_eq!(code, "CMP-001");
    }

    #[test]
    fn test_parse_invalid() {
        assert!(parse_code_string("invalid").is_none());
        assert!(parse_code_string("SESB://UNKNOWN/123").is_none());
        assert!(parse_code_string("OTHER://EQP/123").is_none());
    }

    #[test]
    fn test_generate_equipment_qr() {
        let qr = generate_equipment_qr("000001");
        assert_eq!(qr, "SESB://EQP/000001");

        let qr = generate_equipment_qr("EQP/000002");
        assert_eq!(qr, "SESB://EQP/000002");
    }

    #[test]
    fn test_generate_image() {
        let result = generate_image("SESB://EQP/000001");
        assert!(result.is_ok());

        let bytes = result.unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn test_generate_image_empty_fails() {
        let result = generate_image("");
        assert!(result.is_err());
    }
}
