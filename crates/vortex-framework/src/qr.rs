//! QR code generation — pure Rust, rendered as inline SVG.
//!
//! Platform primitive: LHDN e-invoice validation links, mobile-app
//! pairing, asset tags. Returns `None` when the data cannot be encoded
//! (too long) — callers degrade to showing the raw text.

/// Render `data` as an SVG string sized to at least `min_px` square.
pub fn qr_svg(data: &str, min_px: u32) -> Option<String> {
    use qrcode::render::svg;
    let code = qrcode::QrCode::new(data.as_bytes()).ok()?;
    Some(
        code.render::<svg::Color>()
            .min_dimensions(min_px, min_px)
            .quiet_zone(true)
            .build(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn renders_svg() {
        let svg = super::qr_svg("https://myinvois.hasil.gov.my/x/y", 120).unwrap();
        assert!(svg.starts_with("<?xml") || svg.starts_with("<svg"));
        assert!(svg.contains("svg"));
    }
}
