//! Locale-aware date and number formatting.
//!
//! These are the two formatting concerns that bite every ERP that
//! goes international: `DD/MM/YYYY` vs `MM/DD/YYYY` and `1,234.56`
//! vs `1.234,56`. Getting them wrong costs customers hours of
//! confusion and support tickets.
//!
//! The primitives here are deliberately simple — no `icu4x` dep, no
//! CLDR data files, just a `match` on the locale's language code.
//! This covers the common cases (English, Malay, Chinese, Japanese,
//! European conventions). Deployments with uncommon locale needs can
//! extend the match or layer a full ICU library on top.

use chrono::NaiveDate;
use rust_decimal::Decimal;

use super::locale::Locale;

/// Format a date for display. Returns a string in the locale's
/// conventional date order.
///
/// | Language | Format        | Example       |
/// |----------|---------------|---------------|
/// | en       | MM/DD/YYYY    | 04/12/2026    |
/// | ms, most | DD/MM/YYYY    | 12/04/2026    |
/// | zh, ja, ko | YYYY/MM/DD | 2026/04/12    |
/// | de, fr   | DD.MM.YYYY    | 12.04.2026    |
pub fn format_date(date: NaiveDate, locale: &Locale) -> String {
    match locale.language.as_str() {
        "en" => date.format("%m/%d/%Y").to_string(),
        "zh" | "ja" | "ko" => date.format("%Y/%m/%d").to_string(),
        "de" | "fr" | "it" | "es" | "pt" | "nl" | "ru" | "pl" | "cs" | "sk" | "hu" => {
            date.format("%d.%m.%Y").to_string()
        }
        // Default for ms, id, th, ar, and anything else: DD/MM/YYYY
        // (the most widely used convention globally).
        _ => date.format("%d/%m/%Y").to_string(),
    }
}

/// Thousand separator and decimal point for a locale.
///
/// Returns `(thousands, decimal)`:
///
/// | Convention | Thousands | Decimal | Example       | Locales              |
/// |------------|-----------|---------|---------------|----------------------|
/// | Anglo      | `,`       | `.`     | `1,234.56`    | en, ms, zh, ja, ko   |
/// | European   | `.`       | `,`     | `1.234,56`    | de, fr, it, es, pt   |
/// | Space      | ` `       | `,`     | `1 234,56`    | fr-FR, ru, pl        |
///
/// Note: French is special — metropolitan French uses space+comma,
/// but `fr` without region defaults to dot-comma (EU standard).
/// `fr-FR` gets space-comma.
fn locale_separators(locale: &Locale) -> (char, char) {
    match locale.language.as_str() {
        "fr" => {
            if locale.region.as_deref() == Some("FR") {
                (' ', ',')
            } else {
                ('.', ',')
            }
        }
        "de" | "it" | "es" | "pt" | "nl" | "id" | "tr" => ('.', ','),
        "ru" | "pl" | "cs" | "sk" | "hu" => (' ', ','),
        // en, ms, zh, ja, ko, th, and default
        _ => (',', '.'),
    }
}

/// Format a number with locale-appropriate thousand separators and
/// decimal point.
///
/// `decimal_places` controls how many digits appear after the
/// decimal point. Pass `0` for integers, `2` for currency amounts.
pub fn format_number(value: Decimal, locale: &Locale, decimal_places: u32) -> String {
    let (thousands_sep, decimal_sep) = locale_separators(locale);

    // Round to the requested precision first.
    let rounded = value.round_dp(decimal_places);

    // Split into integer and fractional parts using the canonical
    // Decimal display (which always uses `.` as the decimal point).
    let canonical = if decimal_places > 0 {
        format!("{rounded:.prec$}", prec = decimal_places as usize)
    } else {
        format!("{rounded}")
    };

    let parts: Vec<&str> = canonical.split('.').collect();
    let int_part = parts[0];
    let frac_part = parts.get(1).copied().unwrap_or("");

    // Insert thousand separators into the integer part (right to left).
    let negative = int_part.starts_with('-');
    let digits: &str = if negative { &int_part[1..] } else { int_part };
    let mut grouped = String::with_capacity(digits.len() + digits.len() / 3);
    for (i, ch) in digits.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            grouped.push(thousands_sep);
        }
        grouped.push(ch);
    }
    let grouped: String = grouped.chars().rev().collect();

    let mut result = String::with_capacity(grouped.len() + frac_part.len() + 2);
    if negative {
        result.push('-');
    }
    result.push_str(&grouped);
    if !frac_part.is_empty() {
        result.push(decimal_sep);
        result.push_str(frac_part);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::NaiveDate;
    use rust_decimal_macros::dec;

    fn date(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    // ─── Date formatting ──────────────────────────────────────────

    #[test]
    fn date_en_is_mm_dd_yyyy() {
        let l = Locale::parse("en");
        assert_eq!(format_date(date(2026, 4, 12), &l), "04/12/2026");
    }

    #[test]
    fn date_ms_is_dd_mm_yyyy() {
        let l = Locale::parse("ms");
        assert_eq!(format_date(date(2026, 4, 12), &l), "12/04/2026");
    }

    #[test]
    fn date_ms_my_is_dd_mm_yyyy() {
        let l = Locale::parse("ms-MY");
        assert_eq!(format_date(date(2026, 4, 12), &l), "12/04/2026");
    }

    #[test]
    fn date_zh_cn_is_yyyy_mm_dd() {
        let l = Locale::parse("zh-CN");
        assert_eq!(format_date(date(2026, 4, 12), &l), "2026/04/12");
    }

    #[test]
    fn date_de_is_dd_dot_mm_dot_yyyy() {
        let l = Locale::parse("de");
        assert_eq!(format_date(date(2026, 4, 12), &l), "12.04.2026");
    }

    // ─── Number formatting ────────────────────────────────────────

    #[test]
    fn number_en_anglo_convention() {
        let l = Locale::parse("en");
        assert_eq!(format_number(dec!(1234567.89), &l, 2), "1,234,567.89");
    }

    #[test]
    fn number_de_european_convention() {
        let l = Locale::parse("de");
        assert_eq!(format_number(dec!(1234567.89), &l, 2), "1.234.567,89");
    }

    #[test]
    fn number_fr_fr_space_convention() {
        let l = Locale::parse("fr-FR");
        assert_eq!(format_number(dec!(1234567.89), &l, 2), "1 234 567,89");
    }

    #[test]
    fn number_ms_anglo_convention() {
        let l = Locale::parse("ms");
        assert_eq!(format_number(dec!(1234.56), &l, 2), "1,234.56");
    }

    #[test]
    fn number_zero_decimal_places() {
        let l = Locale::parse("en");
        assert_eq!(format_number(dec!(1234567), &l, 0), "1,234,567");
    }

    #[test]
    fn number_small_has_no_thousands_sep() {
        let l = Locale::parse("en");
        assert_eq!(format_number(dec!(42.5), &l, 2), "42.50");
    }

    #[test]
    fn number_negative() {
        let l = Locale::parse("en");
        assert_eq!(format_number(dec!(-1234.56), &l, 2), "-1,234.56");
    }

    #[test]
    fn number_zero() {
        let l = Locale::parse("de");
        assert_eq!(format_number(dec!(0), &l, 2), "0,00");
    }

    #[test]
    fn number_rounds_to_requested_precision() {
        let l = Locale::parse("en");
        assert_eq!(format_number(dec!(10.999), &l, 2), "11.00");
    }
}
