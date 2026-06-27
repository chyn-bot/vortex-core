//! [`Locale`] type — ISO 639-1 language + optional ISO 3166-1 region.
//!
//! Parsing follows the BCP 47 subset used by `Accept-Language`
//! headers: `en`, `en-US`, `ms-MY`, `zh-CN`, `pt-BR`. Case is
//! normalized on parse (`EN-us` → `en-US`).
//!
//! Fallback chain: `ms-MY` → `ms` → the platform default (`en`).
//! Callers walk the chain until a translation is found.

/// The platform's default locale, used as the ultimate fallback
/// when no translation is found for the user's requested locale.
pub const DEFAULT_LOCALE: &str = "en";

/// A parsed locale identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Locale {
    /// ISO 639-1 lowercase language code, e.g. `"en"`, `"ms"`, `"zh"`.
    pub language: String,
    /// Optional ISO 3166-1 uppercase region code, e.g. `"MY"`, `"US"`, `"CN"`.
    pub region: Option<String>,
}

impl Locale {
    /// Parse a locale string. Accepts `en`, `en-US`, `en_US`
    /// (underscore variant common in POSIX). Case is normalized:
    /// language lowercase, region uppercase.
    pub fn parse(s: &str) -> Self {
        let s = s.trim();
        let parts: Vec<&str> = s.split(|c| c == '-' || c == '_').collect();
        let language = parts
            .first()
            .map(|l| l.to_ascii_lowercase())
            .unwrap_or_else(|| DEFAULT_LOCALE.to_string());
        let region = parts.get(1).map(|r| r.to_ascii_uppercase());
        Self { language, region }
    }

    /// The canonical BCP 47 string: `en`, `en-US`, `ms-MY`.
    pub fn code(&self) -> String {
        match &self.region {
            Some(r) => format!("{}-{}", self.language, r),
            None => self.language.clone(),
        }
    }

    /// The language-only form: `en` from `en-US`, `ms` from `ms-MY`.
    pub fn language_only(&self) -> String {
        self.language.clone()
    }

    /// Produce the fallback chain for translation lookup.
    ///
    /// For `ms-MY`: `["ms-MY", "ms", "en"]`
    /// For `en`: `["en"]`
    /// For `zh-CN`: `["zh-CN", "zh", "en"]`
    ///
    /// The chain always ends with [`DEFAULT_LOCALE`] so lookups
    /// never return "no translation at all" — the English string
    /// is the ultimate fallback.
    pub fn fallback_chain(&self) -> Vec<String> {
        let mut chain = Vec::with_capacity(3);
        let full = self.code();
        chain.push(full.clone());
        if self.region.is_some() {
            let lang = self.language_only();
            if lang != full {
                chain.push(lang.clone());
            }
            if lang != DEFAULT_LOCALE {
                chain.push(DEFAULT_LOCALE.to_string());
            }
        } else if self.language != DEFAULT_LOCALE {
            chain.push(DEFAULT_LOCALE.to_string());
        }
        chain
    }
}

impl std::fmt::Display for Locale {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.code())
    }
}

impl Default for Locale {
    fn default() -> Self {
        Self::parse(DEFAULT_LOCALE)
    }
}

/// Parse the best locale from an `Accept-Language` header value.
///
/// Takes the first entry (highest-quality) and ignores quality
/// weights (`q=0.8`). For an ERP this is sufficient — operators
/// set their browser language once and never think about it again.
/// If the header is empty or missing, returns [`DEFAULT_LOCALE`].
pub fn locale_from_accept_language(header: &str) -> Locale {
    let first = header
        .split(',')
        .next()
        .unwrap_or(DEFAULT_LOCALE)
        .split(';')
        .next()
        .unwrap_or(DEFAULT_LOCALE)
        .trim();
    if first.is_empty() {
        Locale::default()
    } else {
        Locale::parse(first)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_language() {
        let l = Locale::parse("en");
        assert_eq!(l.language, "en");
        assert_eq!(l.region, None);
        assert_eq!(l.code(), "en");
    }

    #[test]
    fn parse_language_with_region() {
        let l = Locale::parse("ms-MY");
        assert_eq!(l.language, "ms");
        assert_eq!(l.region, Some("MY".to_string()));
        assert_eq!(l.code(), "ms-MY");
    }

    #[test]
    fn parse_normalizes_case() {
        let l = Locale::parse("EN-us");
        assert_eq!(l.language, "en");
        assert_eq!(l.region, Some("US".to_string()));
        assert_eq!(l.code(), "en-US");
    }

    #[test]
    fn parse_underscore_variant() {
        let l = Locale::parse("zh_CN");
        assert_eq!(l.language, "zh");
        assert_eq!(l.region, Some("CN".to_string()));
    }

    #[test]
    fn fallback_chain_with_region() {
        let l = Locale::parse("ms-MY");
        assert_eq!(l.fallback_chain(), vec!["ms-MY", "ms", "en"]);
    }

    #[test]
    fn fallback_chain_language_only_non_english() {
        let l = Locale::parse("ms");
        assert_eq!(l.fallback_chain(), vec!["ms", "en"]);
    }

    #[test]
    fn fallback_chain_english_is_terminal() {
        let l = Locale::parse("en");
        assert_eq!(l.fallback_chain(), vec!["en"]);
    }

    #[test]
    fn fallback_chain_en_us_drops_duplicate_en() {
        let l = Locale::parse("en-US");
        assert_eq!(l.fallback_chain(), vec!["en-US", "en"]);
    }

    #[test]
    fn accept_language_picks_first() {
        let l = locale_from_accept_language("ms-MY,en;q=0.9,zh-CN;q=0.8");
        assert_eq!(l.code(), "ms-MY");
    }

    #[test]
    fn accept_language_empty_defaults_to_en() {
        let l = locale_from_accept_language("");
        assert_eq!(l.code(), "en");
    }

    #[test]
    fn accept_language_strips_quality() {
        let l = locale_from_accept_language("zh-CN;q=0.8");
        assert_eq!(l.code(), "zh-CN");
    }

    #[test]
    fn default_locale_is_english() {
        assert_eq!(Locale::default().code(), "en");
    }

    #[test]
    fn display_round_trips() {
        let l = Locale::parse("pt-BR");
        assert_eq!(format!("{l}"), "pt-BR");
    }
}
