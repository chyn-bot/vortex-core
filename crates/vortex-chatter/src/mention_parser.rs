//! Parse @mentions from message text

use regex::Regex;
use std::sync::LazyLock;
use uuid::Uuid;
use vortex_common::VortexResult;

static MENTION_PATTERN: LazyLock<Regex> = LazyLock::new(|| {
    // Match @username or @"Full Name" patterns
    Regex::new(r#"@(\w+|"[^"]+")(?:\s|$|[.,!?])"#).expect("Invalid mention regex")
});

/// Parser for extracting @mentions from message text.
pub struct MentionParser {
    // Future: could cache user lookups
}

impl MentionParser {
    pub fn new() -> Self {
        Self {}
    }

    /// Extract mention strings from text.
    ///
    /// Returns usernames/names without the @ prefix.
    pub fn extract_mention_strings(&self, text: &str) -> Vec<String> {
        MENTION_PATTERN
            .captures_iter(text)
            .map(|cap| {
                let mention = cap.get(1).unwrap().as_str();
                // Remove quotes if present
                mention.trim_matches('"').to_string()
            })
            .collect()
    }

    /// Extract mentions and resolve to user IDs.
    ///
    /// This is a placeholder - in practice, you'd look up users by username.
    /// For now, it tries to parse UUIDs directly (for testing) or returns empty.
    pub fn extract_mentions(&self, text: &str) -> VortexResult<Vec<Uuid>> {
        let mentions = self.extract_mention_strings(text);
        let mut user_ids = Vec::new();

        for mention in mentions {
            // Try parsing as UUID (for testing/direct ID mentions)
            if let Ok(uuid) = Uuid::parse_str(&mention) {
                user_ids.push(uuid);
            }
            // In a real implementation, you'd look up users by username here
        }

        Ok(user_ids)
    }

    /// Replace @mentions with linked HTML.
    ///
    /// Converts `@username` to `<span class="mention">@username</span>`.
    pub fn linkify_mentions(&self, text: &str) -> String {
        MENTION_PATTERN
            .replace_all(text, r#"<span class="mention text-primary font-medium">@$1</span> "#)
            .to_string()
    }
}

impl Default for MentionParser {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_mentions() {
        let parser = MentionParser::new();

        let mentions = parser.extract_mention_strings("Hello @john and @jane!");
        assert_eq!(mentions, vec!["john", "jane"]);

        let mentions = parser.extract_mention_strings(r#"CC @"John Doe" please"#);
        assert_eq!(mentions, vec!["John Doe"]);

        let mentions = parser.extract_mention_strings("No mentions here");
        assert!(mentions.is_empty());
    }

    #[test]
    fn test_linkify_mentions() {
        let parser = MentionParser::new();

        let result = parser.linkify_mentions("Hello @john!");
        assert!(result.contains(r#"class="mention"#));
        assert!(result.contains("@john"));
    }
}
