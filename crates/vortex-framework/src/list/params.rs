//! [`ListParams`] — query-string-driven list parameters.

use std::collections::HashMap;

/// Sort direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SortDir {
    Asc,
    Desc,
}

impl SortDir {
    pub fn as_sql(&self) -> &'static str {
        match self {
            SortDir::Asc => "ASC",
            SortDir::Desc => "DESC",
        }
    }

    pub fn opposite(&self) -> Self {
        match self {
            SortDir::Asc => SortDir::Desc,
            SortDir::Desc => SortDir::Asc,
        }
    }

    pub fn icon(&self) -> &'static str {
        match self {
            SortDir::Asc => "↑",
            SortDir::Desc => "↓",
        }
    }
}

/// Parsed list parameters from the URL query string.
///
/// Convention:
/// - `?search=foo` — free-text search across searchable columns
/// - `?sort=name&dir=asc` — sort by column
/// - `?group=contact_type` — group by column
/// - `?page=2&page_size=25` — pagination
/// - `?filter_<field>=<value>` — column-level filter (prefix `filter_`)
#[derive(Debug, Clone)]
pub struct ListParams {
    pub search: Option<String>,
    pub filters: HashMap<String, String>,
    pub sort_field: Option<String>,
    pub sort_dir: SortDir,
    pub group_by: Option<String>,
    pub page: u64,
    pub page_size: u64,
    /// Keyset cursor: fetch the page *after* this row id (forward nav). The
    /// value is an opaque id; correctness comes from the total `(sort, id)`
    /// order. Mutually exclusive with `before`; ignored unless the list opts
    /// into keyset mode (`ListConfig::keyset`).
    pub after: Option<String>,
    /// Keyset cursor: fetch the page *before* this row id (backward nav).
    pub before: Option<String>,
}

impl Default for ListParams {
    fn default() -> Self {
        Self {
            search: None,
            filters: HashMap::new(),
            sort_field: None,
            sort_dir: SortDir::Asc,
            group_by: None,
            page: 1,
            page_size: 25,
            after: None,
            before: None,
        }
    }
}

impl ListParams {
    /// Parse from a query string HashMap. Recognizes:
    /// `search`, `sort`, `dir`, `group`, `page`, `page_size`,
    /// and any key starting with `filter_`.
    pub fn from_query(q: &HashMap<String, String>) -> Self {
        let search = q.get("search").filter(|s| !s.trim().is_empty()).cloned();
        let sort_field = q.get("sort").filter(|s| !s.is_empty()).cloned();
        let sort_dir = match q.get("dir").map(|s| s.as_str()) {
            Some("desc") => SortDir::Desc,
            _ => SortDir::Asc,
        };
        let group_by = q.get("group").filter(|s| !s.is_empty()).cloned();
        let page = q.get("page").and_then(|s| s.parse().ok()).unwrap_or(1).max(1);
        let page_size = q
            .get("page_size")
            .and_then(|s| s.parse().ok())
            .unwrap_or(25)
            .clamp(5, 200);

        let mut filters = HashMap::new();
        for (k, v) in q {
            if let Some(field) = k.strip_prefix("filter_") {
                if !v.is_empty() {
                    filters.insert(field.to_string(), v.clone());
                }
            }
        }

        // Keyset cursors. `before` wins if both are somehow present so a
        // request is never ambiguous about direction.
        let before = q.get("before").filter(|s| !s.is_empty()).cloned();
        let after = if before.is_some() {
            None
        } else {
            q.get("after").filter(|s| !s.is_empty()).cloned()
        };

        Self { search, filters, sort_field, sort_dir, group_by, page, page_size, after, before }
    }

    /// Build URL query string from current params, overriding one key.
    /// Used by the render layer to build sort/filter/page links.
    pub fn to_query_with(&self, overrides: &[(&str, &str)]) -> String {
        let mut parts: Vec<String> = Vec::new();

        let mut ov: HashMap<&str, &str> = overrides.iter().cloned().collect();

        let search = ov.remove("search").map(String::from)
            .or_else(|| self.search.clone());
        if let Some(s) = &search {
            parts.push(format!("search={}", urlencoded(s)));
        }

        let sort = ov.remove("sort").map(String::from)
            .or_else(|| self.sort_field.clone());
        if let Some(s) = &sort {
            parts.push(format!("sort={}", urlencoded(s)));
        }

        let dir_str = ov.remove("dir").unwrap_or(
            match self.sort_dir { SortDir::Asc => "asc", SortDir::Desc => "desc" }
        );
        parts.push(format!("dir={}", dir_str));

        let group = ov.remove("group").map(String::from)
            .or_else(|| self.group_by.clone());
        if let Some(g) = &group {
            parts.push(format!("group={}", urlencoded(g)));
        }

        // Keyset cursors are emitted only when explicitly overridden (i.e. by
        // the Prev/Next links). They are never carried over from `self`, so a
        // sort / filter / search / page link naturally resets to the first
        // page of the new ordering instead of seeking from a stale cursor.
        if let Some(after) = ov.remove("after") {
            if !after.is_empty() {
                parts.push(format!("after={}", urlencoded(after)));
            }
        } else if let Some(before) = ov.remove("before") {
            if !before.is_empty() {
                parts.push(format!("before={}", urlencoded(before)));
            }
        } else {
            // Only paginate by page number when not seeking by cursor.
            let page = ov.remove("page")
                .and_then(|p| p.parse::<u64>().ok())
                .unwrap_or(self.page);
            parts.push(format!("page={}", page));
        }
        parts.push(format!("page_size={}", self.page_size));

        for (field, value) in &self.filters {
            if !ov.contains_key(format!("filter_{}", field).as_str()) {
                parts.push(format!("filter_{}={}", urlencoded(field), urlencoded(value)));
            }
        }
        for (k, v) in ov {
            if k.starts_with("filter_") {
                parts.push(format!("{}={}", k, urlencoded(v)));
            }
        }

        parts.join("&")
    }

    pub fn offset(&self) -> u64 {
        (self.page - 1) * self.page_size
    }
}

fn urlencoded(s: &str) -> String {
    s.replace('%', "%25")
        .replace(' ', "+")
        .replace('&', "%26")
        .replace('=', "%3D")
        .replace('#', "%23")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn query(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn defaults_when_query_is_empty() {
        let p = ListParams::from_query(&query(&[]));
        assert!(p.search.is_none());
        assert!(p.filters.is_empty());
        assert!(p.sort_field.is_none());
        assert_eq!(p.sort_dir, SortDir::Asc);
        assert_eq!(p.page, 1);
        assert_eq!(p.page_size, 25);
    }

    #[test]
    fn page_size_is_clamped_to_bounds() {
        assert_eq!(ListParams::from_query(&query(&[("page_size", "1000")])).page_size, 200);
        assert_eq!(ListParams::from_query(&query(&[("page_size", "1")])).page_size, 5);
        assert_eq!(ListParams::from_query(&query(&[("page_size", "50")])).page_size, 50);
        // Garbage falls back to the default rather than panicking.
        assert_eq!(ListParams::from_query(&query(&[("page_size", "abc")])).page_size, 25);
    }

    #[test]
    fn page_is_at_least_one() {
        assert_eq!(ListParams::from_query(&query(&[("page", "0")])).page, 1);
        assert_eq!(ListParams::from_query(&query(&[("page", "7")])).page, 7);
        assert_eq!(ListParams::from_query(&query(&[("page", "junk")])).page, 1);
    }

    #[test]
    fn direction_only_desc_is_recognized() {
        assert_eq!(ListParams::from_query(&query(&[("dir", "desc")])).sort_dir, SortDir::Desc);
        assert_eq!(ListParams::from_query(&query(&[("dir", "asc")])).sort_dir, SortDir::Asc);
        assert_eq!(ListParams::from_query(&query(&[("dir", "DESC")])).sort_dir, SortDir::Asc);
    }

    #[test]
    fn blank_search_and_sort_become_none() {
        let p = ListParams::from_query(&query(&[("search", "   "), ("sort", "")]));
        assert!(p.search.is_none());
        assert!(p.sort_field.is_none());
    }

    #[test]
    fn filter_prefix_is_stripped_and_empty_values_dropped() {
        let p = ListParams::from_query(&query(&[
            ("filter_contact_type", "customer"),
            ("filter_status", ""),
            ("search", "acme"),
        ]));
        assert_eq!(p.filters.get("contact_type"), Some(&"customer".to_string()));
        assert!(!p.filters.contains_key("status"));
        assert_eq!(p.search.as_deref(), Some("acme"));
    }

    #[test]
    fn offset_is_zero_based_from_page() {
        let p = ListParams { page: 1, page_size: 25, ..Default::default() };
        assert_eq!(p.offset(), 0);
        let p = ListParams { page: 4, page_size: 25, ..Default::default() };
        assert_eq!(p.offset(), 75);
    }

    #[test]
    fn to_query_with_overrides_and_preserves_filters() {
        let mut filters = HashMap::new();
        filters.insert("contact_type".to_string(), "customer".to_string());
        let p = ListParams {
            sort_field: Some("name".into()),
            sort_dir: SortDir::Desc,
            filters,
            page: 2,
            ..Default::default()
        };
        let qs = p.to_query_with(&[("page", "1")]);
        // The override wins for page; everything else is carried over.
        assert!(qs.contains("page=1"));
        assert!(qs.contains("sort=name"));
        assert!(qs.contains("dir=desc"));
        assert!(qs.contains("filter_contact_type=customer"));
    }
}
