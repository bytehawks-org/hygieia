//! Domain normalisation and suffix matching on a reversed-label trie.

use std::collections::HashMap;

/// Normalise a hostname: lowercase, strip trailing dot and leading `*.`.
/// Returns `None` for anything that is not a plausible ASCII hostname
/// (IDNs must be supplied in punycode).
pub fn normalize(input: &str) -> Option<String> {
    let s = input.trim().trim_end_matches('.');
    let s = s.strip_prefix("*.").unwrap_or(s);
    if s.is_empty() || s.len() > 253 {
        return None;
    }
    let s = s.to_ascii_lowercase();
    for label in s.split('.') {
        if label.is_empty() || label.len() > 63 {
            return None;
        }
        if !label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
    }
    Some(s)
}

#[derive(Default, Debug, Clone)]
struct Node {
    children: HashMap<Box<str>, Node>,
    terminal: bool,
}

/// Set of domains with suffix semantics: inserting `example.com` also matches
/// `ads.example.com`. Lookup is O(number of labels), independent of set size.
#[derive(Default, Debug, Clone)]
pub struct DomainTrie {
    root: Node,
    len: usize,
}

impl DomainTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a domain; returns `false` if invalid or already present.
    pub fn insert(&mut self, domain: &str) -> bool {
        let Some(d) = normalize(domain) else {
            return false;
        };
        let mut node = &mut self.root;
        for label in d.rsplit('.') {
            node = node.children.entry(label.into()).or_default();
        }
        if node.terminal {
            return false;
        }
        node.terminal = true;
        self.len += 1;
        true
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Returns the *shortest* matching rule (the suffix stored in the set).
    pub fn find(&self, host: &str) -> Option<String> {
        let h = normalize(host)?;
        let labels: Vec<&str> = h.split('.').collect();
        let mut node = &self.root;
        for (depth, label) in labels.iter().rev().enumerate() {
            node = node.children.get(*label)?;
            if node.terminal {
                return Some(labels[labels.len() - depth - 1..].join("."));
            }
        }
        None
    }

    pub fn contains(&self, host: &str) -> bool {
        self.find(host).is_some()
    }

    /// All stored domains, sorted (stable serialisation).
    pub fn to_sorted_vec(&self) -> Vec<String> {
        fn walk(n: &Node, path: &mut Vec<String>, out: &mut Vec<String>) {
            if n.terminal {
                out.push(path.iter().rev().cloned().collect::<Vec<_>>().join("."));
            }
            for (k, c) in &n.children {
                path.push(k.to_string());
                walk(c, path, out);
                path.pop();
            }
        }
        let mut out = Vec::with_capacity(self.len);
        walk(&self.root, &mut Vec::new(), &mut out);
        out.sort();
        out
    }
}

impl<'a> FromIterator<&'a str> for DomainTrie {
    fn from_iter<T: IntoIterator<Item = &'a str>>(iter: T) -> Self {
        let mut t = Self::new();
        for d in iter {
            t.insert(d);
        }
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn suffix_match() {
        let t: DomainTrie = ["example.com", "ads.foo.org"].into_iter().collect();
        assert_eq!(t.find("example.com").as_deref(), Some("example.com"));
        assert_eq!(t.find("a.b.EXAMPLE.com.").as_deref(), Some("example.com"));
        assert!(t.contains("x.ads.foo.org"));
        assert!(!t.contains("foo.org"));
        assert!(!t.contains("notexample.com"));
    }

    #[test]
    fn shortest_rule_wins() {
        let t: DomainTrie = ["a.example.com", "example.com"].into_iter().collect();
        assert_eq!(t.find("x.a.example.com").as_deref(), Some("example.com"));
    }

    #[test]
    fn normalize_rejects_garbage() {
        assert!(normalize("").is_none());
        assert!(normalize("a..b").is_none());
        assert!(normalize("exa mple.com").is_none());
        assert_eq!(normalize("*.Example.COM.").as_deref(), Some("example.com"));
    }

    #[test]
    fn roundtrip_sorted() {
        let t: DomainTrie = ["b.com", "a.com", "x.a.com"].into_iter().collect();
        assert_eq!(t.to_sorted_vec(), vec!["a.com", "b.com", "x.a.com"]);
    }
}
