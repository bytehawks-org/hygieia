//! Parser for cosmetic filters (element hiding + scriptlet injection) in
//! ABP / uBlock Origin syntax.
//!
//! Supported:
//!   `##sel`, `a.com,b.org##sel`            element hiding
//!   `a.com#@#sel`, `#@#sel`                 exceptions
//!   `a.com##+js(name, arg, ...)`            uBO scriptlet call (data only)
//!   `~a.com` negation                       generic rule + exception on that host
//! Not supported (counted in `skipped`): procedural selectors (`:has-text`,
//! `:xpath`, `:matches-css`, `:upward`, `:remove`, `:style`...), HTML filters
//! (`##^`), `#?#`, `#$#`, entity domains (`google.*`), AdGuard `#%#`, regex hosts.
//!
//! SECURITY: lists are untrusted input and selectors end up in CSS injected into
//! pages, so they are validated against rule-breakout (`}`, `;`, `@`, `url(`,
//! unbalanced quotes/brackets). Scriptlets named `trusted-*` are privileged in
//! uBO and are dropped unless explicitly allowed for a source.

use std::collections::{HashMap, HashSet};

use crate::cosmetic::{CosmeticRules, HostRules, ScriptletCall};
use crate::domain::normalize;

const MAX_SELECTOR: usize = 1024;
const MAX_ARGS: usize = 8;
const MAX_ARG: usize = 512;

#[derive(Debug, Clone, Copy, Default)]
pub struct CosmeticOptions {
    /// Keep `trusted-*` scriptlets (only for sources you fully trust).
    pub allow_trusted_scriptlets: bool,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedCosmetic {
    pub rules: CosmeticRules,
    pub skipped: usize,
    pub dropped_trusted: usize,
}

/// CSS-injection safety check for a selector.
pub fn is_safe_selector(sel: &str) -> bool {
    if sel.is_empty() || sel.len() > MAX_SELECTOR {
        return false;
    }
    let lower = sel.to_ascii_lowercase();
    if lower.contains("/*")
        || lower.contains("url(")
        || lower.contains("expression(")
        || lower.contains("javascript:")
    {
        return false;
    }
    let mut stack: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut chars = sel.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            if chars.next().is_none() {
                return false;
            }
            continue;
        }
        if c.is_control() {
            return false;
        }
        if let Some(q) = quote {
            if c == q {
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => quote = Some(c),
            '{' | '}' | ';' | '@' | '<' => return false,
            '[' | '(' => stack.push(c),
            ']' if stack.pop() != Some('[') => return false,
            ')' if stack.pop() != Some('(') => return false,
            _ => {}
        }
    }
    stack.is_empty() && quote.is_none()
}

/// Selectors that need a procedural engine, not plain CSS.
fn is_procedural(sel: &str) -> bool {
    const P: [&str; 14] = [
        ":has-text(",
        ":xpath(",
        ":matches-css",
        ":matches-attr(",
        ":matches-media(",
        ":matches-path(",
        ":min-text-length(",
        ":upward(",
        ":remove(",
        ":style(",
        ":others(",
        ":watch-attr(",
        ":-abp-",
        ":contains(",
    ];
    sel.starts_with('^') || P.iter().any(|p| sel.contains(p))
}

/// Split `name, arg1, arg2` honouring quotes and `\,` escapes.
fn split_args(s: &str) -> Option<Vec<String>> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut quote: Option<char> = None;
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\\' => match chars.peek() {
                Some(',') => {
                    cur.push(',');
                    chars.next();
                }
                _ => cur.push('\\'),
            },
            '\'' | '"' if quote.is_none() && cur.trim().is_empty() => {
                quote = Some(c);
                cur.clear();
            }
            c if Some(c) == quote => quote = None,
            ',' if quote.is_none() => out.push(std::mem::take(&mut cur).trim().to_string()),
            c => cur.push(c),
        }
    }
    if quote.is_some() {
        return None;
    }
    out.push(cur.trim().to_string());
    Some(out)
}

fn parse_scriptlet(
    body: &str,
    opts: CosmeticOptions,
    dropped: &mut usize,
) -> Option<ScriptletCall> {
    let inner = body.strip_prefix("+js(")?.strip_suffix(')')?;
    let mut parts = split_args(inner)?;
    if parts.is_empty() || parts.len() > MAX_ARGS + 1 {
        return None;
    }
    let name = parts.remove(0);
    if name.is_empty()
        || !name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.')
    {
        return None;
    }
    if name.starts_with("trusted-") && !opts.allow_trusted_scriptlets {
        *dropped += 1;
        return None;
    }
    if parts
        .iter()
        .any(|a| a.len() > MAX_ARG || a.chars().any(char::is_control))
    {
        return None;
    }
    Some(ScriptletCall { name, args: parts })
}

/// Locate the separator. Returns `(domains, is_exception, body)`.
fn split_rule(line: &str) -> Option<(&str, bool, &str)> {
    // Order matters: longer / special separators first.
    for sep in ["#@#", "#?#", "#$#", "#%#", "##"] {
        if let Some(i) = line.find(sep) {
            let exception = sep == "#@#";
            if sep == "#?#" || sep == "#$#" || sep == "#%#" {
                return None;
            }
            return Some((&line[..i], exception, &line[i + sep.len()..]));
        }
    }
    None
}

pub fn parse_cosmetic(text: &str, opts: CosmeticOptions) -> ParsedCosmetic {
    let mut out = ParsedCosmetic::default();
    let mut generic_seen: HashSet<String> = HashSet::new();
    let mut generic_exceptions: HashSet<String> = HashSet::new();

    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('!') || line.starts_with('[') {
            continue;
        }
        // Cheap prefilter: cosmetic rules contain '#'; network rules are not ours.
        if !line.contains('#') {
            continue;
        }
        if line.starts_with('#') && !line.starts_with("##") && !line.starts_with("#@#") {
            // `# comment` (hosts-style) or exotic syntax
            if line.starts_with("#?#") || line.starts_with("#$#") || line.starts_with("#%#") {
                out.skipped += 1;
            }
            continue;
        }
        let Some((domains, exception, body)) = split_rule(line) else {
            // `#?#`, `#$#`, `#%#` or not a cosmetic rule at all (e.g. '#' inside a URL filter)
            if line.contains("#?#") || line.contains("#$#") || line.contains("#%#") {
                out.skipped += 1;
            }
            continue;
        };
        if domains.contains('/') {
            out.skipped += 1; // regex host or URL fragment in a network rule
            continue;
        }

        // domains
        let mut pos: Vec<String> = Vec::new();
        let mut neg: Vec<String> = Vec::new();
        let mut bad = false;
        for d in domains.split(',').map(str::trim).filter(|d| !d.is_empty()) {
            let (negated, d) = d.strip_prefix('~').map_or((false, d), |r| (true, r));
            if d.ends_with(".*") {
                bad = true; // entity
                break;
            }
            match normalize(d) {
                Some(n) => {
                    if negated {
                        neg.push(n)
                    } else {
                        pos.push(n)
                    }
                }
                None => {
                    bad = true;
                    break;
                }
            }
        }
        if bad {
            out.skipped += 1;
            continue;
        }

        if body.starts_with("+js(") {
            let Some(call) = parse_scriptlet(body, opts, &mut out.dropped_trusted) else {
                if !body.contains("trusted-") {
                    out.skipped += 1;
                }
                continue;
            };
            if exception || pos.is_empty() {
                // scriptlet exceptions / global scriptlets: not representable safely
                out.skipped += 1;
                continue;
            }
            for h in &pos {
                let hr = out.rules.by_host.entry(h.clone()).or_default();
                if !hr.scriptlets.contains(&call) {
                    hr.scriptlets.push(call.clone());
                }
            }
            continue;
        }

        if is_procedural(body) || !is_safe_selector(body) {
            out.skipped += 1;
            continue;
        }
        let sel = body.to_string();

        match (exception, pos.is_empty()) {
            // `sel` hidden on given hosts
            (false, false) => {
                for h in &pos {
                    let hr = out.rules.by_host.entry(h.clone()).or_default();
                    if !hr.selectors.contains(&sel) {
                        hr.selectors.push(sel.clone());
                    }
                }
            }
            // generic, optionally with host exclusions
            (false, true) => {
                if generic_seen.insert(sel.clone()) {
                    out.rules.generic.push(sel.clone());
                }
                for h in &neg {
                    let hr = out.rules.by_host.entry(h.clone()).or_default();
                    if !hr.exceptions.contains(&sel) {
                        hr.exceptions.push(sel.clone());
                    }
                }
            }
            // `a.com#@#sel`: do not apply generic `sel` on a.com
            (true, false) => {
                for h in &pos {
                    let hr = out.rules.by_host.entry(h.clone()).or_default();
                    if !hr.exceptions.contains(&sel) {
                        hr.exceptions.push(sel.clone());
                    }
                }
            }
            // `#@#sel`: globally cancel
            (true, true) => {
                generic_exceptions.insert(sel);
            }
        }
    }
    if !generic_exceptions.is_empty() {
        out.rules
            .generic
            .retain(|s| !generic_exceptions.contains(s));
    }
    out.rules.by_host.retain(|_, h| *h != HostRules::default());
    out
}

impl CosmeticRules {
    /// Merge `other` into `self`, de-duplicating.
    pub fn merge(&mut self, other: CosmeticRules) {
        let seen: HashSet<String> = self.generic.iter().cloned().collect();
        self.generic
            .extend(other.generic.into_iter().filter(|s| !seen.contains(s)));
        let mut idx: HashMap<String, HostRules> = std::mem::take(&mut self.by_host);
        for (h, r) in other.by_host {
            let e = idx.entry(h).or_default();
            for s in r.selectors {
                if !e.selectors.contains(&s) {
                    e.selectors.push(s);
                }
            }
            for s in r.exceptions {
                if !e.exceptions.contains(&s) {
                    e.exceptions.push(s);
                }
            }
            for s in r.scriptlets {
                if !e.scriptlets.contains(&s) {
                    e.scriptlets.push(s);
                }
            }
        }
        self.by_host = idx;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(t: &str) -> ParsedCosmetic {
        parse_cosmetic(t, CosmeticOptions::default())
    }

    #[test]
    fn hiding_generic_and_host() {
        let r = p(
            "! c\n##.ad-banner\nexample.com,other.org###promo\nexample.com#@#.ad-banner\nfoo.test##.x\n",
        );
        assert_eq!(r.rules.generic, vec![".ad-banner"]);
        assert_eq!(r.rules.by_host["example.com"].selectors, vec!["#promo"]);
        assert_eq!(
            r.rules.by_host["example.com"].exceptions,
            vec![".ad-banner"]
        );
        assert_eq!(r.rules.by_host["other.org"].selectors, vec!["#promo"]);
    }

    #[test]
    fn negated_domain_becomes_exception() {
        let r = p("~keep.com##.sponsor\n");
        assert_eq!(r.rules.generic, vec![".sponsor"]);
        assert_eq!(r.rules.by_host["keep.com"].exceptions, vec![".sponsor"]);
        let page = r.rules.for_host("keep.com");
        assert!(page.selectors.is_empty());
        assert_eq!(r.rules.for_host("x.com").selectors, vec![".sponsor"]);
    }

    #[test]
    fn global_exception_removes_generic() {
        let r = p("##.a\n##.b\n#@#.a\n");
        assert_eq!(r.rules.generic, vec![".b"]);
    }

    #[test]
    fn scriptlets() {
        let r = p(
            "a.com##+js(set-constant, adsEnabled, false)\nb.com##+js(abort-on-property-read, 'x,y')\nc.com##+js(trusted-replace-xhr-response, 'a', 'b')\nd.com#@#+js(nostr)\n",
        );
        let a = &r.rules.by_host["a.com"].scriptlets[0];
        assert_eq!(
            (a.name.as_str(), a.args.as_slice()),
            (
                "set-constant",
                &["adsEnabled".to_string(), "false".to_string()][..]
            )
        );
        assert_eq!(r.rules.by_host["b.com"].scriptlets[0].args, vec!["x,y"]);
        assert!(!r.rules.by_host.contains_key("c.com"));
        assert_eq!(r.dropped_trusted, 1);

        let t = parse_cosmetic(
            "c.com##+js(trusted-replace-xhr-response, a, b)",
            CosmeticOptions {
                allow_trusted_scriptlets: true,
            },
        );
        assert_eq!(
            t.rules.by_host["c.com"].scriptlets[0].name,
            "trusted-replace-xhr-response"
        );
    }

    #[test]
    fn escaped_comma_in_arg() {
        let r = p("a.com##+js(rmnt, script, /a\\,b/)\n");
        assert_eq!(
            r.rules.by_host["a.com"].scriptlets[0].args,
            vec!["script", "/a,b/"]
        );
    }

    #[test]
    fn rejects_unsafe_and_unsupported() {
        let r = p(
            "a.com##.x{display:none}\na.com##.y;color:red\na.com##div[a=\"b]\na.com##.z:has-text(Ad)\na.com##^script:has-text(x)\ngoogle.*##.e\na.com#?#.p\na.com##div{}\n##a[href^=\"https://e.com/x\"]\n",
        );
        assert_eq!(r.rules.generic, vec!["a[href^=\"https://e.com/x\"]"]);
        assert!(r.rules.by_host.is_empty());
        assert_eq!(r.skipped, 8);
    }

    #[test]
    fn network_rules_and_comments_ignored() {
        let r = p("||ads.com^\n@@||ok.com^$document\n# hosts comment\n||x.com/#frag^\n");
        assert_eq!(r, ParsedCosmetic::default());
    }

    #[test]
    fn safe_selector_cases() {
        assert!(is_safe_selector("div.ad > a[href*=\"x\"]:not(.y)"));
        assert!(is_safe_selector(".tw\\:flex"));
        assert!(!is_safe_selector("a} body{background:url(x)"));
        assert!(!is_safe_selector("a[href=\"x]"));
        assert!(!is_safe_selector("@import"));
    }

    #[test]
    fn merge_dedups() {
        let mut a = p("##.a\nx.com##.s\n").rules;
        a.merge(p("##.a\n##.b\nx.com##.s\nx.com##.t\n").rules);
        assert_eq!(a.generic, vec![".a", ".b"]);
        assert_eq!(a.by_host["x.com"].selectors, vec![".s", ".t"]);
    }
}
