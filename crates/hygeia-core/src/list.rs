//! Parsers for third-party blocklist formats (domain level).
//!
//! Full ABP/uBO network and cosmetic syntax is handled by the blocker/proxy
//! engines; here only what DNS-level filtering can express is extracted.

use crate::domain::normalize;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListFormat {
    /// `0.0.0.0 domain` / `127.0.0.1 domain`
    Hosts,
    /// One domain per line
    Domains,
    /// Adblock Plus syntax: only `||domain^` and `@@||domain^` are used
    Abp,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ParsedList {
    pub block: Vec<String>,
    pub allow: Vec<String>,
    /// Lines that are neither comments nor representable at domain level.
    pub skipped: usize,
}

pub fn parse_list(format: ListFormat, text: &str) -> ParsedList {
    let mut out = ParsedList::default();
    for raw in text.lines() {
        let line = raw.trim();
        let abp = format == ListFormat::Abp;
        // In ABP syntax `#` starts cosmetic rules (counted as skipped), not comments.
        if line.is_empty()
            || (!abp && line.starts_with('#'))
            || line.starts_with('!')
            || line.starts_with('[')
        {
            continue;
        }
        match format {
            ListFormat::Hosts => parse_hosts(line, &mut out),
            ListFormat::Domains => {
                let l = line.split('#').next().unwrap_or("").trim();
                push(l, &mut out.block, &mut out.skipped);
            }
            ListFormat::Abp => parse_abp(line, &mut out),
        }
    }
    out
}

fn push(d: &str, dst: &mut Vec<String>, skipped: &mut usize) {
    match normalize(d) {
        Some(n) => dst.push(n),
        None => *skipped += 1,
    }
}

fn parse_hosts(line: &str, out: &mut ParsedList) {
    let line = line.split('#').next().unwrap_or("").trim();
    let mut it = line.split_whitespace();
    let (Some(ip), Some(host)) = (it.next(), it.next()) else {
        out.skipped += 1;
        return;
    };
    if !matches!(ip, "0.0.0.0" | "127.0.0.1" | "::" | "::1") {
        out.skipped += 1;
        return;
    }
    if matches!(
        host,
        "localhost" | "localhost.localdomain" | "local" | "broadcasthost"
    ) {
        return;
    }
    push(host, &mut out.block, &mut out.skipped);
}

fn parse_abp(line: &str, out: &mut ParsedList) {
    let (dst, rest) = match line.strip_prefix("@@||") {
        Some(r) => (&mut out.allow, r),
        None => match line.strip_prefix("||") {
            Some(r) => (&mut out.block, r),
            None => {
                out.skipped += 1;
                return;
            }
        },
    };
    // Accept only plain `domain^` (optionally `^$important` is NOT accepted:
    // options change semantics and cannot be honoured at DNS level).
    let Some(domain) = rest.strip_suffix('^') else {
        out.skipped += 1;
        return;
    };
    if domain.contains(['/', '*', '$', '|', '?', ':']) {
        out.skipped += 1;
        return;
    }
    push(domain, dst, &mut out.skipped);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hosts() {
        let p = parse_list(
            ListFormat::Hosts,
            "# c\n127.0.0.1 localhost\n0.0.0.0 ads.example.com # x\n0.0.0.0 tracker.test\nfoo bar\n",
        );
        assert_eq!(p.block, vec!["ads.example.com", "tracker.test"]);
        assert_eq!(p.skipped, 1);
    }

    #[test]
    fn domains() {
        let p = parse_list(ListFormat::Domains, "a.com\n\n# x\nB.com # y\nbad domain\n");
        assert_eq!(p.block, vec!["a.com", "b.com"]);
        assert_eq!(p.skipped, 1);
    }

    #[test]
    fn abp() {
        let p = parse_list(
            ListFormat::Abp,
            "[Adblock Plus 2.0]\n! c\n||ads.example.com^\n@@||ok.example.com^\n||x.com/path^\n||y.com^$third-party\n##.banner\n",
        );
        assert_eq!(p.block, vec!["ads.example.com"]);
        assert_eq!(p.allow, vec!["ok.example.com"]);
        assert_eq!(p.skipped, 3);
    }
}
