//! Website icons. Only on request (button), never while browsing the list, because every
//! download tells the site (or DuckDuckGo) which accounts you have.
//! Direct: the page's <link rel="icon"> (bigger apple-touch-icon preferred), then /favicon.ico.
//! DuckDuckGo: their icon service, so the sites themselves see nothing.

use std::{io::Read, time::Duration};

use base64::{Engine, engine::general_purpose::STANDARD as B64};

const MAX_BYTES: u64 = 512 * 1024;

fn host_url(url: &str) -> Option<url::Url> {
    let u = url::Url::parse(url).or_else(|_| url::Url::parse(&format!("https://{url}"))).ok()?;
    u.host_str()?;
    Some(u)
}

fn get(agent: &ureq::Agent, url: &str) -> Option<(String, Vec<u8>)> {
    let res = agent.get(url).call().ok()?;
    let mime = res.content_type().to_string();
    let mut body = Vec::new();
    res.into_reader().take(MAX_BYTES).read_to_end(&mut body).ok()?;
    Some((mime, body))
}

fn is_image(mime: &str, body: &[u8]) -> bool {
    !body.is_empty() && (mime.starts_with("image/") || body.starts_with(&[0, 0, 1, 0]) || body.starts_with(b"\x89PNG"))
}

/// `<link rel="..icon.." href="..">` candidates, apple-touch-icon first (larger, looks better).
fn icon_links(html: &str) -> Vec<String> {
    let lower = html.to_ascii_lowercase();
    let attr = |tag: &str, name: &str| -> Option<String> {
        let t = tag.to_ascii_lowercase();
        let i = t.find(&format!("{name}="))? + name.len() + 1;
        let rest = &tag[i..];
        let (quote, rest) = match rest.chars().next()? {
            q @ ('"' | '\'') => (Some(q), &rest[1..]),
            _ => (None, rest),
        };
        let end = match quote {
            Some(q) => rest.find(q)?,
            None => rest.find(|c: char| c.is_whitespace() || c == '>').unwrap_or(rest.len()),
        };
        Some(rest[..end].to_string())
    };
    let mut found: Vec<(u8, String)> = Vec::new();
    let mut pos = 0;
    while let Some(i) = lower[pos..].find("<link") {
        let start = pos + i;
        let end = lower[start..].find('>').map(|e| start + e).unwrap_or(lower.len());
        let tag = &html[start..end];
        if let (Some(rel), Some(href)) = (attr(tag, "rel"), attr(tag, "href")) {
            let rel = rel.to_ascii_lowercase();
            if rel.contains("icon") && !rel.contains("mask") {
                found.push((if rel.contains("apple-touch") { 0 } else { 1 }, href));
            }
        }
        pos = end;
    }
    found.sort_by_key(|(rank, _)| *rank);
    found.into_iter().map(|(_, h)| h).collect()
}

fn fetch(url: &str, ddg: bool, timeout: u64) -> Option<Vec<u8>> {
    let base = host_url(url)?;
    let host = base.host_str()?.to_string();
    let agent =
        ureq::AgentBuilder::new().timeout(Duration::from_secs(timeout.clamp(1, 60))).user_agent("Mozilla/5.0 AnotherKeepass").build();
    if ddg {
        return get(&agent, &format!("https://icons.duckduckgo.com/ip3/{host}.ico")).filter(|(m, b)| is_image(m, b)).map(|(_, b)| b);
    }
    let origin = format!("{}://{}", if base.scheme() == "http" { "http" } else { "https" }, base.host_str()?);
    if let Some((_, page)) = get(&agent, &format!("{origin}/")) {
        let page_url = url::Url::parse(&format!("{origin}/")).ok()?;
        for href in icon_links(&String::from_utf8_lossy(&page)) {
            let Ok(abs) = page_url.join(&href) else { continue };
            if abs.scheme() == "data" {
                continue;
            }
            if let Some((_, b)) = get(&agent, abs.as_str()).filter(|(m, b)| is_image(m, b)) {
                return Some(b);
            }
        }
    }
    get(&agent, &format!("{origin}/favicon.ico")).filter(|(m, b)| is_image(m, b)).map(|(_, b)| b)
}

/// Raw icon bytes (base64; PNG/ICO/SVG…). The UI scales it to a 64 px PNG before storing.
#[tauri::command]
pub async fn favicon_fetch(url: String, ddg: bool, timeout: u64) -> Result<String, String> {
    tauri::async_runtime::spawn_blocking(move || fetch(&url, ddg, timeout))
        .await
        .map_err(|e| e.to_string())?
        .map(|b| B64.encode(b))
        .ok_or_else(|| "no_icon".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links() {
        let html = r#"<head><LINK rel="icon" href="/fav.png"><link rel='apple-touch-icon' href='/apple.png'>
            <link rel=mask-icon href=/mask.svg><link rel="stylesheet" href="/a.css"></head>"#;
        assert_eq!(icon_links(html), vec!["/apple.png", "/fav.png"]);
        assert!(host_url("example.com/login").is_some());
        assert!(is_image("", b"\x89PNG..."));
    }
}

#[cfg(test)]
mod net_tests {
    /// needs internet: cargo test --lib favicon_live -- --ignored
    #[test]
    #[ignore]
    fn favicon_live() {
        for (url, ddg) in [("https://github.com/login", false), ("wikipedia.org", false), ("github.com", true)] {
            let b = super::fetch(url, ddg, 10).unwrap_or_else(|| panic!("{url}"));
            assert!(super::is_image("", &b) || b.starts_with(b"<svg") || b.len() > 100, "{url}: {} bytes", b.len());
        }
    }
}
