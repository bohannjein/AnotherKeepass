//! SSO login: a one-shot HTTP listener on this machine that receives the authorization code
//! when the identity provider sends the browser back (`http://localhost:<port>/?code=…&state=…`).
//! Ports 8065–8070 like the Bitwarden CLI, so servers that check redirect addresses accept it.

use std::{
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    sync::atomic::{AtomicBool, Ordering},
    time::{Duration, Instant},
};

const PORTS: std::ops::RangeInclusive<u16> = 8065..=8070;
const WAIT: Duration = Duration::from_secs(300);

static CANCEL: AtomicBool = AtomicBool::new(false);

/// Stop a waiting SSO login (the user pressed cancel).
pub fn cancel() {
    CANCEL.store(true, Ordering::SeqCst);
}

pub fn listen() -> Result<(TcpListener, u16), String> {
    for port in PORTS {
        if let Ok(l) = TcpListener::bind(("127.0.0.1", port)) {
            l.set_nonblocking(true).map_err(|e| format!("sso:{e}"))?;
            return Ok((l, port));
        }
    }
    Err("sso:no_port".into())
}

/// Wait for the browser to come back. Requests without our `state` (favicon, a stale tab) are
/// answered and ignored. Errors: "sso_cancel", "sso_timeout", "sso:<provider error>".
pub fn wait_for_code(listener: &TcpListener, state: &str) -> Result<String, String> {
    CANCEL.store(false, Ordering::SeqCst);
    let end = Instant::now() + WAIT;
    loop {
        if CANCEL.swap(false, Ordering::SeqCst) {
            return Err("sso_cancel".into());
        }
        if Instant::now() > end {
            return Err("sso_timeout".into());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(result) = answer(stream, state) {
                    return result;
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => return Err(format!("sso:{e}")),
        }
    }
}

/// None: not the answer we wait for, keep listening.
fn answer(mut stream: TcpStream, state: &str) -> Option<Result<String, String>> {
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).ok()?;
    let head = String::from_utf8_lossy(&buf[..n]);
    let target = head.lines().next()?.split_whitespace().nth(1)?.to_string();
    let result = parse(&target, state);
    let (status, text) = match &result {
        None => ("404 Not Found", ""),
        Some(Ok(_)) => ("200 OK", "AnotherKeepass: signed in. You can close this window."),
        Some(Err(_)) => ("400 Bad Request", "AnotherKeepass: sign-in failed. You can close this window."),
    };
    let body =
        format!("<!doctype html><meta charset=utf-8><title>AnotherKeepass</title><p style=\"font:16px system-ui;margin:3em\">{text}</p>");
    let _ = write!(
        stream,
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    result
}

/// The redirect target ("/?code=…&state=…"): code if the state is ours.
fn parse(target: &str, state: &str) -> Option<Result<String, String>> {
    let u = url::Url::parse(&format!("http://localhost{target}")).ok()?;
    let q: std::collections::HashMap<_, _> = u.query_pairs().into_owned().collect();
    if q.get("state").map(String::as_str) != Some(state) {
        return None;
    }
    if let Some(e) = q.get("error") {
        let why = q.get("error_description").unwrap_or(e);
        return Some(Err(format!("sso:{why}")));
    }
    Some(q.get("code").filter(|c| !c.is_empty()).cloned().ok_or_else(|| "sso:no code".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_our_state_counts() {
        assert_eq!(parse("/?code=abc&state=s1", "s1"), Some(Ok("abc".into())));
        assert_eq!(parse("/?code=abc&state=other", "s1"), None);
        assert_eq!(parse("/favicon.ico", "s1"), None);
        assert_eq!(parse("/?error=access_denied&state=s1", "s1"), Some(Err("sso:access_denied".into())));
    }

    #[test]
    fn listener_takes_the_code_and_ignores_strangers() {
        let (l, port) = listen().unwrap();
        let t = std::thread::spawn(move || wait_for_code(&l, "st_identifier=x"));
        let send = |path: &str| {
            let mut s = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(s, "GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").unwrap();
            let mut out = String::new();
            let _ = s.read_to_string(&mut out);
            out
        };
        assert!(send("/?code=evil&state=wrong").starts_with("HTTP/1.1 404"));
        assert!(send("/?code=good&state=st_identifier%3Dx").starts_with("HTTP/1.1 200"));
        assert_eq!(t.join().unwrap(), Ok("good".into()));
    }
}
