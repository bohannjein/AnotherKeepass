//! Native-messaging proxy mode: the browser starts our exe with the extension origin as
//! argument; we relay its length-prefixed stdin/stdout messages to the running app's socket.
//! (Same job as keepassxc-proxy, so it works on machines without KeePassXC.)

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Chrome passes "chrome-extension://<id>/", Firefox passes the manifest path and the add-on id.
pub fn is_native_messaging() -> bool {
    std::env::args().skip(1).any(|a| a.starts_with("chrome-extension://") || a == "keepassxc-browser@keepassxc.org")
}

/// Takes every complete JSON message off the front of `buf` (messages may arrive split over
/// several reads or several at once) and leaves an unfinished one in place. Bytes that cannot be
/// JSON are dropped, so garbage never blocks the stream.
pub fn split_messages(buf: &mut Vec<u8>) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut consumed = 0;
    {
        let mut stream = serde_json::Deserializer::from_slice(buf).into_iter::<serde::de::IgnoredAny>();
        loop {
            match stream.next() {
                Some(Ok(_)) => {
                    let end = stream.byte_offset();
                    out.push(buf[consumed..end].trim_ascii().to_vec());
                    consumed = end;
                }
                Some(Err(e)) if e.is_eof() => break,
                Some(Err(_)) => {
                    consumed = buf.len();
                    break;
                }
                None => {
                    consumed = buf.len(); // only whitespace left
                    break;
                }
            }
        }
    }
    buf.drain(..consumed);
    out
}

pub fn run() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    rt.block_on(async {
        let Ok(sock) = connect().await else { return }; // app not running: the extension shows "not connected"
        let (mut sock_rd, mut sock_wr) = tokio::io::split(sock);
        let to_app = async {
            let mut stdin = tokio::io::stdin();
            while let Ok(len) = stdin.read_u32_le().await {
                let len = len as usize;
                if len > 4 * 1024 * 1024 {
                    break;
                }
                let mut msg = vec![0u8; len];
                if stdin.read_exact(&mut msg).await.is_err() || sock_wr.write_all(&msg).await.is_err() {
                    break;
                }
            }
        };
        let to_browser = async {
            let mut stdout = tokio::io::stdout();
            let mut chunk = vec![0u8; 64 * 1024];
            let mut pending = Vec::new();
            'read: loop {
                match sock_rd.read(&mut chunk).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => pending.extend_from_slice(&chunk[..n]),
                }
                if pending.len() > 8 * 1024 * 1024 {
                    break; // not a message stream
                }
                // the browser wants one length-prefixed message at a time, however the bytes arrived
                for msg in split_messages(&mut pending) {
                    if stdout.write_u32_le(msg.len() as u32).await.is_err()
                        || stdout.write_all(&msg).await.is_err()
                        || stdout.flush().await.is_err()
                    {
                        break 'read;
                    }
                }
            }
        };
        tokio::select! { _ = to_app => {}, _ = to_browser => {} }
    });
    // app quit or browser closed: exit right away. Dropping the runtime would wait forever
    // for the blocking stdin read, leaving the proxy (and a lock on the exe) behind.
    std::process::exit(0);
}

#[cfg(windows)]
async fn connect() -> std::io::Result<tokio::net::windows::named_pipe::NamedPipeClient> {
    use std::os::windows::io::AsRawHandle;
    let pipe = tokio::net::windows::named_pipe::ClientOptions::new().open(crate::browser_server::pipe_name())?;
    // passwords only go to a server running as this user (no squatted pipe)
    if !crate::hardening::pipe_server_is_me(pipe.as_raw_handle() as _) {
        return Err(std::io::Error::other("browser pipe served by another user"));
    }
    Ok(pipe)
}

#[cfg(unix)]
async fn connect() -> std::io::Result<tokio::net::UnixStream> {
    use std::os::unix::fs::MetadataExt;
    let path = crate::browser_server::socket_path();
    // passwords only go to a socket this user owns (nobody else can have put one there)
    if let Some(me) = crate::browser_server::my_uid()
        && std::fs::metadata(&path)?.uid() != me
    {
        return Err(std::io::Error::other("browser socket belongs to another user"));
    }
    tokio::net::UnixStream::connect(path).await
}

#[cfg(test)]
mod tests {
    use super::split_messages;

    #[test]
    fn splits_joined_and_split_messages() {
        let mut buf = br#"{"a":1} {"b":"x}y"}{"c":[1,2"#.to_vec();
        let got = split_messages(&mut buf);
        assert_eq!(got, vec![br#"{"a":1}"#.to_vec(), br#"{"b":"x}y"}"#.to_vec()]);
        assert_eq!(buf, br#"{"c":[1,2"#, "the unfinished message waits");
        buf.extend_from_slice(b"]}");
        assert_eq!(split_messages(&mut buf), vec![br#"{"c":[1,2]}"#.to_vec()]);
        assert!(buf.is_empty());
        let mut junk = br#"}}}{"ok":1}"#.to_vec();
        split_messages(&mut junk);
        assert!(junk.len() <= 8, "garbage does not pile up");
    }
}
