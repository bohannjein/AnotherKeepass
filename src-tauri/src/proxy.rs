//! Native-messaging proxy mode: the browser starts our exe with the extension origin as
//! argument; we relay its length-prefixed stdin/stdout messages to the running app's socket.
//! (Same job as keepassxc-proxy, so it works on machines without KeePassXC.)

use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Chrome passes "chrome-extension://<id>/", Firefox passes the manifest path and the add-on id.
pub fn is_native_messaging() -> bool {
    std::env::args().skip(1).any(|a| a.starts_with("chrome-extension://") || a == "keepassxc-browser@keepassxc.org")
}

pub fn run() {
    let rt = tokio::runtime::Builder::new_current_thread().enable_all().build().expect("runtime");
    rt.block_on(async {
        let Ok(sock) = connect().await else { return }; // app not running: the extension shows "not connected"
        let (mut sock_rd, mut sock_wr) = tokio::io::split(sock);
        let to_app = async {
            let mut stdin = tokio::io::stdin();
            loop {
                let len = match stdin.read_u32_le().await { Ok(l) => l as usize, Err(_) => break };
                if len > 4 * 1024 * 1024 { break; }
                let mut msg = vec![0u8; len];
                if stdin.read_exact(&mut msg).await.is_err() || sock_wr.write_all(&msg).await.is_err() { break; }
            }
        };
        let to_browser = async {
            let mut stdout = tokio::io::stdout();
            let mut buf = vec![0u8; 1024 * 1024];
            loop {
                let n = match sock_rd.read(&mut buf).await { Ok(0) | Err(_) => break, Ok(n) => n };
                // one socket read = one JSON message (the app writes each reply in one go)
                if stdout.write_u32_le(n as u32).await.is_err() || stdout.write_all(&buf[..n]).await.is_err() || stdout.flush().await.is_err() { break; }
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
    tokio::net::UnixStream::connect(crate::browser_server::socket_path()).await
}
