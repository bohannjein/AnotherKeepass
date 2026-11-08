//! Updates, as plain as on a phone: one source for stable releases (the signed updater manifest
//! `latest.json`, the same the install uses), download in the background, install on a click or
//! on its own while the app sits unused in the tray. Betas are only looked up on GitHub and
//! opened in the browser. The Tauri updater only accepts packages signed with the project's
//! update key (public key in tauri.conf.json).

use std::sync::{
    Mutex,
    atomic::{AtomicBool, Ordering},
};

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use tauri_plugin_updater::UpdaterExt;

const RELEASES: &str = "https://api.github.com/repos/bohannjein/AnotherKeepass/releases?per_page=10";

#[derive(Serialize, Clone)]
pub struct Update {
    version: String,
    url: String,
    notes: String,
    /// true: signed package from the updater manifest, installable in the app.
    /// false: only a newer beta on GitHub; the UI opens the release page.
    installable: bool,
}

/// The downloaded, not yet installed package.
#[derive(Default)]
pub struct Pending(Mutex<Option<(tauri_plugin_updater::Update, Vec<u8>)>>);

/// Set while a background install waits for an idle moment.
static AUTO_WAIT: AtomicBool = AtomicBool::new(false);

/// "v1.2.3" / "1.2.3-beta.1" → (1, 2, 3); prerelease suffix ignored for ordering.
fn parse(v: &str) -> Option<(u64, u64, u64)> {
    let core = v.trim().trim_start_matches(['v', 'V']).split(['-', '+']).next()?;
    let mut it = core.split('.').map(|p| p.parse::<u64>().ok());
    Some((it.next()??, it.next().flatten().unwrap_or(0), it.next().flatten().unwrap_or(0)))
}

fn newest(json: &serde_json::Value, current: &str, beta: bool) -> Option<Update> {
    let cur = parse(current)?;
    json.as_array()?
        .iter()
        .filter(|r| !r["draft"].as_bool().unwrap_or(false) && (beta || !r["prerelease"].as_bool().unwrap_or(false)))
        .filter_map(|r| {
            let tag = r["tag_name"].as_str()?;
            Some((parse(tag)?, r))
        })
        .filter(|(v, _)| *v > cur)
        .max_by_key(|(v, _)| *v)
        .map(|(_, r)| Update {
            version: r["tag_name"].as_str().unwrap_or_default().trim_start_matches('v').to_string(),
            url: r["html_url"].as_str().unwrap_or_default().to_string(),
            notes: r["body"].as_str().unwrap_or_default().chars().take(500).collect(),
            installable: false,
        })
}

/// Only the Windows installer and the AppImage can replace themselves. A .deb, .rpm or Flatpak
/// belongs to the package manager: the app only reports a new version there.
fn self_update() -> bool {
    !cfg!(target_os = "linux") || std::env::var_os("APPIMAGE").is_some()
}

fn err(e: tauri_plugin_updater::Error) -> String {
    format!("update:{e}")
}

/// Newer release on GitHub, betas included (the manifest only knows the latest stable one).
async fn newest_beta() -> Result<Option<Update>, String> {
    tauri::async_runtime::spawn_blocking(|| {
        let body: serde_json::Value = ureq::get(RELEASES)
            .set("User-Agent", "AnotherKeepass")
            .set("Accept", "application/vnd.github+json")
            .timeout(std::time::Duration::from_secs(15))
            .call()
            .map_err(|e| format!("update:{e}"))?
            .into_json()
            .map_err(|e| format!("update:{e}"))?;
        Ok(newest(&body, env!("CARGO_PKG_VERSION"), true))
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
pub async fn update_check(app: AppHandle, beta: bool) -> Result<Option<Update>, String> {
    let stable = app.updater().map_err(err)?.check().await.map_err(err)?.map(|u| Update {
        url: format!("https://github.com/bohannjein/AnotherKeepass/releases/tag/v{}", u.version),
        notes: u.body.clone().unwrap_or_default().chars().take(500).collect(),
        version: u.version,
        installable: self_update(),
    });
    if !beta {
        return Ok(stable);
    }
    let beta = newest_beta().await.unwrap_or_else(|e| {
        log::warn!("beta check: {e}");
        None
    });
    Ok(match (stable, beta) {
        (Some(s), Some(b)) if parse(&b.version) > parse(&s.version) => Some(b),
        (Some(s), _) => Some(s),
        (None, b) => b,
    })
}

fn pending_version(app: &AppHandle) -> Option<String> {
    app.state::<Pending>().0.lock().ok().and_then(|p| p.as_ref().map(|(u, _)| u.version.clone()))
}

/// Download the newest stable release in the background (progress as `akp-update-progress`,
/// in percent) and keep it for `update_install`. Returns the version that is ready. With
/// `auto`, it is installed on its own as soon as nobody uses the app (see `idle`).
#[tauri::command]
pub async fn update_download(app: AppHandle, auto: bool) -> Result<Option<String>, String> {
    if !self_update() {
        return Ok(None);
    }
    if pending_version(&app).is_none() {
        let Some(update) = app.updater().map_err(err)?.check().await.map_err(err)? else { return Ok(None) };
        log::info!("downloading update {}", update.version);
        let progress = app.clone();
        let (mut done, mut last) = (0u64, 0u64);
        let bytes = update
            .download(
                move |chunk, total| {
                    done += chunk as u64;
                    if let Some(total) = total.filter(|t| *t > 0) {
                        let pct = done * 100 / total;
                        if pct != last {
                            last = pct;
                            let _ = progress.emit("akp-update-progress", pct);
                        }
                    }
                },
                || {},
            )
            .await
            .map_err(err)?;
        log::info!("update {} downloaded and verified ({} bytes)", update.version, bytes.len());
        *app.state::<Pending>().0.lock().map_err(|_| "lock")? = Some((update, bytes));
    }
    if auto && !AUTO_WAIT.swap(true, Ordering::SeqCst) {
        let app = app.clone();
        std::thread::spawn(move || {
            loop {
                std::thread::sleep(std::time::Duration::from_secs(60));
                if pending_version(&app).is_none() {
                    break; // installed by a click meanwhile
                }
                if idle(&app) {
                    log::info!("installing update while the app is unused");
                    crate::desktop::mark_hidden_restart();
                    if let Err(e) = install(&app) {
                        log::error!("background update: {e}");
                        crate::desktop::clear_hidden_restart();
                        break;
                    }
                }
            }
            AUTO_WAIT.store(false, Ordering::SeqCst);
        });
    }
    Ok(pending_version(&app))
}

/// Nobody is using the app: tray icon on, every window hidden, every vault locked.
fn idle(app: &AppHandle) -> bool {
    crate::desktop::prefs(app).tray_icon
        && app.webview_windows().values().all(|w| !w.is_visible().unwrap_or(false))
        && app.state::<crate::vault::Vaults>().0.lock().is_ok_and(|m| m.is_empty())
}

/// Install the downloaded package. On Windows the installer takes over and starts the app
/// again; pending "last access" times are written first.
fn install(app: &AppHandle) -> Result<(), String> {
    let pending = app.state::<Pending>().0.lock().map_err(|_| "lock")?.take();
    let Some((update, bytes)) = pending else { return Err("update:nothing downloaded".into()) };
    if let Ok(mut map) = app.state::<crate::vault::Vaults>().0.lock() {
        map.values_mut().for_each(crate::vault::save_used);
    }
    log::info!("installing update {}", update.version);
    update.install(bytes).map_err(err)?;
    app.restart()
}

/// Install now and restart (downloads first if needed). Ok(false): nothing installable
/// (e.g. only a beta), the UI opens the release page instead.
#[tauri::command]
pub async fn update_install(app: AppHandle) -> Result<bool, String> {
    if update_download(app.clone(), false).await?.is_none() {
        return Ok(false);
    }
    install(&app)?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn picks_newest_stable() {
        let rel = json!([
            { "tag_name": "v0.3.0-beta.1", "prerelease": true, "draft": false, "html_url": "b" },
            { "tag_name": "v0.2.0", "prerelease": false, "draft": false, "html_url": "s", "body": "notes" },
            { "tag_name": "v0.1.0", "prerelease": false, "draft": false, "html_url": "old" },
            { "tag_name": "v9.0.0", "prerelease": false, "draft": true, "html_url": "draft" },
        ]);
        assert_eq!(newest(&rel, "0.1.0", false).unwrap().url, "s");
        assert_eq!(newest(&rel, "0.1.0", true).unwrap().url, "b");
        assert!(newest(&rel, "0.2.0", false).is_none());
        assert_eq!(parse("v1.10"), Some((1, 10, 0)));
    }
}
