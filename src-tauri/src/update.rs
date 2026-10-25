//! Updates from the GitHub releases of the project. The check tells the UI about a newer version
//! (beta releases included when wanted); installing goes through the Tauri updater, which only
//! accepts packages signed with the project's update key (public key in tauri.conf.json).

use serde::Serialize;

const RELEASES: &str = "https://api.github.com/repos/bohannjein/AnotherKeepass/releases?per_page=10";

#[derive(Serialize)]
pub struct Update {
    version: String,
    url: String,
    notes: String,
}

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
        })
}

#[tauri::command]
pub async fn update_check(beta: bool) -> Result<Option<Update>, String> {
    tauri::async_runtime::spawn_blocking(move || {
        let body: serde_json::Value = ureq::get(RELEASES)
            .set("User-Agent", "AnotherKeepass")
            .set("Accept", "application/vnd.github+json")
            .timeout(std::time::Duration::from_secs(15))
            .call()
            .map_err(|e| format!("update:{e}"))?
            .into_json()
            .map_err(|e| format!("update:{e}"))?;
        Ok(newest(&body, env!("CARGO_PKG_VERSION"), beta))
    })
    .await
    .map_err(|e| e.to_string())?
}

/// Download, verify and install the newest stable release, then restart. Ok(false): nothing to
/// install through the updater (e.g. a beta release), the UI opens the release page instead.
#[tauri::command]
pub async fn update_install(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_updater::UpdaterExt;
    let err = |e: tauri_plugin_updater::Error| format!("update:{e}");
    let Some(update) = app.updater().map_err(err)?.check().await.map_err(err)? else { return Ok(false) };
    log::info!("installing update {}", update.version);
    update.download_and_install(|_, _| {}, || {}).await.map_err(err)?;
    app.restart()
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
