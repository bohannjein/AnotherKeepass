//! Quick access: a small always-on-top search window on a global shortcut (like 1Password /
//! Proton Pass). Enter copies the password, Ctrl+Enter types it via Auto-Type into the window
//! that was active before. The window is created on the shortcut and destroyed when it closes or
//! loses focus: a hidden, transparent, always-on-top window lingering in the background got drawn
//! as an empty white box by screen hooks (e.g. TeamViewer) once capture protection was off.

use tauri::{AppHandle, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};

use crate::{
    autotype::Target,
    desktop,
    vault::{VaultDto, Vaults},
};

pub const LABEL: &str = "quick";

fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html?quick=1".into()))
        .title("AnotherKeepass")
        .inner_size(640.0, 460.0)
        .resizable(false)
        .decorations(false)
        .transparent(true)
        .shadow(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .center()
        .focused(true)
        .content_protected(desktop::prefs(app).screen_protect)
        .build()?;
    Ok(())
}

/// Shortcut pressed: show the search (vaults unlocked) or the main window to unlock first.
pub fn toggle<R: Runtime>(app: &AppHandle<R>) {
    if let Some(w) = app.get_webview_window(LABEL) {
        let _ = w.destroy();
        return;
    }
    if app.state::<Vaults>().0.lock().map(|m| m.is_empty()).unwrap_or(true) {
        desktop::show_for_unlock(app);
        return;
    }
    // remember the window the user came from: Ctrl+Enter types there
    if let Ok(mut t) = app.state::<Target>().0.lock() {
        *t = crate::autotype::foreground_hwnd();
    }
    // a press right after closing can still find the label taken; the next press works
    if let Err(e) = create(app) {
        log::warn!("quick access window: {e}");
    }
}

/// All open vaults (the quick window has no state of its own).
#[tauri::command]
pub fn vaults_listing(state: tauri::State<'_, Vaults>) -> Result<Vec<VaultDto>, String> {
    let map = state.0.lock().map_err(|_| "lock")?;
    Ok(map.iter().map(|(id, v)| v.listing(id)).collect())
}

#[tauri::command]
pub fn quick_hide(app: AppHandle) {
    if let Some(w) = app.get_webview_window(LABEL) {
        let _ = w.destroy();
    }
}
