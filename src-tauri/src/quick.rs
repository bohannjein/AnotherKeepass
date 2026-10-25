//! Quick access: a small always-on-top search window on a global shortcut (like 1Password /
//! Proton Pass). Enter copies the password, Ctrl+Enter types it via Auto-Type into the window
//! that was active before. Hides itself when it loses focus.

use tauri::{AppHandle, Emitter, Manager, Runtime, WebviewUrl, WebviewWindowBuilder};

use crate::{
    autotype::Target,
    desktop,
    vault::{VaultDto, Vaults},
};

pub const LABEL: &str = "quick";

pub fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let w = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html?quick=1".into()))
        .title("AnotherKeepass")
        .inner_size(640.0, 460.0)
        .resizable(false)
        .decorations(false)
        .transparent(true)
        .shadow(false)
        .always_on_top(true)
        .skip_taskbar(true)
        .center()
        .visible(false)
        .build()?;
    // always hidden from capture: TeamViewer & co. draw this hidden, transparent, topmost
    // window as a white box in front of everything
    let _ = w.set_content_protected(true);
    Ok(())
}

/// Shortcut pressed: show the search (vaults unlocked) or the main window to unlock first.
pub fn toggle<R: Runtime>(app: &AppHandle<R>) {
    let Some(w) = app.get_webview_window(LABEL) else { return };
    if w.is_visible().unwrap_or(false) {
        let _ = w.hide();
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
    let _ = w.center();
    let _ = w.show();
    let _ = w.set_focus();
    let _ = app.emit_to(LABEL, "akp-quick-open", ());
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
        let _ = w.hide();
    }
}
