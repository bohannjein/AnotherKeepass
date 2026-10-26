//! Quick access: a small always-on-top search window on a global shortcut (like 1Password /
//! Proton Pass). Enter copies the password, Ctrl+Enter types it via Auto-Type into the window
//! that was active before. The global Auto-Type uses the same window to pick an entry.
//! The window is created on the shortcut and destroyed when it closes or
//! loses focus: a hidden, transparent, always-on-top window lingering in the background got drawn
//! as an empty white box by screen hooks (e.g. TeamViewer) once capture protection was off.

use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

use tauri::{AppHandle, Manager, PhysicalPosition, Runtime, WebviewUrl, WebviewWindowBuilder};

use crate::{
    autotype::{Pick, Target},
    desktop,
    vault::{VaultDto, Vaults},
};

pub const LABEL: &str = "quick";
const SIZE: (f64, f64) = (640.0, 460.0);

/// Auto-Type picker request for the open window (None = plain quick access).
static PICK: Mutex<Option<Pick>> = Mutex::new(None);
/// When the window was opened: a focus loss right after that is the focus settling, not a click outside.
static OPENED: Mutex<Option<Instant>> = Mutex::new(None);

/// Focus lost: close, unless the window has only just opened.
pub fn on_blur<R: Runtime>(window: &tauri::Window<R>) {
    let settled = OPENED.lock().ok().and_then(|o| *o).is_none_or(|at| at.elapsed() > Duration::from_millis(400));
    if settled {
        let _ = window.destroy();
    }
}

fn create<R: Runtime>(app: &AppHandle<R>) -> tauri::Result<()> {
    let w = WebviewWindowBuilder::new(app, LABEL, WebviewUrl::App("index.html?quick=1".into()))
        .title("AnotherKeepass")
        .inner_size(SIZE.0, SIZE.1)
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
    // then move it to the screen with the mouse (no cursor position on Wayland: stays centered).
    // Not created hidden and shown later: that window lost the focus at once and closed again.
    if let Some(m) = app.cursor_position().ok().and_then(|p| app.monitor_from_point(p.x, p.y).ok().flatten()) {
        let (pos, size, scale) = (m.position(), m.size(), m.scale_factor());
        let x = pos.x + (size.width as i32 - (SIZE.0 * scale) as i32) / 2;
        let y = pos.y + (size.height as i32 - (SIZE.1 * scale) as i32) / 2;
        w.set_position(PhysicalPosition::new(x, y))?;
    }
    // take the keyboard focus for sure: without it neither Esc nor a click outside reach us
    w.set_focus()?;
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
    show(app, None);
}

/// Open the window: plain search, or the Auto-Type picker (target window already remembered).
pub fn show<R: Runtime>(app: &AppHandle<R>, pick: Option<Pick>) {
    if let Ok(mut p) = PICK.lock() {
        *p = pick;
    }
    if let Some(w) = app.get_webview_window(LABEL) {
        // already open (Auto-Type while searching): load it again for the new request
        let _ = w.eval("location.reload()");
        let _ = w.set_focus();
        return;
    }
    if let Ok(mut o) = OPENED.lock() {
        *o = Some(Instant::now());
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

/// What the quick window was opened for: Some = Auto-Type picker.
#[tauri::command]
pub fn quick_pick() -> Option<Pick> {
    PICK.lock().ok().and_then(|p| p.clone())
}

#[tauri::command]
pub fn quick_hide(app: AppHandle) {
    if let Some(w) = app.get_webview_window(LABEL) {
        let _ = w.destroy();
    }
}
