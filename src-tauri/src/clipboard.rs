//! Secret-aware clipboard: excluded from Windows clipboard history/cloud sync,
//! and cleared after a timeout only if it still holds the value we put there.

use std::{thread, time::Duration};

use arboard::Clipboard;
use zeroize::Zeroizing;

pub fn copy_secret(value: String, clear_after: Option<u64>) -> Result<(), String> {
    let value = Zeroizing::new(value);
    let mut cb = Clipboard::new().map_err(|e| format!("clipboard:{e}"))?;
    set_excluded(&mut cb, &value)?;

    if let Some(secs) = clear_after.filter(|s| *s > 0) {
        thread::spawn(move || {
            thread::sleep(Duration::from_secs(secs));
            if let Ok(mut cb) = Clipboard::new() {
                let still_ours = cb.get_text().map(Zeroizing::new).is_ok_and(|now| *now == *value);
                if still_ours {
                    let _ = cb.clear();
                }
            }
        });
    }
    Ok(())
}

/// Plain text copy for non-secret values (no auto-clear needed, but same API).
#[tauri::command]
pub fn clipboard_copy_text(text: String, clear_after: Option<u64>) -> Result<(), String> {
    copy_secret(text, clear_after)
}

#[cfg(windows)]
fn set_excluded(cb: &mut Clipboard, value: &str) -> Result<(), String> {
    use arboard::SetExtWindows;
    cb.set().exclude_from_history().text(value).map_err(|e| format!("clipboard:{e}"))
}

#[cfg(not(windows))]
fn set_excluded(cb: &mut Clipboard, value: &str) -> Result<(), String> {
    cb.set_text(value).map_err(|e| format!("clipboard:{e}"))
}

/// Text for the app's own "Paste" menu entry (the WebView would ask for clipboard permission).
#[tauri::command]
pub fn clipboard_read_text() -> Result<String, String> {
    Clipboard::new().and_then(|mut cb| cb.get_text()).map_err(|e| format!("clipboard:{e}"))
}
