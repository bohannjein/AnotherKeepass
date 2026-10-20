mod clipboard;
mod vault;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  tauri::Builder::default()
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_dialog::init())
    .manage(vault::Vaults::default())
    .invoke_handler(tauri::generate_handler![
      vault::vault_create,
      vault::vault_open,
      vault::vault_close,
      vault::vault_lock_all,
      vault::vault_change_key,
      vault::vault_rename,
      vault::entry_save,
      vault::entry_secrets,
      vault::entry_totp,
      vault::entry_copy,
      vault::entry_trash,
      vault::entry_restore,
      vault::entry_delete,
      vault::trash_empty,
      vault::entry_history_restore,
      vault::entry_move,
      vault::entry_move_to_vault,
      vault::entry_duplicate,
      vault::attachment_save,
      vault::folder_create,
      vault::folder_rename,
      vault::folder_trash,
      clipboard::clipboard_copy_text,
      clipboard::clipboard_read_text,
    ])
    .setup(|app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while building tauri application");
}
