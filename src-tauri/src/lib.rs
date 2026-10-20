mod autotype;
mod browser;
mod browser_server;
pub mod proxy;

use tauri::Manager;
mod clipboard;
mod desktop;
mod vault;


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  let prefs = desktop::load_prefs();
  let mut builder = tauri::Builder::default();
  // must be the first plugin: a second start only focuses the running window
  if prefs.single_instance {
    builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| desktop::show_main(app)));
  }
  builder
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_dialog::init())
    .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, None))
    .plugin(tauri_plugin_global_shortcut::Builder::new().build())
    .manage(vault::Vaults::default())
    .manage(desktop::Desktop { prefs: std::sync::Mutex::new(prefs.clone()) })
    .manage(autotype::Target::default())
    .on_window_event(desktop::on_window_event)
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
      desktop::desktop_apply,
      desktop::window_minimize,
      autotype::autotype_perform,
      autotype::autotype_entry,
      browser_server::browser_answer,
      browser_server::browser_set_active,
    ])
    .setup(move |app| {
      if cfg!(debug_assertions) {
        app.handle().plugin(
          tauri_plugin_log::Builder::default()
            .level(log::LevelFilter::Info)
            .build(),
        )?;
      }
      let handle = app.handle();
      let host = std::sync::Arc::new(browser_server::AppHost::new(handle.clone()));
      app.manage(host.clone());
      if prefs.browser_enabled {
        if let Err(e) = browser_server::start(host) {
          log::warn!("{e}");
        }
      }
      desktop::create_tray(handle, &prefs)?;
      if let Err(e) = autotype::register_shortcut(handle, &prefs.at_shortcut) {
        log::warn!("auto-type shortcut: {e}");
      }
      desktop::watch_session(handle.clone());
      desktop::initial_show(handle, &prefs);
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while building tauri application");
}
