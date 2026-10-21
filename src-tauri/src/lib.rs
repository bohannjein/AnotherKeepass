mod autotype;
mod browser;
mod browser_server;
pub mod proxy;

use tauri::Manager;
mod clipboard;
mod desktop;
mod favicon;
mod health;
mod quick;
mod transfer;
mod passkeys;
mod update;
mod keeshare;
mod ssh;
mod hello;
mod vault;


#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
  let prefs = desktop::load_prefs();
  desktop::apply_backup(&prefs);
  desktop::apply_ssh(&prefs);
  desktop::apply_keeshare(&prefs);
  vault::quick_unlock_enable(prefs.quick_unlock);
  vault::HELLO_BOTH.store(prefs.hello_both, std::sync::atomic::Ordering::Relaxed);
  let mut builder = tauri::Builder::default();
  // must be the first plugin: a second start only focuses the running window
  if prefs.single_instance {
    builder = builder.plugin(tauri_plugin_single_instance::init(|app, _args, _cwd| desktop::show_main(app)));
  }
  builder
    .plugin(tauri_plugin_opener::init())
    .plugin(tauri_plugin_dialog::init())
    .plugin(tauri_plugin_autostart::init(tauri_plugin_autostart::MacosLauncher::LaunchAgent, Some(vec![desktop::AUTOSTART_ARG])))
    .plugin(tauri_plugin_global_shortcut::Builder::new().build())
    .manage(vault::Vaults::default())
    .manage(desktop::Desktop { prefs: std::sync::Mutex::new(prefs.clone()) })
    .manage(autotype::Target::default())
    .on_window_event(desktop::on_window_event)
    .invoke_handler(tauri::generate_handler![
      vault::vault_create,
      vault::vault_open,
      vault::vault_close,
      vault::paths_exist,
      vault::vault_lock_all,
      vault::vault_change_key,
      vault::vault_rename,
      vault::entry_save,
      vault::entry_import,
      quick::vaults_listing,
      quick::quick_hide,
      transfer::vault_export_csv,
      transfer::vault_save_copy,
      transfer::vault_merge,
      transfer::attachment_get,
      vault::vault_settings_get,
      vault::vault_settings_set,
      vault::kdf_benchmark,
      update::update_check,
      vault::keeshare_get,
      vault::keeshare_set,
      ssh::ssh_settings,
      ssh::ssh_status,
      ssh::ssh_settings_set,
      ssh::ssh_agent_add,
      ssh::ssh_agent_remove,
      vault::quick_unlock_available,
      vault::vault_quick_unlock,
      vault::entry_icons_set,
      favicon::favicon_fetch,
      health::health_report,
      health::password_bits,
      health::entry_password_bits,
      health::password_breached,
      health::health_breach_prefixes,
      health::health_breach_match,
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
      desktop::window_after_unlock,
      desktop::ui_log,
      autotype::autotype_perform,
      autotype::autotype_entry,
      browser_server::browser_answer,
      browser_server::browser_set_active,
    ])
    .setup(move |app| {
      // log file in the app log dir (release too): actions, timings and errors, never secrets
      app.handle().plugin(
        tauri_plugin_log::Builder::default()
          .clear_targets()
          .target(tauri_plugin_log::Target::new(tauri_plugin_log::TargetKind::LogDir { file_name: Some("anotherkeepass".into()) }))
          .max_file_size(1_000_000)
          .level(if cfg!(debug_assertions) { log::LevelFilter::Debug } else { log::LevelFilter::Info })
          .build(),
      )?;
      log::info!("start v{} single_instance={} tray={} start_minimized={} config={:?}", env!("CARGO_PKG_VERSION"), prefs.single_instance, prefs.tray_icon, prefs.start_minimized, desktop::config_path());
      let handle = app.handle();
      let host = std::sync::Arc::new(browser_server::AppHost::new(handle.clone()));
      app.manage(host.clone());
      if prefs.browser_enabled {
        if let Err(e) = browser_server::start(host) {
          log::warn!("{e}");
        }
      }
      desktop::create_tray(handle, &prefs)?;
      if let Err(e) = quick::create(handle) {
        log::warn!("quick access window: {e}");
      }
      for p in autotype::register_shortcuts(handle, &prefs.at_shortcut, &prefs.quick_shortcut) {
        log::warn!("{p}");
        desktop::SHORTCUT_FAILED.store(true, std::sync::atomic::Ordering::Relaxed);
      }
      desktop::watch_session(handle.clone());
      desktop::poll_lock(handle.clone());
      desktop::apply_screen_protect(handle, prefs.screen_protect);
      vault::watch_files(handle.clone());
      desktop::initial_show(handle, &prefs);
      Ok(())
    })
    .run(tauri::generate_context!())
    .expect("error while building tauri application");
}
