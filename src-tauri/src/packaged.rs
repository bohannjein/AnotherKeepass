//! Running as an MSIX package (Microsoft Store)? The same exe ships as NSIS installer, AppImage,
//! … and as MSIX; a few things differ inside a package: the Store installs updates, autostart is
//! a StartupTask declared in the package manifest, and other programs (browsers) reach the exe
//! only through its app execution alias.

/// true inside an MSIX package (has a package identity)
#[cfg(windows)]
pub fn is_packaged() -> bool {
    use std::sync::OnceLock;
    static PACKAGED: OnceLock<bool> = OnceLock::new();
    *PACKAGED.get_or_init(|| {
        use windows_sys::Win32::Storage::Packaging::Appx::GetCurrentPackageFullName;
        const APPMODEL_ERROR_NO_PACKAGE: i32 = 15700;
        let mut len = 0u32;
        let r = unsafe { GetCurrentPackageFullName(&mut len, std::ptr::null_mut()) };
        r as i32 != APPMODEL_ERROR_NO_PACKAGE
    })
}

#[cfg(not(windows))]
pub fn is_packaged() -> bool {
    false
}

/// For the UI: hide what the Store does itself (updates).
#[tauri::command]
pub fn app_packaged() -> bool {
    is_packaged()
}

/// Id of the StartupTask in the package manifest (msix/AppxManifest.xml).
#[cfg(windows)]
const STARTUP_TASK: &str = "AnotherKeepassStartup";

/// Turn the package's StartupTask on or off. Runs on its own thread: WinRT calls must not block
/// the UI thread, and enabling may wait for Windows.
#[cfg(windows)]
pub fn set_startup_task(enable: bool) {
    std::thread::spawn(move || {
        use windows::{
            ApplicationModel::{StartupTask, StartupTaskState},
            core::HSTRING,
        };
        let result = (|| -> windows::core::Result<StartupTaskState> {
            let task = StartupTask::GetAsync(&HSTRING::from(STARTUP_TASK))?.get()?;
            let state = task.State()?;
            let on = state == StartupTaskState::Enabled || state == StartupTaskState::EnabledByPolicy;
            if enable && !on {
                return task.RequestEnableAsync()?.get();
            }
            if !enable && on {
                task.Disable()?;
                return Ok(StartupTaskState::Disabled);
            }
            Ok(state)
        })();
        match result {
            Ok(state) => log::info!("startup task: state {}", state.0),
            Err(e) => log::warn!("startup task: {e}"),
        }
    });
}

/// The exe as other programs can start it: inside a package that is the app execution alias
/// (the real path under WindowsApps is not accessible to them). Only the Windows manifests use it.
#[cfg_attr(not(windows), allow(dead_code))]
pub fn launch_path() -> std::path::PathBuf {
    #[cfg(windows)]
    if is_packaged()
        && let Some(local) = std::env::var_os("LOCALAPPDATA")
    {
        return std::path::PathBuf::from(local).join(r"Microsoft\WindowsApps\anotherkeepass.exe");
    }
    std::env::current_exe().unwrap_or_default()
}
