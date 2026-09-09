//! VaultDrive: portable, password-protected encrypted folder vaults.
//!
//! The engine lives in this library so the integration tests in `tests/` can
//! drive it directly, without a window. `main.rs` is a four-line shim.

pub mod cli;
pub mod commands;
pub mod crypto;
pub mod error;
pub mod filesystem;
pub mod logging;
pub mod password;
pub mod settings;
pub mod vault;

use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager};

use crate::commands::AppState;

/// How often the auto-lock thread wakes up.
///
/// Fifteen seconds is fine granularity for intervals measured in minutes, and
/// costs nothing: the thread checks one instant and goes back to sleep.
const AUTO_LOCK_TICK: Duration = Duration::from_secs(15);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        .setup(|app| {
            let config_dir = app
                .path()
                .app_config_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            crate::logging::init(&config_dir);

            let state = Arc::new(AppState::new(config_dir));
            app.manage(state.clone());

            // Auto-lock is enforced here rather than in JavaScript. A stopped
            // renderer, a paused tab or an open devtools console cannot keep a
            // vault unlocked past its interval.
            let handle = app.handle().clone();
            std::thread::spawn(move || loop {
                std::thread::sleep(AUTO_LOCK_TICK);
                if state.session.enforce_auto_lock() {
                    let _ = handle.emit("vault:auto-locked", ());
                }
            });

            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::list_drives,
            commands::estimate_password_strength,
            commands::scan_folder,
            commands::peek_vault,
            commands::read_diagnostics,
            commands::get_settings,
            commands::save_settings,
            commands::forget_recent,
            commands::create_vault,
            commands::cancel_operation,
            commands::folder_lock_state,
            commands::lock_folder,
            commands::unlock_folder,
            commands::remove_source_folder,
            commands::unlock_vault,
            commands::lock_vault,
            commands::vault_status,
            commands::keep_awake,
            commands::list_entries,
            commands::breadcrumbs,
            commands::list_folders,
            commands::read_entry,
            commands::create_folder,
            commands::rename_entry,
            commands::move_entry,
            commands::delete_entry,
            commands::import_paths,
            commands::export_entry,
            commands::verify_vault,
            commands::compact_vault,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VaultDrive");
}
