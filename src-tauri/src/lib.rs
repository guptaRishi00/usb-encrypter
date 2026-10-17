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
pub mod remote;
pub mod settings;
pub mod vault;

use std::sync::Arc;
use std::time::Duration;

use tauri::{Emitter, Manager, WebviewUrl, WebviewWindowBuilder, WindowEvent};

use crate::commands::popup::{launch_target, Popup};
use crate::commands::AppState;

/// How often the auto-lock thread wakes up.
///
/// Fifteen seconds is fine granularity for intervals measured in minutes, and
/// costs nothing: the thread checks one instant and goes back to sleep.
const AUTO_LOCK_TICK: Duration = Duration::from_secs(15);

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let args: Vec<String> = std::env::args().collect();
    let exe = std::env::current_exe().ok();
    let popup = launch_target(&args, exe.as_deref()).map(|t| Arc::new(Popup::new(t)));

    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_opener::init())
        // Watch-only playback: the <video> element reads slices of the film
        // through this protocol, decrypted in memory, never from a file.
        .register_asynchronous_uri_scheme_protocol("vault", |ctx, request, responder| {
            let app = ctx.app_handle().clone();
            std::thread::spawn(move || {
                responder.respond(commands::popup::serve_media(&app, &request));
            });
        })
        .on_window_event(|window, event| {
            // In a popup, closing an open folder locks it first; the relock
            // thread exits the app once that is done.
            if let WindowEvent::CloseRequested { api, .. } = event {
                if let Some(p) = window.try_state::<Arc<Popup>>() {
                    if p.on_close_requested() {
                        api.prevent_close();
                    }
                }
            }
        })
        .setup(move |app| {
            let config_dir = app
                .path()
                .app_config_dir()
                .unwrap_or_else(|_| std::path::PathBuf::from("."));
            crate::logging::init(&config_dir);

            let state = Arc::new(AppState::new(config_dir));
            app.manage(state.clone());

            // The window is created here rather than from the config, because
            // a double-click on the program inside a locked folder gets a small
            // fixed-size popup instead of the full application.
            match popup {
                Some(p) => {
                    WebviewWindowBuilder::new(app, "main", WebviewUrl::default())
                        .title(format!("VaultDrive: {}", p.folder_name()))
                        .inner_size(440.0, 480.0)
                        .resizable(false)
                        .maximizable(false)
                        // Shows as black to screenshots, OBS and screen
                        // sharing. A camera pointed at the screen still works.
                        .content_protected(true)
                        .center()
                        .build()?;
                    app.manage(p);
                }
                None => {
                    let config = app.config().app.windows.first().cloned().ok_or(
                        "tauri.conf.json must define the main window",
                    )?;
                    WebviewWindowBuilder::from_config(app.handle(), &config)?.build()?;
                }
            }

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
            commands::folder_auth_mode,
            commands::begin_authenticator_enrolment,
            commands::lock_folder_with_authenticator,
            commands::unlock_folder_with_authenticator,
            commands::relock_folder_with_authenticator,
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
            commands::popup::popup_info,
            commands::popup::popup_unlock,
            commands::popup::popup_lock,
            commands::popup::popup_lock_now,
        ])
        .run(tauri::generate_context!())
        .expect("error while running VaultDrive");
}
