//! The small window that opens when someone double-clicks the VaultDrive
//! program that travels inside a locked folder.
//!
//! It is the windowed counterpart of `Unlock.cmd`: one field for the code or
//! password, a progress bar, and a countdown after which the folder locks
//! itself again. No console appears at any point.
//!
//! The countdown is owned by Rust, not by the web view. Once the folder is
//! open, a thread holds the key and waits for the deadline or a "lock now"
//! signal; closing the window sends that signal instead of closing, and the
//! process exits only after the folder is locked again. A paused or crashed
//! renderer therefore cannot keep the folder open. Killing the process from
//! Task Manager still can, exactly as closing the console window does for the
//! launcher.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};
use zeroize::Zeroizing;

use super::{blocking, AppState, St, WindowProgress};
use crate::crypto::KdfParams;
use crate::error::{Result, VaultError};
use crate::vault::{self, AuthMode, FolderLockState};

/// The folder a popup launch is about, and how long it stays open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LaunchTarget {
    pub folder: PathBuf,
    pub relock_after: u64,
}

/// Decide whether this launch is a popup launch.
///
/// Two ways in:
///
/// * `--popup <folder> [--relock-after SECONDS]`, which the macOS launcher
///   uses because Finder cannot open a bare binary without Terminal.
/// * No arguments at all, from a copy of the program that sits inside a folder
///   VaultDrive locked. That is a double-click in Explorer. The installed app
///   never sits next to a vault or a `Lock.cmd`, so it still opens normally.
pub fn launch_target(args: &[String], exe: Option<&Path>) -> Option<LaunchTarget> {
    if args.get(1).map(String::as_str) == Some("--popup") {
        let folder = PathBuf::from(args.get(2)?);
        let relock_after = crate::cli::relock_after_arg(args)
            .unwrap_or(crate::cli::DEFAULT_RELOCK_AFTER_SECS);
        return Some(LaunchTarget { folder, relock_after });
    }
    if args.len() != 1 {
        return None;
    }
    let folder = exe?.parent()?;
    let ours = folder.join(vault::IN_PLACE_VAULT_NAME).is_file()
        || folder.join(vault::LOCK_CMD_NAME).is_file();
    ours.then(|| LaunchTarget {
        folder: folder.to_path_buf(),
        relock_after: crate::cli::DEFAULT_RELOCK_AFTER_SECS,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// Nothing of ours is unlocked. Closing simply closes.
    Idle,
    /// Unlocking, or locking from the popup's own form. Closing waits, then
    /// leaves the folder locked.
    Busy,
    /// Unlocked, key held, waiting for the deadline or "lock now".
    Holding,
    /// Encrypting again. Closing waits for this to finish.
    Locking,
    /// The last lock attempt failed and the user has been told. Closing is
    /// allowed, because the window has said the folder is still open.
    Failed,
    /// A watch-only folder is open in memory for playback. Nothing is on
    /// disk, so closing simply closes and the key goes with the process.
    Playing,
}

/// Popup-mode state, managed by Tauri only when the window is a popup.
pub struct Popup {
    target: LaunchTarget,
    phase: Mutex<Phase>,
    /// Wakes the relock thread: "lock now", or "try again" after a failure.
    signal: Mutex<Option<Sender<()>>>,
    exit_after_lock: AtomicBool,
}

impl Popup {
    pub fn new(target: LaunchTarget) -> Self {
        Self {
            target,
            phase: Mutex::new(Phase::Idle),
            signal: Mutex::new(None),
            exit_after_lock: AtomicBool::new(false),
        }
    }

    pub fn folder(&self) -> &Path {
        &self.target.folder
    }

    pub fn folder_name(&self) -> String {
        self.target
            .folder
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| self.target.folder.display().to_string())
    }

    fn phase(&self) -> Phase {
        self.phase.lock().map(|p| *p).unwrap_or(Phase::Failed)
    }

    fn set_phase(&self, phase: Phase) {
        if let Ok(mut p) = self.phase.lock() {
            *p = phase;
        }
    }

    fn poke(&self) {
        if let Ok(s) = self.signal.lock() {
            if let Some(tx) = s.as_ref() {
                let _ = tx.send(());
            }
        }
    }

    /// Called for the window's close button. Returns whether to keep the
    /// window open: an unlocked folder is locked first, then the app exits.
    pub fn on_close_requested(&self) -> bool {
        match self.phase() {
            Phase::Holding => {
                self.exit_after_lock.store(true, Ordering::SeqCst);
                self.poke();
                true
            }
            Phase::Busy | Phase::Locking => {
                self.exit_after_lock.store(true, Ordering::SeqCst);
                true
            }
            Phase::Idle | Phase::Failed | Phase::Playing => false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PopupInfo {
    pub folder: String,
    pub name: String,
    pub state: FolderLockState,
    pub auth_mode: AuthMode,
    /// Seconds an unlocked folder stays open. Zero means until "Lock now".
    pub relock_after: u64,
}

/// One video a watch-only folder can play.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PlayableVideo {
    pub id: u64,
    pub name: String,
    pub size: u64,
}

/// What entering the code did: restored the folder to disk, or opened a
/// watch-only folder for playback.
#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PopupOpened {
    pub player: bool,
    pub report: Option<vault::UnlockReport>,
    pub videos: Vec<PlayableVideo>,
    /// Files in a watch-only folder that are not videos and cannot be opened.
    pub other_files: u64,
}

const VIDEO_EXTENSIONS: [&str; 5] = ["mp4", "m4v", "mov", "webm", "mkv"];

fn extension(name: &str) -> String {
    name.rsplit_once('.').map(|(_, e)| e.to_ascii_lowercase()).unwrap_or_default()
}

fn playable(index: &vault::VaultIndex) -> (Vec<PlayableVideo>, u64) {
    let mut videos = Vec::new();
    let mut other = 0;
    for n in index.nodes.iter().filter(|n| !n.is_dir()) {
        if VIDEO_EXTENSIONS.contains(&extension(&n.name).as_str()) {
            videos.push(PlayableVideo { id: n.id, name: n.name.clone(), size: n.size });
        } else {
            other += 1;
        }
    }
    videos.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
    (videos, other)
}

/// The popup is a small form; a film needs room.
fn enlarge_for_playback(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.set_resizable(true);
        let _ = w.set_maximizable(true);
        let _ = w.set_min_size(Some(tauri::LogicalSize::new(640.0, 420.0)));
        let _ = w.set_size(tauri::LogicalSize::new(1120.0, 720.0));
        let _ = w.center();
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct LockFailure {
    message: String,
    /// Plaintext entries still on disk, if the vault was written but some
    /// originals could not be deleted.
    still_readable: Vec<String>,
}

fn popup_state(app: &AppHandle) -> Result<Arc<Popup>> {
    app.try_state::<Arc<Popup>>()
        .map(|s| s.inner().clone())
        .ok_or_else(|| VaultError::InvalidInput("This window is not a folder popup.".into()))
}

/// Turn what the user typed into the bytes the vault is locked with: the code
/// is exchanged for the key at the server, a password is used as typed.
fn secret_for(folder: &Path, typed: String) -> Result<Zeroizing<Vec<u8>>> {
    let typed = Zeroizing::new(typed);
    match crate::remote::RemoteAuth::load(folder) {
        Some(auth) => crate::remote::redeem(&auth.site, &auth.token, typed.trim()),
        None => Ok(Zeroizing::new(typed.as_bytes().to_vec())),
    }
}

/// `None` in the normal app window; the folder's details in a popup.
#[tauri::command]
pub fn popup_info(app: AppHandle) -> Option<PopupInfo> {
    let popup = popup_state(&app).ok()?;
    Some(PopupInfo {
        folder: popup.folder().to_string_lossy().into_owned(),
        name: popup.folder_name(),
        state: vault::folder_lock_state(popup.folder()),
        auth_mode: vault::folder_auth_mode(popup.folder()),
        relock_after: popup.target.relock_after,
    })
}

/// Restore the folder, then hold the key until it is time to lock again. A
/// watch-only folder is not restored: it is opened in memory for playback.
#[tauri::command]
pub async fn popup_unlock(
    app: AppHandle,
    state: St<'_>,
    secret: String,
) -> Result<PopupOpened> {
    let st = state.inner().clone();
    let popup = popup_state(&app)?;
    if popup.phase() != Phase::Idle {
        return Err(VaultError::InvalidInput("The folder is already open.".into()));
    }
    popup.set_phase(Phase::Busy);
    st.session.cancel_flag().begin();

    enum Opened {
        Restored(vault::UnlockReport),
        Player(vault::OpenVault),
    }

    blocking(move || {
        let opened = secret_for(popup.folder(), secret).and_then(|key| {
            let vault = vault::open_folder_vault(popup.folder(), &key)?;
            if vault.index().watch_only {
                return Ok((key, Opened::Player(vault)));
            }
            let progress = WindowProgress::new(app.clone(), st.clone());
            vault::restore_folder(popup.folder(), vault, &progress)
                .map(|r| (key, Opened::Restored(r)))
        });
        let (key, opened) = match opened {
            Ok(v) => v,
            Err(e) => {
                popup.set_phase(Phase::Idle);
                if popup.exit_after_lock.load(Ordering::SeqCst) {
                    app.exit(0);
                }
                return Err(e);
            }
        };

        let report = match opened {
            Opened::Restored(r) => r,
            Opened::Player(vault) => {
                // The key is not needed again: the open vault holds its own
                // subkeys, and nothing will ever be re-encrypted from here.
                drop(key);
                let (videos, other_files) = playable(vault.index());
                // A paused film must not lock itself; the window is the session.
                st.session.set_auto_lock(None);
                st.session.set_vault(vault);
                popup.set_phase(Phase::Playing);
                if popup.exit_after_lock.load(Ordering::SeqCst) {
                    app.exit(0);
                }
                enlarge_for_playback(&app);
                return Ok(PopupOpened { player: true, report: None, videos, other_files });
            }
        };

        let (tx, rx) = mpsc::channel();
        if let Ok(mut s) = popup.signal.lock() {
            *s = Some(tx);
        }
        popup.set_phase(Phase::Holding);
        // The window was closed while this was unlocking: lock straight away.
        if popup.exit_after_lock.load(Ordering::SeqCst) {
            popup.poke();
        }
        std::thread::spawn(move || hold_then_relock(app, st, popup, key, rx));
        Ok(PopupOpened { player: false, report: Some(report), videos: Vec::new(), other_files: 0 })
    })
    .await
}

/// Largest slice of a video handed to the web view in one response. The
/// player asks again for the next slice as it plays, so memory stays bounded
/// whatever the size of the film.
const MEDIA_SLICE: u64 = 4 * 1024 * 1024;

/// Parse an HTTP `Range` header into an inclusive byte range, capped at one
/// slice. `None` means the range cannot be satisfied.
fn media_range(header: Option<&str>, size: u64) -> Option<(u64, u64)> {
    if size == 0 {
        return None;
    }
    let spec = header.and_then(|h| h.trim().strip_prefix("bytes=")).unwrap_or("0-");
    let spec = spec.split(',').next()?.trim();
    let (a, b) = spec.split_once('-')?;
    let (start, end) = if a.is_empty() {
        // "bytes=-N": the last N bytes.
        let n: u64 = b.parse().ok()?;
        (size.saturating_sub(n), size - 1)
    } else {
        let start: u64 = a.parse().ok()?;
        let end = if b.is_empty() { size - 1 } else { b.parse::<u64>().ok()?.min(size - 1) };
        (start, end)
    };
    if start >= size || end < start {
        return None;
    }
    Some((start, end.min(start + MEDIA_SLICE - 1)))
}

fn media_type(name: &str) -> &'static str {
    match extension(name).as_str() {
        "mp4" | "m4v" | "mov" => "video/mp4",
        "webm" => "video/webm",
        "mkv" => "video/x-matroska",
        _ => "application/octet-stream",
    }
}

/// Serve a slice of a video from the open watch-only vault to the web view's
/// `<video>` element, through the `vault:` protocol.
///
/// Only while this window is a popup in playback: the main application and a
/// popup that restored a folder get nothing. Every byte comes from
/// [`vault::OpenVault::read_range`], so it is authenticated before it is sent,
/// and `no-store` keeps the web view from caching plaintext on disk.
pub fn serve_media(
    app: &AppHandle,
    request: &tauri::http::Request<Vec<u8>>,
) -> tauri::http::Response<Vec<u8>> {
    use tauri::http::{header, Response, StatusCode};

    let empty = |status: StatusCode, extra: Option<(header::HeaderName, String)>| {
        let mut r = Response::builder().status(status).header(header::CACHE_CONTROL, "no-store");
        if let Some((k, v)) = extra {
            r = r.header(k, v);
        }
        r.body(Vec::new()).unwrap_or_default()
    };

    let playing = popup_state(app).map(|p| p.phase() == Phase::Playing).unwrap_or(false);
    let Some(st) = app.try_state::<Arc<AppState>>().filter(|_| playing) else {
        return empty(StatusCode::FORBIDDEN, None);
    };
    let Ok(id) = request.uri().path().trim_start_matches('/').parse::<u64>() else {
        return empty(StatusCode::NOT_FOUND, None);
    };
    let meta = st.session.with(|v| {
        let n = v.index().get(id)?;
        if n.is_dir() {
            return Err(VaultError::NoSuchEntry);
        }
        Ok((n.size, n.name.clone()))
    });
    let Ok((size, name)) = meta else {
        return empty(StatusCode::NOT_FOUND, None);
    };

    let range = request.headers().get(header::RANGE).and_then(|v| v.to_str().ok());
    let Some((start, end)) = media_range(range, size) else {
        return empty(
            StatusCode::RANGE_NOT_SATISFIABLE,
            Some((header::CONTENT_RANGE, format!("bytes */{size}"))),
        );
    };
    let body = match st.session.with(|v| v.read_range(id, start, (end - start + 1) as usize)) {
        Ok(b) if !b.is_empty() => b,
        _ => {
            // Tampered, truncated or unplugged: fail closed, send nothing.
            tracing::warn!("a media slice could not be read");
            return empty(StatusCode::INTERNAL_SERVER_ERROR, None);
        }
    };
    let last = start + body.len() as u64 - 1;
    Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, media_type(&name))
        .header(header::CONTENT_LENGTH, body.len().to_string())
        .header(header::CONTENT_RANGE, format!("bytes {start}-{last}/{size}"))
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CACHE_CONTROL, "no-store")
        .body(body)
        .unwrap_or_default()
}

/// Lock now instead of waiting, or try again after a failed lock.
#[tauri::command]
pub fn popup_lock_now(app: AppHandle) -> Result<()> {
    popup_state(&app)?.poke();
    Ok(())
}

/// Lock a folder that was opened some other way, from inside the popup.
#[tauri::command]
pub async fn popup_lock(
    app: AppHandle,
    state: St<'_>,
    secret: String,
) -> Result<vault::LockReport> {
    let st = state.inner().clone();
    let popup = popup_state(&app)?;
    if popup.phase() != Phase::Idle {
        return Err(VaultError::InvalidInput("The folder is busy.".into()));
    }
    popup.set_phase(Phase::Busy);
    st.session.cancel_flag().begin();

    blocking(move || {
        let result = secret_for(popup.folder(), secret).and_then(|key| {
            let progress = WindowProgress::new(app.clone(), st.clone());
            vault::lock_folder_in_place(popup.folder(), &key, KdfParams::interactive(), true, &progress)
        });
        popup.set_phase(Phase::Idle);
        if popup.exit_after_lock.load(Ordering::SeqCst) {
            app.exit(0);
        }
        result
    })
    .await
}

/// Wait for the deadline or a signal, then lock with the key used to unlock.
///
/// A failed attempt is reported and the thread waits for "try again". If the
/// vault was written but some originals could not be deleted (a file open in
/// another program), the retry restores the folder first and locks it whole,
/// the same recovery the console launcher uses.
fn hold_then_relock(
    app: AppHandle,
    st: Arc<AppState>,
    popup: Arc<Popup>,
    key: Zeroizing<Vec<u8>>,
    rx: Receiver<()>,
) {
    // A disconnected channel can only mean the app is going away: lock.
    match popup.target.relock_after {
        0 => {
            let _ = rx.recv();
        }
        secs => {
            let _ = rx.recv_timeout(Duration::from_secs(secs));
        }
    }

    loop {
        popup.set_phase(Phase::Locking);
        let _ = app.emit("popup:locking", ());
        st.session.cancel_flag().begin();
        let progress = WindowProgress::new(app.clone(), st.clone());
        let folder = popup.folder();

        let attempt = (|| {
            if vault::folder_lock_state(folder) == FolderLockState::Locked {
                vault::unlock_folder_in_place(folder, &key, &progress)?;
            }
            vault::lock_folder_in_place(folder, &key, KdfParams::interactive(), true, &progress)
        })();

        let failure = match attempt {
            Ok(r) if r.removal_failures.is_empty() => {
                popup.set_phase(Phase::Idle);
                if let Ok(mut s) = popup.signal.lock() {
                    *s = None;
                }
                let _ = app.emit("popup:locked", &r);
                if popup.exit_after_lock.load(Ordering::SeqCst) {
                    app.exit(0);
                }
                return;
            }
            Ok(r) => LockFailure {
                message: "The folder is encrypted, but these are open in another program and \
                          could not be removed, so they are still readable. Close them, then \
                          try again."
                    .into(),
                still_readable: r.removal_failures,
            },
            Err(e) => LockFailure { message: e.to_string(), still_readable: Vec::new() },
        };

        tracing::warn!("popup relock did not complete");
        popup.set_phase(Phase::Failed);
        popup.exit_after_lock.store(false, Ordering::SeqCst);
        let _ = app.emit("popup:lock-failed", &failure);
        if rx.recv().is_err() {
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn the_popup_flag_names_the_folder_and_defaults_the_countdown() {
        let t = launch_target(&args(&["vd", "--popup", "/x/Photos"]), None).unwrap();
        assert_eq!(t.folder, PathBuf::from("/x/Photos"));
        assert_eq!(t.relock_after, crate::cli::DEFAULT_RELOCK_AFTER_SECS);

        let t = launch_target(&args(&["vd", "--popup", "/x", "--relock-after", "5"]), None);
        assert_eq!(t.unwrap().relock_after, 5);

        assert!(launch_target(&args(&["vd", "--popup"]), None).is_none());
    }

    #[test]
    fn a_bare_launch_is_a_popup_only_beside_a_locked_folders_artefacts() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(vault::LAUNCHER_EXE_NAME);
        std::fs::write(&exe, b"").unwrap();
        assert!(launch_target(&args(&["vd"]), Some(&exe)).is_none(), "installed app");

        std::fs::write(dir.path().join(vault::IN_PLACE_VAULT_NAME), b"").unwrap();
        let t = launch_target(&args(&["vd"]), Some(&exe)).unwrap();
        assert_eq!(t.folder, dir.path());

        // Any argument at all means somebody asked for something specific.
        assert!(launch_target(&args(&["vd", "--help"]), Some(&exe)).is_none());
    }

    #[test]
    fn an_unlocked_folder_with_launchers_also_opens_the_popup() {
        let dir = tempfile::tempdir().unwrap();
        let exe = dir.path().join(vault::LAUNCHER_EXE_NAME);
        std::fs::write(dir.path().join(vault::LOCK_CMD_NAME), b"").unwrap();
        assert!(launch_target(&args(&["vd"]), Some(&exe)).is_some());
    }

    #[test]
    fn media_ranges_are_parsed_and_capped_to_one_slice() {
        let mb = 1024 * 1024;
        assert_eq!(media_range(None, 10), Some((0, 9)));
        assert_eq!(media_range(Some("bytes=0-"), 100 * mb), Some((0, MEDIA_SLICE - 1)));
        assert_eq!(media_range(Some("bytes=5-9"), 100), Some((5, 9)));
        assert_eq!(media_range(Some("bytes=95-500"), 100), Some((95, 99)));
        assert_eq!(media_range(Some("bytes=-10"), 100), Some((90, 99)));
        assert_eq!(media_range(Some("bytes=100-"), 100), None, "past the end");
        assert_eq!(media_range(Some("bytes=9-5"), 100), None, "backwards");
        assert_eq!(media_range(Some("bytes=x-"), 100), None);
        assert_eq!(media_range(Some("bytes=0-"), 0), None, "empty file");
    }

    #[test]
    fn only_video_files_are_offered_for_playback() {
        assert_eq!(media_type("Film.MP4"), "video/mp4");
        assert_eq!(media_type("clip.webm"), "video/webm");
        assert_eq!(media_type("notes.txt"), "application/octet-stream");
        assert!(VIDEO_EXTENSIONS.contains(&extension("a.b.MKV").as_str()));
        assert!(!VIDEO_EXTENSIONS.contains(&extension("noext").as_str()));
    }

    #[test]
    fn closing_waits_only_while_the_folder_is_open_or_locking() {
        let p = Popup::new(LaunchTarget { folder: PathBuf::from("x"), relock_after: 60 });
        assert!(!p.on_close_requested(), "idle closes");

        p.set_phase(Phase::Busy);
        assert!(p.on_close_requested(), "a half-finished unlock is never abandoned");
        assert!(p.exit_after_lock.load(Ordering::SeqCst));
        p.exit_after_lock.store(false, Ordering::SeqCst);

        let (tx, rx) = mpsc::channel();
        *p.signal.lock().unwrap() = Some(tx);
        p.set_phase(Phase::Holding);
        assert!(p.on_close_requested(), "an open folder is locked first");
        assert!(rx.try_recv().is_ok(), "and the relock thread is woken");
        assert!(p.exit_after_lock.load(Ordering::SeqCst));

        p.set_phase(Phase::Locking);
        assert!(p.on_close_requested());

        p.set_phase(Phase::Failed);
        assert!(!p.on_close_requested(), "after a reported failure the user may leave");

        p.set_phase(Phase::Playing);
        assert!(!p.on_close_requested(), "playback leaves nothing on disk to lock");
    }
}
