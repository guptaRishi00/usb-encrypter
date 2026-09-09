//! The Tauri command surface.
//!
//! This is the only bridge between the web view and the vault engine. The rules
//! it enforces:
//!
//! * The frontend never receives a key, a nonce, a salt, or the master key. It
//!   receives entry ids, names, sizes and progress numbers.
//! * A password arrives as a string, is wrapped in `Zeroizing` immediately, and
//!   is wiped when the command returns.
//! * Every long-running job runs on a blocking thread so the window stays
//!   responsive, and checks the shared cancel flag between chunks.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use serde::Serialize;
use tauri::{AppHandle, Emitter, State};
use zeroize::Zeroizing;

use crate::error::{Result, VaultError};
use crate::filesystem::{self, DriveInfo};
use crate::password::{self, Strength};
use crate::settings::Settings;
use crate::vault::{
    self, now_secs, CreateReport, NodeKind, OpenVault, ProgressSink, ProgressSnapshot, VaultSession,
    ROOT_ID,
};

/// Largest file the in-app viewer will decrypt into the web view.
const PREVIEW_IPC_LIMIT: usize = 8 * 1024 * 1024;

pub struct AppState {
    pub session: VaultSession,
    pub settings: Mutex<Settings>,
    pub config_dir: PathBuf,
}

impl AppState {
    pub fn new(config_dir: PathBuf) -> Self {
        let settings = Settings::load(&config_dir);
        let session = VaultSession::new();
        session.set_auto_lock(settings.auto_lock_duration());
        Self { session, settings: Mutex::new(settings), config_dir }
    }

    fn persist_settings(&self) -> Result<()> {
        let s = self.settings.lock().map_err(|_| VaultError::Io("Settings are busy.".into()))?;
        s.save(&self.config_dir)
    }
}

type St<'a> = State<'a, Arc<AppState>>;

// ---------------------------------------------------------------------------
// Progress plumbing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct ProgressEvent {
    #[serde(flatten)]
    snapshot: ProgressSnapshot,
    current_name: String,
}

/// Emits `vault:progress` to the window, at most ten times a second.
///
/// Throttling matters: a folder of ten thousand small files would otherwise
/// spend more time serialising progress events than encrypting.
struct WindowProgress {
    app: AppHandle,
    state: Arc<AppState>,
    last_emit_ms: AtomicU64,
    started: std::time::Instant,
}

impl WindowProgress {
    fn new(app: AppHandle, state: Arc<AppState>) -> Self {
        Self {
            app,
            state,
            last_emit_ms: AtomicU64::new(0),
            started: std::time::Instant::now(),
        }
    }

    fn emit(&self, snapshot: ProgressSnapshot, current_name: &str, force: bool) {
        let now = self.started.elapsed().as_millis() as u64;
        let last = self.last_emit_ms.load(Ordering::Relaxed);
        if !force && now.saturating_sub(last) < 100 {
            return;
        }
        self.last_emit_ms.store(now, Ordering::Relaxed);
        let _ = self.app.emit(
            "vault:progress",
            ProgressEvent { snapshot, current_name: current_name.to_string() },
        );
    }
}

impl ProgressSink for WindowProgress {
    fn report(&self, snapshot: ProgressSnapshot, current_name: &str) {
        let done = snapshot.files_done == snapshot.total_files;
        self.emit(snapshot, current_name, done);
    }

    fn is_cancelled(&self) -> bool {
        self.state.session.cancel_flag().is_cancelled()
    }
}

/// Run a blocking job off the UI thread.
async fn blocking<T, F>(f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    tauri::async_runtime::spawn_blocking(f)
        .await
        .map_err(|_| VaultError::Io("The operation could not be started.".into()))?
}

// ---------------------------------------------------------------------------
// Data shapes sent to the frontend
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EntryDto {
    pub id: u64,
    pub name: String,
    pub is_dir: bool,
    pub size: u64,
    pub modified: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultStatus {
    pub unlocked: bool,
    pub name: Option<String>,
    pub path: Option<String>,
    pub read_only: bool,
    pub files: u64,
    pub folders: u64,
    pub total_bytes: u64,
    /// Bytes of superseded ciphertext still occupying the container.
    pub reclaimable_bytes: u64,
    pub generation: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BreadcrumbDto {
    pub id: u64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FolderDto {
    pub id: u64,
    /// Slash-joined path from the vault root; empty string for the root itself.
    pub path: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VaultHeaderInfo {
    pub format_version: u16,
    pub cipher: String,
    pub kdf: String,
    pub memory_cost_mib: u32,
    pub passes: u32,
    pub lanes: u32,
}

// ---------------------------------------------------------------------------
// Commands: environment
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_drives() -> Vec<DriveInfo> {
    filesystem::list_drives()
}

#[tauri::command]
pub fn estimate_password_strength(password: String) -> Strength {
    let password = Zeroizing::new(password);
    password::estimate(&password)
}

#[tauri::command]
pub async fn scan_folder(path: String) -> Result<crate::filesystem::ScanSummary> {
    blocking(move || {
        let (_, summary) = filesystem::scan_folder(Path::new(&path))?;
        Ok(summary)
    })
    .await
}

#[tauri::command]
pub fn peek_vault(path: String) -> Result<VaultHeaderInfo> {
    let h = OpenVault::peek_header(Path::new(&path))?;
    Ok(VaultHeaderInfo {
        format_version: h.version,
        cipher: "XChaCha20-Poly1305".into(),
        kdf: "Argon2id".into(),
        memory_cost_mib: h.kdf_params.m_cost_kib / 1024,
        passes: h.kdf_params.t_cost,
        lanes: h.kdf_params.p_cost,
    })
}

#[tauri::command]
pub fn read_diagnostics() -> String {
    crate::logging::read_diagnostics()
}

// ---------------------------------------------------------------------------
// Commands: settings
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn get_settings(state: St<'_>) -> Result<Settings> {
    state
        .settings
        .lock()
        .map(|s| s.clone())
        .map_err(|_| VaultError::Io("Settings are busy.".into()))
}

#[tauri::command]
pub fn save_settings(state: St<'_>, settings: Settings) -> Result<Settings> {
    {
        let mut guard = state
            .settings
            .lock()
            .map_err(|_| VaultError::Io("Settings are busy.".into()))?;
        *guard = settings;
        // Auto-lock is enforced by the Rust side, so the new interval has to
        // reach the session, not just the settings file.
        state.session.set_auto_lock(guard.auto_lock_duration());
    }
    state.persist_settings()?;
    get_settings(state)
}

#[tauri::command]
pub fn forget_recent(state: St<'_>, path: String) -> Result<Settings> {
    {
        let mut guard = state
            .settings
            .lock()
            .map_err(|_| VaultError::Io("Settings are busy.".into()))?;
        guard.forget(&path);
    }
    state.persist_settings()?;
    get_settings(state)
}

// ---------------------------------------------------------------------------
// Commands: create
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn create_vault(
    app: AppHandle,
    state: St<'_>,
    source_folder: String,
    destination: String,
    password: String,
    vault_name: String,
) -> Result<CreateReport> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    let report = blocking(move || {
        let password = Zeroizing::new(password);
        let progress = WindowProgress::new(app, st.clone());
        let name = if vault_name.trim().is_empty() {
            Path::new(&destination)
                .file_stem()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_else(|| "Vault".into())
        } else {
            vault_name.trim().to_string()
        };
        vault::create_vault_from_folder(
            Path::new(&source_folder),
            Path::new(&destination),
            password.as_bytes(),
            &name,
            crate::crypto::KdfParams::interactive(),
            &progress,
        )
    })
    .await?;

    {
        let mut guard = state
            .settings
            .lock()
            .map_err(|_| VaultError::Io("Settings are busy.".into()))?;
        let display = Path::new(&report.vault_path)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| "Vault".into());
        guard.remember(&report.vault_path, &display, now_secs());
    }
    state.persist_settings()?;
    Ok(report)
}

#[tauri::command]
pub fn cancel_operation(state: St<'_>) {
    state.session.cancel_flag().cancel();
}

// ---------------------------------------------------------------------------
// Commands: locking a folder in place
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn folder_lock_state(path: String) -> vault::FolderLockState {
    vault::folder_lock_state(Path::new(&path))
}

/// Encrypt a folder's contents into a container inside that same folder.
///
/// The folder stays where it is; what was in it becomes unreadable. The
/// plaintext is deleted only after the finished vault has been reopened with
/// the same password.
#[tauri::command]
pub async fn lock_folder(
    app: AppHandle,
    state: St<'_>,
    folder: String,
    password: String,
    launchers: bool,
) -> Result<vault::LockReport> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let password = Zeroizing::new(password);
        let progress = WindowProgress::new(app, st.clone());
        vault::lock_folder_in_place(
            Path::new(&folder),
            password.as_bytes(),
            crate::crypto::KdfParams::interactive(),
            launchers,
            &progress,
        )
    })
    .await
}

// ---------------------------------------------------------------------------
// Commands: authenticator-server mode
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn folder_auth_mode(path: String) -> vault::AuthMode {
    vault::folder_auth_mode(Path::new(&path))
}

/// Ask the server for a new authenticator secret and show it as a QR.
/// Nothing is written until `lock_folder_with_authenticator` succeeds.
#[tauri::command]
pub async fn begin_authenticator_enrolment(name: String) -> Result<crate::remote::Enrolment> {
    blocking(move || crate::remote::enrol(crate::remote::DEFAULT_SITE, &name)).await
}

/// Lock a folder so that it unlocks with a code from the authenticator app.
///
/// The code is redeemed with the server *first*, which proves the QR was
/// scanned correctly before anything is encrypted under a key the user could
/// otherwise never reproduce. The sidecar is written before the lock so the
/// artefact exclusion protects it during the plaintext removal.
#[tauri::command]
pub async fn lock_folder_with_authenticator(
    app: AppHandle,
    state: St<'_>,
    folder: String,
    enrolment: crate::remote::RemoteAuth,
    code: String,
    launchers: bool,
) -> Result<vault::LockReport> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let key = crate::remote::redeem(&enrolment.site, &enrolment.token, &code)?;
        let folder = Path::new(&folder);
        enrolment.save(folder)?;
        let progress = WindowProgress::new(app, st.clone());
        let result = vault::lock_folder_in_place(
            folder,
            &key,
            crate::crypto::KdfParams::interactive(),
            launchers,
            &progress,
        );
        if result.is_err() {
            // A folder that is not locked must not look like an authenticator
            // folder, or the next lock would try to reuse a token for nothing.
            let _ = std::fs::remove_file(folder.join(crate::remote::REMOTE_AUTH_FILE));
        }
        result
    })
    .await
}

/// Restore a folder locked in authenticator mode.
#[tauri::command]
pub async fn unlock_folder_with_authenticator(
    app: AppHandle,
    state: St<'_>,
    folder: String,
    code: String,
) -> Result<vault::UnlockReport> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let folder = Path::new(&folder);
        let auth = crate::remote::RemoteAuth::load(folder).ok_or_else(|| {
            VaultError::InvalidInput("That folder is not set up for an authenticator.".into())
        })?;
        let key = crate::remote::redeem(&auth.site, &auth.token, &code)?;
        let progress = WindowProgress::new(app, st.clone());
        vault::unlock_folder_in_place(folder, &key, &progress)
    })
    .await
}

/// Re-lock a folder that was set up for an authenticator, reusing its token so
/// the same entry in the app keeps working.
#[tauri::command]
pub async fn relock_folder_with_authenticator(
    app: AppHandle,
    state: St<'_>,
    folder: String,
    code: String,
    launchers: bool,
) -> Result<vault::LockReport> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let folder = Path::new(&folder);
        let auth = crate::remote::RemoteAuth::load(folder).ok_or_else(|| {
            VaultError::InvalidInput("That folder is not set up for an authenticator.".into())
        })?;
        let key = crate::remote::redeem(&auth.site, &auth.token, &code)?;
        let progress = WindowProgress::new(app, st.clone());
        vault::lock_folder_in_place(
            folder,
            &key,
            crate::crypto::KdfParams::interactive(),
            launchers,
            &progress,
        )
    })
    .await
}

/// Restore a folder that was locked in place.
#[tauri::command]
pub async fn unlock_folder(
    app: AppHandle,
    state: St<'_>,
    folder: String,
    password: String,
) -> Result<vault::UnlockReport> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let password = Zeroizing::new(password);
        let progress = WindowProgress::new(app, st.clone());
        vault::unlock_folder_in_place(Path::new(&folder), password.as_bytes(), &progress)
    })
    .await
}

/// Delete the original plaintext folder. Called only after the user has
/// confirmed it in a dialog that says what it does and does not guarantee.
#[tauri::command]
pub async fn remove_source_folder(
    path: String,
) -> Result<crate::filesystem::secure_delete::RemovalReport> {
    blocking(move || filesystem::secure_delete::remove_source_tree(Path::new(&path))).await
}

// ---------------------------------------------------------------------------
// Commands: unlock / lock
// ---------------------------------------------------------------------------

#[tauri::command]
pub async fn unlock_vault(state: St<'_>, path: String, password: String) -> Result<VaultStatus> {
    let vault_path = path.clone();
    let vault = blocking(move || {
        let password = Zeroizing::new(password);
        OpenVault::unlock(Path::new(&vault_path), password.as_bytes())
    })
    .await?;

    let display = vault.index().vault_name.clone();
    state.session.set_vault(vault);

    {
        let mut guard = state
            .settings
            .lock()
            .map_err(|_| VaultError::Io("Settings are busy.".into()))?;
        guard.remember(&path, &display, now_secs());
    }
    state.persist_settings()?;
    vault_status(state)
}

#[tauri::command]
pub fn lock_vault(state: St<'_>) -> bool {
    state.session.lock()
}

#[tauri::command]
pub fn vault_status(state: St<'_>) -> Result<VaultStatus> {
    if !state.session.is_unlocked() {
        return Ok(VaultStatus {
            unlocked: false,
            name: None,
            path: None,
            read_only: false,
            files: 0,
            folders: 0,
            total_bytes: 0,
            reclaimable_bytes: 0,
            generation: 0,
        });
    }
    state.session.with(|v| {
        let (files, folders, total_bytes) = v.index().stats();
        Ok(VaultStatus {
            unlocked: true,
            name: Some(v.index().vault_name.clone()),
            path: Some(v.path().to_string_lossy().into_owned()),
            read_only: v.is_read_only(),
            files,
            folders,
            total_bytes,
            reclaimable_bytes: v.dead_bytes(),
            generation: v.generation(),
        })
    })
}

/// Called by the frontend on user activity so the inactivity clock restarts.
/// The clock itself lives in Rust; this only feeds it.
#[tauri::command]
pub fn keep_awake(state: St<'_>) {
    state.session.touch();
}

// ---------------------------------------------------------------------------
// Commands: browsing
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn list_entries(state: St<'_>, parent_id: Option<u64>) -> Result<Vec<EntryDto>> {
    let parent = parent_id.unwrap_or(ROOT_ID);
    state.session.with(|v| {
        Ok(v.index()
            .children(parent)
            .into_iter()
            .map(|n| EntryDto {
                id: n.id,
                name: n.name.clone(),
                is_dir: matches!(n.kind, NodeKind::Dir),
                size: n.size,
                modified: n.mtime,
            })
            .collect())
    })
}

#[tauri::command]
pub fn breadcrumbs(state: St<'_>, id: u64) -> Result<Vec<BreadcrumbDto>> {
    state.session.with(|v| {
        let idx = v.index();
        let mut out = Vec::new();
        let mut cur = id;
        let mut hops = 0usize;
        while cur != ROOT_ID {
            let n = idx.get(cur)?;
            out.push(BreadcrumbDto { id: n.id, name: n.name.clone() });
            cur = n.parent;
            hops += 1;
            if hops > idx.nodes.len() {
                return Err(VaultError::Integrity);
            }
        }
        out.push(BreadcrumbDto { id: ROOT_ID, name: idx.vault_name.clone() });
        out.reverse();
        Ok(out)
    })
}

/// Every folder in the vault, so the user can pick a move destination.
///
/// The frontend hides the impossible choices; [`OpenVault::move_entry`] refuses
/// them regardless, so a stale list cannot produce an invalid tree.
#[tauri::command]
pub fn list_folders(state: St<'_>) -> Result<Vec<FolderDto>> {
    state.session.with(|v| {
        let idx = v.index();
        let mut out = vec![FolderDto { id: ROOT_ID, path: String::new() }];
        for n in idx.nodes.iter().filter(|n| n.is_dir() && n.id != ROOT_ID) {
            out.push(FolderDto { id: n.id, path: idx.path_of(n.id)? });
        }
        out.sort_by(|a, b| a.path.cmp(&b.path));
        Ok(out)
    })
}

/// Decrypt a small file into the web view for preview.
///
/// Returns raw bytes over the binary IPC channel, so nothing is base64-inflated
/// and nothing is written to disk. Anything larger than
/// [`PREVIEW_IPC_LIMIT`] must be exported instead.
#[tauri::command]
pub fn read_entry(state: St<'_>, id: u64) -> Result<tauri::ipc::Response> {
    let bytes = state.session.with(|v| v.read_file_to_vec(id, PREVIEW_IPC_LIMIT))?;
    Ok(tauri::ipc::Response::new(bytes))
}

// ---------------------------------------------------------------------------
// Commands: editing
// ---------------------------------------------------------------------------

#[tauri::command]
pub fn create_folder(state: St<'_>, parent_id: u64, name: String) -> Result<u64> {
    state.session.with(|v| v.create_folder(parent_id, &name))
}

#[tauri::command]
pub fn rename_entry(state: St<'_>, id: u64, name: String) -> Result<()> {
    state.session.with(|v| v.rename(id, &name))
}

#[tauri::command]
pub fn move_entry(state: St<'_>, id: u64, new_parent_id: u64) -> Result<()> {
    state.session.with(|v| v.move_entry(id, new_parent_id))
}

#[tauri::command]
pub fn delete_entry(state: St<'_>, id: u64) -> Result<()> {
    state.session.with(|v| v.delete(id))
}

#[tauri::command]
pub async fn import_paths(
    app: AppHandle,
    state: St<'_>,
    parent_id: u64,
    paths: Vec<String>,
) -> Result<u64> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();
    let app2 = app.clone();

    blocking(move || {
        let progress = WindowProgress::new(app2, st.clone());
        let mut added = 0u64;
        for p in paths {
            if progress.is_cancelled() {
                return Err(VaultError::Cancelled);
            }
            let path = PathBuf::from(&p);
            st.session.with(|v| {
                if path.is_dir() {
                    v.import_folder(parent_id, &path, &progress)?;
                } else {
                    v.import_file(parent_id, &path, &progress)?;
                }
                Ok(())
            })?;
            added += 1;
        }
        Ok(added)
    })
    .await
}

#[tauri::command]
pub async fn export_entry(
    app: AppHandle,
    state: St<'_>,
    id: u64,
    destination: String,
) -> Result<String> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let progress = WindowProgress::new(app, st.clone());
        st.session.with(|v| {
            let out = v.export(id, Path::new(&destination), &progress)?;
            Ok(out.to_string_lossy().into_owned())
        })
    })
    .await
}

// ---------------------------------------------------------------------------
// Commands: maintenance
// ---------------------------------------------------------------------------

/// Decrypt every file in the vault to confirm every authentication tag still
/// verifies. Reports progress and can be cancelled.
#[tauri::command]
pub async fn verify_vault(app: AppHandle, state: St<'_>) -> Result<bool> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();

    blocking(move || {
        let progress = WindowProgress::new(app, st.clone());
        st.session.with(|v| v.verify_all(&progress))?;
        Ok(true)
    })
    .await
}

/// Rewrite the container without the dead space left behind by deletions.
#[tauri::command]
pub async fn compact_vault(app: AppHandle, state: St<'_>) -> Result<VaultStatus> {
    let st = state.inner().clone();
    st.session.cancel_flag().begin();
    let st2 = st.clone();

    blocking(move || {
        let progress = WindowProgress::new(app, st2.clone());
        st2.session.replace_with(|v| v.compact(&progress))
    })
    .await?;

    vault_status(state)
}
