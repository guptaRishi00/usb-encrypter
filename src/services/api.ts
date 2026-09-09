/**
 * The only place the frontend talks to Rust.
 *
 * Every vault operation lives behind a command. The web view never sees a key,
 * never reads a byte off the disk itself, and never decides what is safe: it
 * asks, and Rust validates. A password is passed straight through to a command
 * and the local reference is dropped immediately afterwards.
 */

import { invoke } from '@tauri-apps/api/core';
import { listen, type UnlistenFn } from '@tauri-apps/api/event';

import type {
  Breadcrumb,
  CreateReport,
  DriveInfo,
  AuthMode,
  Enrolment,
  Entry,
  FolderLockState,
  FolderRef,
  LockReport,
  ProgressEvent,
  RemoteAuth,
  RemovalReport,
  ScanSummary,
  Settings,
  Strength,
  UnlockReport,
  VaultError,
  VaultHeaderInfo,
  VaultStatus,
} from '../types';

/** Rust returns `{ kind, message }`; anything else is a bug, not a user error. */
export function asVaultError(e: unknown): VaultError {
  if (e && typeof e === 'object' && 'kind' in e && 'message' in e) {
    return e as VaultError;
  }
  return { kind: 'io', message: 'Something went wrong. Please try again.' };
}

// --- environment -----------------------------------------------------------

export const listDrives = () => invoke<DriveInfo[]>('list_drives');
export const scanFolder = (path: string) => invoke<ScanSummary>('scan_folder', { path });
export const peekVault = (path: string) => invoke<VaultHeaderInfo>('peek_vault', { path });
export const readDiagnostics = () => invoke<string>('read_diagnostics');

export const estimatePassword = (password: string) =>
  invoke<Strength>('estimate_password_strength', { password });

// --- settings --------------------------------------------------------------

export const getSettings = () => invoke<Settings>('get_settings');
export const saveSettings = (settings: Settings) =>
  invoke<Settings>('save_settings', { settings });
export const forgetRecent = (path: string) => invoke<Settings>('forget_recent', { path });

// --- create ----------------------------------------------------------------

export const createVault = (args: {
  sourceFolder: string;
  destination: string;
  password: string;
  vaultName: string;
}) => invoke<CreateReport>('create_vault', args);

export const cancelOperation = () => invoke<void>('cancel_operation');

// --- lock a folder in place ------------------------------------------------

export const folderLockState = (path: string) =>
  invoke<FolderLockState>('folder_lock_state', { path });

/**
 * Encrypt a folder's contents into a container inside that same folder.
 * With `launchers`, a copy of VaultDrive.exe plus Unlock.cmd and Lock.cmd are
 * placed in the folder so it opens on a machine without VaultDrive.
 */
export const lockFolder = (folder: string, password: string, launchers: boolean) =>
  invoke<LockReport>('lock_folder', { folder, password, launchers });

/** Restore a folder that was locked in place. */
export const unlockFolder = (folder: string, password: string) =>
  invoke<UnlockReport>('unlock_folder', { folder, password });

// --- authenticator-server mode (needs internet) -----------------------------

export const folderAuthMode = (path: string) => invoke<AuthMode>('folder_auth_mode', { path });

/** Ask the server for a QR to scan. Nothing is written until the lock succeeds. */
export const beginAuthenticatorEnrolment = (name: string) =>
  invoke<Enrolment>('begin_authenticator_enrolment', { name });

/** Prove the scan with one code, then lock the folder under the released key. */
export const lockFolderWithAuthenticator = (
  folder: string,
  enrolment: RemoteAuth,
  code: string,
  launchers: boolean,
) =>
  invoke<LockReport>('lock_folder_with_authenticator', { folder, enrolment, code, launchers });

export const unlockFolderWithAuthenticator = (folder: string, code: string) =>
  invoke<UnlockReport>('unlock_folder_with_authenticator', { folder, code });

/** Lock again, reusing the folder's existing authenticator entry. */
export const relockFolderWithAuthenticator = (folder: string, code: string, launchers: boolean) =>
  invoke<LockReport>('relock_folder_with_authenticator', { folder, code, launchers });
export const removeSourceFolder = (path: string) =>
  invoke<RemovalReport>('remove_source_folder', { path });

// --- lock / unlock ---------------------------------------------------------

export const unlockVault = (path: string, password: string) =>
  invoke<VaultStatus>('unlock_vault', { path, password });

export const lockVault = () => invoke<boolean>('lock_vault');
export const vaultStatus = () => invoke<VaultStatus>('vault_status');
export const keepAwake = () => invoke<void>('keep_awake');

// --- browsing --------------------------------------------------------------

export const listEntries = (parentId: number | null) =>
  invoke<Entry[]>('list_entries', { parentId });

export const breadcrumbs = (id: number) => invoke<Breadcrumb[]>('breadcrumbs', { id });

/** Every folder in the vault, for choosing a move destination. */
export const listFolders = () => invoke<FolderRef[]>('list_folders');

/** Decrypt a small file into memory for preview. Never touches the disk. */
export const readEntry = (id: number) => invoke<ArrayBuffer>('read_entry', { id });

// --- editing ---------------------------------------------------------------

export const createFolder = (parentId: number, name: string) =>
  invoke<number>('create_folder', { parentId, name });

export const renameEntry = (id: number, name: string) =>
  invoke<void>('rename_entry', { id, name });

export const moveEntry = (id: number, newParentId: number) =>
  invoke<void>('move_entry', { id, newParentId });

export const deleteEntry = (id: number) => invoke<void>('delete_entry', { id });

export const importPaths = (parentId: number, paths: string[]) =>
  invoke<number>('import_paths', { parentId, paths });

export const exportEntry = (id: number, destination: string) =>
  invoke<string>('export_entry', { id, destination });

// --- maintenance -----------------------------------------------------------

export const verifyVault = () => invoke<boolean>('verify_vault');
export const compactVault = () => invoke<VaultStatus>('compact_vault');

// --- events ----------------------------------------------------------------

export const onProgress = (handler: (p: ProgressEvent) => void): Promise<UnlistenFn> =>
  listen<ProgressEvent>('vault:progress', (e) => handler(e.payload));

export const onAutoLocked = (handler: () => void): Promise<UnlistenFn> =>
  listen('vault:auto-locked', () => handler());
