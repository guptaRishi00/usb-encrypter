/** Shapes returned by the Rust commands. Kept in step with `src-tauri/src/commands`. */

export type ErrorKind =
  | 'authentication'
  | 'integrity'
  | 'not_a_vault'
  | 'version_mismatch'
  | 'truncated'
  | 'unsupported_kdf'
  | 'unsupported_cipher'
  | 'permission_denied'
  | 'file_locked'
  | 'device_unavailable'
  | 'insufficient_space'
  | 'source_changed'
  | 'unsupported_entry'
  | 'cancelled'
  | 'locked'
  | 'already_exists'
  | 'no_such_entry'
  | 'invalid_move'
  | 'invalid_input'
  | 'io';

export interface VaultError {
  kind: ErrorKind;
  message: string;
}

export interface DriveInfo {
  label: string;
  mountPoint: string;
  totalBytes: number;
  availableBytes: number;
  removable: boolean;
  fileSystem: string;
}

export interface Strength {
  score: 0 | 1 | 2 | 3;
  label: string;
  entropyBits: number;
  notes: string[];
}

export interface ScanSummary {
  files: number;
  folders: number;
  total_bytes: number;
  skipped: string[];
}

export interface CreateReport {
  vaultPath: string;
  files: number;
  folders: number;
  totalBytes: number;
  skipped: string[];
  verified: boolean;
}

export type FolderLockState = 'locked' | 'unlocked' | 'empty' | 'unavailable';

/** Result of locking a folder in place. */
export interface LockReport {
  folder: string;
  files: number;
  folders: number;
  totalBytes: number;
  skipped: string[];
  verified: boolean;
  removedFiles: number;
  removedFolders: number;
  removalFailures: string[];
  /** Whether VaultDrive.exe, Unlock.cmd and Lock.cmd were placed in the folder. */
  launchers: boolean;
}

/** Result of restoring a folder that was locked in place. */
export interface UnlockReport {
  folder: string;
  files: number;
  folders: number;
  totalBytes: number;
}

export interface VaultStatus {
  unlocked: boolean;
  name: string | null;
  path: string | null;
  readOnly: boolean;
  files: number;
  folders: number;
  totalBytes: number;
  reclaimableBytes: number;
  generation: number;
}

export interface Entry {
  id: number;
  name: string;
  isDir: boolean;
  size: number;
  modified: number | null;
}

export interface Breadcrumb {
  id: number;
  name: string;
}

/** A folder in the vault, addressed by its slash-joined path from the root. */
export interface FolderRef {
  id: number;
  /** Empty string for the vault root. */
  path: string;
}

export interface RecentVault {
  path: string;
  name: string;
  lastOpened: number;
}

export interface Settings {
  theme: 'system' | 'light' | 'dark';
  autoLockMinutes: number;
  recent: RecentVault[];
}

export interface ProgressEvent {
  filesDone: number;
  totalFiles: number;
  bytesDone: number;
  totalBytes: number;
  currentName: string;
}

export interface RemovalReport {
  filesRemoved: number;
  foldersRemoved: number;
  failures: string[];
}

export interface VaultHeaderInfo {
  formatVersion: number;
  cipher: string;
  kdf: string;
  memoryCostMib: number;
  passes: number;
  lanes: number;
}

export const ROOT_ID = 1;
