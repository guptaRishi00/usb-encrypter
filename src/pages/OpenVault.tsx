import { useEffect, useState } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';

import { KeyIcon, SpinnerIcon } from '../components/Icons';
import { Note } from '../components/Note';
import { PasswordField } from '../components/PasswordField';
import * as api from '../services/api';
import { asVaultError } from '../services/api';
import { basename, bytes, quantity, shortPath } from '../services/format';
import type { FolderLockState, UnlockReport, VaultError, VaultHeaderInfo } from '../types';

/**
 * Two ways in, because there are two ways a folder can be protected: a
 * separate `.vault` file, or a folder locked where it stands.
 */
type Source = 'file' | 'folder';

export function OpenVault({
  initialPath,
  onUnlocked,
}: {
  initialPath?: string;
  onUnlocked: () => void;
}) {
  const [source, setSource] = useState<Source>('file');
  const [path, setPath] = useState(initialPath ?? '');
  const [folder, setFolder] = useState('');
  const [folderState, setFolderState] = useState<FolderLockState | null>(null);
  const [password, setPassword] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<VaultError | null>(null);
  const [header, setHeader] = useState<VaultHeaderInfo | null>(null);
  const [restored, setRestored] = useState<UnlockReport | null>(null);

  useEffect(() => {
    setPath(initialPath ?? '');
    setPassword('');
    setError(null);
    if (initialPath) setSource('file');
  }, [initialPath]);

  useEffect(() => {
    if (!path) {
      setHeader(null);
      return;
    }
    let alive = true;
    api
      .peekVault(path)
      .then((h) => alive && (setHeader(h), setError(null)))
      .catch((e) => {
        if (!alive) return;
        setHeader(null);
        setError(asVaultError(e));
      });
    return () => {
      alive = false;
    };
  }, [path]);

  useEffect(() => {
    if (!folder) {
      setFolderState(null);
      return;
    }
    let alive = true;
    api
      .folderLockState(folder)
      .then((s) => alive && setFolderState(s))
      .catch(() => alive && setFolderState('unavailable'));
    return () => {
      alive = false;
    };
  }, [folder]);

  async function pickFile() {
    const picked = await openDialog({
      multiple: false,
      title: 'Choose a vault',
      filters: [{ name: 'VaultDrive vault', extensions: ['vault'] }],
    });
    if (typeof picked === 'string') {
      setPath(picked);
      setError(null);
      setPassword('');
      setRestored(null);
    }
  }

  async function pickFolder() {
    const picked = await openDialog({
      directory: true,
      multiple: false,
      title: 'Choose the locked folder',
    });
    if (typeof picked === 'string') {
      setFolder(picked);
      setError(null);
      setPassword('');
      setRestored(null);
    }
  }

  async function unlock() {
    if (!password || busy) return;
    setBusy(true);
    setError(null);
    try {
      if (source === 'folder') {
        const report = await api.unlockFolder(folder, password);
        setPassword('');
        setRestored(report);
        setFolderState('unlocked');
      } else {
        await api.unlockVault(path, password);
        // The password is not needed again until the vault is locked.
        setPassword('');
        onUnlocked();
      }
    } catch (e) {
      setError(asVaultError(e));
      setPassword('');
    } finally {
      setBusy(false);
    }
  }

  const integrityProblem = error && (error.kind === 'integrity' || error.kind === 'truncated');
  const canUnlock =
    source === 'file' ? Boolean(path && header) : folder !== '' && folderState === 'locked';
  const target = source === 'file' ? basename(path) : basename(folder);

  return (
    <div className="page">
      <div className="page-head">
        <h1>Open a vault</h1>
        <p>Everything happens on this computer. No account, no network.</p>
      </div>

      <div className="stack">
        <div className="panel stack">
          <span className="field-label">What are you opening?</span>

          <label className={`choice ${source === 'file' ? 'chosen' : ''}`}>
            <input
              type="radio"
              name="open-source"
              checked={source === 'file'}
              onChange={() => {
                setSource('file');
                setError(null);
                setRestored(null);
              }}
            />
            <span>
              <strong>A .vault file</strong>
              <span className="choice-detail">
                A separate portable vault, wherever you put it.
              </span>
            </span>
          </label>

          <label className={`choice ${source === 'folder' ? 'chosen' : ''}`}>
            <input
              type="radio"
              name="open-source"
              checked={source === 'folder'}
              onChange={() => {
                setSource('folder');
                setError(null);
                setRestored(null);
              }}
            />
            <span>
              <strong>A locked folder</strong>
              <span className="choice-detail">
                A folder that VaultDrive locked in place. Unlocking restores its contents
                where they were.
              </span>
            </span>
          </label>
        </div>

        {source === 'file' ? (
          <div className="panel stack">
            <label className="field">
              <span className="field-label">Vault file</span>
              <div className="path-picker">
                <div className={`path-value ${path ? '' : 'empty'}`}>
                  {path ? shortPath(path) : 'No vault chosen yet'}
                </div>
                <button className="btn" onClick={pickFile}>
                  Choose file
                </button>
              </div>
            </label>
            {header && (
              <div className="faint">
                Format v{header.formatVersion} · {header.cipher} · {header.kdf} at{' '}
                {header.memoryCostMib} MiB, {header.passes} passes, {header.lanes} lanes
              </div>
            )}
          </div>
        ) : (
          <div className="panel stack">
            <label className="field">
              <span className="field-label">Locked folder</span>
              <div className="path-picker">
                <div className={`path-value ${folder ? '' : 'empty'}`}>
                  {folder ? shortPath(folder) : 'No folder chosen yet'}
                </div>
                <button className="btn" onClick={pickFolder}>
                  Choose folder
                </button>
              </div>
            </label>
            {folder && folderState === 'unlocked' && !restored && (
              <Note tone="warn">
                That folder is not locked by VaultDrive. Its contents are readable as they are.
              </Note>
            )}
            {folder && folderState === 'empty' && (
              <Note tone="warn">That folder is empty.</Note>
            )}
            {folder && folderState === 'unavailable' && (
              <Note tone="danger">That folder cannot be read.</Note>
            )}
            {folderState === 'locked' && (
              <div className="faint">Locked by VaultDrive. Enter the password to restore it.</div>
            )}
          </div>
        )}

        {restored && (
          <Note tone="ok" title="Folder unlocked">
            {quantity(restored.files, 'file')} and {quantity(restored.folders, 'folder')},{' '}
            {bytes(restored.totalBytes)} in total, are back in {basename(restored.folder)}. The
            encrypted file has been removed.
          </Note>
        )}

        {canUnlock && !restored && (
          <div className="panel stack">
            <PasswordField
              label={`Password for ${target}`}
              value={password}
              onChange={setPassword}
              autoFocus
              onEnter={unlock}
            />
            <div className="row">
              <button className="btn btn-primary" disabled={!password || busy} onClick={unlock}>
                {busy ? <SpinnerIcon /> : <KeyIcon size={16} />}
                {busy
                  ? source === 'folder'
                    ? 'Restoring…'
                    : 'Deriving key…'
                  : source === 'folder'
                    ? 'Unlock folder'
                    : 'Unlock vault'}
              </button>
              {busy && (
                <span className="faint">
                  Argon2id is deliberately slow. This is what makes guessing expensive.
                </span>
              )}
            </div>
          </div>
        )}

        {integrityProblem ? (
          <Note tone="danger" title="Vault integrity check failed">
            {error.message}
          </Note>
        ) : (
          error && (
            <Note tone="danger" title="Could not open the vault">
              {error.message}
            </Note>
          )
        )}
      </div>
    </div>
  );
}
