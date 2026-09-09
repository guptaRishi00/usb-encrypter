import { useEffect, useState } from 'react';
import { open as openDialog, save as saveDialog } from '@tauri-apps/plugin-dialog';

import { Dialog } from '../components/Dialog';
import { DriveList } from '../components/DriveList';
import { CheckIcon, SpinnerIcon } from '../components/Icons';
import { Note } from '../components/Note';
import { PasswordField } from '../components/PasswordField';
import { ProgressPanel } from '../components/ProgressPanel';
import { useProgress } from '../hooks/useProgress';
import * as api from '../services/api';
import { asVaultError } from '../services/api';
import { basename, bytes, quantity, shortPath } from '../services/format';
import type {
  CreateReport,
  LockReport,
  RemovalReport,
  ScanSummary,
  VaultError,
} from '../types';

type Phase = 'form' | 'working' | 'done';

/**
 * `in-place` locks the chosen folder where it stands: its contents become one
 * encrypted file inside it. `file` writes a separate portable vault elsewhere
 * and leaves the folder alone. In-place is the default because "lock this
 * folder" is what people come here to do; the separate file is for carrying a
 * copy on a USB drive.
 */
type Mode = 'in-place' | 'file';

export function CreateVault({
  onOpenVault,
  onSettingsChanged,
}: {
  onOpenVault: (path: string) => void;
  onSettingsChanged: () => void;
}) {
  const [phase, setPhase] = useState<Phase>('form');
  const [mode, setMode] = useState<Mode>('in-place');
  // On by default: the point of locking a folder on a USB stick is opening it
  // on a computer that has never seen VaultDrive.
  const [launchers, setLaunchers] = useState(true);
  const [source, setSource] = useState('');
  const [destination, setDestination] = useState('');
  const [vaultName, setVaultName] = useState('');
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [scan, setScan] = useState<ScanSummary | null>(null);
  const [scanning, setScanning] = useState(false);
  const [error, setError] = useState<VaultError | null>(null);
  const [report, setReport] = useState<CreateReport | null>(null);
  const [lockReport, setLockReport] = useState<LockReport | null>(null);
  const [askRemove, setAskRemove] = useState(false);
  const [removal, setRemoval] = useState<RemovalReport | null>(null);
  const [removing, setRemoving] = useState(false);
  const [destinationIsRemovable, setDestinationIsRemovable] = useState(false);

  const progress = useProgress(phase === 'working');

  useEffect(() => {
    if (!source) {
      setScan(null);
      return;
    }
    let alive = true;
    setScanning(true);
    api
      .scanFolder(source)
      .then((s) => alive && setScan(s))
      .catch((e) => alive && setError(asVaultError(e)))
      .finally(() => alive && setScanning(false));
    return () => {
      alive = false;
    };
  }, [source]);

  async function pickSource() {
    const picked = await openDialog({ directory: true, multiple: false, title: 'Choose the folder to protect' });
    if (typeof picked === 'string') {
      setSource(picked);
      setError(null);
      if (!vaultName) setVaultName(basename(picked));
    }
  }

  async function pickDestination() {
    const suggested = vaultName || basename(source) || 'MyVault';
    const picked = await saveDialog({
      title: 'Where should the encrypted vault be created?',
      defaultPath: `${suggested}.vault`,
      filters: [{ name: 'VaultDrive vault', extensions: ['vault'] }],
    });
    if (typeof picked === 'string') {
      setDestination(picked.endsWith('.vault') ? picked : `${picked}.vault`);
      setError(null);
      const drives = await api.listDrives().catch(() => []);
      setDestinationIsRemovable(
        drives.some((d) => d.removable && picked.toLowerCase().startsWith(d.mountPoint.toLowerCase())),
      );
    }
  }

  const mismatch = confirm.length > 0 && password !== confirm;
  const ready = Boolean(
    source &&
      password &&
      password === confirm &&
      !scanning &&
      (mode === 'in-place' || destination),
  );

  async function encrypt() {
    setError(null);
    setPhase('working');
    try {
      if (mode === 'in-place') {
        const locked = await api.lockFolder(source, password, launchers);
        setPassword('');
        setConfirm('');
        setLockReport(locked);
        setPhase('done');
        return;
      }
      const result = await api.createVault({
        sourceFolder: source,
        destination,
        password,
        vaultName: vaultName.trim(),
      });
      // The password has done its job. Drop both copies before rendering the
      // success screen; the vault is opened again by typing it.
      setPassword('');
      setConfirm('');
      setReport(result);
      setPhase('done');
      onSettingsChanged();
    } catch (e) {
      setError(asVaultError(e));
      setPhase('form');
    }
  }

  async function removeOriginals() {
    setRemoving(true);
    try {
      setRemoval(await api.removeSourceFolder(source));
    } catch (e) {
      setError(asVaultError(e));
    } finally {
      setRemoving(false);
      setAskRemove(false);
    }
  }

  function startOver() {
    setPhase('form');
    setSource('');
    setDestination('');
    setVaultName('');
    setPassword('');
    setConfirm('');
    setScan(null);
    setReport(null);
    setLockReport(null);
    setRemoval(null);
    setError(null);
  }

  // ---------------------------------------------------------------- working

  if (phase === 'working') {
    return (
      <div className="page">
        <div className="page-head">
          <h1>{mode === 'in-place' ? 'Locking folder' : 'Encrypting vault'}</h1>
          <p>
            {mode === 'in-place'
              ? 'Nothing is deleted yet. The encrypted file is written first and reopened with your password; only then are the originals removed.'
              : 'Your original folder is not being modified. The vault is written to a temporary file and only replaces the destination once it is complete.'}
          </p>
        </div>
        <ProgressPanel
          title={mode === 'in-place' ? basename(source) : vaultName || basename(destination)}
          progress={progress}
          removableWarning={destinationIsRemovable}
          onCancel={() => void api.cancelOperation()}
        />
      </div>
    );
  }

  // ------------------------------------------------------------------- done

  if (phase === 'done' && lockReport) {
    const failures = lockReport.removalFailures;
    return (
      <div className="page">
        <div className="page-head">
          <h1>Folder locked</h1>
          <p>
            {quantity(lockReport.files, 'file')} and{' '}
            {quantity(lockReport.folders, 'folder')}, {bytes(lockReport.totalBytes)} in total, are
            now encrypted inside the folder itself.
          </p>
        </div>

        <div className="stack">
          <Note tone="ok" title="Verified before anything was deleted">
            The encrypted file was reopened with your password and its contents checked, and only
            then were the originals removed.
          </Note>

          <div className="panel">
            <div className="stat-label">Locked folder</div>
            <div className="mono selectable" style={{ marginTop: 4, wordBreak: 'break-all' }}>
              {lockReport.folder}
            </div>
            <p className="muted" style={{ marginTop: 10, fontSize: 12.5 }}>
              {lockReport.launchers
                ? 'It holds the encrypted file, a plain note, and VaultDrive.exe with Unlock.cmd and Lock.cmd. Plug the drive into any Windows computer, double-click Unlock.cmd and type the password. Nothing else in the folder is readable.'
                : 'It still holds two things: the encrypted file, and a plain note explaining how to get the contents back. Open it in Explorer and there is nothing readable there.'}
            </p>
          </div>

          {failures.length > 0 && (
            <Note tone="warn" title={`${quantity(failures.length, 'item')} could not be deleted`}>
              These are still on disk in plain form, most likely because another program has them
              open. Close it and lock the folder again.
              <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                {failures.slice(0, 6).map((f) => (
                  <li key={f}>{f}</li>
                ))}
              </ul>
            </Note>
          )}

          {lockReport.skipped.length > 0 && (
            <Note
              tone="warn"
              title={`${quantity(lockReport.skipped.length, 'item')} could not be stored`}
            >
              <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                {lockReport.skipped.slice(0, 8).map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            </Note>
          )}

          <Note tone="accent" title="Remember the password.">
            The only way back into this folder is the password you just set. There is no master
            password and no backdoor.
          </Note>

          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn btn-primary" onClick={startOver}>
              Lock another folder
            </button>
          </div>
        </div>
      </div>
    );
  }

  if (phase === 'done' && report) {
    return (
      <div className="page">
        <div className="page-head">
          <h1>Vault created</h1>
          <p>
            {quantity(report.files, 'file')} and {quantity(report.folders, 'folder')},{' '}
            {bytes(report.totalBytes)} in total.
          </p>
        </div>

        <div className="stack">
          {report.verified ? (
            <Note tone="ok" title="Verified">
              The finished vault was reopened with your password before this screen appeared, so
              it is known to unlock.
            </Note>
          ) : (
            <Note tone="warn" title="Could not fully verify">
              The vault was written but the check afterwards did not match. Open it and confirm
              its contents before removing anything.
            </Note>
          )}

          <div className="panel">
            <div className="stat-label">Vault file</div>
            <div className="mono selectable" style={{ marginTop: 4, wordBreak: 'break-all' }}>
              {report.vaultPath}
            </div>
          </div>

          {report.skipped.length > 0 && (
            <Note
              tone="warn"
              title={`${quantity(report.skipped.length, 'item')} could not be stored`}
            >
              <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                {report.skipped.slice(0, 8).map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
              {report.skipped.length > 8 && <div className="faint">and more…</div>}
            </Note>
          )}

          {removal ? (
            <Note tone={removal.failures.length ? 'warn' : 'ok'} title="Original folder removed">
              {quantity(removal.filesRemoved, 'file')} and{' '}
              {quantity(removal.foldersRemoved, 'folder')} were overwritten and deleted.
              {removal.failures.length > 0 && (
                <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                  {removal.failures.slice(0, 6).map((f) => (
                    <li key={f}>{f}</li>
                  ))}
                </ul>
              )}
            </Note>
          ) : (
            <div className="panel">
              <div className="row-between">
                <div className="setting-copy">
                  <h3>Remove the original unencrypted folder?</h3>
                  <p className="muted" style={{ marginTop: 4 }}>
                    The plaintext copy at {shortPath(source, 44)} is still there. VaultDrive never
                    deletes it on its own.
                  </p>
                </div>
                <button
                  className="btn btn-danger"
                  disabled={!report.verified}
                  onClick={() => setAskRemove(true)}
                >
                  Remove originals
                </button>
              </div>
            </div>
          )}

          <div className="row" style={{ marginTop: 6 }}>
            <button className="btn btn-primary" onClick={() => onOpenVault(report.vaultPath)}>
              Open this vault
            </button>
            <button className="btn" onClick={startOver}>
              Create another
            </button>
          </div>
        </div>

        {askRemove && (
          <Dialog
            title="Remove the original folder?"
            onClose={() => setAskRemove(false)}
            footer={
              <>
                <button className="btn" onClick={() => setAskRemove(false)}>
                  Keep them
                </button>
                <button className="btn btn-danger" disabled={removing} onClick={removeOriginals}>
                  {removing ? <SpinnerIcon /> : null}
                  Delete permanently
                </button>
              </>
            }
          >
            <div className="stack" style={{ marginTop: 10 }}>
              <p className="muted">
                Every file under {basename(source)} will be overwritten with random bytes and
                deleted. This cannot be undone, and the only remaining copy will be the vault.
              </p>
              <Note tone="warn" title="What overwriting can and cannot do">
                On SSDs and USB flash drives the controller spreads writes across physical cells,
                so an overwrite usually lands elsewhere and the original cells may keep their
                contents until the drive reuses them. This defeats ordinary undelete tools, not a
                forensic laboratory.
              </Note>
            </div>
          </Dialog>
        )}
      </div>
    );
  }

  // ------------------------------------------------------------------- form

  return (
    <div className="page">
      <div className="page-head">
        <h1>Create a secure vault</h1>
        <p>
          Choose a folder, pick where the encrypted vault should live, and set a password. Nothing
          leaves this computer and no account is needed.
        </p>
      </div>

      <div className="stack">
        {error && (
          <Note tone="danger" title={mode === 'in-place' ? 'Could not lock the folder' : 'Could not create the vault'}>
            {error.message}
          </Note>
        )}

        <div className="panel stack">
          <label className="field">
            <span className="field-label">1 · Folder to protect</span>
            <div className="path-picker">
              <div className={`path-value ${source ? '' : 'empty'}`}>
                {source ? shortPath(source) : 'No folder chosen yet'}
              </div>
              <button className="btn" onClick={pickSource}>
                Choose folder
              </button>
            </div>
          </label>

          {scanning && (
            <div className="row faint">
              <SpinnerIcon /> Reading the folder…
            </div>
          )}
          {scan && !scanning && (
            <div className="faint">
              {quantity(scan.files, 'file')} · {quantity(scan.folders, 'folder')} ·{' '}
              {bytes(scan.total_bytes)}
              {scan.skipped.length > 0 &&
                ` · ${quantity(scan.skipped.length, 'item')} will be skipped`}
            </div>
          )}
          {scan && scan.skipped.length > 0 && (
            <Note tone="warn" title="Some items cannot be stored">
              <ul style={{ margin: '6px 0 0', paddingLeft: 18 }}>
                {scan.skipped.slice(0, 5).map((s) => (
                  <li key={s}>{s}</li>
                ))}
              </ul>
            </Note>
          )}
        </div>

        <div className="panel stack">
          <span className="field-label">2 · What should happen to it</span>

          <label className={`choice ${mode === 'in-place' ? 'chosen' : ''}`}>
            <input
              type="radio"
              name="create-mode"
              checked={mode === 'in-place'}
              onChange={() => setMode('in-place')}
            />
            <span>
              <strong>Lock this folder where it is</strong>
              <span className="choice-detail">
                {basename(source) || 'The folder'} keeps its name and its location. Everything
                inside it is encrypted into a single file within the folder, and the originals are
                deleted once that file is verified. Unlock it later and the contents come back
                exactly where they were.
              </span>
            </span>
          </label>

          {mode === 'in-place' && (
            <label className="row" style={{ gap: 10, alignItems: 'flex-start', padding: '2px 4px' }}>
              <input
                type="checkbox"
                checked={launchers}
                onChange={(e) => setLaunchers(e.target.checked)}
                style={{ marginTop: 3, accentColor: 'var(--accent)' }}
              />
              <span>
                <strong style={{ fontWeight: 560 }}>Make it open on other computers too</strong>
                <span className="choice-detail">
                  Puts a copy of VaultDrive.exe (about 5 MB) plus Unlock.cmd and Lock.cmd inside the
                  folder. On any Windows machine, double-click Unlock.cmd and type the password. No
                  installation, no window.
                </span>
              </span>
            </label>
          )}

          <label className={`choice ${mode === 'file' ? 'chosen' : ''}`}>
            <input
              type="radio"
              name="create-mode"
              checked={mode === 'file'}
              onChange={() => setMode('file')}
            />
            <span>
              <strong>Create a separate .vault file somewhere else</strong>
              <span className="choice-detail">
                The original folder is left alone and a portable vault file is written wherever you
                choose. Use this to put a copy on a USB drive.
              </span>
            </span>
          </label>

          {mode === 'file' && (
            <>
              <label className="field" style={{ marginTop: 4 }}>
                <span className="field-label">Where to create the vault</span>
                <div className="path-picker">
                  <div className={`path-value ${destination ? '' : 'empty'}`}>
                    {destination ? shortPath(destination) : 'No destination chosen yet'}
                  </div>
                  <button className="btn" onClick={pickDestination} disabled={!source}>
                    Choose location
                  </button>
                </div>
              </label>
              <div className="stack-sm">
                <span className="field-label">Available drives</span>
                <DriveList />
              </div>
            </>
          )}
        </div>

        <div className="panel stack">
          {mode === 'file' && (
            <label className="field">
              <span className="field-label">3 · Vault name (optional)</span>
              <input
                type="text"
                value={vaultName}
                placeholder="My Documents"
                onChange={(e) => setVaultName(e.target.value)}
              />
            </label>
          )}

          <PasswordField
            label="Password"
            value={password}
            onChange={setPassword}
            showStrength
            placeholder="A passphrase of several words works well"
          />
          <PasswordField
            label="Confirm password"
            value={confirm}
            onChange={setConfirm}
            onEnter={() => ready && void encrypt()}
          />
          {mismatch && (
            <div style={{ color: 'var(--danger)', fontSize: 12.5 }}>
              The two passwords do not match.
            </div>
          )}
        </div>

        <Note tone="accent" title="Write your password down somewhere safe.">
          If you forget it, the encrypted vault cannot be recovered by VaultDrive. There is no
          master password and no backdoor.
        </Note>

        <div className="row">
          <button className="btn btn-primary btn-lg" disabled={!ready} onClick={encrypt}>
            <CheckIcon size={16} />
            {mode === 'in-place' ? 'Lock This Folder' : 'Encrypt & Create Vault'}
          </button>
        </div>
      </div>
    </div>
  );
}
