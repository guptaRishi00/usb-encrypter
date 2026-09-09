import { useCallback, useEffect, useMemo, useState } from 'react';
import { open as openDialog } from '@tauri-apps/plugin-dialog';

import { Dialog } from '../components/Dialog';
import {
  ChevronIcon,
  FileIcon,
  FolderIcon,
  LockIcon,
  PlusIcon,
  SpinnerIcon,
  TrashIcon,
} from '../components/Icons';
import { Note } from '../components/Note';
import { ProgressPanel } from '../components/ProgressPanel';
import { useProgress } from '../hooks/useProgress';
import * as api from '../services/api';
import { asVaultError } from '../services/api';
import { bytes, previewKind, quantity, when } from '../services/format';
import {
  ROOT_ID,
  type Breadcrumb,
  type Entry,
  type FolderRef,
  type VaultError,
  type VaultStatus,
} from '../types';

type Busy = null | 'import' | 'export' | 'verify' | 'compact';

export function VaultBrowser({
  status,
  onLock,
  onStatus,
}: {
  status: VaultStatus;
  onLock: () => void;
  onStatus: () => void;
}) {
  const [parent, setParent] = useState<number>(ROOT_ID);
  const [entries, setEntries] = useState<Entry[]>([]);
  const [crumbs, setCrumbs] = useState<Breadcrumb[]>([]);
  const [selected, setSelected] = useState<number | null>(null);
  const [error, setError] = useState<VaultError | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [loading, setLoading] = useState(true);

  const [newFolder, setNewFolder] = useState(false);
  const [newFolderName, setNewFolderName] = useState('');
  const [renaming, setRenaming] = useState<Entry | null>(null);
  const [renameTo, setRenameTo] = useState('');
  const [deleting, setDeleting] = useState<Entry | null>(null);
  const [moving, setMoving] = useState<Entry | null>(null);
  const [folders, setFolders] = useState<FolderRef[]>([]);
  const [moveTarget, setMoveTarget] = useState<number>(ROOT_ID);
  const [preview, setPreview] = useState<{ entry: Entry; body: string; mime?: string } | null>(
    null,
  );

  const progress = useProgress(busy !== null);
  const selectedEntry = useMemo(
    () => entries.find((e) => e.id === selected) ?? null,
    [entries, selected],
  );

  const refresh = useCallback(
    async (target = parent) => {
      setLoading(true);
      try {
        const [items, trail] = await Promise.all([
          api.listEntries(target),
          api.breadcrumbs(target),
        ]);
        setEntries(items);
        setCrumbs(trail);
        setError(null);
      } catch (e) {
        setError(asVaultError(e));
      } finally {
        setLoading(false);
      }
    },
    [parent],
  );

  useEffect(() => {
    void refresh(parent);
    setSelected(null);
  }, [parent, refresh]);

  function fail(e: unknown) {
    setError(asVaultError(e));
  }

  async function act<T>(kind: Busy, run: () => Promise<T>): Promise<T | undefined> {
    setBusy(kind);
    setError(null);
    setNotice(null);
    try {
      return await run();
    } catch (e) {
      fail(e);
      return undefined;
    } finally {
      setBusy(null);
      await refresh(parent);
      onStatus();
    }
  }

  async function openEntry(entry: Entry) {
    if (entry.isDir) {
      setParent(entry.id);
      return;
    }
    const kind = previewKind(entry.name);
    if (kind.kind === 'none') {
      setNotice(
        `VaultDrive cannot display ${entry.name} without writing it to disk first. Export it to open it in another program.`,
      );
      return;
    }
    try {
      const buffer = await api.readEntry(entry.id);
      const data = new Uint8Array(buffer);
      if (kind.kind === 'text') {
        setPreview({ entry, body: new TextDecoder().decode(data) });
      } else {
        let binary = '';
        for (const byte of data) binary += String.fromCharCode(byte);
        setPreview({ entry, body: btoa(binary), mime: kind.mime });
      }
    } catch (e) {
      fail(e);
    }
  }

  async function importFiles(directory: boolean) {
    const picked = await openDialog({
      multiple: !directory,
      directory,
      title: directory ? 'Choose a folder to add' : 'Choose files to add',
    });
    const paths = Array.isArray(picked) ? picked : typeof picked === 'string' ? [picked] : [];
    if (paths.length === 0) return;
    await act('import', () => api.importPaths(parent, paths));
  }

  async function exportSelection() {
    const target = selectedEntry ?? { id: ROOT_ID, name: status.name ?? 'Vault' };
    const dest = await openDialog({
      directory: true,
      multiple: false,
      title: `Where should ${target.name} be written?`,
    });
    if (typeof dest !== 'string') return;
    const out = await act('export', () => api.exportEntry(target.id, dest));
    if (out) setNotice(`Exported to ${out}`);
  }

  async function doDelete() {
    const victim = deleting;
    setDeleting(null);
    if (!victim) return;
    await act(null, () => api.deleteEntry(victim.id));
    setSelected(null);
  }

  async function doRename() {
    const target = renaming;
    const name = renameTo.trim();
    setRenaming(null);
    if (!target || !name) return;
    await act(null, () => api.renameEntry(target.id, name));
  }

  async function doCreateFolder() {
    const name = newFolderName.trim();
    setNewFolder(false);
    setNewFolderName('');
    if (!name) return;
    await act(null, () => api.createFolder(parent, name));
  }

  /**
   * Offer every folder except the item itself and anything under it. Rust
   * refuses those moves anyway; filtering here means the impossible choice is
   * never presented in the first place.
   */
  async function startMove() {
    if (!selectedEntry) return;
    try {
      const all = await api.listFolders();
      const own = selectedEntry.isDir
        ? (all.find((f) => f.id === selectedEntry.id)?.path ?? null)
        : null;
      const allowed = all.filter((f) => {
        if (f.id === parent) return false;
        if (own === null) return true;
        return f.path !== own && !f.path.startsWith(`${own}/`);
      });
      setFolders(allowed);
      setMoveTarget(allowed[0]?.id ?? ROOT_ID);
      setMoving(selectedEntry);
    } catch (e) {
      fail(e);
    }
  }

  async function doMove() {
    const target = moving;
    const destination = moveTarget;
    setMoving(null);
    if (!target) return;
    await act(null, () => api.moveEntry(target.id, destination));
    setSelected(null);
  }

  if (busy === 'import' || busy === 'export' || busy === 'verify' || busy === 'compact') {
    const titles = {
      import: 'Adding to vault',
      export: 'Exporting from vault',
      verify: 'Checking vault integrity',
      compact: 'Compacting vault',
    } as const;
    return (
      <div className="page">
        <ProgressPanel
          title={titles[busy]}
          progress={progress}
          onCancel={busy === 'import' || busy === 'export' ? () => void api.cancelOperation() : undefined}
        />
      </div>
    );
  }

  return (
    <div className="browser">
      <div className="browser-bar">
        <span style={{ color: 'var(--accent)', display: 'flex' }}>
          <LockIcon size={18} />
        </span>
        <div className="crumbs">
          {crumbs.map((c, i) => (
            <span key={c.id} style={{ display: 'contents' }}>
              {i > 0 && (
                <span className="crumb-sep" aria-hidden>
                  <ChevronIcon size={12} />
                </span>
              )}
              <button className="crumb" onClick={() => setParent(c.id)}>
                {c.name}
              </button>
            </span>
          ))}
        </div>
        <div className="spacer" />
        <span className="faint">
          {quantity(status.files, 'file')} · {bytes(status.totalBytes)}
        </span>
        <button className="btn" onClick={onLock}>
          <LockIcon size={15} />
          Lock Vault
        </button>
      </div>

      <div className="browser-body">
        {status.readOnly && (
          <div style={{ margin: '10px 4px' }}>
            <Note tone="warn" title="Read-only">
              This vault file cannot be written to, so it can be browsed and exported but not
              changed.
            </Note>
          </div>
        )}
        {error && (
          <div style={{ margin: '10px 4px' }}>
            <Note tone={error.kind === 'integrity' ? 'danger' : 'danger'} title="Something went wrong">
              {error.message}
            </Note>
          </div>
        )}
        {notice && (
          <div style={{ margin: '10px 4px' }}>
            <Note tone="ok">{notice}</Note>
          </div>
        )}

        {loading ? (
          <div className="row faint" style={{ padding: 16 }}>
            <SpinnerIcon /> Loading…
          </div>
        ) : entries.length === 0 ? (
          <div className="empty-state" style={{ margin: 12 }}>
            This folder is empty. Use Import to add files.
          </div>
        ) : (
          <div role="listbox" aria-label="Vault contents" tabIndex={0}>
            {entries.map((e) => (
              <div
                key={e.id}
                className="file-row"
                role="option"
                aria-selected={selected === e.id}
                tabIndex={-1}
                onClick={() => setSelected(e.id)}
                onDoubleClick={() => void openEntry(e)}
                onKeyDown={(k) => {
                  if (k.key === 'Enter') void openEntry(e);
                }}
              >
                <span className={`file-icon ${e.isDir ? 'folder' : ''}`}>
                  {e.isDir ? <FolderIcon /> : <FileIcon />}
                </span>
                <span className="file-name">{e.name}</span>
                <span className="file-meta">{e.isDir ? '' : bytes(e.size)}</span>
                <span className="file-meta" style={{ width: 96, textAlign: 'right' }}>
                  {when(e.modified)}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div className="browser-actions">
        <button className="btn" onClick={() => void importFiles(false)} disabled={status.readOnly}>
          <PlusIcon size={15} />
          Import files
        </button>
        <button className="btn" onClick={() => void importFiles(true)} disabled={status.readOnly}>
          Import folder
        </button>
        <button className="btn" onClick={() => void exportSelection()}>
          {selectedEntry ? `Export ${selectedEntry.name}` : 'Export all'}
        </button>
        <button
          className="btn"
          onClick={() => setNewFolder(true)}
          disabled={status.readOnly}
        >
          New folder
        </button>
        <button
          className="btn"
          disabled={!selectedEntry || status.readOnly}
          onClick={() => {
            if (!selectedEntry) return;
            setRenameTo(selectedEntry.name);
            setRenaming(selectedEntry);
          }}
        >
          Rename
        </button>
        <button
          className="btn"
          disabled={!selectedEntry || status.readOnly}
          onClick={() => void startMove()}
          title="Move the selected item to another folder in this vault"
        >
          Move to…
        </button>
        <button
          className="btn btn-danger"
          disabled={!selectedEntry || status.readOnly}
          onClick={() => selectedEntry && setDeleting(selectedEntry)}
        >
          <TrashIcon size={15} />
          Delete
        </button>
        <div className="spacer" />
        <button
          className="btn btn-ghost"
          onClick={async () => {
            // A silent pass is indistinguishable from a button that did
            // nothing, which is the wrong impression for a security check.
            const ok = await act('verify', api.verifyVault);
            if (ok) {
              setNotice(
                `Integrity verified. All ${quantity(status.files, 'file')} decrypted and every authentication tag matched.`,
              );
            }
          }}
        >
          Check integrity
        </button>
        {status.reclaimableBytes > 0 && (
          <button
            className="btn btn-ghost"
            disabled={status.readOnly}
            onClick={() => void act('compact', api.compactVault)}
            title="Rewrite the vault without the space left by deleted files"
          >
            Compact ({bytes(status.reclaimableBytes)})
          </button>
        )}
      </div>

      {newFolder && (
        <Dialog
          title="New folder"
          onClose={() => setNewFolder(false)}
          footer={
            <>
              <button className="btn" onClick={() => setNewFolder(false)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={() => void doCreateFolder()}>
                Create
              </button>
            </>
          }
        >
          <input
            type="text"
            autoFocus
            value={newFolderName}
            placeholder="Folder name"
            onChange={(e) => setNewFolderName(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void doCreateFolder()}
            style={{ marginTop: 12 }}
          />
        </Dialog>
      )}

      {renaming && (
        <Dialog
          title={`Rename ${renaming.name}`}
          onClose={() => setRenaming(null)}
          footer={
            <>
              <button className="btn" onClick={() => setRenaming(null)}>
                Cancel
              </button>
              <button className="btn btn-primary" onClick={() => void doRename()}>
                Rename
              </button>
            </>
          }
        >
          <input
            type="text"
            autoFocus
            value={renameTo}
            onChange={(e) => setRenameTo(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && void doRename()}
            style={{ marginTop: 12 }}
          />
        </Dialog>
      )}

      {moving && (
        <Dialog
          title={`Move ${moving.name}`}
          onClose={() => setMoving(null)}
          footer={
            <>
              <button className="btn" onClick={() => setMoving(null)}>
                Cancel
              </button>
              <button
                className="btn btn-primary"
                disabled={folders.length === 0}
                onClick={() => void doMove()}
              >
                Move
              </button>
            </>
          }
        >
          <div className="stack" style={{ marginTop: 12 }}>
            {folders.length === 0 ? (
              <p className="muted">There is nowhere else to move this. Create a folder first.</p>
            ) : (
              <label className="field">
                <span className="field-label">Destination folder</span>
                <select
                  autoFocus
                  value={moveTarget}
                  onChange={(e) => setMoveTarget(Number(e.target.value))}
                >
                  {folders.map((f) => (
                    <option key={f.id} value={f.id}>
                      {f.path === '' ? `${status.name ?? 'Vault'} (root)` : f.path}
                    </option>
                  ))}
                </select>
              </label>
            )}
          </div>
        </Dialog>
      )}

      {deleting && (
        <Dialog
          title={`Delete ${deleting.name}?`}
          onClose={() => setDeleting(null)}
          footer={
            <>
              <button className="btn" onClick={() => setDeleting(null)}>
                Cancel
              </button>
              <button className="btn btn-danger" onClick={() => void doDelete()}>
                Delete
              </button>
            </>
          }
        >
          <div className="stack" style={{ marginTop: 10 }}>
            <p className="muted">
              {deleting.isDir
                ? 'This folder and everything inside it will be removed from the vault.'
                : 'This file will be removed from the vault.'}
            </p>
            <Note tone="info">
              The encrypted bytes stay in the vault file as unused space until you compact it. They
              are unreachable, but Compact is what actually removes them from the drive.
            </Note>
          </div>
        </Dialog>
      )}

      {preview && (
        <Dialog
          title={preview.entry.name}
          wide
          onClose={() => setPreview(null)}
          footer={
            <button className="btn" onClick={() => setPreview(null)}>
              Close
            </button>
          }
        >
          <div className="faint">
            {bytes(preview.entry.size)} · decrypted in memory, not written to disk
          </div>
          <div className="preview-body">
            {preview.mime ? (
              <img src={`data:${preview.mime};base64,${preview.body}`} alt={preview.entry.name} />
            ) : (
              <pre className="selectable">{preview.body}</pre>
            )}
          </div>
        </Dialog>
      )}
    </div>
  );
}
