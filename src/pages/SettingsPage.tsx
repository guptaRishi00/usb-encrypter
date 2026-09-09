import { useState } from 'react';

import { Note } from '../components/Note';
import { readDiagnostics } from '../services/api';
import type { Settings } from '../types';

const AUTO_LOCK = [
  { minutes: 0, label: 'Never' },
  { minutes: 5, label: '5 minutes' },
  { minutes: 10, label: '10 minutes' },
  { minutes: 30, label: '30 minutes' },
  { minutes: 60, label: '1 hour' },
] as const;

const THEMES = [
  { value: 'system', label: 'System' },
  { value: 'light', label: 'Light' },
  { value: 'dark', label: 'Dark' },
] as const;

export function SettingsPage({
  settings,
  onChange,
}: {
  settings: Settings;
  onChange: (patch: Partial<Settings>) => void;
}) {
  const [log, setLog] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  async function showLog() {
    setLog(await readDiagnostics().catch(() => 'The diagnostic log could not be read.'));
  }

  async function copyLog() {
    if (!log) return;
    try {
      await navigator.clipboard.writeText(log);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch {
      setCopied(false);
    }
  }

  return (
    <div className="page">
      <div className="page-head">
        <h1>Settings</h1>
        <p>Preferences are stored on this computer. Nothing is synced anywhere.</p>
      </div>

      <div className="panel">
        <div className="setting-row">
          <div className="setting-copy">
            <h3>Appearance</h3>
            <p>Follow the operating system, or pick one.</p>
          </div>
          <div className="segmented">
            {THEMES.map((t) => (
              <button
                key={t.value}
                aria-pressed={settings.theme === t.value}
                onClick={() => onChange({ theme: t.value })}
              >
                {t.label}
              </button>
            ))}
          </div>
        </div>

        <div className="setting-row">
          <div className="setting-copy">
            <h3>Auto lock</h3>
            <p>
              Lock the open vault after this much inactivity. The timer runs inside VaultDrive
              itself, not in the interface, so it keeps counting even if the window stops
              responding.
            </p>
          </div>
          <select
            value={settings.autoLockMinutes}
            style={{ width: 160 }}
            onChange={(e) => onChange({ autoLockMinutes: Number(e.target.value) })}
          >
            {AUTO_LOCK.map((a) => (
              <option key={a.minutes} value={a.minutes}>
                {a.label}
              </option>
            ))}
          </select>
        </div>

        <div className="setting-row">
          <div className="setting-copy">
            <h3>Recent vaults</h3>
            <p>
              {settings.recent.length} remembered. Only the file location and a display name are
              stored, never a password or a key.
            </p>
          </div>
          <button
            className="btn"
            disabled={settings.recent.length === 0}
            onClick={() => onChange({ recent: [] })}
          >
            Clear list
          </button>
        </div>
      </div>

      <div className="panel">
        <div className="row-between">
          <div className="setting-copy">
            <h3>Diagnostic log</h3>
            <p className="muted" style={{ marginTop: 3, fontSize: 12.5 }}>
              Counts, sizes, durations and error types. Passwords, keys, file contents and file
              names are never written to it.
            </p>
          </div>
          <div className="row">
            {log && (
              <button className="btn" onClick={copyLog}>
                {copied ? 'Copied' : 'Copy'}
              </button>
            )}
            <button className="btn" onClick={showLog}>
              {log ? 'Refresh' : 'Show log'}
            </button>
          </div>
        </div>
        {log && <div className="log-view selectable">{log}</div>}
      </div>

      <div style={{ marginTop: 16 }}>
        <Note tone="accent" title="How your vaults are protected">
          Each vault holds a random 256-bit key, encrypted with a key derived from your password
          by Argon2id at 128 MiB, 3 passes and 4 lanes. File contents are encrypted with
          XChaCha20-Poly1305 in 1 MiB authenticated chunks. Names and folder structure live only
          inside the encrypted index.
        </Note>
      </div>
    </div>
  );
}
