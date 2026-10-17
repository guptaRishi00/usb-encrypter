import { useEffect, useState } from 'react';
import { convertFileSrc } from '@tauri-apps/api/core';
import { getCurrentWindow } from '@tauri-apps/api/window';

import { BrandMark, KeyIcon, LockIcon, SpinnerIcon } from '../components/Icons';
import { Note } from '../components/Note';
import { PasswordField } from '../components/PasswordField';
import { useProgress } from '../hooks/useProgress';
import { useSettings, useTheme } from '../hooks/useSettings';
import * as api from '../services/api';
import { asVaultError } from '../services/api';
import { bytes, quantity } from '../services/format';
import type { LockFailure, LockReport, PlayableVideo, PopupInfo, UnlockReport } from '../types';

/**
 * The small window that opens when the VaultDrive program inside a locked
 * folder is double-clicked.
 *
 * Rust owns the countdown and the relock; this only shows them. Closing the
 * window while the folder is open locks it before the app exits.
 */
type Phase = 'enter' | 'working' | 'open' | 'locking' | 'locked' | 'failed' | 'player';

/**
 * Attributes React's types do not list. `nodownload` removes the Download
 * item Chromium puts in a video's own menu, which would otherwise save the
 * decrypted film to disk.
 */
const VIDEO_LOCKDOWN = { controlsList: 'nodownload noremoteplayback', disableRemotePlayback: true };

const CODE = /^\d{6}$/;

export function FolderPopup({ info }: { info: PopupInfo }) {
  const { settings } = useSettings();
  useTheme(settings.theme);

  const locking = info.state === 'unlocked';
  const byCode = info.authMode === 'authenticator';

  const [phase, setPhase] = useState<Phase>('enter');
  const [secret, setSecret] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [restored, setRestored] = useState<UnlockReport | null>(null);
  const [locked, setLocked] = useState<LockReport | null>(null);
  const [failure, setFailure] = useState<LockFailure | null>(null);
  const [left, setLeft] = useState(info.relockAfter);
  const [videos, setVideos] = useState<PlayableVideo[]>([]);
  const [otherFiles, setOtherFiles] = useState(0);
  const [current, setCurrent] = useState<number | null>(null);
  const [playError, setPlayError] = useState(false);
  const progress = useProgress(phase === 'working' || phase === 'locking');

  // Relock happens on its own schedule, so listen for it for the whole life of
  // the window rather than only after a button press.
  useEffect(() => {
    const subs = [
      api.onPopupLocking(() => setPhase('locking')),
      api.onPopupLocked((r) => {
        setLocked(r);
        setPhase('locked');
      }),
      api.onPopupLockFailed((f) => {
        setFailure(f);
        setPhase('failed');
      }),
    ];
    return () => {
      subs.forEach((p) => p.then((off) => off()).catch(() => undefined));
    };
  }, []);

  // Display only. The deadline that matters is the one Rust is waiting on.
  useEffect(() => {
    if (phase !== 'open' || info.relockAfter === 0) return;
    setLeft(info.relockAfter);
    const started = Date.now();
    const t = window.setInterval(() => {
      setLeft(Math.max(0, info.relockAfter - Math.floor((Date.now() - started) / 1000)));
    }, 250);
    return () => window.clearInterval(t);
  }, [phase, info.relockAfter]);

  const ready = byCode
    ? CODE.test(secret.trim())
    : secret.length > 0 && (!locking || confirm.length > 0);

  async function submit() {
    if (!ready || phase === 'working') return;
    if (locking && !byCode && secret !== confirm) {
      setError('The two passwords do not match.');
      return;
    }
    setError(null);
    setPhase('working');
    const typed = byCode ? secret.trim() : secret;
    setSecret('');
    setConfirm('');
    try {
      if (locking) {
        setLocked(await api.popupLock(typed));
        setPhase('locked');
      } else {
        const opened = await api.popupUnlock(typed);
        if (opened.player) {
          setVideos(opened.videos);
          setOtherFiles(opened.otherFiles);
          setCurrent(opened.videos[0]?.id ?? null);
          setPhase('player');
        } else {
          setRestored(opened.report);
          setPhase('open');
        }
      }
    } catch (e) {
      setError(asVaultError(e).message);
      setPhase('enter');
    }
  }

  const pct =
    progress && progress.totalBytes > 0
      ? Math.min(100, Math.round((progress.bytesDone / progress.totalBytes) * 100))
      : null;

  return (
    <div className="popup">
      <div className="popup-head">
        <BrandMark size={30} className="brand-mark" />
        <div style={{ minWidth: 0 }}>
          <div className="popup-title truncate">{info.name}</div>
          <div className="faint">
            {phase === 'player'
              ? 'Watch only. Nothing is unlocked on disk.'
              : phase === 'open'
              ? 'Open'
              : phase === 'locked'
                ? 'Locked'
                : info.state === 'locked'
                  ? 'Locked by VaultDrive'
                  : 'Not locked'}
          </div>
        </div>
      </div>

      {info.state === 'empty' && <Note tone="warn">This folder is empty. There is nothing to lock.</Note>}
      {info.state === 'unavailable' && <Note tone="danger">This folder cannot be read.</Note>}

      {phase === 'enter' && (info.state === 'locked' || info.state === 'unlocked') && (
        <div className="stack">
          {byCode ? (
            <label className="field">
              <span className="field-label">Code from your authenticator app</span>
              <input
                type="text"
                inputMode="numeric"
                autoComplete="one-time-code"
                autoFocus
                value={secret}
                placeholder="123456"
                maxLength={6}
                className="popup-code"
                onChange={(e) => setSecret(e.target.value.replace(/\D/g, ''))}
                onKeyDown={(e) => e.key === 'Enter' && void submit()}
              />
            </label>
          ) : (
            <>
              <PasswordField
                label={locking ? 'Choose a password' : 'Password'}
                value={secret}
                onChange={setSecret}
                autoFocus
                onEnter={locking ? undefined : () => void submit()}
              />
              {locking && (
                <PasswordField
                  label="Type it again"
                  value={confirm}
                  onChange={setConfirm}
                  onEnter={() => void submit()}
                />
              )}
            </>
          )}

          {error && <Note tone="danger">{error}</Note>}

          <button className="btn btn-primary btn-lg btn-block" disabled={!ready} onClick={() => void submit()}>
            {locking ? <LockIcon size={16} /> : <KeyIcon size={16} />}
            {locking ? 'Lock folder' : 'Unlock'}
          </button>
          <span className="faint">
            {byCode
              ? 'Needs an internet connection. Each code works once.'
              : locking
                ? 'If this password is forgotten, nothing in the folder can be recovered.'
                : `The folder locks itself again ${info.relockAfter > 0 ? `${info.relockAfter} seconds after it opens` : 'when you close this window'}.`}
          </span>
        </div>
      )}

      {(phase === 'working' || phase === 'locking') && (
        <div className="stack">
          <div className="row-between">
            <strong>
              {phase === 'locking' || locking
                ? 'Locking…'
                : pct === null
                  ? byCode
                    ? 'Checking the code…'
                    : 'Checking the password…'
                  : 'Unlocking…'}
            </strong>
            <span className="muted" style={{ fontVariantNumeric: 'tabular-nums' }}>
              {pct === null ? <SpinnerIcon /> : `${pct}%`}
            </span>
          </div>
          <div className="progress-track">
            <div className="progress-fill" style={{ width: `${pct ?? 0}%` }} />
          </div>
          <span className="faint truncate">
            {progress?.currentName || 'Please keep the drive plugged in.'}
          </span>
        </div>
      )}

      {phase === 'open' && restored && (
        <div className="stack">
          <Note tone="ok" title="Folder unlocked">
            {quantity(restored.files, 'file')}, {bytes(restored.totalBytes)}, are back in the
            folder.
          </Note>
          {info.relockAfter > 0 ? (
            <div className="popup-countdown">
              <span className="faint">Locks again in</span>
              <span className="popup-count">
                {Math.floor(left / 60)}:{String(left % 60).padStart(2, '0')}
              </span>
            </div>
          ) : null}
          <button className="btn btn-primary btn-lg btn-block" onClick={() => void api.popupLockNow()}>
            <LockIcon size={16} />
            Lock now
          </button>
          <span className="faint">
            The folder stays open while this window is open. Closing the window locks it, so
            close anything playing from the folder first.
          </span>
        </div>
      )}

      {phase === 'locked' && (
        <div className="stack">
          <Note tone="ok" title="Folder locked">
            {locked ? `${quantity(locked.files, 'file')} encrypted. ` : ''}
            Double-click VaultDrive in the folder to open it again.
          </Note>
          <button className="btn btn-lg btn-block" onClick={() => void getCurrentWindow().close()}>
            Close
          </button>
        </div>
      )}

      {phase === 'player' && (
        <div className="player">
          {current === null ? (
            <Note tone="warn">There are no videos in this folder to play.</Note>
          ) : (
            <video
              key={current}
              className="player-video"
              src={convertFileSrc(String(current), 'vault')}
              controls
              autoPlay
              disablePictureInPicture
              {...VIDEO_LOCKDOWN}
              onPlaying={() => setPlayError(false)}
              onError={() => setPlayError(true)}
            />
          )}
          {playError && (
            <Note tone="danger" title="This video cannot be played here">
              MP4 files with H.264 video play everywhere. Other formats depend on what this
              computer supports; convert the film to MP4 before locking it.
            </Note>
          )}
          {videos.length > 1 && (
            <div className="player-list">
              {videos.map((v) => (
                <button
                  key={v.id}
                  className={`btn ${v.id === current ? 'btn-primary' : ''}`}
                  onClick={() => {
                    setPlayError(false);
                    setCurrent(v.id);
                  }}
                >
                  <span className="truncate">{v.name}</span>
                  <span className="faint">{bytes(v.size)}</span>
                </button>
              ))}
            </div>
          )}
          {otherFiles > 0 && (
            <span className="faint">
              {quantity(otherFiles, 'other file')} in this folder cannot be opened in watch-only
              mode.
            </span>
          )}
        </div>
      )}

      {phase === 'failed' && failure && (
        <div className="stack">
          <Note tone="danger" title="The folder is not locked">
            {failure.message}
          </Note>
          {failure.stillReadable.length > 0 && (
            <ul className="popup-list mono">
              {failure.stillReadable.map((f) => (
                <li key={f} className="truncate">
                  {f}
                </li>
              ))}
            </ul>
          )}
          <button className="btn btn-primary btn-lg btn-block" onClick={() => void api.popupLockNow()}>
            Try again
          </button>
          <span className="faint">Closing this window now leaves the folder unlocked.</span>
        </div>
      )}
    </div>
  );
}
