import { bytes, count } from '../services/format';
import type { ProgressEvent } from '../types';
import { Note } from './Note';

/**
 * The encryption / export progress panel.
 *
 * Percentage is driven by bytes, not by file count, so a folder holding one
 * large video and a thousand small notes does not sit at 99% for two minutes.
 */
export function ProgressPanel({
  title,
  progress,
  onCancel,
  removableWarning = false,
}: {
  title: string;
  progress: ProgressEvent | null;
  onCancel?: () => void;
  removableWarning?: boolean;
}) {
  const totalBytes = progress?.totalBytes ?? 0;
  const doneBytes = progress?.bytesDone ?? 0;
  const pct =
    totalBytes > 0
      ? Math.min(100, Math.round((doneBytes / totalBytes) * 100))
      : progress && progress.totalFiles > 0
        ? Math.round((progress.filesDone / progress.totalFiles) * 100)
        : 0;

  return (
    <div className="panel">
      <div className="row-between" style={{ marginBottom: 14 }}>
        <h2>{title}</h2>
        <span style={{ fontVariantNumeric: 'tabular-nums', fontWeight: 560 }}>{pct}%</span>
      </div>

      <div
        className="progress-track"
        role="progressbar"
        aria-valuenow={pct}
        aria-valuemin={0}
        aria-valuemax={100}
      >
        <div className="progress-fill" style={{ width: `${pct}%` }} />
      </div>

      <div className="progress-stats">
        <div>
          <div className="stat-label">Files processed</div>
          <div className="stat-value">
            {count(progress?.filesDone ?? 0)}
            <span className="muted" style={{ fontWeight: 400 }}>
              {' '}
              / {count(progress?.totalFiles ?? 0)}
            </span>
          </div>
        </div>
        <div>
          <div className="stat-label">Data processed</div>
          <div className="stat-value">
            {bytes(doneBytes)}
            <span className="muted" style={{ fontWeight: 400 }}> / {bytes(totalBytes)}</span>
          </div>
        </div>
      </div>

      <div className="stat-label" style={{ marginTop: 16 }}>
        Current file
      </div>
      <div className="truncate mono" style={{ marginTop: 3, color: 'var(--text-muted)' }}>
        {progress?.currentName || 'Preparing…'}
      </div>

      {removableWarning && (
        <div style={{ marginTop: 18 }}>
          <Note tone="warn">Please do not remove the USB drive until this finishes.</Note>
        </div>
      )}

      {onCancel && (
        <div style={{ marginTop: 18 }}>
          <button className="btn" onClick={onCancel}>
            Cancel
          </button>
          <span className="faint" style={{ marginLeft: 12 }}>
            Cancelling deletes the partly written vault and leaves your files alone.
          </span>
        </div>
      )}
    </div>
  );
}
