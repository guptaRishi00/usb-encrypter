import { useEffect, useState } from 'react';

import { listDrives } from '../services/api';
import { bytes } from '../services/format';
import type { DriveInfo } from '../types';
import { DiskIcon, DriveIcon } from './Icons';

/**
 * Mounted volumes, removable ones first.
 *
 * Best effort by design: an operating system may hide a volume or report a
 * removable drive as fixed. This list is a shortcut, never the only way to
 * reach a folder, so the file picker is always available alongside it.
 */
export function DriveList({ onPick }: { onPick?: (drive: DriveInfo) => void }) {
  const [drives, setDrives] = useState<DriveInfo[] | null>(null);

  useEffect(() => {
    let alive = true;
    const load = () =>
      listDrives()
        .then((d) => alive && setDrives(d))
        .catch(() => alive && setDrives([]));
    load();
    // Cheap poll so plugging a stick in shows up without a restart.
    const t = setInterval(load, 4000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  if (!drives) return <div className="faint">Looking for drives…</div>;
  if (drives.length === 0) {
    return <div className="faint">No drives reported by the system.</div>;
  }

  return (
    <div className="drive-grid">
      {drives.map((d) => {
        const used = d.totalBytes > 0 ? 1 - d.availableBytes / d.totalBytes : 0;
        const Icon = d.removable ? DriveIcon : DiskIcon;
        return (
          <button
            key={d.mountPoint}
            className="drive"
            onClick={() => onPick?.(d)}
            disabled={!onPick}
            style={onPick ? undefined : { cursor: 'default' }}
          >
            <span style={{ color: d.removable ? 'var(--accent)' : 'var(--text-muted)' }}>
              <Icon />
            </span>
            <span style={{ minWidth: 0, flex: 1 }}>
              <span className="truncate" style={{ display: 'block', fontWeight: 540 }}>
                {d.label}
              </span>
              <span className="faint">
                {d.removable ? 'Removable' : 'Local'} · {bytes(d.availableBytes)} free of{' '}
                {bytes(d.totalBytes)}
              </span>
              <span className="drive-bar">
                <span style={{ width: `${Math.round(used * 100)}%` }} />
              </span>
            </span>
          </button>
        );
      })}
    </div>
  );
}
