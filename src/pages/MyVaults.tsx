import { ChevronIcon, CloseIcon, PlusIcon, VaultIcon } from '../components/Icons';
import { DriveList } from '../components/DriveList';
import { shortPath, when } from '../services/format';
import type { RecentVault } from '../types';

export function MyVaults({
  recent,
  onOpen,
  onForget,
  onCreate,
}: {
  recent: RecentVault[];
  onOpen: (path: string) => void;
  onForget: (path: string) => void;
  onCreate: () => void;
}) {
  return (
    <div className="page">
      <div className="page-head">
        <h1>My vaults</h1>
        <p>
          Vaults you have created or opened on this computer. The list is a convenience only:
          the vault files themselves are wherever you put them, and moving one does not break it.
        </p>
      </div>

      {recent.length === 0 ? (
        <div className="stack">
          <div className="empty-state">No vaults yet.</div>
          <div>
            <button className="btn btn-primary" onClick={onCreate}>
              <PlusIcon size={16} />
              Create your first vault
            </button>
          </div>
        </div>
      ) : (
        <div className="recent-list">
          {recent.map((r) => (
            <div className="recent-item" key={r.path}>
              <button className="recent-open" onClick={() => onOpen(r.path)}>
                <span style={{ color: 'var(--accent)', display: 'flex' }}>
                  <VaultIcon size={18} />
                </span>
                <span style={{ minWidth: 0, flex: 1 }}>
                  <span className="recent-name truncate" style={{ display: 'block' }}>
                    {r.name}
                  </span>
                  <span className="recent-path truncate" style={{ display: 'block' }}>
                    {shortPath(r.path, 72)}
                  </span>
                </span>
                <span className="faint" style={{ flex: 'none' }}>
                  Last opened {when(r.lastOpened)}
                </span>
                <span className="faint" style={{ flex: 'none', display: 'flex' }}>
                  <ChevronIcon size={14} />
                </span>
              </button>
              <button
                className="btn btn-ghost recent-forget"
                aria-label={`Remove ${r.name} from this list`}
                title="Remove from this list"
                style={{ padding: 5, flex: 'none' }}
                onClick={() => onForget(r.path)}
              >
                <CloseIcon size={13} />
              </button>
            </div>
          ))}
        </div>
      )}

      <div style={{ marginTop: 32 }}>
        <div className="section-title">Available drives</div>
        <DriveList />
      </div>
    </div>
  );
}
