import { BrandMark, ChevronIcon, CloseIcon, KeyIcon, PlusIcon, VaultIcon } from '../components/Icons';
import { Note } from '../components/Note';
import { shortPath, when } from '../services/format';
import type { RecentVault } from '../types';

export function Home({
  recent,
  onCreate,
  onOpen,
  onOpenRecent,
  onForget,
}: {
  recent: RecentVault[];
  onCreate: () => void;
  onOpen: () => void;
  onOpenRecent: (path: string) => void;
  onForget: (path: string) => void;
}) {
  return (
    <div className="page">
      <div className="hero">
        <BrandMark size={60} className="hero-mark" />
        <h1>Protect your private files anywhere.</h1>
        <p>
          VaultDrive locks a folder where it stands, or packs it into a single portable file for
          a USB drive. Either way it opens with your password, and with nothing else.
        </p>
        <div className="hero-actions">
          <button className="btn btn-primary btn-lg" onClick={onCreate}>
            <PlusIcon size={16} />
            Lock a Folder
          </button>
          <button className="btn btn-lg" onClick={onOpen}>
            <KeyIcon size={16} />
            Unlock
          </button>
        </div>
      </div>

      <div style={{ marginTop: 12 }}>
        <div className="section-title">Recent vaults</div>
        {recent.length === 0 ? (
          <div className="empty-state">
            Vaults you create or open will be listed here. Only the file location is remembered.
          </div>
        ) : (
          <div className="recent-list">
            {recent.map((r) => (
              <div className="recent-item" key={r.path}>
                <button className="recent-open" onClick={() => onOpenRecent(r.path)}>
                  <span style={{ color: 'var(--accent)', display: 'flex' }}>
                    <VaultIcon size={18} />
                  </span>
                  <span style={{ minWidth: 0, flex: 1 }}>
                    <span className="recent-name truncate" style={{ display: 'block' }}>
                      {r.name}
                    </span>
                    <span className="recent-path truncate" style={{ display: 'block' }}>
                      {shortPath(r.path)}
                    </span>
                  </span>
                  <span className="faint" style={{ flex: 'none' }}>
                    {when(r.lastOpened)}
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
      </div>

      <div style={{ marginTop: 26 }}>
        <Note tone="accent" title="There is no way back in without your password.">
          VaultDrive derives the encryption key from your password alone. It has no master
          password, no recovery key and no backdoor. If you forget it, the vault cannot be
          opened by anyone, including us.
        </Note>
      </div>
    </div>
  );
}
