import { useCallback, useEffect, useState } from 'react';

import {
  BrandMark,
  GearIcon,
  HomeIcon,
  KeyIcon,
  PlusIcon,
  VaultIcon,
} from './components/Icons';
import { Note } from './components/Note';
import { useActivity } from './hooks/useActivity';
import { useSettings, useTheme } from './hooks/useSettings';
import { CreateVault } from './pages/CreateVault';
import { Home } from './pages/Home';
import { MyVaults } from './pages/MyVaults';
import { OpenVault } from './pages/OpenVault';
import { SettingsPage } from './pages/SettingsPage';
import { VaultBrowser } from './pages/VaultBrowser';
import * as api from './services/api';
import type { VaultStatus } from './types';

type Route = 'home' | 'vaults' | 'create' | 'open' | 'settings';

const NAV: Array<{ id: Route; label: string; icon: typeof HomeIcon }> = [
  { id: 'home', label: 'Home', icon: HomeIcon },
  { id: 'vaults', label: 'My Vaults', icon: VaultIcon },
  { id: 'create', label: 'Lock a Folder', icon: PlusIcon },
  { id: 'open', label: 'Open Vault', icon: KeyIcon },
  { id: 'settings', label: 'Settings', icon: GearIcon },
];

const LOCKED: VaultStatus = {
  unlocked: false,
  name: null,
  path: null,
  readOnly: false,
  files: 0,
  folders: 0,
  totalBytes: 0,
  reclaimableBytes: 0,
  generation: 0,
};

export default function App() {
  const { settings, update, reload } = useSettings();
  const [route, setRoute] = useState<Route>('home');
  const [status, setStatus] = useState<VaultStatus>(LOCKED);
  const [pendingVault, setPendingVault] = useState<string | undefined>(undefined);
  const [autoLocked, setAutoLocked] = useState(false);

  useTheme(settings.theme);
  useActivity(status.unlocked);

  const refreshStatus = useCallback(async () => {
    try {
      setStatus(await api.vaultStatus());
    } catch {
      setStatus(LOCKED);
    }
  }, []);

  useEffect(() => {
    void refreshStatus();
  }, [refreshStatus]);

  // The Rust side is the authority on locking. When its timer fires, the
  // interface follows: the browser disappears and the password is required
  // again.
  useEffect(() => {
    let unlisten: (() => void) | undefined;
    api
      .onAutoLocked(() => {
        setStatus(LOCKED);
        setAutoLocked(true);
        setRoute('open');
      })
      .then((fn) => {
        unlisten = fn;
      })
      .catch(() => undefined);
    return () => unlisten?.();
  }, []);

  const goOpen = useCallback((path?: string) => {
    setPendingVault(path);
    setAutoLocked(false);
    setRoute('open');
  }, []);

  async function lock() {
    await api.lockVault().catch(() => undefined);
    setStatus(LOCKED);
    setAutoLocked(false);
    setRoute('home');
  }

  async function forget(path: string) {
    await api.forgetRecent(path).catch(() => undefined);
    await reload();
  }

  // An unlocked vault takes over the whole window. Navigation while a vault is
  // open would mean either leaving it unlocked in the background or locking it
  // behind the user's back; showing one thing at a time avoids both.
  if (status.unlocked) {
    return (
      <VaultBrowser status={status} onLock={() => void lock()} onStatus={() => void refreshStatus()} />
    );
  }

  return (
    <div className="shell">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark size={28} className="brand-mark" />
          <span className="brand-name">VaultDrive</span>
        </div>

        <nav className="nav">
          {NAV.map((n) => {
            const Icon = n.icon;
            return (
              <button
                key={n.id}
                className="nav-item"
                aria-current={route === n.id ? 'page' : undefined}
                onClick={() => {
                  if (n.id === 'open') setPendingVault(undefined);
                  setRoute(n.id);
                }}
              >
                <Icon />
                {n.label}
              </button>
            );
          })}
        </nav>

        <div className="sidebar-foot">
          Encryption runs on this computer only.
          <br />
          No account, no network, no backdoor.
        </div>
      </aside>

      <main className="main">
        {autoLocked && route === 'open' && (
          <div style={{ padding: '24px 44px 0', maxWidth: 880 }}>
            <Note tone="warn" title="Vault locked automatically">
              The vault was locked after {settings.autoLockMinutes} minutes of inactivity. Enter
              the password to open it again.
            </Note>
          </div>
        )}

        {route === 'home' && (
          <Home
            recent={settings.recent}
            onCreate={() => setRoute('create')}
            onOpen={() => goOpen()}
            onOpenRecent={goOpen}
            onForget={(p) => void forget(p)}
          />
        )}

        {route === 'vaults' && (
          <MyVaults
            recent={settings.recent}
            onOpen={goOpen}
            onForget={(p) => void forget(p)}
            onCreate={() => setRoute('create')}
          />
        )}

        {route === 'create' && (
          <CreateVault onOpenVault={goOpen} onSettingsChanged={() => void reload()} />
        )}

        {route === 'open' && (
          <OpenVault
            initialPath={pendingVault}
            onUnlocked={() => {
              setAutoLocked(false);
              void refreshStatus();
              void reload();
            }}
          />
        )}

        {route === 'settings' && <SettingsPage settings={settings} onChange={update} />}
      </main>
    </div>
  );
}
