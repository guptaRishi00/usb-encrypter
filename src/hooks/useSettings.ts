import { useCallback, useEffect, useState } from 'react';

import { getSettings, saveSettings } from '../services/api';
import type { Settings } from '../types';

const FALLBACK: Settings = { theme: 'system', autoLockMinutes: 10, recent: [] };

/**
 * Preferences and the recent-vault list, owned by Rust.
 *
 * The auto-lock interval in particular is not a frontend value: saving it here
 * pushes it into the session so the Rust-side timer uses the new one.
 */
export function useSettings() {
  const [settings, setSettings] = useState<Settings>(FALLBACK);
  const [loaded, setLoaded] = useState(false);

  const reload = useCallback(async () => {
    try {
      setSettings(await getSettings());
    } catch {
      setSettings(FALLBACK);
    } finally {
      setLoaded(true);
    }
  }, []);

  useEffect(() => {
    void reload();
  }, [reload]);

  const update = useCallback(async (patch: Partial<Settings>) => {
    setSettings((current) => {
      const next = { ...current, ...patch };
      void saveSettings(next)
        .then(setSettings)
        .catch(() => undefined);
      return next;
    });
  }, []);

  return { settings, loaded, update, reload, setSettings };
}

/** Resolve `system` against the OS preference and stamp it on the document. */
export function useTheme(theme: Settings['theme']) {
  useEffect(() => {
    const media = window.matchMedia('(prefers-color-scheme: light)');
    const apply = () => {
      const resolved = theme === 'system' ? (media.matches ? 'light' : 'dark') : theme;
      document.documentElement.dataset.theme = resolved;
    };
    apply();
    media.addEventListener('change', apply);
    return () => media.removeEventListener('change', apply);
  }, [theme]);
}
