import { useEffect } from 'react';

import { keepAwake } from '../services/api';

/**
 * Tell Rust the user is still here.
 *
 * The inactivity clock lives in Rust; this only feeds it. If this hook stopped
 * firing -- a hung renderer, a paused window, devtools open on a breakpoint --
 * the vault would lock on schedule rather than stay open forever, which is the
 * behaviour we want from a security control.
 *
 * Events are coalesced to at most one call every fifteen seconds so moving the
 * mouse does not generate a command per frame.
 */
export function useActivity(active: boolean) {
  useEffect(() => {
    if (!active) return;
    let last = 0;

    const ping = () => {
      const now = Date.now();
      if (now - last < 15_000) return;
      last = now;
      void keepAwake().catch(() => undefined);
    };

    ping();
    const events = ['pointerdown', 'keydown', 'wheel', 'focus'] as const;
    for (const e of events) window.addEventListener(e, ping, { passive: true });
    return () => {
      for (const e of events) window.removeEventListener(e, ping);
    };
  }, [active]);
}
