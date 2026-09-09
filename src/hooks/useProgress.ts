import { useEffect, useState } from 'react';

import { onProgress } from '../services/api';
import type { ProgressEvent } from '../types';

/** Subscribe to `vault:progress` while `active` is true. */
export function useProgress(active: boolean) {
  const [progress, setProgress] = useState<ProgressEvent | null>(null);

  useEffect(() => {
    if (!active) {
      setProgress(null);
      return;
    }
    let unlisten: (() => void) | undefined;
    let cancelled = false;

    onProgress(setProgress)
      .then((fn) => {
        // The operation may have finished before the listener attached.
        if (cancelled) fn();
        else unlisten = fn;
      })
      .catch(() => undefined);

    return () => {
      cancelled = true;
      unlisten?.();
    };
  }, [active]);

  return progress;
}
