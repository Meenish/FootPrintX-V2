import { useCallback, useEffect, useRef, useState } from 'react';
import { api } from './api.js';

/** Loads a GET endpoint with loading/error state and a reload function. */
export function useResource(path, { pollMs = 0 } = {}) {
  const [state, setState] = useState({ data: null, error: null, loading: !!path });
  const ctrl = useRef(null);
  const load = useCallback(
    async ({ quiet = false } = {}) => {
      if (!path) return;
      ctrl.current?.abort();
      const c = new AbortController();
      ctrl.current = c;
      if (!quiet) setState((s) => ({ ...s, loading: true, error: null }));
      try {
        const data = await api.get(path, { signal: c.signal });
        setState({ data, error: null, loading: false });
      } catch (error) {
        if (error.name === 'AbortError') return;
        // Keep showing the last good data during a background refresh failure.
        setState((s) => ({ data: quiet ? s.data : null, error, loading: false }));
      }
    },
    [path]
  );
  useEffect(() => {
    load();
    return () => ctrl.current?.abort();
  }, [load]);
  useVisiblePoll(pollMs ? () => load({ quiet: true }) : null, pollMs);
  return { ...state, reload: load };
}

/** Runs fn every ms while the tab is visible (no polling in background tabs). */
export function useVisiblePoll(fn, ms) {
  const saved = useRef(fn);
  saved.current = fn;
  useEffect(() => {
    if (!ms || !saved.current) return undefined;
    const id = setInterval(() => {
      if (document.visibilityState === 'visible') saved.current?.();
    }, ms);
    return () => clearInterval(id);
  }, [ms]);
}

/** Wraps an async action with busy/error state. */
export function useAction(fn) {
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);
  const run = useCallback(
    async (...args) => {
      setBusy(true);
      setError(null);
      try {
        return await fn(...args);
      } catch (e) {
        setError(e);
        return undefined;
      } finally {
        setBusy(false);
      }
    },
    [fn]
  );
  return { run, busy, error, setError };
}
