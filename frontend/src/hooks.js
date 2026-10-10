import { useEffect, useRef, useState, useCallback } from 'react';
import { api } from './api';

// Poll an API path on an interval; pause when the tab is hidden.
export function usePoll(path, intervalMs = 5000, deps = []) {
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const [loading, setLoading] = useState(true);
  const timer = useRef(null);

  const load = useCallback(async () => {
    try { setData(await api.get(path)); setError(null); }
    catch (e) { setError(e); }
    finally { setLoading(false); }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path]);

  useEffect(() => {
    let active = true;
    setLoading(true);
    load();
    const tick = () => { if (active && !document.hidden) load(); };
    timer.current = setInterval(tick, intervalMs);
    const onVis = () => { if (!document.hidden) load(); };
    document.addEventListener('visibilitychange', onVis);
    return () => { active = false; clearInterval(timer.current); document.removeEventListener('visibilitychange', onVis); };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [path, intervalMs, ...deps]);

  return { data, error, loading, reload: load };
}
