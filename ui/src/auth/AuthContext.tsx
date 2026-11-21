import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { createClient } from '../api/client';
import type { ApiClient } from '../api/client';
import { clearKey, loadKey, saveKey } from '../api/session';
import type { GraphEnvelope, SourceInfo } from '../api/types';

interface Auth {
  client: ApiClient;
  authed: boolean;
  graph: GraphEnvelope | null;
  sources: SourceInfo[];
  notice: string | null;
  login: (key: string) => Promise<void>;
  logout: () => void;
}

const Ctx = createContext<Auth | null>(null);

export function useAuth(): Auth {
  const v = useContext(Ctx);
  if (!v) throw new Error('AuthProvider missing');
  return v;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [authed, setAuthed] = useState(() => loadKey() !== null);
  const [graph, setGraph] = useState<GraphEnvelope | null>(null);
  const [sources, setSources] = useState<SourceInfo[]>([]);
  const [notice, setNotice] = useState<string | null>(null);

  const client = useMemo(
    () =>
      createClient({
        getKey: loadKey,
        onGraph: setGraph,
        onUnauthorized: () => {
          clearKey();
          setAuthed(false);
          setSources([]);
          setNotice('key is invalid or revoked');
        },
      }),
    [],
  );

  const login = useCallback(
    async (key: string) => {
      await client.login(key); // throws unless HTTP 200
      saveKey(key);
      setNotice(null);
      setAuthed(true);
    },
    [client],
  );

  const logout = useCallback(() => {
    clearKey();
    setAuthed(false);
    setSources([]);
    setGraph(null);
    setNotice(null);
  }, []);

  // Sources (attribution texts) are fetched once after login.
  useEffect(() => {
    if (!authed) return;
    const ctrl = new AbortController();
    client
      .sources(ctrl.signal)
      .then(setSources)
      .catch(() => undefined);
    return () => ctrl.abort();
  }, [authed, client]);

  const value = useMemo(
    () => ({ client, authed, graph, sources, notice, login, logout }),
    [client, authed, graph, sources, notice, login, logout],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}
