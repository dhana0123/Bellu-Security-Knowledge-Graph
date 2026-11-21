import { useState } from 'react';
import type { FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { ApiError } from '../api/errors';
import { btnPrimary, card, errorBox, input, label } from '../common/classes';
import { ErrorMessage } from '../common/ErrorMessage';
import { useAuth } from './AuthContext';

export function Login() {
  const { authed, login, notice } = useAuth();
  const nav = useNavigate();
  const [key, setKey] = useState('');
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  if (authed) return <Navigate to="/" replace />;

  async function submit(e: FormEvent) {
    e.preventDefault();
    if (!key.trim() || busy) return;
    setBusy(true);
    setError(null);
    try {
      await login(key.trim());
      setKey('');
      nav('/', { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err : new ApiError('login', 'network error'));
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="mx-auto mt-16 max-w-md px-4">
      <h1 className="mb-1 text-2xl font-semibold text-slate-50">BSKG sign in</h1>
      <p className="mb-4 text-sm text-slate-400">Bellu security knowledge graph</p>
      {notice && (
        <p role="alert" className={`${errorBox} mb-3`}>
          {notice}
        </p>
      )}
      <form onSubmit={submit} autoComplete="off" className={`${card} space-y-3`}>
        <div>
          <label htmlFor="key" className={label}>
            API key
          </label>
          <input id="key" type="password" className={input} value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" />
        </div>
        <button type="submit" className={btnPrimary} disabled={busy || !key.trim()}>
          {busy ? 'Checking…' : 'Sign in'}
        </button>
      </form>
      <ErrorMessage error={error} />
    </main>
  );
}
