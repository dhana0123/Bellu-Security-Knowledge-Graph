import { useState } from 'react';
import type { FormEvent } from 'react';
import { Navigate, useNavigate } from 'react-router';
import { ApiError } from '../api/errors';
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
    <main>
      <h1>BSKG sign in</h1>
      {notice && <p role="alert" className="error">{notice}</p>}
      <form onSubmit={submit} autoComplete="off">
        <label htmlFor="key">API key</label>
        <input id="key" type="password" value={key} onChange={(e) => setKey(e.target.value)} autoComplete="off" />
        <button type="submit" disabled={busy || !key.trim()}>
          {busy ? 'Checking…' : 'Sign in'}
        </button>
      </form>
      <ErrorMessage error={error} />
    </main>
  );
}
