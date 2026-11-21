import type { ApiError } from '../api/errors';

export function ErrorMessage({ error }: { error: ApiError | null }) {
  if (!error) return null;
  return (
    <p role="alert" className="error">
      {error.message}
      {error.detail ? ` (${error.detail})` : ''}
    </p>
  );
}

export function Loading({ active }: { active: boolean }) {
  return active ? <p role="status">Loading…</p> : null;
}
