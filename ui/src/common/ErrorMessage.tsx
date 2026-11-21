import type { ApiError } from '../api/errors';
import { errorBox } from './classes';

export function ErrorMessage({ error }: { error: ApiError | null }) {
  if (!error) return null;
  return (
    <p role="alert" className={`${errorBox} my-2`}>
      {error.message}
      {error.detail ? ` (${error.detail})` : ''}
    </p>
  );
}

export function Loading({ active }: { active: boolean }) {
  return active ? (
    <p role="status" className="my-2 text-sm text-slate-400">
      Loading…
    </p>
  ) : null;
}
