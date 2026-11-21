// The API key lives in memory and sessionStorage only (never in a URL or localStorage).
const STORAGE_KEY = 'bskg.key';

let memoryKey: string | null = null;

function storage(): Storage | null {
  try {
    return typeof sessionStorage === 'undefined' ? null : sessionStorage;
  } catch {
    return null;
  }
}

export function loadKey(): string | null {
  if (memoryKey) return memoryKey;
  const stored = storage()?.getItem(STORAGE_KEY) ?? null;
  memoryKey = stored;
  return stored;
}

export function saveKey(key: string): void {
  memoryKey = key;
  try {
    storage()?.setItem(STORAGE_KEY, key);
  } catch {
    // Storage may be full or blocked; the in-memory copy still works.
  }
}

export function clearKey(): void {
  memoryKey = null;
  try {
    storage()?.removeItem(STORAGE_KEY);
  } catch {
    // ignore
  }
}
