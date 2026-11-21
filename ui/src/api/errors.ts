export type FailureKind = number | 'network error' | 'timeout';

/** A failed API call. The message never contains the API key or a URL. */
export class ApiError extends Error {
  readonly action: string;
  readonly status: FailureKind;
  readonly code?: string;
  readonly parameter?: string;

  constructor(action: string, status: FailureKind, code?: string, parameter?: string, detail?: string) {
    super(formatFailure(action, status));
    this.name = 'ApiError';
    this.action = action;
    this.status = status;
    this.code = code;
    this.parameter = parameter;
    this.detail = detail;
  }
  readonly detail?: string;
}

export function formatFailure(action: string, status: FailureKind): string {
  return typeof status === 'number' ? `${action} failed: HTTP ${status}` : `${action} failed: ${status}`;
}
