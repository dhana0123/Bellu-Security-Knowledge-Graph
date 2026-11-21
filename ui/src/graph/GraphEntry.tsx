import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { btnPrimary, errorBox, input } from '../common/classes';
import { graphPath } from '../cve/links';
import { normalizeCveId } from './entry';

/** A shortcut at the top of the Graph page: type a CVE id and open its graph (/graph/Vulnerability/<id>). */
export function CveShortcut() {
  const nav = useNavigate();
  const [value, setValue] = useState('');
  const [error, setError] = useState('');

  function submit(e: FormEvent) {
    e.preventDefault();
    const id = normalizeCveId(value);
    if (!id) {
      setError('Enter a CVE id such as CVE-2021-44228.');
      return;
    }
    setError('');
    nav(graphPath('Vulnerability', id));
  }

  return (
    <form onSubmit={submit} noValidate role="search" aria-label="Open a CVE graph" className="max-w-xl">
      <div className="flex items-center gap-2">
        <label htmlFor="graph-cve" className="text-sm text-slate-300">
          CVE id
        </label>
        <input
          id="graph-cve"
          className={input}
          value={value}
          placeholder="CVE-2021-44228"
          aria-invalid={error ? true : undefined}
          aria-describedby={error ? 'graph-cve-err' : undefined}
          onChange={(e) => setValue(e.target.value)}
        />
        <button type="submit" className={btnPrimary}>
          Open graph
        </button>
      </div>
      {error && (
        <p id="graph-cve-err" role="alert" className={`${errorBox} mt-2`}>
          {error}
        </p>
      )}
    </form>
  );
}
