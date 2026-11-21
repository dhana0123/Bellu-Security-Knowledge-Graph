import { useState } from 'react';
import type { FormEvent } from 'react';
import { useNavigate } from 'react-router';
import { btnPrimary, card, errorBox, h1, input, label, muted } from '../common/classes';
import { graphPath } from '../cve/links';
import { normalizeCveId } from './entry';

/** /graph without parameters: asks for a CVE id and opens its graph. */
export function GraphEntry() {
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
    <section>
      <h1 className={h1}>Graph</h1>
      <form onSubmit={submit} noValidate className={`${card} max-w-xl`}>
        <label htmlFor="graph-cve" className={label}>
          CVE id
        </label>
        <div className="flex gap-2">
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
        <p className={`${muted} mt-3 text-sm`}>Shows the vulnerability with its exploits, weaknesses, products and vendors.</p>
      </form>
    </section>
  );
}
