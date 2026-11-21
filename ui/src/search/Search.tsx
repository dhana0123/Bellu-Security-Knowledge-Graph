import { useState } from 'react';
import type { FormEvent } from 'react';
import { useAuth } from '../auth/AuthContext';
import type { SearchFilters } from '../api/types';
import { btn, btnPrimary, card, errorBox, h1, input, label, muted } from '../common/classes';
import { ErrorMessage, Loading } from '../common/ErrorMessage';
import { useRequest } from '../common/useRequest';
import { Results } from './Results';
import { canPrev, currentCursor, goNext, goPrev, initialPager } from './paging';
import type { PagerState } from './paging';
import { emptyFilters, filtersToParams, validateFilters } from './validation';
import type { FilterErrors } from './validation';

const PAGE_SIZE = 50;

export function Search() {
  const { client, graph } = useAuth();
  const [form, setForm] = useState<SearchFilters>(emptyFilters);
  const [errors, setErrors] = useState<FilterErrors>({});
  const [applied, setApplied] = useState<SearchFilters>(emptyFilters);
  const [pager, setPager] = useState<PagerState>(initialPager);
  const cursor = currentCursor(pager);

  const req = useRequest(
    (signal) => client.search(filtersToParams(applied), PAGE_SIZE, cursor, signal),
    [client, applied, cursor],
  );

  const kevAvailable = graph?.sources ? 'kev' in graph.sources : false;

  function set<K extends keyof SearchFilters>(k: K, v: SearchFilters[K]) {
    setForm((f) => ({ ...f, [k]: v }));
  }

  function submit(e: FormEvent) {
    e.preventDefault();
    if (req.loading) return;
    const errs = validateFilters(form);
    setErrors(errs);
    if (Object.keys(errs).length > 0) return; // no request; values stay
    setApplied(form);
    setPager(initialPager);
  }

  function field(k: 'q' | 'publishedFrom' | 'publishedTo' | 'cvssV3Min' | 'cvssV3Max' | 'cwe', text: string, hint?: string) {
    return (
      <div>
        <label htmlFor={`f-${k}`} className={label}>
          {text}
        </label>
        <input
          id={`f-${k}`}
          className={input}
          value={form[k]}
          placeholder={hint}
          aria-invalid={errors[k] ? true : undefined}
          aria-describedby={errors[k] ? `e-${k}` : undefined}
          onChange={(e) => set(k, e.target.value)}
        />
        {errors[k] && (
          <div id={`e-${k}`} role="alert" className={`${errorBox} mt-1`}>
            {errors[k]}
          </div>
        )}
      </div>
    );
  }

  const items = req.data?.items ?? [];
  return (
    <section>
      <h1 className={h1}>Search vulnerabilities</h1>
      <form onSubmit={submit} noValidate className={`${card} mb-6 space-y-4`}>
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          {field('q', 'Text search')}
          {field('publishedFrom', 'Published from', 'YYYY-MM-DD')}
          {field('publishedTo', 'Published to', 'YYYY-MM-DD')}
          {field('cvssV3Min', 'CVSS v3 minimum', '0.0')}
          {field('cvssV3Max', 'CVSS v3 maximum', '10.0')}
          {field('cwe', 'Weakness (CWE)', 'CWE-79')}
          <div>
            <label htmlFor="f-expl" className={label}>
              Exploitability
            </label>
            <select id="f-expl" className={input} value={form.exploitability} onChange={(e) => set('exploitability', e.target.value)}>
              <option value="">Any</option>
              <option value="exploited">Exploited</option>
              <option value="unexploited">Not exploited</option>
            </select>
          </div>
        </div>
        <label className="flex items-center gap-2 text-sm text-slate-300">
          <input type="checkbox" checked={form.includeRejected} onChange={(e) => set('includeRejected', e.target.checked)} />{' '}
          Include rejected CVEs
        </label>
        {kevAvailable && (
          <label className="flex items-center gap-2 text-sm text-slate-300">
            <input type="checkbox" checked={form.kev} onChange={(e) => set('kev', e.target.checked)} /> Known exploited (KEV) only
          </label>
        )}
        <button type="submit" className={btnPrimary} disabled={req.loading}>
          Search
        </button>
      </form>
      <Loading active={req.loading} />
      <ErrorMessage error={req.error} />
      {req.data && items.length === 0 && !req.loading && <p className={muted}>No vulnerabilities match these filters.</p>}
      {items.length > 0 && <Results items={items} page={pager.index + 1} />}
      <div className="mt-4 flex items-center gap-2">
        <button type="button" className={btn} disabled={!canPrev(pager) || req.loading} onClick={() => setPager(goPrev(pager))}>
          Previous
        </button>
        <button
          type="button"
          className={btn}
          disabled={!req.data?.nextCursor || req.loading}
          onClick={() => req.data && setPager(goNext({ ...pager, next: req.data.nextCursor }))}
        >
          Next
        </button>
        <span className={`${muted} text-sm`}>Page {pager.index + 1}</span>
      </div>
    </section>
  );
}
