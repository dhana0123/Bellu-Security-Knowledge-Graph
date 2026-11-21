// Cursor paging: a stack of the cursors used for each visited page.
export interface PagerState {
  /** cursors[i] is the cursor that fetched page i (page 0 has none). */
  cursors: (string | undefined)[];
  index: number;
  next?: string;
}

export const initialPager: PagerState = { cursors: [undefined], index: 0 };

/** Record the next cursor returned by the page at the current index. */
export function withNext(p: PagerState, next: string | undefined): PagerState {
  return { ...p, next };
}

export const canNext = (p: PagerState): boolean => p.next !== undefined;
export const canPrev = (p: PagerState): boolean => p.index > 0;

export function goNext(p: PagerState): PagerState {
  if (p.next === undefined) return p;
  return { cursors: [...p.cursors.slice(0, p.index + 1), p.next], index: p.index + 1 };
}

export function goPrev(p: PagerState): PagerState {
  if (p.index === 0) return p;
  return { cursors: p.cursors, index: p.index - 1 };
}

export const currentCursor = (p: PagerState): string | undefined => p.cursors[p.index];
