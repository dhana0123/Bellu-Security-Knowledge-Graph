/** Route for an entity's graph view. */
export function graphPath(type: string, id: string): string {
  return `/graph/${encodeURIComponent(type)}/${encodeURIComponent(id)}`;
}
