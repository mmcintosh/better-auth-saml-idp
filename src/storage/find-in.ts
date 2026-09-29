// `field IN (values)` in batches. D1 allows 100 bound parameters per statement and SQLite builds
// can be lower, so a list of tenants or a user's organizations is read in slices well under that.
type Adapter = {
  findMany(a: { model: string; where: { field: string; value: unknown; operator?: "in" }[]; limit?: number }): Promise<unknown[]>;
};

/** Values per query: well under D1's 100 bound parameters, leaving room for the adapter's own. */
export const IN_BATCH = 50;

/** Rows whose `field` is one of `values`, at most `perValue` per value. Exact matches only. */
export async function findManyIn(adapter: Adapter, model: string, field: string, values: string[], perValue: number): Promise<unknown[]> {
  const out: unknown[] = [];
  for (let i = 0; i < values.length; i += IN_BATCH) {
    const slice = values.slice(i, i + IN_BATCH);
    const wanted = new Set(slice);
    const rows = (await adapter.findMany({ model, where: [{ field, value: slice, operator: "in" }], limit: slice.length * perValue + perValue })) as Record<string, unknown>[];
    // A case-insensitive collation must not widen the match (R4-L8).
    for (const r of rows) if (wanted.has(String(r[field]))) out.push(r);
  }
  return out;
}
