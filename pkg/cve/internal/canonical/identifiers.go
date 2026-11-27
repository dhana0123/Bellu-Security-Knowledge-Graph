package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
)

// record_identifier holds one row per (record, trimmed identifier) and resolve_dirty marks the
// records changed since the last Resolve (migration 0005). Both are derived from source_record.

// cleanIdents trims, drops empties and deduplicates, keeping first-seen order.
func cleanIdents(in []string) []string {
	seen := make(map[string]struct{}, len(in))
	out := make([]string, 0, len(in))
	for _, x := range in {
		x = strings.TrimSpace(x)
		if x == "" {
			continue
		}
		if _, ok := seen[x]; ok {
			continue
		}
		seen[x] = struct{}{}
		out = append(out, x)
	}
	return out
}

// indexRecord replaces the identifier rows of one record and marks it dirty for Resolve.
func (s *Store) indexRecord(ctx context.Context, tx *sql.Tx, source, id string, idents []string, hash string) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM record_identifier WHERE source=? AND external_id=?`, source, id); err != nil {
		return err
	}
	for _, v := range cleanIdents(idents) {
		if _, err := tx.ExecContext(ctx, `INSERT INTO record_identifier(source, external_id, value) VALUES(?,?,?) ON CONFLICT DO NOTHING`, source, id, v); err != nil {
			return err
		}
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO resolve_dirty(source, external_id, content_hash) VALUES(?,?,?)
ON CONFLICT(source, external_id) DO UPDATE SET content_hash=excluded.content_hash`, source, id, hash)
	return err
}

// indexMissingRecords adopts source_record rows that have no record_identifier rows (stores
// created before migration 0005, or rows written outside UpsertRecord): it indexes their
// identifiers and marks them dirty. A store without such rows costs one anti-join.
func (s *Store) indexMissingRecords(ctx context.Context) error {
	const page = 5000
	lastSrc, lastID := "", ""
	first := true
	for {
		type rec struct{ src, id, aliases, hash string }
		var batch []rec
		q := `SELECT sr.source, sr.external_id, sr.aliases, sr.content_hash FROM source_record sr
WHERE NOT EXISTS (SELECT 1 FROM record_identifier ri WHERE ri.source=sr.source AND ri.external_id=sr.external_id)`
		args := []any{}
		if !first {
			q += ` AND (sr.source>? OR (sr.source=? AND sr.external_id>?))`
			args = append(args, lastSrc, lastSrc, lastID)
		}
		q += ` ORDER BY sr.source, sr.external_id LIMIT ?`
		args = append(args, page)
		rows, err := s.DB.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var r rec
			if err := rows.Scan(&r.src, &r.id, &r.aliases, &r.hash); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		if len(batch) == 0 {
			return nil
		}
		tx, err := s.DB.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		for _, r := range batch {
			var list []string
			_ = json.Unmarshal([]byte(r.aliases), &list)
			if err := s.indexRecord(ctx, tx, r.src, r.id, append([]string{r.id}, list...), r.hash); err != nil {
				tx.Rollback()
				return err
			}
		}
		if err := tx.Commit(); err != nil {
			return err
		}
		first = false
		last := batch[len(batch)-1]
		lastSrc, lastID = last.src, last.id
		if len(batch) < page {
			return nil
		}
	}
}
