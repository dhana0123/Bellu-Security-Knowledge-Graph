package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// Read path used by projection (task 88.7). Projection runs a handful of identical queries
// per vulnerability, so statements are prepared once and cached on the Store; preparing was a
// sixth of the projection time. The cache is closed with the Store.

// QueryCached runs a read query through a cached prepared statement. The caller closes the rows.
func (s *Store) QueryCached(ctx context.Context, q string, args ...any) (*sql.Rows, error) {
	s.stmtMu.Lock()
	st := s.stmts[q]
	if st == nil {
		var err error
		if st, err = s.DB.PrepareContext(ctx, q); err != nil {
			s.stmtMu.Unlock()
			return nil, err
		}
		if s.stmts == nil {
			s.stmts = map[string]*sql.Stmt{}
		}
		s.stmts[q] = st
	}
	s.stmtMu.Unlock()
	return st.QueryContext(ctx, args...)
}

func (s *Store) closeStmts() {
	s.stmtMu.Lock()
	defer s.stmtMu.Unlock()
	for q, st := range s.stmts {
		_ = st.Close()
		delete(s.stmts, q)
	}
}

const enrichmentChunk = 200

// EnrichmentMany returns Enrichment for each key with the same rules (linked KEV and EPSS
// only; the latest linked EPSS date) using one query per table for the whole key list instead
// of five per key. Keys without any enrichment are absent from the result.
func (s *Store) EnrichmentMany(ctx context.Context, keys []string) (map[string]*EnrichmentView, error) {
	out := map[string]*EnrichmentView{}
	view := func(k string) *EnrichmentView {
		v := out[k]
		if v == nil {
			v = &EnrichmentView{}
			out[k] = v
		}
		return v
	}
	for start := 0; start < len(keys); start += enrichmentChunk {
		end := start + enrichmentChunk
		if end > len(keys) {
			end = len(keys)
		}
		chunk := keys[start:end]
		in := "(" + strings.TrimSuffix(strings.Repeat("?,", len(chunk)), ",") + ")"
		args := make([]any, len(chunk))
		for i, k := range chunk {
			args[i] = k
		}
		if err := s.eachRow(ctx, `SELECT cve, json FROM kev WHERE +status='linked' AND cve IN `+in, args, func(rs *sql.Rows) error {
			var cve, j string
			if err := rs.Scan(&cve, &j); err != nil {
				return err
			}
			k := &model.KEV{}
			if err := json.Unmarshal([]byte(j), k); err != nil {
				return err
			}
			view(cve).KEV = k
			return nil
		}); err != nil {
			return nil, err
		}
		if err := s.eachRow(ctx, `SELECT cve, score, percentile, score_date FROM epss_history WHERE +status='linked' AND cve IN `+in+` ORDER BY cve, score_date DESC`, args, func(rs *sql.Rows) error {
			var sc, pc sql.NullFloat64
			e := &model.EPSS{}
			if err := rs.Scan(&e.CVE, &sc, &pc, &e.Date); err != nil {
				return err
			}
			if v := view(e.CVE); v.EPSS == nil { // newest date first
				e.Score, e.Percentile = sc.Float64, pc.Float64
				v.EPSS = e
			}
			return nil
		}); err != nil {
			return nil, err
		}
		if err := s.eachRow(ctx, `SELECT vulnerability_id, cwe_id FROM weakness_link WHERE vulnerability_id IN `+in+` ORDER BY vulnerability_id, cwe_id`, args, func(rs *sql.Rows) error {
			var k, c string
			if err := rs.Scan(&k, &c); err != nil {
				return err
			}
			v := view(k)
			v.Weaknesses = append(v.Weaknesses, c)
			return nil
		}); err != nil {
			return nil, err
		}
		if err := s.eachRow(ctx, `SELECT vulnerability_id, url, source, COALESCE(fixed_version,'') FROM patch WHERE vulnerability_id IN `+in+` ORDER BY vulnerability_id, url, source`, args, func(rs *sql.Rows) error {
			var k string
			var p model.Patch
			if err := rs.Scan(&k, &p.URL, &p.Source, &p.FixedVersion); err != nil {
				return err
			}
			v := view(k)
			v.Patches = append(v.Patches, p)
			return nil
		}); err != nil {
			return nil, err
		}
		if err := s.eachRow(ctx, `SELECT vulnerability_id, url, source FROM exploit_ref WHERE vulnerability_id IN `+in+` ORDER BY vulnerability_id, url, source`, args, func(rs *sql.Rows) error {
			var k string
			var x model.Exploit
			if err := rs.Scan(&k, &x.URL, &x.Source); err != nil {
				return err
			}
			v := view(k)
			v.Exploits = append(v.Exploits, x)
			return nil
		}); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func (s *Store) eachRow(ctx context.Context, q string, args []any, fn func(*sql.Rows) error) error {
	rs, err := s.QueryCached(ctx, q, args...)
	if err != nil {
		return err
	}
	defer rs.Close()
	for rs.Next() {
		if err := fn(rs); err != nil {
			return err
		}
	}
	return rs.Err()
}
