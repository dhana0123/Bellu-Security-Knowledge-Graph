package canonical

import (
	"context"
	"encoding/json"
)

// Collision is one recorded identifier collision: records bridged two different CVE ids, so
// the resolver kept the two CVE groups separate. Collisions live in entity_resolution with
// method "identifier-collision" (left_id and right_id are the two CVE ids, ordered by string).
type Collision struct {
	CVEA, CVEB string
	Records    []string // "source:external_id" of the bridging records
	RecordedAt string
}

// CountCollisions returns the number of recorded identifier collisions.
func (s *Store) CountCollisions(ctx context.Context) (int, error) {
	var n int
	err := s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM entity_resolution WHERE method=?`, RuleIdentifierCollision).Scan(&n)
	return n, err
}

// ListCollisions returns recorded collisions ordered by CVE pair; limit <= 0 means all.
func (s *Store) ListCollisions(ctx context.Context, limit int) ([]Collision, error) {
	q := `SELECT left_id, right_id, decision, recorded_at FROM entity_resolution WHERE method=? ORDER BY left_id, right_id`
	args := []any{RuleIdentifierCollision}
	if limit > 0 {
		q += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Collision{}
	for rows.Next() {
		var c Collision
		var body string
		if err := rows.Scan(&c.CVEA, &c.CVEB, &body, &c.RecordedAt); err != nil {
			return nil, err
		}
		var d struct {
			Records []string `json:"source_record_ids"`
		}
		_ = json.Unmarshal([]byte(body), &d)
		c.Records = d.Records
		out = append(out, c)
	}
	return out, rows.Err()
}
