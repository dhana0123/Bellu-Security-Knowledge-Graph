package canonical

import (
	"context"
	"encoding/json"
	"errors"
	"iter"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// ErrInvalidAsOf is returned for a zero or future as-of time (R8.4).
var ErrInvalidAsOf = errors.New("invalid as-of time")

const tsLayout = "2006-01-02T15:04:05.000Z"

// View is a read-only temporal view over source_record_version.
type View interface {
	// Records yields the latest version of every source record visible in this view.
	Records(ctx context.Context) iter.Seq2[*model.Record, error]
	// Vulnerability returns the source records that are members of vulnerability id
	// in this view, or nil when there are none.
	Vulnerability(ctx context.Context, id string) (*VulnView, error)
}

// VulnView is a minimal vulnerability view: its id and visible member records.
type VulnView struct {
	ID      string
	Records []*model.Record
}

type sqlView struct {
	s           *Store
	at          string // recorded_at upper bound, inclusive
	excludeWith bool   // drop records whose latest version is withdrawn
}

// AsOf returns the view of the store as recorded at t. A zero t, or a t after the store
// clock's Now(), yields ErrInvalidAsOf. Facts withdrawn after t are still returned.
func (s *Store) AsOf(t time.Time) (View, error) {
	if t.IsZero() || t.Year() < 1 {
		return nil, ErrInvalidAsOf
	}
	t = t.UTC().Truncate(time.Millisecond)
	if t.After(s.clock.Now().UTC().Truncate(time.Millisecond)) {
		return nil, ErrInvalidAsOf
	}
	return &sqlView{s: s, at: t.Format(tsLayout)}, nil
}

// Current is AsOf(Now()) with withdrawn records filtered out (R8.7).
func (s *Store) Current() View {
	return &sqlView{s: s, at: s.now(), excludeWith: true}
}

const asOfSQL = `SELECT v.json FROM source_record_version v
WHERE v.recorded_at <= ?1
  AND v.version = (SELECT MAX(version) FROM source_record_version
                   WHERE source=v.source AND external_id=v.external_id AND recorded_at <= ?1)
  AND (?2 = 0 OR v.state <> 'withdrawn')`

func (v *sqlView) query(ctx context.Context, extra string, args ...any) ([]*model.Record, error) {
	ex := 0
	if v.excludeWith {
		ex = 1
	}
	rows, err := v.s.DB.QueryContext(ctx, asOfSQL+extra+` ORDER BY v.source, v.external_id`,
		append([]any{v.at, ex}, args...)...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*model.Record
	for rows.Next() {
		var j string
		if err := rows.Scan(&j); err != nil {
			return nil, err
		}
		r := new(model.Record)
		if err := json.Unmarshal([]byte(j), r); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (v *sqlView) Records(ctx context.Context) iter.Seq2[*model.Record, error] {
	return func(yield func(*model.Record, error) bool) {
		recs, err := v.query(ctx, "")
		if err != nil {
			yield(nil, err)
			return
		}
		for _, r := range recs {
			if !yield(r, nil) {
				return
			}
		}
	}
}

func (v *sqlView) Vulnerability(ctx context.Context, id string) (*VulnView, error) {
	recs, err := v.query(ctx, ` AND EXISTS (SELECT 1 FROM record_vulnerability rv
 WHERE rv.source=v.source AND rv.external_id=v.external_id AND rv.vulnerability_id=?3)`, id)
	if err != nil || len(recs) == 0 {
		return nil, err
	}
	return &VulnView{ID: id, Records: recs}, nil
}
