package canonical

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/trust"
)

const (
	LayerRaw       = "raw"
	LayerResolved  = "resolved"
	LayerInferred  = "inferred"
	LayerValidated = "validated"
)

var (
	ErrLayerRejectsPredictions = errors.New("canonical: layer rejects predicted facts")
	ErrInvalidLayer            = errors.New("canonical: invalid layer")
	ErrPromotionRejected       = errors.New("canonical: promotion requires new direct evidence")
	ErrMissingFactField        = errors.New("canonical: fact id, kind and subject are required")
)

func validLayer(l string) bool {
	switch l {
	case LayerRaw, LayerResolved, LayerInferred, LayerValidated:
		return true
	}
	return false
}

// FactInput is one write to fact_version. If Evidence is nil it is derived from
// the provenance: a direct fact carries itself as direct evidence, an inferred
// fact has none.
type FactInput struct {
	FactID    string
	Layer     string
	Kind      string
	Subject   string
	Payload   string
	Prov      trust.Provenance
	EventTime *time.Time
	Evidence  []trust.Evidence
}

// Fact is a stored fact_version row.
type Fact struct {
	FactID      string
	Version     int
	Layer       string
	Kind        string
	Subject     string
	Payload     string
	Source      string
	Direction   string
	PublishTime *string
	EventTime   *string
	RecordedAt  string
	Confidence  *float64
	RuleID      string
	TrustState  trust.TrustState
	State       string
}

// WriteResult describes what WriteFact did.
type WriteResult struct {
	Version int
	Changed bool
}

func fmtTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func fmtTimePtr(t *time.Time) any {
	if t == nil || t.IsZero() {
		return nil
	}
	return fmtTime(*t)
}

const factCols = `fact_id,version,layer,kind,subject,payload,source,direction,publish_time,event_time,recorded_at,confidence,rule_id,trust_state,state`

type scanner interface{ Scan(...any) error }

func scanFact(r scanner) (Fact, error) {
	var f Fact
	var pub, ev, rule sql.NullString
	var conf sql.NullFloat64
	var ts string
	if err := r.Scan(&f.FactID, &f.Version, &f.Layer, &f.Kind, &f.Subject, &f.Payload, &f.Source, &f.Direction,
		&pub, &ev, &f.RecordedAt, &conf, &rule, &ts, &f.State); err != nil {
		return f, err
	}
	if pub.Valid {
		f.PublishTime = &pub.String
	}
	if ev.Valid {
		f.EventTime = &ev.String
	}
	if conf.Valid {
		f.Confidence = &conf.Float64
	}
	f.RuleID = rule.String
	f.TrustState = trust.TrustState(ts)
	return f, nil
}

func confStr(c *float64) string {
	if c == nil {
		return "unset"
	}
	return fmt.Sprintf("%.2f", *c)
}

func strPtr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func appendHistory(ctx context.Context, tx *sql.Tx, fact, oldV, newV, cause, at string) error {
	var o any
	if oldV != "" {
		o = oldV
	}
	_, err := tx.ExecContext(ctx, `INSERT INTO change_history(fact,old_value,new_value,cause,changed_at) VALUES(?,?,?,?,?)`,
		fact, o, newV, cause, at)
	return err
}

// WriteFact is the single entry point that writes fact_version. Provenance and
// layer checks run before any row is written, so a rejection leaves fact_version
// unchanged. A rejected promotion appends one change_history row and nothing else.
func (s *Store) WriteFact(ctx context.Context, in FactInput) (WriteResult, error) {
	if err := trust.Validate(in.Prov); err != nil {
		return WriteResult{}, err
	}
	if !validLayer(in.Layer) {
		return WriteResult{}, fmt.Errorf("%w: %q", ErrInvalidLayer, in.Layer)
	}
	if in.FactID == "" || in.Kind == "" || in.Subject == "" {
		return WriteResult{}, ErrMissingFactField
	}

	ev := in.Evidence
	if ev == nil && in.Prov.Direction == trust.Direct {
		ev = []trust.Evidence{{Source: in.Prov.Source, Direct: true, IngestedAt: in.Prov.IngestTime}}
	}
	state := trust.Classify(ev)
	var conf *float64
	rule := ""
	if state == trust.Predicted {
		conf, rule = in.Prov.Confidence, in.Prov.RuleID
		if rule == "" {
			conf, rule = nil, trust.RuleInferredNoRule
		}
		if in.Layer == LayerRaw || in.Layer == LayerValidated {
			return WriteResult{}, fmt.Errorf("%w: %s", ErrLayerRejectsPredictions, in.Layer)
		}
	} else {
		conf, rule, _ = trust.Confidence(ev)
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return WriteResult{}, err
	}
	defer tx.Rollback()
	now := s.now()

	prev, err := latestFact(ctx, tx, in.FactID)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return WriteResult{}, err
	}
	havePrev := err == nil

	if havePrev && prev.TrustState == trust.Predicted && state != trust.Predicted {
		predictedAt, err := predictedSince(ctx, tx, in.FactID, prev.Version)
		if err != nil {
			return WriteResult{}, err
		}
		if !trust.CanPromote(trust.Fact{State: trust.Predicted, PredictedAt: predictedAt}, ev) {
			cause := "promotion-rejected: no new direct evidence"
			if err := appendHistory(ctx, tx, in.FactID, string(prev.TrustState), string(state), cause, now); err != nil {
				return WriteResult{}, err
			}
			if err := tx.Commit(); err != nil {
				return WriteResult{}, err
			}
			return WriteResult{Version: prev.Version}, ErrPromotionRejected
		}
	}

	pub, evt := fmtTimePtr(in.Prov.PublishTime), fmtTimePtr(in.EventTime)
	if havePrev && sameFact(prev, in, state, conf, rule, pub, evt) {
		return WriteResult{Version: prev.Version}, nil
	}

	version := 1
	if havePrev {
		version = prev.Version + 1
	}
	var confArg any
	if conf != nil {
		confArg = *conf
	}
	var ruleArg any
	if rule != "" {
		ruleArg = rule
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO fact_version(`+factCols+`) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,'active')`,
		in.FactID, version, in.Layer, in.Kind, in.Subject, in.Payload, in.Prov.Source, string(in.Prov.Direction),
		pub, evt, now, confArg, ruleArg, string(state)); err != nil {
		return WriteResult{}, err
	}

	if havePrev {
		if prev.TrustState != state {
			if err := appendHistory(ctx, tx, in.FactID, string(prev.TrustState), string(state), "trust-change", now); err != nil {
				return WriteResult{}, err
			}
		}
		if prev.Source != in.Prov.Source || prev.Direction != string(in.Prov.Direction) {
			if err := appendHistory(ctx, tx, in.FactID, prev.Source+"/"+prev.Direction,
				in.Prov.Source+"/"+string(in.Prov.Direction), "provenance-change", now); err != nil {
				return WriteResult{}, err
			}
		}
	}
	if state == trust.Predicted && rule == trust.RuleInferredNoRule {
		if err := appendHistory(ctx, tx, in.FactID, "", string(trust.Predicted),
			trust.RuleInferredNoRule+": no rule applies, confidence unset", now); err != nil {
			return WriteResult{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return WriteResult{}, err
	}
	return WriteResult{Version: version, Changed: true}, nil
}

func sameFact(p Fact, in FactInput, state trust.TrustState, conf *float64, rule string, pub, evt any) bool {
	opt := func(v any) string {
		if v == nil {
			return ""
		}
		return v.(string)
	}
	if p.Layer != in.Layer || p.Kind != in.Kind || p.Subject != in.Subject || p.Payload != in.Payload ||
		p.Source != in.Prov.Source || p.Direction != string(in.Prov.Direction) || p.TrustState != state ||
		p.RuleID != rule || confStr(p.Confidence) != confStr(conf) || p.State != "active" ||
		strPtr(p.PublishTime) != opt(pub) || strPtr(p.EventTime) != opt(evt) {
		return false
	}
	return true
}

func latestFact(ctx context.Context, tx *sql.Tx, id string) (Fact, error) {
	return scanFact(tx.QueryRowContext(ctx, `SELECT `+factCols+` FROM fact_version WHERE fact_id=? ORDER BY version DESC LIMIT 1`, id))
}

// predictedSince returns the recorded_at of the first version in the trailing run
// of predicted versions ending at version `last`.
func predictedSince(ctx context.Context, tx *sql.Tx, id string, last int) (time.Time, error) {
	rows, err := tx.QueryContext(ctx, `SELECT trust_state, recorded_at FROM fact_version WHERE fact_id=? AND version<=? ORDER BY version DESC`, id, last)
	if err != nil {
		return time.Time{}, err
	}
	defer rows.Close()
	var at string
	for rows.Next() {
		var st, rec string
		if err := rows.Scan(&st, &rec); err != nil {
			return time.Time{}, err
		}
		if st != string(trust.Predicted) {
			break
		}
		at = rec
	}
	if err := rows.Err(); err != nil {
		return time.Time{}, err
	}
	return time.Parse("2006-01-02T15:04:05.000Z", at)
}

// FactsInLayers returns the latest version of every fact whose layer is in layers,
// ordered by fact id. An empty layer set returns no facts.
func (s *Store) FactsInLayers(ctx context.Context, layers ...string) ([]Fact, error) {
	if len(layers) == 0 {
		return nil, nil
	}
	args := make([]any, len(layers))
	for i, l := range layers {
		if !validLayer(l) {
			return nil, fmt.Errorf("%w: %q", ErrInvalidLayer, l)
		}
		args[i] = l
	}
	q := `SELECT ` + factCols + ` FROM fact_version v WHERE v.version=(SELECT MAX(version) FROM fact_version WHERE fact_id=v.fact_id)
AND v.layer IN (?` + strings.Repeat(",?", len(layers)-1) + `) ORDER BY v.fact_id`
	rows, err := s.DB.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Fact
	for rows.Next() {
		f, err := scanFact(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}
