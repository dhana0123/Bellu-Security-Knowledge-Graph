package canonical

import (
	"context"
	"database/sql"
	"encoding/json"
	"sort"
	"time"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// SourceRecordCause is the change_history.cause value that identifies the source record
// whose upsert produced a change (R4.8, R7.10).
func SourceRecordCause(source, id string) string { return "source_record:" + source + ":" + id }

func jsonStr(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// recordFacts flattens a record into comparable fact values keyed by fact kind.
func recordFacts(r *model.Record) map[string]string {
	f := map[string]string{}
	if r.Summary != "" {
		f["summary"] = r.Summary
	}
	type sev struct {
		Version string   `json:"version,omitempty"`
		Vector  string   `json:"vector,omitempty"`
		Score   *float64 `json:"score,omitempty"`
	}
	sevs := map[string][]sev{}
	for _, s := range r.Severities {
		k := "severity:" + s.Source + ":" + s.Type
		sevs[k] = append(sevs[k], sev{s.Version, s.Vector, s.Score})
	}
	for k, v := range sevs {
		sort.Slice(v, func(i, j int) bool { return jsonStr(v[i]) < jsonStr(v[j]) })
		f[k] = jsonStr(v)
	}
	aff := map[string][]model.Affected{}
	for _, a := range r.Affected {
		k := "affected:" + a.Name
		if a.Ecosystem != "" {
			k = "affected:" + a.Ecosystem + "/" + a.Name
		}
		aff[k] = append(aff[k], a)
	}
	for k, v := range aff {
		sort.Slice(v, func(i, j int) bool { return jsonStr(v[i]) < jsonStr(v[j]) })
		f[k] = jsonStr(v)
	}
	if len(r.Weaknesses) > 0 {
		w := append([]string(nil), r.Weaknesses...)
		sort.Strings(w)
		f["weakness"] = jsonStr(w)
	}
	if !r.Withdrawn.IsZero() {
		f["withdrawn"] = r.Withdrawn.UTC().Format(time.RFC3339)
	}
	if len(r.References) > 0 {
		refs := make([]string, 0, len(r.References))
		for _, x := range r.References {
			refs = append(refs, x.Type+"|"+x.URL)
		}
		sort.Strings(refs)
		f["reference"] = jsonStr(refs)
	}
	return f
}

// diffFacts returns the sorted fact keys whose values differ between old and new.
func diffFacts(oldF, newF map[string]string) []string {
	var keys []string
	for k, nv := range newF {
		if ov, ok := oldF[k]; !ok || ov != nv {
			keys = append(keys, k)
		}
	}
	for k := range oldF {
		if _, ok := newF[k]; !ok {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

// appendVersionAndHistory writes the source_record_version row and, when oldJSON is
// non-empty, one change_history row per changed fact. It runs in the caller's transaction.
func (s *Store) appendVersionAndHistory(ctx context.Context, tx *sql.Tx, rec *model.Record, hash, body, oldJSON string) error {
	var ver int
	if err := tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(version),0)+1 FROM source_record_version WHERE source=? AND external_id=?`,
		rec.Source, rec.ID).Scan(&ver); err != nil {
		return err
	}
	state := "active"
	if !rec.Withdrawn.IsZero() {
		state = "withdrawn"
	}
	evt := rec.Modified
	if evt.IsZero() {
		evt = rec.Withdrawn
	}
	at := s.now()
	if _, err := tx.ExecContext(ctx, `INSERT INTO source_record_version(source,external_id,version,content_hash,json,event_time,recorded_at,state) VALUES(?,?,?,?,?,?,?,?)`,
		rec.Source, rec.ID, ver, hash, body, ts(evt), at, state); err != nil {
		return err
	}
	if oldJSON == "" {
		return nil
	}
	var old model.Record
	if err := json.Unmarshal([]byte(oldJSON), &old); err != nil {
		return err
	}
	oldF, newF := recordFacts(&old), recordFacts(rec)
	cause := SourceRecordCause(rec.Source, rec.ID)
	for _, k := range diffFacts(oldF, newF) {
		var ov, nv any
		if v, ok := oldF[k]; ok {
			ov = v
		}
		if v, ok := newF[k]; ok {
			nv = v
		}
		if _, err := tx.ExecContext(ctx, `INSERT INTO change_history(fact,old_value,new_value,cause,changed_at) VALUES(?,?,?,?,?)`,
			rec.Source+":"+rec.ID+"#"+k, ov, nv, cause, at); err != nil {
			return err
		}
	}
	return nil
}
