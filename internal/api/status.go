package api

import (
	"context"
	"net/http"
	"sort"
	"time"

	"github.com/bellu/bskg/internal/checkpoint"
	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/worker"
)

// SourceStatusFunc reads per-source status; checkpoint.ReadStatus backs it.
type SourceStatusFunc func(ctx context.Context, sources []string) ([]checkpoint.SourceStatus, error)

// ReadSourceStatus returns the production SourceStatusFunc.
func ReadSourceStatus(g *graph.Client) SourceStatusFunc {
	return func(ctx context.Context, sources []string) ([]checkpoint.SourceStatus, error) {
		return checkpoint.ReadStatus(ctx, g, sources)
	}
}

// Wire shapes of GET /v1/status (also embedded in /v1/stats as "sync").
type checkpointJSON struct {
	Found     bool       `json:"found"`
	Watermark *time.Time `json:"watermark"`
	Resume    string     `json:"resume"`
	Version   string     `json:"version"`
}

type lastRunJSON struct {
	Status    string     `json:"status"`
	StartedAt *time.Time `json:"startedAt"`
	Step      string     `json:"step"`
	Processed int64      `json:"processed"`
	Total     int64      `json:"total"`
	Error     string     `json:"error"`
}

type sourceStatusJSON struct {
	Source      string         `json:"source"`
	NeverRun    bool           `json:"neverRun"`
	Checkpoint  checkpointJSON `json:"checkpoint"`
	LastRun     *lastRunJSON   `json:"lastRun"`
	LastSuccess *time.Time     `json:"lastSuccess"`
	DeadLetters int64          `json:"deadLetters"`
}

type jobJSON struct {
	Name      string     `json:"name"`
	State     string     `json:"state"`
	Attempts  int64      `json:"attempts"`
	Error     string     `json:"error"`
	Mode      string     `json:"mode"`
	Limit     int64      `json:"limit"`
	StartedAt *time.Time `json:"startedAt"`
	EndedAt   *time.Time `json:"endedAt"`
}

type validationJSON struct {
	Status    string     `json:"status"`
	BuildMode string     `json:"buildMode"`
	EndedAt   *time.Time `json:"endedAt"`
}

type queueJSON struct {
	Complete bool      `json:"complete"`
	Jobs     []jobJSON `json:"jobs"`
}

// statusResult is the body of GET /v1/status.
type statusResult struct {
	BuildState  string             `json:"buildState"`
	BuildMode   *string            `json:"buildMode"`
	SampleLimit *int64             `json:"sampleLimit"`
	Sources     []sourceStatusJSON `json:"sources"`
	Queue       queueJSON          `json:"queue"`
	Validation  *validationJSON    `json:"validation"`
}

func tptr(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func toSourceJSON(s checkpoint.SourceStatus) sourceStatusJSON {
	out := sourceStatusJSON{
		Source:   s.Source,
		NeverRun: s.LastStatus == "" && !s.Checkpoint.Found,
		Checkpoint: checkpointJSON{
			Found: s.Checkpoint.Found, Watermark: tptr(s.Checkpoint.Watermark),
			Resume: s.Checkpoint.Resume, Version: s.Checkpoint.Version,
		},
		LastSuccess: tptr(s.LastSuccess),
		DeadLetters: s.DeadLetters,
	}
	if s.LastStatus != "" {
		out.LastRun = &lastRunJSON{
			Status: s.LastStatus, StartedAt: tptr(s.LastStarted), Step: s.Step,
			Processed: s.Processed, Total: s.Total, Error: s.LastError,
		}
	}
	return out
}

var jobOrder = map[string]int{
	worker.JobMigrate: 0, worker.JobCWE: 1, worker.JobNVD: 2, worker.JobExploits: 3,
}

func timeOf(v any) *time.Time {
	if t, ok := asTime(v); ok {
		return &t
	}
	return nil
}

// status reads the live status (never cached).
func (o *ops) status(ctx context.Context) (*statusResult, error) {
	srcs, err := o.sourceStatus(ctx, o.s.cfg.Sources)
	if err != nil {
		return nil, err
	}
	res := &statusResult{BuildState: DefaultBuildState, Sources: make([]sourceStatusJSON, 0, len(srcs)), Queue: queueJSON{Jobs: []jobJSON{}}}
	for _, s := range srcs {
		res.Sources = append(res.Sources, toSourceJSON(s))
	}
	rows, err := o.q(ctx, cypherStatusBuild, nil)
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		r := rows[0]
		if f, _ := r["found"].(bool); f {
			if s, _ := r["buildState"].(string); s != "" {
				res.BuildState = s
			}
			if m, _ := r["buildMode"].(string); m != "" {
				res.BuildMode = &m
			}
			if n, ok := r["sampleLimit"].(int64); ok && n > 0 {
				res.SampleLimit = &n
			}
			res.Queue.Complete, _ = r["queueComplete"].(bool)
			if st, _ := r["validationStatus"].(string); st != "" {
				mode, _ := r["validationMode"].(string)
				res.Validation = &validationJSON{Status: st, BuildMode: mode, EndedAt: timeOf(r["validationEndedAt"])}
			}
		}
	}
	rows, err = o.q(ctx, cypherStatusJobs, nil)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		j := jobJSON{StartedAt: timeOf(r["startedAt"]), EndedAt: timeOf(r["endedAt"])}
		j.Name, _ = r["name"].(string)
		j.State, _ = r["state"].(string)
		j.Error, _ = r["error"].(string)
		j.Mode, _ = r["mode"].(string)
		j.Attempts = asInt(r["attempts"])
		j.Limit = asInt(r["limit"])
		res.Queue.Jobs = append(res.Queue.Jobs, j)
	}
	sort.SliceStable(res.Queue.Jobs, func(i, k int) bool {
		a, aok := jobOrder[res.Queue.Jobs[i].Name]
		b, bok := jobOrder[res.Queue.Jobs[k].Name]
		if aok != bok {
			return aok
		}
		if a != b {
			return a < b
		}
		return res.Queue.Jobs[i].Name < res.Queue.Jobs[k].Name
	})
	return res, nil
}

func (o *ops) statusHandler(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := o.s.QueryContext(r)
	defer cancel()
	res, err := o.status(ctx)
	if err != nil {
		o.s.WriteGraphError(w, r, err)
		return
	}
	o.s.WriteJSON(w, r, http.StatusOK, map[string]any{
		"buildState":  res.BuildState,
		"buildMode":   res.BuildMode,
		"sampleLimit": res.SampleLimit,
		"sources":     res.Sources,
		"queue":       res.Queue,
		"validation":  res.Validation,
	})
}
