package api

import (
	"context"
	"time"
)

// OpsConfig holds the dependencies of the status, statistics, and
// neighborhood endpoints.
type OpsConfig struct {
	Q            func(ctx context.Context, query string, params map[string]any) ([]Row, error)
	Batch        BatchFunc // one read transaction for the statistics queries
	SourceStatus SourceStatusFunc
	StatsTTL     time.Duration // default 5m
	StatsTimeout time.Duration // default 30s
}

type ops struct {
	s            *Server
	q            queryFunc
	sourceStatus SourceStatusFunc
	cache        *statsCache
}

// OpsRoutes registers GET /v1/status, /v1/stats and /v1/graph/neighborhood.
func OpsRoutes(s *Server, c OpsConfig) {
	if c.StatsTTL <= 0 {
		c.StatsTTL = 5 * time.Minute
	}
	if c.StatsTimeout <= 0 {
		c.StatsTimeout = 30 * time.Second
	}
	o := &ops{s: s, q: c.Q, sourceStatus: c.SourceStatus}
	o.cache = &statsCache{
		ttl: c.StatsTTL, timeout: c.StatsTimeout, now: s.cfg.Now,
		compute: func(ctx context.Context) (*StatsResult, error) {
			var res *StatsResult
			err := c.Batch(ctx, func(q queryFunc) error {
				var err error
				res, err = computeStats(ctx, q, s.cfg.Now())
				return err
			})
			return res, err
		},
	}
	s.Handle("GET /status", o.statusHandler)
	s.Handle("GET /stats", o.stats)
	s.Handle("GET /graph/neighborhood", o.neighborhood)
}

// MigrationPending returns a Pending function for Config: true when the
// highest applied Migration version is below want.
func MigrationPending(q queryFunc, want int) func(ctx context.Context) (bool, error) {
	return func(ctx context.Context) (bool, error) {
		rows, err := q(ctx, cypherMigrationVersion, nil)
		if err != nil {
			return false, err
		}
		if len(rows) == 0 {
			return true, nil
		}
		v, ok := rows[0]["version"].(int64)
		return !ok || int(v) < want, nil
	}
}
