// Package config parses and validates BSKG settings from environment variables.
//
// Every setting is validated in one pass and all problems are reported together.
// Error text names settings and never contains their values.
package config

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Scope selects which groups of settings a subcommand needs validated.
type Scope uint

const (
	// ScopeCore covers settings every command shares: Neo4j access and logging.
	ScopeCore Scope = 1 << iota
	// ScopeServe covers the REST API.
	ScopeServe
	// ScopeSync covers the pipeline, sources, schedule and retention.
	ScopeSync
	// ScopeWorker is everything the worker runs.
	ScopeWorker = ScopeCore | ScopeSync
)

// Variable names.
const (
	EnvNeo4jPassword       = "NEO4J_PASSWORD"
	EnvNeo4jURI            = "BSKG_NEO4J_URI"
	EnvNeo4jUser           = "BSKG_NEO4J_USER"
	EnvLogLevel            = "BSKG_LOG_LEVEL"
	EnvAPIAddr             = "BSKG_API_ADDR"
	EnvAPITLSCertFile      = "BSKG_API_TLS_CERT_FILE"
	EnvAPITLSKeyFile       = "BSKG_API_TLS_KEY_FILE"
	EnvAPIRateLimit        = "BSKG_API_RATE_LIMIT"
	EnvQueryTimeout        = "BSKG_QUERY_TIMEOUT"
	EnvCursorSecret        = "BSKG_CURSOR_SECRET"
	EnvStatsTTL            = "BSKG_STATS_TTL"
	EnvStatsTimeout        = "BSKG_STATS_TIMEOUT"
	EnvEnableCoExploit     = "BSKG_ENABLE_COEXPLOITATION"
	EnvBatchSize           = "BSKG_BATCH_SIZE"
	EnvNVDAPIKey           = "NVD_API_KEY"
	EnvEnabledSources      = "BSKG_ENABLED_SOURCES"
	EnvNVDSyncTime         = "BSKG_NVD_SYNC_TIME"
	EnvStaleAfterHours     = "BSKG_STALE_AFTER_HOURS"
	EnvChangeRetentionDays = "BSKG_CHANGE_RETENTION_DAYS"
	EnvSampleLimit         = "BSKG_SAMPLE_LIMIT"
	EnvSampleOrder         = "BSKG_SAMPLE_ORDER"
	EnvGitHubToken         = "GITHUB_TOKEN"
	EnvEPSSThreshold       = "BSKG_EPSS_CHANGE_THRESHOLD"
)

// Config holds validated settings. Fields outside the requested scopes are
// left at their zero value, except defaults that are always filled in.
type Config struct {
	Neo4jURI      string
	Neo4jUser     string
	Neo4jPassword Secret
	LogLevel      string

	APIAddr      string
	TLSCertFile  string
	TLSKeyFile   string
	APIRateLimit int
	QueryTimeout time.Duration
	CursorSecret Secret
	// StatsTTL is how long /v1/stats results are cached (1m to 60m).
	StatsTTL time.Duration
	// StatsTimeout bounds one statistics computation (1s to 120s).
	StatsTimeout   time.Duration
	CoExploitation bool

	BatchSize           int
	NVDAPIKey           Secret
	EnabledSources      []string
	NVDSyncTime         string // HH:MM UTC
	StaleAfterHours     int
	ChangeRetentionDays int
	// SampleLimit is the Sample_Build record limit; 0 means a full build.
	SampleLimit int
	// SampleOrder selects the NVD sample: "first" (oldest records) or "latest".
	SampleOrder         string
	GitHubToken         Secret
	EPSSChangeThreshold float64
}

// Secret holds a secret value and hides it from formatting.
type Secret struct{ v string }

// Value returns the secret text.
func (s Secret) Value() string { return s.v }

// IsSet reports whether the secret is non-empty.
func (s Secret) IsSet() bool { return s.v != "" }

// String implements fmt.Stringer and never reveals the value.
func (s Secret) String() string { return "[redacted]" }

// GoString implements fmt.GoStringer and never reveals the value.
func (s Secret) GoString() string { return "[redacted]" }

// Issue is one invalid setting. Setting names the variable; Problem never holds a value.
type Issue struct {
	Setting string
	Problem string
}

// ValidationError lists every invalid setting.
type ValidationError struct{ Issues []Issue }

func (e *ValidationError) Error() string {
	parts := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		parts[i] = is.Setting + ": " + is.Problem
	}
	return "invalid configuration: " + strings.Join(parts, "; ")
}

// Settings returns the names of the invalid settings, sorted.
func (e *ValidationError) Settings() []string {
	out := make([]string, len(e.Issues))
	for i, is := range e.Issues {
		out[i] = is.Setting
	}
	sort.Strings(out)
	return out
}

// Env abstracts the environment lookup and file reads for tests.
type Env struct {
	Getenv   func(string) string
	ReadFile func(string) ([]byte, error)
}

// OSEnv reads the real process environment and file system.
func OSEnv() Env { return Env{Getenv: os.Getenv, ReadFile: os.ReadFile} }

// Load reads the process environment and validates the given scopes.
func Load(scopes ...Scope) (*Config, error) { return LoadFrom(OSEnv(), scopes...) }

// LoadFrom validates the given scopes against env. It returns a *ValidationError
// that names every invalid setting, or a Config. No scope means ScopeCore.
func LoadFrom(env Env, scopes ...Scope) (*Config, error) {
	var sc Scope
	for _, s := range scopes {
		sc |= s
	}
	if sc == 0 {
		sc = ScopeCore
	}
	p := &parser{env: env}
	c := &Config{}

	// Always-defaulted values that other scopes may rely on.
	c.LogLevel = p.enum(EnvLogLevel, "info", "debug", "info", "warn", "error")
	c.Neo4jURI = p.str(EnvNeo4jURI, "bolt://neo4j:7687")
	c.Neo4jUser = p.str(EnvNeo4jUser, "neo4j")
	if sc&ScopeCore != 0 {
		c.Neo4jPassword = p.secret(EnvNeo4jPassword, true)
		p.uriScheme(EnvNeo4jURI, c.Neo4jURI, "bolt", "bolt+s", "bolt+ssc", "neo4j", "neo4j+s", "neo4j+ssc")
	}

	if sc&ScopeServe != 0 {
		c.APIAddr = p.str(EnvAPIAddr, ":8080")
		c.TLSCertFile = p.str(EnvAPITLSCertFile, "")
		c.TLSKeyFile = p.str(EnvAPITLSKeyFile, "")
		if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
			p.add(EnvAPITLSCertFile, "must be set together with "+EnvAPITLSKeyFile)
		}
		c.APIRateLimit = p.intRange(EnvAPIRateLimit, 120, 1, 1_000_000)
		c.QueryTimeout = p.duration(EnvQueryTimeout, 10*time.Second)
		c.CursorSecret = p.secret(EnvCursorSecret, true)
		c.StatsTTL = p.durationRange(EnvStatsTTL, 5*time.Minute, time.Minute, time.Hour)
		c.StatsTimeout = p.durationRange(EnvStatsTimeout, 30*time.Second, time.Second, 120*time.Second)
		c.CoExploitation = p.boolean(EnvEnableCoExploit, false)
	}

	if sc&ScopeSync != 0 {
		c.BatchSize = p.intRange(EnvBatchSize, 500, 1, 10000)
		c.NVDAPIKey = p.secret(EnvNVDAPIKey, false)
		c.GitHubToken = p.secret(EnvGitHubToken, false)
		c.EnabledSources = p.list(EnvEnabledSources, "cwe,nvd,exploitdb")
		for _, s := range c.EnabledSources {
			if !validSourceName(s) {
				p.add(EnvEnabledSources, "contains an invalid source name")
				break
			}
		}
		c.NVDSyncTime = p.str(EnvNVDSyncTime, "03:00")
		if _, err := time.Parse("15:04", c.NVDSyncTime); err != nil || len(c.NVDSyncTime) != 5 {
			p.add(EnvNVDSyncTime, "must be HH:MM in UTC")
		}
		c.StaleAfterHours = p.intRange(EnvStaleAfterHours, 48, 1, 720)
		c.ChangeRetentionDays = p.intRange(EnvChangeRetentionDays, 365, 1, 3650)
		c.SampleLimit = p.sampleLimit()
		c.SampleOrder = p.sampleOrder()
		c.EPSSChangeThreshold = p.floatRange(EnvEPSSThreshold, 0.01, 0, 1)
	}

	if len(p.issues) > 0 {
		return nil, &ValidationError{Issues: p.issues}
	}
	return c, nil
}

func validSourceName(s string) bool {
	if len(s) == 0 || len(s) > 16 || s[0] < 'a' || s[0] > 'z' {
		return false
	}
	for i := 1; i < len(s); i++ {
		ch := s[i]
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9') {
			return false
		}
	}
	return true
}

type parser struct {
	env    Env
	issues []Issue
}

func (p *parser) add(name, problem string) { p.issues = append(p.issues, Issue{name, problem}) }

func (p *parser) raw(name string) string { return strings.TrimSpace(p.env.Getenv(name)) }

func (p *parser) str(name, def string) string {
	if v := p.raw(name); v != "" {
		return v
	}
	return def
}

func (p *parser) enum(name, def string, allowed ...string) string {
	v := strings.ToLower(p.str(name, def))
	for _, a := range allowed {
		if v == a {
			return v
		}
	}
	p.add(name, "must be one of: "+strings.Join(allowed, ", "))
	return def
}

func (p *parser) uriScheme(name, v string, schemes ...string) {
	i := strings.Index(v, "://")
	if i <= 0 || i+3 >= len(v) {
		p.add(name, "must be a URI such as bolt://host:7687")
		return
	}
	for _, s := range schemes {
		if v[:i] == s {
			return
		}
	}
	p.add(name, "has an unsupported URI scheme")
}

func (p *parser) intRange(name string, def, lo, hi int) int {
	s := p.raw(name)
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		p.add(name, fmt.Sprintf("must be an integer from %d to %d", lo, hi))
		return def
	}
	return n
}

func (p *parser) floatRange(name string, def, lo, hi float64) float64 {
	s := p.raw(name)
	if s == "" {
		return def
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f != f || f < lo || f > hi {
		p.add(name, fmt.Sprintf("must be a number from %g to %g", lo, hi))
		return def
	}
	return f
}

func (p *parser) boolean(name string, def bool) bool {
	s := p.raw(name)
	if s == "" {
		return def
	}
	b, err := strconv.ParseBool(s)
	if err != nil {
		p.add(name, "must be true or false")
		return def
	}
	return b
}

func (p *parser) duration(name string, def time.Duration) time.Duration {
	s := p.raw(name)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		p.add(name, "must be a positive duration such as 10s")
		return def
	}
	return d
}

func (p *parser) durationRange(name string, def, lo, hi time.Duration) time.Duration {
	s := p.raw(name)
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil || d < lo || d > hi {
		p.add(name, fmt.Sprintf("must be a duration from %s to %s", lo, hi))
		return def
	}
	return d
}
func (p *parser) list(name, def string) []string {
	var out []string
	for _, part := range strings.Split(p.str(name, def), ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

// secret reads NAME or NAME_FILE. A file value has one trailing newline removed.
func (p *parser) secret(name string, required bool) Secret {
	direct := p.env.Getenv(name)
	file := p.raw(name + "_FILE")
	if direct != "" && file != "" {
		p.add(name, "set both directly and through "+name+"_FILE")
		return Secret{}
	}
	val := direct
	if file != "" {
		b, err := p.env.ReadFile(file)
		if err != nil {
			p.add(name+"_FILE", "file cannot be read")
			return Secret{}
		}
		val = strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	}
	if val == "" {
		if required {
			p.add(name, "required but missing or empty")
		}
		return Secret{}
	}
	return Secret{v: val}
}

// sampleLimit parses BSKG_SAMPLE_LIMIT: unset or empty means 0 (full build);
// otherwise an unsigned base-10 integer from 1 to 1,000,000.
func (p *parser) sampleLimit() int {
	v := p.raw(EnvSampleLimit)
	if v == "" {
		return 0
	}
	n := 0
	for _, ch := range v {
		if ch < '0' || ch > '9' || n > 1000000 {
			p.add(EnvSampleLimit, "must be an integer from 1 to 1000000")
			return 0
		}
		n = n*10 + int(ch-'0')
	}
	if n < 1 || n > 1000000 {
		p.add(EnvSampleLimit, "must be an integer from 1 to 1000000")
		return 0
	}
	return n
}

// Sample orders for BSKG_SAMPLE_ORDER.
const (
	SampleOrderFirst  = "first"
	SampleOrderLatest = "latest"
)

// sampleOrder parses BSKG_SAMPLE_ORDER: "first" (default) or "latest".
func (p *parser) sampleOrder() string {
	v := p.raw(EnvSampleOrder)
	switch v {
	case "", SampleOrderFirst:
		return SampleOrderFirst
	case SampleOrderLatest:
		return SampleOrderLatest
	}
	p.add(EnvSampleOrder, "must be first or latest")
	return SampleOrderFirst
}
