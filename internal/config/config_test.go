package config

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"pgregory.net/rapid"
)

func env(m map[string]string, files map[string]string) Env {
	return Env{
		Getenv: func(k string) string { return m[k] },
		ReadFile: func(p string) ([]byte, error) {
			if c, ok := files[p]; ok {
				return []byte(c), nil
			}
			return nil, errors.New("nope")
		},
	}
}

type tb interface {
	Helper()
	Fatalf(string, ...any)
}

func settings(t tb, err error) []string {
	t.Helper()
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("want ValidationError, got %v", err)
	}
	return ve.Settings()
}

func TestDefaultsCore(t *testing.T) {
	c, err := LoadFrom(env(map[string]string{EnvNeo4jPassword: "pw"}, nil), ScopeCore)
	if err != nil {
		t.Fatal(err)
	}
	if c.Neo4jURI != "bolt://neo4j:7687" || c.Neo4jUser != "neo4j" || c.LogLevel != "info" {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestWorkerDefaults(t *testing.T) {
	c, err := LoadFrom(env(map[string]string{EnvNeo4jPassword: "pw"}, nil), ScopeWorker)
	if err != nil {
		t.Fatal(err)
	}
	if c.BatchSize != 500 || c.SampleLimit != 0 || c.StaleAfterHours != 48 ||
		c.ChangeRetentionDays != 365 || c.NVDSyncTime != "03:00" || c.EPSSChangeThreshold != 0.01 ||
		strings.Join(c.EnabledSources, ",") != "cwe,nvd,exploitdb,attack,atlas,capec,kev,epss,osv,ghsa" ||
		strings.Join(c.OSVEcosystems, ",") != DefaultOSVEcosystems || c.CacheDir != "/var/cache/bskg" {
		t.Fatalf("bad defaults: %+v", c)
	}
}

func TestScopesAreIndependent(t *testing.T) {
	// serve needs the cursor secret; core alone does not.
	m := map[string]string{EnvNeo4jPassword: "pw"}
	if _, err := LoadFrom(env(m, nil), ScopeCore); err != nil {
		t.Fatal(err)
	}
	got := settings(t, func() error { _, e := LoadFrom(env(m, nil), ScopeCore|ScopeServe); return e }())
	if len(got) != 1 || got[0] != EnvCursorSecret {
		t.Fatalf("got %v", got)
	}
	// bad sync setting is ignored when sync is not requested
	m[EnvBatchSize] = "0"
	if _, err := LoadFrom(env(m, nil), ScopeCore); err != nil {
		t.Fatal(err)
	}
}

func TestSampleLimit(t *testing.T) {
	for _, tc := range []struct {
		v    string
		want int
		ok   bool
	}{{"", 0, true}, {" 1000 ", 1000, true}, {"1", 1, true}, {"1000000", 1000000, true},
		{"0", 0, false}, {"1000001", 0, false}, {"-5", 0, false}, {"+5", 0, false}, {"1.5", 0, false}, {"abc", 0, false}} {
		m := map[string]string{EnvNeo4jPassword: "p", EnvSampleLimit: tc.v}
		c, err := LoadFrom(env(m, nil), ScopeWorker)
		if (err == nil) != tc.ok {
			t.Errorf("limit %q: err=%v", tc.v, err)
			continue
		}
		if tc.ok && c.SampleLimit != tc.want {
			t.Errorf("limit %q: got %d", tc.v, c.SampleLimit)
		}
		if !tc.ok && !strings.Contains(err.Error(), EnvSampleLimit) {
			t.Errorf("limit %q: error does not name the setting: %v", tc.v, err)
		}
	}
}
func TestSampleOrder(t *testing.T) {
	for _, tc := range []struct {
		v, want string
		ok      bool
	}{{"", "first", true}, {"first", "first", true}, {"latest", "latest", true}, {" latest ", "latest", true},
		{"newest", "", false}, {"LATEST", "", false}} {
		m := map[string]string{EnvNeo4jPassword: "p", EnvSampleOrder: tc.v}
		c, err := LoadFrom(env(m, nil), ScopeWorker)
		if (err == nil) != tc.ok {
			t.Errorf("order %q: err=%v", tc.v, err)
			continue
		}
		if tc.ok && c.SampleOrder != tc.want {
			t.Errorf("order %q: got %q", tc.v, c.SampleOrder)
		}
		if !tc.ok && !strings.Contains(err.Error(), EnvSampleOrder) {
			t.Errorf("order %q: error does not name the setting: %v", tc.v, err)
		}
	}
}
func TestCollectsAllErrorsWithoutValues(t *testing.T) {
	m := map[string]string{
		EnvBatchSize:           "abc-secretish",
		EnvChangeRetentionDays: "0",
		EnvStaleAfterHours:     "721",
		EnvNVDSyncTime:         "25:99",
		EnvLogLevel:            "loud",
	}
	_, err := LoadFrom(env(m, nil), ScopeWorker)
	got := settings(t, err)
	want := "BSKG_BATCH_SIZE,BSKG_CHANGE_RETENTION_DAYS,BSKG_LOG_LEVEL,BSKG_NVD_SYNC_TIME,BSKG_STALE_AFTER_HOURS,NEO4J_PASSWORD"
	if strings.Join(got, ",") != want {
		t.Fatalf("got %v", got)
	}
	for _, v := range []string{"abc-secretish", "10001", "25:99", "loud"} {
		if strings.Contains(err.Error(), v) {
			t.Fatalf("error leaks value %q: %v", v, err)
		}
	}
}

func TestBatchSizeBoundaries(t *testing.T) {
	for _, tc := range []struct {
		v  string
		ok bool
	}{{"1", true}, {"10000", true}, {"0", false}, {"10001", false}, {"1.5", false}, {"-3", false}} {
		m := map[string]string{EnvNeo4jPassword: "p", EnvBatchSize: tc.v}
		_, err := LoadFrom(env(m, nil), ScopeWorker)
		if (err == nil) != tc.ok {
			t.Errorf("batch %q: err=%v", tc.v, err)
		}
	}
}

func TestSecretFile(t *testing.T) {
	files := map[string]string{"/s/pw": "from-file\n"}
	c, err := LoadFrom(env(map[string]string{EnvNeo4jPassword + "_FILE": "/s/pw"}, files), ScopeCore)
	if err != nil || c.Neo4jPassword.Value() != "from-file" {
		t.Fatalf("%v %v", c, err)
	}
	// unreadable file
	_, err = LoadFrom(env(map[string]string{EnvNeo4jPassword + "_FILE": "/missing"}, files), ScopeCore)
	if got := settings(t, err); got[0] != "NEO4J_PASSWORD_FILE" {
		t.Fatalf("got %v", got)
	}
	if strings.Contains(err.Error(), "/missing") {
		t.Fatal("leaks path")
	}
	// both set
	_, err = LoadFrom(env(map[string]string{EnvNeo4jPassword: "a", EnvNeo4jPassword + "_FILE": "/s/pw"}, files), ScopeCore)
	if err == nil {
		t.Fatal("want error for both")
	}
	// empty file counts as missing
	_, err = LoadFrom(env(map[string]string{EnvNeo4jPassword + "_FILE": "/e"}, map[string]string{"/e": "\n"}), ScopeCore)
	if err == nil {
		t.Fatal("want error for empty file")
	}
}

func TestSecretRedaction(t *testing.T) {
	c, _ := LoadFrom(env(map[string]string{EnvNeo4jPassword: "hunter2"}, nil), ScopeCore)
	for _, s := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), fmt.Sprint(c.Neo4jPassword)} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("leaked: %s", s)
		}
	}
}

func TestTLSPairAndSources(t *testing.T) {
	m := map[string]string{EnvNeo4jPassword: "p", EnvCursorSecret: "c", EnvAPITLSCertFile: "/c"}
	_, err := LoadFrom(env(m, nil), ScopeCore|ScopeServe)
	if got := settings(t, err); got[0] != EnvAPITLSCertFile {
		t.Fatalf("got %v", got)
	}
	m = map[string]string{EnvNeo4jPassword: "p", EnvEnabledSources: "nvd, Bad!"}
	_, err = LoadFrom(env(m, nil), ScopeWorker)
	if got := settings(t, err); got[0] != EnvEnabledSources {
		t.Fatalf("got %v", got)
	}
}

// Feature: bellu-security-knowledge-graph, Property 41: Configuration validation
// **Validates: Requirements 4.2, 7.12, 20.4, 20.5**
func TestPropertyBatchSizeValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		n := rapid.IntRange(-5, 20000).Draw(t, "n")
		m := map[string]string{EnvNeo4jPassword: "p", EnvBatchSize: fmt.Sprint(n)}
		c, err := LoadFrom(env(m, nil), ScopeWorker)
		valid := n >= 1 && n <= 10000
		if valid != (err == nil) {
			t.Fatalf("n=%d valid=%v err=%v", n, valid, err)
		}
		if valid && c.BatchSize != n {
			t.Fatalf("batch %d != %d", c.BatchSize, n)
		}
		if !valid {
			s := settings(t, err)
			if len(s) != 1 || s[0] != EnvBatchSize {
				t.Fatalf("got %v", s)
			}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 42: Secrets never appear in output
// **Validates: Requirements 20.2, 20.3**
func TestPropertySecretNotInErrors(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sec := rapid.StringMatching(`[A-Za-z0-9]{12,24}`).Draw(t, "secret")
		m := map[string]string{EnvNeo4jPassword: sec, EnvNVDAPIKey: sec, EnvBatchSize: "bad"}
		c, err := LoadFrom(env(m, nil), ScopeWorker)
		if err == nil {
			t.Fatal("want error")
		}
		if strings.Contains(err.Error(), sec) {
			t.Fatal("error leaks secret")
		}
		_ = c
	})
}

// Feature: bellu-security-knowledge-graph, Property 41: Configuration validation
// **Validates: Requirements 4.2, 7.12, 20.2, 20.4, 20.5**
func TestPropertyMultiSettingValidation(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		m := map[string]string{}
		var want []string
		if rapid.Bool().Draw(t, "hasPw") {
			m[EnvNeo4jPassword] = "p"
		} else {
			want = append(want, EnvNeo4jPassword)
		}
		sl := rapid.IntRange(-2, 1000010).Draw(t, "sampleLimit")
		m[EnvSampleLimit] = fmt.Sprint(sl)
		if sl < 1 || sl > 1000000 {
			want = append(want, EnvSampleLimit)
		}
		rd := rapid.IntRange(-2, 4000).Draw(t, "retention")
		m[EnvChangeRetentionDays] = fmt.Sprint(rd)
		if rd < 1 || rd > 3650 {
			want = append(want, EnvChangeRetentionDays)
		}
		sh := rapid.IntRange(-2, 1000).Draw(t, "stale")
		m[EnvStaleAfterHours] = fmt.Sprint(sh)
		if sh < 1 || sh > 720 {
			want = append(want, EnvStaleAfterHours)
		}
		hh := rapid.IntRange(0, 30).Draw(t, "hh")
		mm := rapid.IntRange(0, 70).Draw(t, "mm")
		m[EnvNVDSyncTime] = fmt.Sprintf("%02d:%02d", hh, mm)
		if hh > 23 || mm > 59 {
			want = append(want, EnvNVDSyncTime)
		}
		_, err := LoadFrom(env(m, nil), ScopeWorker)
		if len(want) == 0 {
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			return
		}
		got := settings(t, err)
		sort.Strings(want)
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Fatalf("got %v want %v", got, want)
		}
		for _, v := range m {
			if len(v) > 4 && strings.Contains(err.Error(), v) {
				t.Fatalf("error leaks value %q", v)
			}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 42: Secrets never appear in output
// **Validates: Requirements 20.2, 20.3**
func TestPropertySecretNotInFormattedConfig(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sec := rapid.StringMatching(`[A-Za-z0-9]{12,24}`).Draw(t, "secret")
		var m map[string]string
		files := map[string]string{"/s/pw": sec + "\n"}
		if rapid.Bool().Draw(t, "viaFile") {
			m = map[string]string{EnvNeo4jPassword + "_FILE": "/s/pw", EnvNVDAPIKey: sec}
		} else {
			m = map[string]string{EnvNeo4jPassword: sec, EnvNVDAPIKey: sec}
		}
		c, err := LoadFrom(env(m, files), ScopeWorker)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c)} {
			if strings.Contains(s, sec) {
				t.Fatalf("config formatting leaks secret: %s", s)
			}
		}
		m[EnvBatchSize] = "bad"
		_, err = LoadFrom(env(m, files), ScopeWorker)
		if err == nil || strings.Contains(err.Error(), sec) {
			t.Fatalf("bad error: %v", err)
		}
	})
}

func TestStatsSettings(t *testing.T) {
	base := map[string]string{EnvNeo4jPassword: "p", EnvCursorSecret: "c"}
	c, err := LoadFrom(env(base, nil), ScopeCore|ScopeServe)
	if err != nil || c.StatsTTL != 5*time.Minute || c.StatsTimeout != 30*time.Second {
		t.Fatalf("defaults: %v %v", c, err)
	}
	cases := []struct {
		name, ttl, timeout string
		ok                 bool
	}{
		{"edges ok", "1m", "1s", true},
		{"upper edges ok", "60m", "120s", true},
		{"ttl low", "59s", "", false},
		{"ttl high", "61m", "", false},
		{"timeout low", "", "999ms", false},
		{"timeout high", "", "121s", false},
		{"not a duration", "five", "", false},
	}
	for _, tc := range cases {
		m := map[string]string{EnvNeo4jPassword: "p", EnvCursorSecret: "c", EnvStatsTTL: tc.ttl, EnvStatsTimeout: tc.timeout}
		_, err := LoadFrom(env(m, nil), ScopeCore|ScopeServe)
		if (err == nil) != tc.ok {
			t.Errorf("%s: err=%v", tc.name, err)
		}
	}
}

func TestOSVEcosystemsAndCacheDir(t *testing.T) {
	base := map[string]string{EnvNeo4jPassword: "p"}
	with := func(extra map[string]string) (*Config, error) {
		m := map[string]string{}
		for k, v := range base {
			m[k] = v
		}
		for k, v := range extra {
			m[k] = v
		}
		return LoadFrom(Env{Getenv: func(k string) string { return m[k] }}, ScopeWorker)
	}
	c, err := with(map[string]string{EnvOSVEcosystems: " pypi, npm ,GO,npm", EnvCacheDir: "/data/cache"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(c.OSVEcosystems, ",") != "PyPI,npm,Go" || c.CacheDir != "/data/cache" {
		t.Fatalf("got %v %q", c.OSVEcosystems, c.CacheDir)
	}
	_, err = with(map[string]string{EnvOSVEcosystems: "npm,Debian", EnvCacheDir: "relative/dir"})
	got := settings(t, err)
	if len(got) != 2 || got[0] != EnvCacheDir || got[1] != EnvOSVEcosystems {
		t.Fatalf("settings %v", got)
	}
	if strings.Contains(err.Error(), "Debian") || strings.Contains(err.Error(), "relative") {
		t.Fatalf("error leaks a value: %v", err)
	}
	if _, err := with(map[string]string{EnvOSVEcosystems: " , "}); err == nil {
		t.Fatal("an empty list must fail")
	}
}
