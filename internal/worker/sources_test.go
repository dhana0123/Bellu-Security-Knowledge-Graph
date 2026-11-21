package worker

import (
	"reflect"
	"testing"
)

func TestSourceJobsOrderAndNames(t *testing.T) {
	var names []string
	for _, s := range SourceJobs {
		names = append(names, s.Source)
		if s.Source != "nvd" && s.Job != s.Source {
			t.Errorf("job %q differs from source %q", s.Job, s.Source)
		}
		if s.Source != "cwe" && s.Source != "nvd" && s.Source != "exploitdb" && s.BuildState != "loading_"+s.Source {
			t.Errorf("%s build state %q", s.Source, s.BuildState)
		}
	}
	want := []string{"cwe", "nvd", "exploitdb", "attack", "atlas", "capec", "kev", "epss", "osv", "ghsa"}
	if !reflect.DeepEqual(names, want) {
		t.Fatalf("order %v", names)
	}
	mode := map[string]bool{"nvd": true, "exploitdb": true, "kev": true, "epss": true, "osv": true, "ghsa": true}
	for _, s := range SourceJobs {
		if s.ModeSpecific != mode[s.Source] {
			t.Errorf("%s ModeSpecific = %v", s.Source, s.ModeSpecific)
		}
	}
	if j, _ := JobForSource("nvd"); j.Job != JobNVD || j.BuildState != "nvd_catch_up" {
		t.Errorf("nvd job %+v", j)
	}
	if s, _ := JobForSource("cwe"); s.BuildState != "loading_cwe" {
		t.Errorf("cwe state %q", s.BuildState)
	}
	if !IsCoreSource("exploitdb") || IsCoreSource("attack") {
		t.Error("core sources")
	}
}

func TestOrderedSources(t *testing.T) {
	got := OrderedSources([]string{"ghsa", "zzz", "nvd", "kev", "ghsa", "cwe", "aaa"})
	want := []string{"cwe", "nvd", "kev", "ghsa", "zzz", "aaa"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v", got)
	}
}
