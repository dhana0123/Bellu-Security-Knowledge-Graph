package worker

// SourceJob ties a source (adapter name) to its build-queue job.
type SourceJob struct {
	// Source is the adapter name (source.Adapter.Name).
	Source string
	// Job is the queue job name. It equals Source except for the NVD job
	// ("nvd-catch-up", adapter "nvd").
	Job string
	// BuildState is written to (:BuildMeta).buildState while the job runs.
	BuildState string
	// ModeSpecific jobs are redone when the build mode or sample limit
	// changed since they succeeded (see Done).
	ModeSpecific bool
}

// Build states of the Phase 2 and 3 sources.
const (
	StateLoadingAttack = "loading_attack"
	StateLoadingAtlas  = "loading_atlas"
	StateLoadingCAPEC  = "loading_capec"
	StateLoadingKEV    = "loading_kev"
	StateLoadingEPSS   = "loading_epss"
	StateLoadingOSV    = "loading_osv"
	StateLoadingGHSA   = "loading_ghsa"
)

// SourceJobs lists every source in the order the build queue runs them and
// the daily schedule syncs them. The first three always run; a later source
// runs only when it is enabled and its adapter is registered.
//
// An adapter author adds nothing here: the job name is the adapter name and
// the build state is "loading_<name>".
var SourceJobs = []SourceJob{
	{Source: "cwe", Job: JobCWE, BuildState: StateLoadingCWE},
	{Source: "nvd", Job: JobNVD, BuildState: StateNVDCatchUp, ModeSpecific: true},
	{Source: "exploitdb", Job: JobExploits, BuildState: StateLoadingExploit, ModeSpecific: true},
	{Source: "attack", Job: "attack", BuildState: StateLoadingAttack},
	{Source: "atlas", Job: "atlas", BuildState: StateLoadingAtlas},
	{Source: "capec", Job: "capec", BuildState: StateLoadingCAPEC},
	{Source: "kev", Job: "kev", BuildState: StateLoadingKEV, ModeSpecific: true},
	{Source: "epss", Job: "epss", BuildState: StateLoadingEPSS, ModeSpecific: true},
	{Source: "osv", Job: "osv", BuildState: StateLoadingOSV, ModeSpecific: true},
	{Source: "ghsa", Job: "ghsa", BuildState: StateLoadingGHSA, ModeSpecific: true},
}

// coreSources always have a queue job, enabled or not.
const coreSources = 3

// IsCoreSource reports whether source is one of the first three, which the
// queue always lists.
func IsCoreSource(source string) bool {
	for _, s := range SourceJobs[:coreSources] {
		if s.Source == source {
			return true
		}
	}
	return false
}

// JobForSource returns the queue job definition of a source.
func JobForSource(source string) (SourceJob, bool) {
	for _, s := range SourceJobs {
		if s.Source == source {
			return s, true
		}
	}
	return SourceJob{}, false
}

// OrderedSources returns names in queue order: the known sources in the
// SourceJobs order, then any other name in the order given. Duplicates are
// dropped.
func OrderedSources(names []string) []string {
	want := map[string]bool{}
	for _, n := range names {
		want[n] = true
	}
	var out []string
	for _, s := range SourceJobs {
		if want[s.Source] {
			out = append(out, s.Source)
			delete(want, s.Source)
		}
	}
	for _, n := range names {
		if want[n] {
			out = append(out, n)
			delete(want, n)
		}
	}
	return out
}
