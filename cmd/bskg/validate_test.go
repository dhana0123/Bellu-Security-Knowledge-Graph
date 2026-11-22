package main

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/bellu/bskg/internal/validate"
)

func TestValidateExit(t *testing.T) {
	pass := validate.Report{Status: "passed"}
	fail := validate.Report{Status: "failed"}
	if validateExit(pass, nil) != 0 {
		t.Fatal("passed must exit 0")
	}
	if validateExit(fail, nil) != 1 {
		t.Fatal("failed must exit 1")
	}
	if validateExit(pass, errors.New("x")) != 1 {
		t.Fatal("error must exit non-zero")
	}
}

func TestAttachQueriesFailsReport(t *testing.T) {
	r := validate.Report{Status: "passed", Failed: []string{}}
	validate.AttachQueries(&r, []validate.QueryResult{{Name: "q1", Passed: true}, {Name: "q2"}})
	if r.Passed() || len(r.Failed) != 1 || r.Failed[0] != "query:q2" {
		t.Fatalf("got %+v", r)
	}
}

func TestPrintSummary(t *testing.T) {
	var b bytes.Buffer
	printSummary(&b, validate.Report{Status: "failed", Failed: []string{"reject"}}, "r.json")
	if !strings.Contains(b.String(), "failed: reject") || !strings.Contains(b.String(), "r.json") {
		t.Fatal(b.String())
	}
}

func TestValidateUnknownFlag(t *testing.T) {
	var o, e bytes.Buffer
	if run([]string{"validate", "--profile", "nope"}, &o, &e) != 2 {
		t.Fatal("want exit 2")
	}
}

func TestPrintSummaryModeWarningsAndSmokeCounts(t *testing.T) {
	var b bytes.Buffer
	rep := validate.Report{
		Status: "passed", BuildMode: "sample", Warnings: []string{"AFFECTS count is 0"},
		Smoke: &validate.SmokeResult{Counts: map[string]int64{"Weakness": 3, "AFFECTS": 0}},
	}
	printSummary(&b, rep, "r.json")
	for _, want := range []string{"validation passed", "build mode: sample", "failed checks: 0", "warning: AFFECTS count is 0", "  AFFECTS: 0", "  Weakness: 3"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("missing %q in %q", want, b.String())
		}
	}
}
