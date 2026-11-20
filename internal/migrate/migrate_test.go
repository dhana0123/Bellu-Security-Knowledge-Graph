package migrate

import (
	"context"
	"errors"
	"strings"
	"testing"
	"testing/fstest"
)

func TestSplitStatements(t *testing.T) {
	got := SplitStatements("// header\n;\nCREATE A\nFOO\n  ;  \n\n;\nCREATE B\n")
	want := []string{"CREATE A\nFOO", "CREATE B"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("got %q want %q", got, want)
	}
}

func TestLoadOrderAndErrors(t *testing.T) {
	fsys := fstest.MapFS{
		"V010__b.cypher": {Data: []byte("B")},
		"V002__a.cypher": {Data: []byte("A\n;\nA2")},
		"README.md":      {Data: []byte("x")},
	}
	ms, err := Load(fsys)
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 2 || ms[0].Version != 2 || ms[1].Version != 10 || len(ms[0].Statements) != 2 {
		t.Fatalf("bad load: %+v", ms)
	}
	if _, err := Load(fstest.MapFS{"V1__a.cypher": {Data: []byte("A")}, "V001__b.cypher": {Data: []byte("B")}}); err == nil {
		t.Error("duplicate version accepted")
	}
	if _, err := Load(fstest.MapFS{"bad.cypher": {Data: []byte("A")}}); err == nil {
		t.Error("malformed name accepted")
	}
}

func TestEmbedded(t *testing.T) {
	ms, err := Embedded()
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i < len(ms); i++ {
		if ms[i-1].Version >= ms[i].Version {
			t.Fatal("not ascending")
		}
	}
}

func TestPlan(t *testing.T) {
	files := []Migration{{Version: 1, Checksum: "a"}, {Version: 2, Checksum: "b"}, {Version: 3, Checksum: "c"}}
	p, err := Plan(files, []Applied{{1, "a"}})
	if err != nil || len(p) != 2 || p[0].Version != 2 {
		t.Fatalf("pending %v err %v", p, err)
	}
	p, err = Plan(files, []Applied{{1, "a"}, {2, "b"}, {3, "c"}})
	if err != nil || len(p) != 0 {
		t.Fatalf("expected no pending, got %v %v", p, err)
	}
	if _, err := Plan(files, []Applied{{1, "x"}}); err == nil || !strings.Contains(err.Error(), "V001") {
		t.Errorf("checksum mismatch not reported: %v", err)
	}
	if _, err := Plan(files, []Applied{{9, "x"}}); err == nil {
		t.Error("unknown applied version accepted")
	}
}

type fakeStore struct {
	applied  []Applied
	failStmt string
	locked   bool
	exec     []string
	recorded []int
	released bool
}

func (f *fakeStore) Bootstrap(context.Context) error { return nil }
func (f *fakeStore) Acquire(context.Context, string) (bool, error) {
	return !f.locked, nil
}
func (f *fakeStore) Release(context.Context, string) error { f.released = true; return nil }
func (f *fakeStore) Applied(context.Context) ([]Applied, error) {
	return f.applied, nil
}
func (f *fakeStore) Exec(_ context.Context, s string) error {
	if s == f.failStmt {
		return errors.New("boom")
	}
	f.exec = append(f.exec, s)
	return nil
}
func (f *fakeStore) AwaitIndexes(context.Context) error { return nil }
func (f *fakeStore) Record(_ context.Context, m Migration) error {
	f.recorded = append(f.recorded, m.Version)
	f.applied = append(f.applied, Applied{m.Version, m.Checksum})
	return nil
}

func files3() []Migration {
	return []Migration{
		{Version: 1, Name: "a", Checksum: "a", Statements: []string{"s1"}},
		{Version: 2, Name: "b", Checksum: "b", Statements: []string{"s2", "s3"}},
	}
}

func TestRunnerAppliesThenNoop(t *testing.T) {
	st := &fakeStore{}
	r := &Runner{Store: st, Files: files3(), Owner: "o"}
	res, err := r.Run(context.Background())
	if err != nil || len(res.Applied) != 2 || len(st.exec) != 3 || !st.released {
		t.Fatalf("res %v err %v exec %v", res, err, st.exec)
	}
	res, err = r.Run(context.Background())
	if err != nil || len(res.Applied) != 0 || len(st.exec) != 3 {
		t.Fatalf("rerun not a no-op: %v %v", res, err)
	}
}

func TestRunnerFailureNotRecorded(t *testing.T) {
	st := &fakeStore{failStmt: "s3"}
	r := &Runner{Store: st, Files: files3(), Owner: "o"}
	res, err := r.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "V002") {
		t.Fatalf("want error naming V002, got %v", err)
	}
	if len(st.recorded) != 1 || st.recorded[0] != 1 || len(res.Applied) != 1 || !st.released {
		t.Fatalf("recorded %v res %v", st.recorded, res)
	}
}

func TestRunnerLocked(t *testing.T) {
	st := &fakeStore{locked: true}
	_, err := (&Runner{Store: st, Files: files3(), Owner: "o"}).Run(context.Background())
	if !errors.Is(err, ErrLocked) || len(st.exec) != 0 {
		t.Fatalf("err %v", err)
	}
}
