package graph

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

func TestClassify(t *testing.T) {
	mk := func(code string) error { return &neo4j.Neo4jError{Code: code, Msg: "m"} }
	cases := []struct {
		err  error
		want Class
	}{
		{nil, ClassNone},
		{mk("Neo.TransientError.Transaction.DeadlockDetected"), ClassTransient},
		{mk("Neo.ClientError.Schema.ConstraintValidationFailed"), ClassClient},
		{mk("Neo.ClientError.Statement.SyntaxError"), ClassClient},
		{mk("Neo.ClientError.Security.Unauthorized"), ClassFatal},
		{mk("Neo.DatabaseError.General.UnknownError"), ClassFatal},
		{context.DeadlineExceeded, ClassFatal},
		{context.Canceled, ClassFatal},
		{errors.New("boom"), ClassFatal},
		{fmt.Errorf("wrap: %w", mk("Neo.TransientError.General.X")), ClassTransient},
	}
	for i, c := range cases {
		if got := Classify(c.err); got != c.want {
			t.Errorf("case %d: got %v want %v", i, got, c.want)
		}
	}
}

func TestWrapKeepsClassAndCode(t *testing.T) {
	err := wrap(&neo4j.Neo4jError{Code: "Neo.ClientError.Statement.SyntaxError", Msg: "bad"})
	var ge *Error
	if !errors.As(err, &ge) || ge.Class != ClassClient || ge.Code == "" {
		t.Fatalf("unexpected: %v", err)
	}
	if Classify(wrap(err)) != ClassClient {
		t.Fatal("double wrap changed class")
	}
	if wrap(nil) != nil {
		t.Fatal("wrap(nil)")
	}
}

func TestDelaySchedule(t *testing.T) {
	want := []time.Duration{1, 2, 4, 8, 16, 30, 30}
	for k, w := range want {
		if got := BatchPolicy.Delay(k); got != w*time.Second {
			t.Errorf("k=%d got %v want %vs", k, got, w)
		}
	}
}

func fakeSleep(log *[]time.Duration) SleepFunc {
	return func(_ context.Context, d time.Duration) error { *log = append(*log, d); return nil }
}

var errTransient = &neo4j.Neo4jError{Code: "Neo.TransientError.General.Busy", Msg: "busy"}

func TestRetryTransientThenSuccess(t *testing.T) {
	var slept []time.Duration
	n := 0
	err := Retry(context.Background(), BatchPolicy, fakeSleep(&slept), func(context.Context) error {
		n++
		if n < 4 {
			return errTransient
		}
		return nil
	})
	if err != nil || n != 4 || len(slept) != 3 || slept[2] != 4*time.Second {
		t.Fatalf("err=%v n=%d slept=%v", err, n, slept)
	}
}

func TestRetryExhaustion(t *testing.T) {
	var slept []time.Duration
	n := 0
	err := Retry(context.Background(), BatchPolicy, fakeSleep(&slept), func(context.Context) error { n++; return errTransient })
	if err == nil || n != 6 || len(slept) != 5 {
		t.Fatalf("err=%v n=%d slept=%v", err, n, slept)
	}
}

func TestRetrySkipsNonTransient(t *testing.T) {
	for _, e := range []error{
		&neo4j.Neo4jError{Code: "Neo.ClientError.Statement.SyntaxError"},
		errors.New("fatal"),
	} {
		n := 0
		err := Retry(context.Background(), BatchPolicy, fakeSleep(new([]time.Duration)), func(context.Context) error { n++; return e })
		if err == nil || n != 1 {
			t.Fatalf("n=%d err=%v", n, err)
		}
	}
}

func TestRetryStopsOnCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	n := 0
	err := Retry(ctx, BatchPolicy, func(context.Context, time.Duration) error { cancel(); return context.Canceled },
		func(context.Context) error { n++; return errTransient })
	if err == nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestErrorMessageOmitsParams(t *testing.T) {
	secret := "s3cr3t-param"
	_ = map[string]any{"p": secret}
	err := wrap(&neo4j.Neo4jError{Code: "Neo.ClientError.Statement.SyntaxError", Msg: "bad query"})
	if strings.Contains(err.Error(), secret) {
		t.Fatal("leak")
	}
}

func TestNewValidation(t *testing.T) {
	if _, err := New(Params{}); err == nil {
		t.Fatal("expected error for empty URI")
	}
	c, err := New(Params{URI: "bolt://localhost:7687", User: "neo4j", Password: "x"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Timeout() != DefaultTimeout {
		t.Fatal("default timeout")
	}
	_ = c.Close(context.Background())
}
