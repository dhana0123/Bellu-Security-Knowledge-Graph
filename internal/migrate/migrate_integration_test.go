//go:build integration

package migrate_test

import (
	"context"
	"strings"
	"testing"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"

	"github.com/bellu/bskg/internal/graph"
	"github.com/bellu/bskg/internal/graph/graphtest"
	"github.com/bellu/bskg/internal/migrate"
)

func TestMain(m *testing.M) { graphtest.Main(m) }

func count(t *testing.T, c *graph.Client, q string) int64 {
	t.Helper()
	v, err := c.Read(context.Background(), func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return nil, err
		}
		return rec.Values[0], nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return v.(int64)
}

func TestMigrateAppliesAndRerunsAsNoop(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	files, err := migrate.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "t1"}
	res, err := r.Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != len(files) {
		t.Fatalf("applied %v, want %d", res.Applied, len(files))
	}
	if n := count(t, c, "MATCH (m:Migration) RETURN count(m)"); n != int64(len(files)) {
		t.Fatalf("Migration nodes = %d", n)
	}
	res, err = r.Run(ctx)
	if err != nil || len(res.Applied) != 0 {
		t.Fatalf("rerun: %v %v", res, err)
	}
}

func TestMigrateFailureNotRecorded(t *testing.T) {
	c := graphtest.New(t)
	files := []migrate.Migration{
		{Version: 1, Name: "ok", Checksum: "a", Statements: []string{"CREATE CONSTRAINT t_ok IF NOT EXISTS FOR (n:T) REQUIRE n.id IS UNIQUE"}},
		{Version: 2, Name: "bad", Checksum: "b", Statements: []string{"THIS IS NOT CYPHER"}},
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "t2"}
	_, err := r.Run(context.Background())
	if err == nil || !strings.Contains(err.Error(), "V002") {
		t.Fatalf("want error naming V002, got %v", err)
	}
	if n := count(t, c, "MATCH (m:Migration {version: 2}) RETURN count(m)"); n != 0 {
		t.Fatal("failed migration was recorded")
	}
	if n := count(t, c, "MATCH (m:Migration {version: 1}) RETURN count(m)"); n != 1 {
		t.Fatal("first migration not recorded")
	}
}

func TestMigrateDetectsEditedFile(t *testing.T) {
	c := graphtest.New(t)
	files := []migrate.Migration{{Version: 1, Name: "a", Checksum: "a", Statements: []string{"RETURN 1"}}}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "t3"}
	if _, err := r.Run(context.Background()); err != nil {
		t.Fatal(err)
	}
	files[0].Checksum = "changed"
	if _, err := r.Run(context.Background()); err == nil {
		t.Fatal("edited migration not detected")
	}
}

func TestMigrateLockHeld(t *testing.T) {
	c := graphtest.New(t)
	s := migrate.GraphStore{C: c}
	ctx := context.Background()
	if err := s.Bootstrap(ctx); err != nil {
		t.Fatal(err)
	}
	if ok, err := s.Acquire(ctx, "a"); err != nil || !ok {
		t.Fatalf("first acquire: %v %v", ok, err)
	}
	if ok, _ := s.Acquire(ctx, "b"); ok {
		t.Fatal("second owner acquired a live lock")
	}
	if err := s.Release(ctx, "a"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := s.Acquire(ctx, "b"); !ok {
		t.Fatal("lock not free after release")
	}
}

func names(t *testing.T, c *graph.Client, q string) map[string]string {
	t.Helper()
	v, err := c.Read(context.Background(), func(ctx context.Context, tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, q, nil)
		if err != nil {
			return nil, err
		}
		out := map[string]string{}
		for res.Next(ctx) {
			r := res.Record()
			n, _ := r.Get("name")
			s, _ := r.Get("extra")
			out[n.(string)] = s.(string)
		}
		return out, res.Err()
	})
	if err != nil {
		t.Fatal(err)
	}
	return v.(map[string]string)
}

func TestSchemaSmoke(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	files, err := migrate.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "smoke"}
	if _, err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}

	cons := names(t, c, "SHOW CONSTRAINTS YIELD name, type AS extra RETURN name, extra")
	for _, n := range []string{"UniqueCveID", "UniqueEID", "UniqueAuthorName", "UniquecweID",
		"UniqueDomainName", "UniqueProductName", "UniqueVendorName"} {
		if cons[n] != "UNIQUENESS" {
			t.Errorf("constraint %s missing or wrong type (%q)", n, cons[n])
		}
	}

	idx := names(t, c, "SHOW INDEXES YIELD name, state AS extra RETURN name, extra")
	for _, n := range []string{"VulnerabilityV2Version", "VulnerabilityV3Version", "VulnerabilityPublishedDate",
		"ExploitPublishDate", "VulnerabilityDescriptionFullTextSchema"} {
		if idx[n] != "ONLINE" {
			t.Errorf("index %s state = %q, want ONLINE", n, idx[n])
		}
	}

	n := count(t, c, "SHOW INDEXES YIELD type, labelsOrTypes, properties "+
		"WHERE type = 'RANGE' AND 'Vulnerability' IN labelsOrTypes AND 'description' IN properties "+
		"RETURN count(*)")
	if n != 0 {
		t.Fatalf("found %d RANGE index(es) on Vulnerability.description", n)
	}
}

func TestSchemaIdempotentRerun(t *testing.T) {
	c := graphtest.New(t)
	ctx := context.Background()
	files, err := migrate.Embedded()
	if err != nil {
		t.Fatal(err)
	}
	r := &migrate.Runner{Store: migrate.GraphStore{C: c}, Files: files, Owner: "idem"}
	if _, err := r.Run(ctx); err != nil {
		t.Fatal(err)
	}
	before := count(t, c, "SHOW CONSTRAINTS YIELD name RETURN count(*)")
	res, err := r.Run(ctx)
	if err != nil || len(res.Applied) != 0 {
		t.Fatalf("rerun: %v %v", res, err)
	}
	if after := count(t, c, "SHOW CONSTRAINTS YIELD name RETURN count(*)"); after != before {
		t.Fatalf("constraints changed on rerun: %d -> %d", before, after)
	}
}
