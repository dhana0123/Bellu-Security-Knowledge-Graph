// Package graphtest is the Neo4j test-container harness (build tag
// "integration"). It starts one neo4j:2026.10.2-community container per test
// package (2 GB memory limit, 512 MB heap, 512 MB page cache), resets the
// database between tests, and offers a dialer that blocks every outbound
// connection except the container's.
//
// Without the tag this package is empty, so `go test ./...` and the CI unit
// job never need Docker. Typical use in an integration test package:
//
//	//go:build integration
//
//	func TestMain(m *testing.M) { graphtest.Main(m) }
//
//	func TestX(t *testing.T) {
//	    c := graphtest.New(t) // skips when Docker is unavailable; DB is empty
//	}
package graphtest
