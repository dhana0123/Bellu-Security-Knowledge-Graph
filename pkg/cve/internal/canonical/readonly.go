package canonical

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"os"
)

// OpenReadOnly opens an existing canonical database without creating it,
// without running migrations and without any ability to write. It fails if the
// file is missing, unreadable, or not a migrated canonical store.
func OpenReadOnly(path string) (*Store, error) {
	if _, err := os.Stat(path); err != nil {
		return nil, fmt.Errorf("canonical: open read-only: %w", err)
	}
	u := url.URL{Scheme: "file", Opaque: (&url.URL{Path: path}).EscapedPath(), RawQuery: "mode=ro&_pragma=busy_timeout(10000)&_pragma=query_only(1)"}
	db, err := sql.Open("sqlite", u.String())
	if err != nil {
		return nil, err
	}
	var n int
	err = db.QueryRowContext(context.Background(),
		`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='schema_migrations'`).Scan(&n)
	if err == nil && n == 0 {
		err = fmt.Errorf("schema_migrations table missing")
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("canonical: open read-only %s: %w", path, err)
	}
	return &Store{DB: db, clock: wallClock{}}, nil
}
