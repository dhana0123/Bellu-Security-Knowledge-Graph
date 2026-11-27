package graph

import (
	"database/sql"
	"fmt"
)

// CompareDBs reports an error unless the nodes and edges rows (including h) of
// the two graph.db files are identical.
func CompareDBs(a, b string) error {
	for _, q := range []string{
		"SELECT id,type,props,h FROM nodes ORDER BY id",
		"SELECT id,type,src,dst,props,h FROM edges ORDER BY id",
	} {
		ra, err := dumpRows(a, q)
		if err != nil {
			return err
		}
		rb, err := dumpRows(b, q)
		if err != nil {
			return err
		}
		if len(ra) != len(rb) {
			return fmt.Errorf("row count differs: %d vs %d for %q", len(ra), len(rb), q)
		}
		for i := range ra {
			if ra[i] != rb[i] {
				return fmt.Errorf("row %d differs: %s vs %s", i, ra[i], rb[i])
			}
		}
	}
	return nil
}

func dumpRows(path, q string) ([]string, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var out []string
	for rows.Next() {
		vals := make([]string, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%q", vals))
	}
	return out, rows.Err()
}
