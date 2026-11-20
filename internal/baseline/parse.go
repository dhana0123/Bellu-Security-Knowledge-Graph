package baseline

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// FieldType is the stored type of a CSV column.
type FieldType int

// Field types used by the VulKG schema.
const (
	TString FieldType = iota
	TInt
	TFloat // decimal, never truncated
	TBool
	TDate
	TStringList // comma-separated
)

// Field maps a CSV column to a node or relationship property.
type Field struct {
	Column string
	Prop   string
	Type   FieldType
}

// ParseInt parses an integer. A value such as "2.0" is accepted when it has
// no fractional part.
func ParseInt(s string) (int64, error) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return n, nil
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || f != math.Trunc(f) || math.Abs(f) > 1<<53 {
		return 0, fmt.Errorf("invalid integer %q", s)
	}
	return int64(f), nil
}

// ParseDecimal parses a decimal number without integer truncation.
func ParseDecimal(s string) (float64, error) {
	f, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil || math.IsNaN(f) || math.IsInf(f, 0) {
		return 0, fmt.Errorf("invalid decimal %q", s)
	}
	return f, nil
}

// ParseBool accepts true/false in any letter case.
func ParseBool(s string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true":
		return true, nil
	case "false":
		return false, nil
	}
	return false, fmt.Errorf("invalid boolean %q", s)
}

// ParseDate parses YYYY-MM-DD into a Neo4j date.
func ParseDate(s string) (neo4j.Date, error) {
	t, err := time.Parse("2006-01-02", strings.TrimSpace(s))
	if err != nil {
		return neo4j.Date{}, fmt.Errorf("invalid date %q", s)
	}
	return neo4j.Date(t), nil
}

// ParseList splits a comma-separated list, trimming items and dropping empty ones.
func ParseList(s string) []string {
	out := []string{}
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ParseValue converts a non-empty field to its stored Go value.
func ParseValue(t FieldType, s string) (any, error) {
	switch t {
	case TString:
		return s, nil
	case TInt:
		return ParseInt(s)
	case TFloat:
		return ParseDecimal(s)
	case TBool:
		return ParseBool(s)
	case TDate:
		return ParseDate(s)
	case TStringList:
		return ParseList(s), nil
	}
	return nil, fmt.Errorf("unknown field type %d", t)
}

// Props builds the property map for a row. Empty fields are absent from the
// map. A malformed value returns an error naming the file line, column.
func (r Row) Props(fields []Field) (map[string]any, error) {
	out := make(map[string]any, len(fields))
	for _, f := range fields {
		s, ok := r.Get(f.Column)
		if !ok {
			continue
		}
		v, err := ParseValue(f.Type, s)
		if err != nil {
			return nil, fmt.Errorf("line %d column %s: %w", r.Line, f.Column, err)
		}
		out[f.Prop] = v
	}
	return out, nil
}
