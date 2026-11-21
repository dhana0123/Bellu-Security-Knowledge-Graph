package change

import (
	"encoding/json"
	"reflect"
	"time"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

// Typed JSON codec for Change old/new values. Dates are {"$date": "YYYY-MM-DD"},
// date-times are {"$datetime": RFC3339Nano, UTC, millisecond precision}.

func typed(v any) any {
	switch x := v.(type) {
	case nil:
		return nil
	case neo4j.Date:
		return map[string]any{"$date": x.Time().Format("2006-01-02")}
	case time.Time:
		u := x.UTC()
		if u.Equal(u.Truncate(24 * time.Hour)) {
			return map[string]any{"$date": u.Format("2006-01-02")}
		}
		return map[string]any{"$datetime": u.Truncate(time.Millisecond).Format(time.RFC3339Nano)}
	}
	rv := reflect.ValueOf(v)
	if rv.Kind() == reflect.Slice && rv.Type().Elem().Kind() != reflect.Uint8 {
		out := make([]any, rv.Len())
		for i := range out {
			out[i] = typed(rv.Index(i).Interface())
		}
		return out
	}
	return v
}

// EncodeValue returns the typed JSON text of v, or "null" if it cannot be encoded.
func EncodeValue(v any) string {
	b, err := json.Marshal(typed(v))
	if err != nil {
		return "null"
	}
	return string(b)
}

// EncodeProps returns the typed JSON object text of m, or "{}" on failure.
func EncodeProps(m map[string]any) string {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = typed(v)
	}
	b, err := json.Marshal(out)
	if err != nil {
		return "{}"
	}
	return string(b)
}
