package baseline

import (
	"math"
	"strconv"
	"testing"

	"pgregory.net/rapid"
)

// decimalStringGen yields a decimal string and its expected numeric value.
func decimalStringGen() *rapid.Generator[[2]any] {
	return rapid.Custom(func(t *rapid.T) [2]any {
		switch rapid.IntRange(0, 3).Draw(t, "fmt") {
		case 0: // one decimal place, CVSS style
			n := rapid.IntRange(0, 100).Draw(t, "tenths")
			s := strconv.Itoa(n/10) + "." + strconv.Itoa(n%10)
			f, _ := strconv.ParseFloat(s, 64)
			return [2]any{s, f}
		case 1: // integer text
			n := rapid.IntRange(0, 10).Draw(t, "int")
			return [2]any{strconv.Itoa(n), float64(n)}
		case 2: // arbitrary float, shortest repr
			f := rapid.Float64Range(-1e6, 1e6).Draw(t, "f")
			return [2]any{strconv.FormatFloat(f, 'f', -1, 64), f}
		default: // fixed precision
			f := rapid.Float64Range(0, 10).Draw(t, "p")
			s := strconv.FormatFloat(f, 'f', 2, 64)
			v, _ := strconv.ParseFloat(s, 64)
			return [2]any{s, v}
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 8: Decimal and empty-field parsing
// **Validates: Requirements 4.9**
func TestProperty8DecimalParsing(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		p := decimalStringGen().Draw(t, "dec")
		s, want := p[0].(string), p[1].(float64)
		got, err := ParseDecimal(s)
		if err != nil {
			t.Fatalf("ParseDecimal(%q): %v", s, err)
		}
		if got != want {
			t.Fatalf("ParseDecimal(%q) = %v, want %v", s, got, want)
		}
		if want != math.Trunc(want) && got == math.Trunc(got) {
			t.Fatalf("ParseDecimal(%q) truncated to %v", s, got)
		}
		// Through Row.Props with a TFloat field the value is the same float64.
		row := Row{fields: []string{s}, header: map[string]int{"c": 0}, Line: 2}
		props, err := row.Props([]Field{{Column: "c", Prop: "p", Type: TFloat}})
		if err != nil {
			t.Fatal(err)
		}
		if v, ok := props["p"].(float64); !ok || v != want {
			t.Fatalf("Props = %#v, want %v", props["p"], want)
		}
	})
}

// Feature: bellu-security-knowledge-graph, Property 8: Decimal and empty-field parsing
// **Validates: Requirements 4.9**
func TestProperty8EmptyFieldAbsent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		blank := rapid.StringMatching(`[ \t]{0,5}`).Draw(t, "blank")
		ft := rapid.SampledFrom([]FieldType{TString, TInt, TFloat, TBool, TDate, TStringList}).Draw(t, "type")
		row := Row{
			fields: []string{blank, "9.8"},
			header: map[string]int{"empty": 0, "full": 1},
			Line:   3,
		}
		props, err := row.Props([]Field{
			{Column: "empty", Prop: "e", Type: ft},
			{Column: "full", Prop: "f", Type: TFloat},
		})
		if err != nil {
			t.Fatal(err)
		}
		if _, present := props["e"]; present {
			t.Fatalf("empty field present as %#v", props["e"])
		}
		if props["f"] != 9.8 {
			t.Fatalf("full = %#v", props["f"])
		}
	})
}
