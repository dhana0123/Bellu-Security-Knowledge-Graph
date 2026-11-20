package baseline

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDecimalKeepsFraction(t *testing.T) {
	for in, want := range map[string]float64{"9.8": 9.8, "4.3": 4.3, "10": 10, " 0.5 ": 0.5, "2.8": 2.8} {
		got, err := ParseDecimal(in)
		if err != nil || got != want {
			t.Errorf("ParseDecimal(%q) = %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "x", "NaN", "Inf", "1,5"} {
		if _, err := ParseDecimal(bad); err == nil {
			t.Errorf("ParseDecimal(%q) accepted", bad)
		}
	}
}

func TestParseIntBoolDateList(t *testing.T) {
	if n, err := ParseInt("2.0"); err != nil || n != 2 {
		t.Error(n, err)
	}
	if _, err := ParseInt("2.5"); err == nil {
		t.Error("2.5 accepted as int")
	}
	if b, err := ParseBool("TRUE"); err != nil || !b {
		t.Error(b, err)
	}
	if _, err := ParseBool("yes"); err == nil {
		t.Error("yes accepted")
	}
	if d, err := ParseDate("2019-02-08"); err != nil || d.String() != "2019-02-08" {
		t.Error(d, err)
	}
	if _, err := ParseDate("2019-13-01"); err == nil {
		t.Error("bad date accepted")
	}
	if got := ParseList("1000, 699,,"); !reflect.DeepEqual(got, []string{"1000", "699"}) {
		t.Error(got)
	}
}

func TestRowPropsEmptyIsAbsent(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.csv")
	data := "cveID,score,ver,ok,pub,types\nCVE-1,4.3,3.1,true,2019-02-08,\"a,b\"\nCVE-2,,,,,\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenCSV(p, "cveID")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	fields := []Field{
		{"cveID", "cveID", TString}, {"score", "score", TFloat}, {"ver", "ver", TFloat},
		{"ok", "ok", TBool}, {"pub", "pub", TDate}, {"types", "types", TStringList},
	}
	row, _ := r.Next()
	m, err := row.Props(fields)
	if err != nil || m["score"] != 4.3 || m["ver"] != 3.1 || m["ok"] != true || len(m) != 6 {
		t.Fatalf("%v %v", m, err)
	}
	if !reflect.DeepEqual(m["types"], []string{"a", "b"}) {
		t.Fatal(m["types"])
	}
	row, _ = r.Next()
	m, err = row.Props(fields)
	if err != nil || len(m) != 1 || m["cveID"] != "CVE-2" {
		t.Fatalf("%v %v", m, err)
	}
	if _, err := r.Next(); !errors.Is(err, io.EOF) {
		t.Fatal(err)
	}
}

func TestRowPropsBadValueNamesColumn(t *testing.T) {
	p := filepath.Join(t.TempDir(), "v.csv")
	os.WriteFile(p, []byte("a,b\nx,zz\n"), 0o600)
	r, _ := OpenCSV(p)
	defer r.Close()
	row, _ := r.Next()
	_, err := row.Props([]Field{{"b", "b", TFloat}})
	if err == nil || !strings.Contains(err.Error(), "column b") || !strings.Contains(err.Error(), "line 2") {
		t.Fatal(err)
	}
}

func TestOpenCSVMissingColumnAndBatches(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "x.csv")
	os.WriteFile(p, []byte("a,b\n1,2\n3,4\n5,6\n"), 0o600)
	if _, err := OpenCSV(p, "zzz"); err == nil {
		t.Fatal("missing column accepted")
	}
	r, _ := OpenCSV(p, "a")
	defer r.Close()
	var sizes []int
	for {
		rows, err := r.NextBatch(2)
		if len(rows) > 0 {
			sizes = append(sizes, len(rows))
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatal(err)
			}
			break
		}
	}
	if !reflect.DeepEqual(sizes, []int{2, 1}) {
		t.Fatal(sizes)
	}
	if n, err := CountRows(p); err != nil || n != 3 {
		t.Fatal(n, err)
	}
}

func TestValidateBatchSize(t *testing.T) {
	for _, n := range []int{0, -1, 10001} {
		if !errors.Is(ValidateBatchSize(n), ErrBatchSize) {
			t.Errorf("%d accepted", n)
		}
	}
	for _, n := range []int{1, 5000, 10000} {
		if ValidateBatchSize(n) != nil {
			t.Errorf("%d rejected", n)
		}
	}
}

func TestFixtureVulnerabilityNodesParse(t *testing.T) {
	r, err := OpenCSV("../../testdata/baseline/VulnerabilityNodes.csv", "cveID")
	if err != nil {
		t.Skip(err)
	}
	defer r.Close()
	fields := []Field{
		{"cveID", "cveID", TString}, {"publishedDate", "publishedDate", TDate},
		{"num_reference", "numOfReference", TInt}, {"v2version", "v2version", TInt},
		{"v2baseScore", "v2baseScore", TFloat}, {"v2impactScore", "v2impactScore", TFloat},
		{"v3version", "v3version", TFloat}, {"v3baseScore", "v3baseScore", TFloat},
		{"v2userInteractionRequired", "v2userInteractionRequired", TBool},
	}
	n := 0
	for {
		row, err := r.Next()
		if err != nil {
			break
		}
		if _, err := row.Props(fields); err != nil {
			t.Fatal(err)
		}
		n++
	}
	if n != 41 {
		t.Fatalf("rows = %d", n)
	}
}
