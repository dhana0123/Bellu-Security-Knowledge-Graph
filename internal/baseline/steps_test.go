package baseline

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func firstRow(t *testing.T, csvText string) Row {
	t.Helper()
	p := filepath.Join(t.TempDir(), "f.csv")
	if err := os.WriteFile(p, []byte(csvText), 0o600); err != nil {
		t.Fatal(err)
	}
	r, err := OpenCSV(p)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	row, err := r.Next()
	if err != nil {
		t.Fatal(err)
	}
	return row
}

func TestMapVulnNodeDecimalsAndAbsent(t *testing.T) {
	row := firstRow(t, "cveID,publishedDate,description_value,num_reference,v2version,v2impactScore,v3version,v3baseScore,v3scope\n"+
		"CVE-2019-1,2019-02-08,desc,2,2.0,2.8,3.1,9.8,\n")
	m, err := mapVulnNode(row)
	if err != nil {
		t.Fatal(err)
	}
	p := m["props"].(map[string]any)
	if m["cveID"] != "CVE-2019-1" || p["description"] != "desc" || p["numOfReference"] != int64(2) || p["v2version"] != int64(2) {
		t.Fatalf("%v", m)
	}
	if p["v2impactScore"] != 2.8 || p["v3baseScore"] != 9.8 || p["v3version"] != 3.1 {
		t.Fatalf("scores must stay decimal: %v", p)
	}
	if _, ok := p["v3scope"]; ok {
		t.Fatal("empty field must be absent")
	}
}

func TestMapVulnNodeBadValueNamesLine(t *testing.T) {
	row := firstRow(t, "cveID,num_reference\nCVE-1,abc\n")
	if _, err := mapVulnNode(row); err == nil {
		t.Fatal("want error")
	}
}

func TestMapPairsAndSkips(t *testing.T) {
	row := firstRow(t, "eid,cveID\n40001,CVE-1\n")
	m, _ := mapExploitsRel(row)
	if !reflect.DeepEqual(m, map[string]any{"eid": "40001", "cveID": "CVE-1"}) {
		t.Fatalf("%v", m)
	}
	row = firstRow(t, "cveID,CWEID\nCVE-1,\n")
	if m, _ := mapExampleOf(row); m != nil {
		t.Fatalf("row without CWEID must be skipped: %v", m)
	}
}

func TestMapAddProps(t *testing.T) {
	row := firstRow(t, "cveID,CWEID,GainedAccess,VulnerabilityType\nCVE-1,CWE-1,Gain Privileges,\"Execute Code,Overflow\"\n")
	m, _ := mapAddProps(row)
	if m["gainedAccess"] != "Gain Privileges" || !reflect.DeepEqual(m["vulnerabilityType"], []string{"Execute Code", "Overflow"}) {
		t.Fatalf("%v", m)
	}
	row = firstRow(t, "cveID,GainedAccess,VulnerabilityType\nCVE-2,,\n")
	m, _ = mapAddProps(row)
	if m["gainedAccess"] != nil || m["vulnerabilityType"] != nil {
		t.Fatalf("absent fields must be null: %v", m)
	}
}

func TestMapWeaknessAndExploit(t *testing.T) {
	row := firstRow(t, "cweID,cweView,cweName\nCWE-79,\"1000,699\",XSS\n")
	m, _ := mapWeakness(row)
	p := m["props"].(map[string]any)
	if !reflect.DeepEqual(p["cweView"], []string{"1000", "699"}) || p["cweName"] != "XSS" {
		t.Fatalf("%v", p)
	}
	row = firstRow(t, "ExploitID,Exploit_Date,Author,Exploit_Type,Platform\n40001,2019-01-01,alice,remote,linux\n")
	m, _ = mapExploitNode(row)
	if m["eid"] != "40001" || m["props"].(map[string]any)["platform"] != "linux" {
		t.Fatalf("%v", m)
	}
	if a, _ := mapAuthorNode(row); a["authorName"] != "alice" {
		t.Fatalf("%v", a)
	}
}
