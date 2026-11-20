// Package infratest holds text-based policy checks on the Terraform files in
// infra/. They run without terraform or AWS access.
package infratest

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func readInfra(t *testing.T) string {
	t.Helper()
	files, err := filepath.Glob(filepath.Join("..", "..", "infra", "*.tf"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no infra/*.tf files found: %v", err)
	}
	var sb strings.Builder
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sb.Write(b)
		sb.WriteString("\n")
	}
	return sb.String()
}

// blocks returns the brace-balanced body of every block that starts with the
// given header regexp (for example `resource "aws_instance" "host" \{`).
func blocks(src string, header *regexp.Regexp) []string {
	var out []string
	for _, loc := range header.FindAllStringIndex(src, -1) {
		depth := 1
		i := loc[1]
		for ; i < len(src) && depth > 0; i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
			}
		}
		out = append(out, src[loc[1]:i-1])
	}
	return out
}

func attr(body, name string) string {
	m := regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(name) + `\s*=\s*(.+?)\s*(#.*)?$`).FindStringSubmatch(body)
	if m == nil {
		return ""
	}
	return strings.TrimSpace(m[1])
}

func TestSecurityGroupIngress(t *testing.T) {
	src := readInfra(t)
	sgs := blocks(src, regexp.MustCompile(`resource\s+"aws_security_group"\s+"\w+"\s*\{`))
	if len(sgs) == 0 {
		t.Fatal("no aws_security_group found")
	}
	if regexp.MustCompile(`resource\s+"aws_security_group_rule"`).MatchString(src) {
		t.Fatal("aws_security_group_rule is not allowed; keep rules inline so they are checked")
	}
	for _, sg := range sgs {
		ingress := blocks(sg, regexp.MustCompile(`(?m)^\s*ingress\s*\{`))
		if len(ingress) != 2 {
			t.Fatalf("want exactly 2 ingress blocks (API, SSH), got %d", len(ingress))
		}
		seen := map[int]string{}
		for _, in := range ingress {
			from, err1 := strconv.Atoi(attr(in, "from_port"))
			to, err2 := strconv.Atoi(attr(in, "to_port"))
			if err1 != nil || err2 != nil {
				t.Fatalf("ingress ports must be literal numbers:\n%s", in)
			}
			if from != to {
				t.Fatalf("ingress port range %d-%d not allowed", from, to)
			}
			for _, bad := range []int{7687, 7474} {
				if from <= bad && bad <= to {
					t.Fatalf("ingress opens Neo4j port %d", bad)
				}
			}
			seen[from] = attr(in, "cidr_blocks")
			if attr(in, "ipv6_cidr_blocks") != "" || attr(in, "security_groups") != "" {
				t.Fatalf("unexpected ingress source on port %d", from)
			}
		}
		if got := seen[22]; got != "[var.operator_cidr]" {
			t.Errorf("SSH cidr_blocks = %q, want [var.operator_cidr]", got)
		}
		if got := seen[8080]; got != "var.api_allowed_cidrs" {
			t.Errorf("API cidr_blocks = %q, want var.api_allowed_cidrs", got)
		}
		if len(seen) != 2 {
			t.Errorf("ingress ports = %v, want only 22 and 8080", seen)
		}
	}
}

func TestNoStaticCredentials(t *testing.T) {
	src := readInfra(t)
	for _, re := range []string{
		`resource\s+"aws_iam_access_key"`,
		`resource\s+"aws_iam_user"`,
		`resource\s+"aws_iam_user_login_profile"`,
		`(?i)\baccess_key\s*=`,
		`(?i)\bsecret_key\s*=`,
		`AKIA[0-9A-Z]{16}`,
	} {
		if regexp.MustCompile(re).MatchString(src) {
			t.Errorf("static credential pattern found: %s", re)
		}
	}
}

func TestInstanceMetadataV2AndEncryption(t *testing.T) {
	src := readInfra(t)
	inst := blocks(src, regexp.MustCompile(`resource\s+"aws_instance"\s+"\w+"\s*\{`))
	if len(inst) == 0 {
		t.Fatal("no aws_instance found")
	}
	for _, in := range inst {
		md := blocks(in, regexp.MustCompile(`metadata_options\s*\{`))
		if len(md) != 1 || attr(md[0], "http_tokens") != `"required"` {
			t.Error(`aws_instance must set metadata_options.http_tokens = "required"`)
		}
		root := blocks(in, regexp.MustCompile(`root_block_device\s*\{`))
		if len(root) != 1 || attr(root[0], "encrypted") != "true" {
			t.Error("root_block_device must set encrypted = true")
		}
	}
	vols := blocks(src, regexp.MustCompile(`resource\s+"aws_ebs_volume"\s+"\w+"\s*\{`))
	if len(vols) == 0 {
		t.Fatal("no aws_ebs_volume found")
	}
	for _, v := range vols {
		if attr(v, "encrypted") != "true" {
			t.Error("aws_ebs_volume must set encrypted = true")
		}
	}
}

func TestBaselineIAMPolicy(t *testing.T) {
	src := readInfra(t)
	docs := blocks(src, regexp.MustCompile(`data\s+"aws_iam_policy_document"\s+"baseline_read"\s*\{`))
	if len(docs) != 1 {
		t.Fatal("data.aws_iam_policy_document.baseline_read not found")
	}
	stmts := blocks(docs[0], regexp.MustCompile(`(?m)^\s*statement\s*\{`))
	if len(stmts) != 2 {
		t.Fatalf("want 2 statements, got %d", len(stmts))
	}
	var sawGet, sawList bool
	for _, s := range stmts {
		if strings.Contains(s, `effect`) && !strings.Contains(attr(s, "effect"), "Allow") {
			t.Error("statement effect must be Allow")
		}
		switch attr(s, "actions") {
		case `["s3:GetObject"]`:
			sawGet = true
			if r := attr(s, "resources"); r != `["${aws_s3_bucket.baseline.arn}/vulkg/*"]` {
				t.Errorf("GetObject resources = %s, want only the vulkg/* prefix", r)
			}
		case `["s3:ListBucket"]`:
			sawList = true
			if r := attr(s, "resources"); r != `[aws_s3_bucket.baseline.arn]` {
				t.Errorf("ListBucket resources = %s", r)
			}
			c := blocks(s, regexp.MustCompile(`condition\s*\{`))
			if len(c) != 1 || attr(c[0], "variable") != `"s3:prefix"` || attr(c[0], "values") != `["vulkg/*"]` {
				t.Error("ListBucket needs a condition limiting s3:prefix to vulkg/*")
			}
		default:
			t.Errorf("unexpected actions %s in baseline_read", attr(s, "actions"))
		}
	}
	if !sawGet || !sawList {
		t.Errorf("missing statements: GetObject=%v ListBucket=%v", sawGet, sawList)
	}
	// The role policy must use this document and no other S3 grants may exist.
	if regexp.MustCompile(`s3:(\*|Put|Delete)`).MatchString(src) {
		t.Error("write or wildcard S3 actions found")
	}
	if regexp.MustCompile(`"AdministratorAccess"|policy/Admin`).MatchString(src) {
		t.Error("administrator policy attachment found")
	}
}
