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

func TestNoS3AndNoWideIAM(t *testing.T) {
	src := readInfra(t)
	if regexp.MustCompile(`resource\s+"aws_s3_`).MatchString(src) {
		t.Error("aws_s3_* resource found; the design has no S3 (Requirement 24.4)")
	}
	if regexp.MustCompile(`s3:`).MatchString(src) {
		t.Error("s3: action found in infra")
	}
	if regexp.MustCompile(`resource\s+"aws_iam_role_policy"\s+"(baseline|host)\w*"`).MatchString(src) {
		t.Error("the host role must carry no inline policy")
	}
	if regexp.MustCompile(`"AdministratorAccess"|policy/Admin`).MatchString(src) {
		t.Error("administrator policy attachment found")
	}
}

func varDefault(t *testing.T, src, name string) string {
	t.Helper()
	v := blocks(src, regexp.MustCompile(`variable\s+"`+name+`"\s*\{`))
	if len(v) != 1 {
		t.Fatalf("variable %s not found", name)
	}
	return attr(v[0], "default")
}

func TestArm64HostDefaults(t *testing.T) {
	src := readInfra(t)
	if got := varDefault(t, src, "instance_type"); got != `"t4g.large"` {
		t.Errorf("instance_type default = %s, want t4g.large", got)
	}
	if got := varDefault(t, src, "data_volume_size_gb"); got != "50" {
		t.Errorf("data_volume_size_gb default = %s, want 50", got)
	}
	if got := varDefault(t, src, "snapshot_retain_count"); got != "3" {
		t.Errorf("snapshot_retain_count default = %s, want 3", got)
	}
	ami := blocks(src, regexp.MustCompile(`data\s+"aws_ami"\s+"ubuntu"\s*\{`))
	if len(ami) != 1 || !strings.Contains(ami[0], "ubuntu-jammy-22.04-arm64-server-*") || !strings.Contains(ami[0], `values = ["arm64"]`) {
		t.Error("AMI must filter for the Ubuntu 22.04 arm64 server image and architecture arm64")
	}
	for _, in := range blocks(src, regexp.MustCompile(`resource\s+"aws_instance"\s+"\w+"\s*\{`)) {
		md := blocks(in, regexp.MustCompile(`metadata_options\s*\{`))
		if len(md) != 1 || attr(md[0], "http_put_response_hop_limit") != "1" {
			t.Error("aws_instance must set http_put_response_hop_limit = 1")
		}
	}
}
