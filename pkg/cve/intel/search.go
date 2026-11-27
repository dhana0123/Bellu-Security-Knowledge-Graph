package intel

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/model"
)

// MaxSearchLimit is the largest page SearchPackage/SearchProduct return.
const MaxSearchLimit = 1000

// PageReq is a keyset page request. After is the last vulnerability id of the
// previous page ("" for the first page). Limit is the maximum row count.
type PageReq struct {
	After string
	Limit int
}

// VulnRef is a vulnerability that affects a searched package or product.
type VulnRef struct {
	Vulnerability VulnerabilitySummary
	Introduced    string
	Fixed         string
	Status        string
}

// Exploit is an exploit reference of a vulnerability.
type Exploit struct {
	ID     string
	URL    string
	Source string
}

// SearchPackage lists vulnerabilities affecting a package, ordered by
// vulnerability id, without a version filter.
func (c *sqliteClient) SearchPackage(ctx context.Context, ecosystem, name string, p PageReq) ([]VulnRef, error) {
	if strings.TrimSpace(ecosystem) == "" || strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("%w: ecosystem and name must not be empty", ErrInvalidRequest)
	}
	return c.searchAffects(ctx, model.PackageID(ecosystem, name), p)
}

// SearchProduct lists vulnerabilities affecting a vendor/product pair.
func (c *sqliteClient) SearchProduct(ctx context.Context, vendor, product string, p PageReq) ([]VulnRef, error) {
	if strings.TrimSpace(vendor) == "" || strings.TrimSpace(product) == "" {
		return nil, fmt.Errorf("%w: vendor and product must not be empty", ErrInvalidRequest)
	}
	return c.searchAffects(ctx, model.ProductID(vendor, product), p)
}

func (c *sqliteClient) searchAffects(ctx context.Context, dst string, p PageReq) ([]VulnRef, error) {
	if p.Limit < 1 || p.Limit > MaxSearchLimit {
		return nil, fmt.Errorf("%w: limit must be between 1 and %d", ErrInvalidRequest, MaxSearchLimit)
	}
	after := ""
	if p.After != "" {
		after = "vuln:" + p.After
	}
	rows, err := c.db.QueryContext(ctx, `SELECT e.props, n.id, n.props FROM edges e JOIN nodes n ON n.id=e.src
		WHERE e.dst=? AND e.type='AFFECTS' AND e.src>? ORDER BY e.src LIMIT ?`, dst, after, p.Limit)
	if err != nil {
		return nil, unavailable(err)
	}
	defer rows.Close()
	out := []VulnRef{}
	for rows.Next() {
		var ep, vid, vp string
		if err := rows.Scan(&ep, &vid, &vp); err != nil {
			return nil, unavailable(err)
		}
		var e, v map[string]any
		if err := json.Unmarshal([]byte(ep), &e); err != nil {
			return nil, unavailable(err)
		}
		if err := json.Unmarshal([]byte(vp), &v); err != nil {
			return nil, unavailable(err)
		}
		out = append(out, VulnRef{
			Vulnerability: VulnerabilitySummary{ID: strings.TrimPrefix(vid, "vuln:"), Summary: str(v, "summary"), TrustState: str(v, "trust_state")},
			Introduced:    str(e, "introduced"), Fixed: str(e, "fixed"), Status: str(e, "status"),
		})
	}
	if err := rows.Err(); err != nil {
		return nil, unavailable(err)
	}
	return out, nil
}

// GetExploits lists the exploit references (HAS_EXPLOIT) of a vulnerability.
func (c *sqliteClient) GetExploits(ctx context.Context, cveID string, opts ...Option) ([]Exploit, error) {
	if err := c.checkAsOf(ctx, opts); err != nil {
		return nil, err
	}
	vn, err := c.resolveVulnerability(ctx, cveID)
	if err != nil {
		return nil, unavailable(err)
	}
	ns, err := c.neighbors(ctx, vn.ID, "HAS_EXPLOIT")
	if err != nil {
		return nil, unavailable(err)
	}
	out := []Exploit{}
	for _, n := range ns {
		out = append(out, Exploit{ID: n.ID, URL: str(n.Props, "url"), Source: str(n.Props, "source")})
	}
	return out, nil
}
