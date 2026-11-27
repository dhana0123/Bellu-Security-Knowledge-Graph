// Package gitref turns reference URLs into git repository and fix-commit
// entities. It is shared by the NVD, OSV, and GHSA adapters.
package gitref

import (
	"net/url"
	"strings"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/resolve"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
)

// Link is what one reference URL says about git: a repository and, for a
// commit link, a commit id (not yet validated).
type Link struct {
	Repo      string // repository URL, normalized by resolve.NormalizeRepoURL
	SHA       string // empty for a plain repository link
	BadCommit bool   // commit link whose sha is not 40 hex digits
}

// githubReserved are first path segments of github.com that are not owners.
var githubReserved = map[string]bool{
	"advisories": true, "orgs": true, "topics": true, "sponsors": true, "features": true,
	"settings": true, "marketplace": true, "apps": true, "collections": true, "search": true,
	"explore": true, "about": true, "security": true, "login": true, "notifications": true,
	"enterprise": true, "pricing": true, "site": true, "readme": true, "trending": true,
	"users": true, "customer-stories": true, "events": true, "sitemap": true,
}

// gitlabLegacyMarkers start the non-repository part of a GitLab path that has
// no "/-/" separator (old-style URLs such as /group/repo/issues/1).
var gitlabLegacyMarkers = map[string]bool{
	"commit": true, "commits": true, "issues": true, "merge_requests": true, "tree": true,
	"blob": true, "tags": true, "releases": true, "wikis": true, "pipelines": true, "raw": true,
}

// Parse recognises commit and repository links on github.com,
// gitlab.com, and bitbucket.org. Other URLs return ok == false.
func Parse(raw string) (Link, bool) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return Link{}, false
	}
	host := strings.ToLower(u.Hostname())
	var segs []string
	for _, s := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if s != "" {
			segs = append(segs, s)
		}
	}
	var repoSegs []string
	var sha string
	hasSha := false
	switch host {
	case "github.com":
		if len(segs) < 2 || githubReserved[strings.ToLower(segs[0])] {
			return Link{}, false
		}
		repoSegs = segs[:2]
		if len(segs) >= 4 && segs[2] == "commit" {
			sha, hasSha = segs[3], true
		}
	case "bitbucket.org":
		if len(segs) < 2 {
			return Link{}, false
		}
		repoSegs = segs[:2]
		if len(segs) >= 4 && (segs[2] == "commits" || segs[2] == "commit") {
			sha, hasSha = segs[3], true
		}
	case "gitlab.com":
		cut := len(segs)
		for i, s := range segs {
			if s == "-" || (i >= 2 && gitlabLegacyMarkers[s]) {
				cut = i
				break
			}
		}
		repoSegs = segs[:cut]
		if cut < len(segs) {
			rest := segs[cut:]
			if rest[0] == "-" {
				rest = rest[1:]
			}
			if len(rest) >= 2 && rest[0] == "commit" {
				sha, hasSha = rest[1], true
			}
		}
	default:
		return Link{}, false
	}
	repo, err := resolve.NormalizeRepoURL("https://" + host + "/" + strings.Join(repoSegs, "/"))
	if err != nil {
		return Link{}, false
	}
	l := Link{Repo: repo}
	if hasSha {
		sha = strings.TrimSuffix(strings.TrimSuffix(sha, ".patch"), ".diff")
		if _, err := resolve.FixCommitKey(repo, sha); err != nil {
			l.BadCommit = true
		} else {
			l.SHA = sha
		}
	}
	return l, true
}

// Append maps the reference URLs of one record (id is used in notes) to
// Repository and FixCommit entities and the three git relationships from and
// to vref, deduplicated per record.
// REFERS_TO_REPOSITORY is owned by the anchor; HAS_FIX_COMMIT starts at the
// Repository and FIXES ends at the Vulnerability, so neither is marked
// removed when a reference disappears (Requirement 9.14).
func Append(id string, vref source.Ref, urls []string, n *source.Normalized) {
	seenRepo := map[string]bool{}
	seenFix := map[string]bool{}
	for _, raw := range urls {
		l, ok := Parse(raw)
		if !ok {
			continue
		}
		repo := source.Ref{Kind: source.RefRepository, Raw: l.Repo}
		if !seenRepo[l.Repo] {
			seenRepo[l.Repo] = true
			host := strings.TrimPrefix(l.Repo, "https://")
			host = host[:strings.Index(host, "/")]
			n.Entities = append(n.Entities, source.Entity{Ref: repo, Props: map[string]any{"host": host}})
			n.Rels = append(n.Rels, source.Rel{From: vref, To: repo, Type: "REFERS_TO_REPOSITORY"})
		}
		if l.BadCommit {
			n.Notes = append(n.Notes, source.Note{Kind: "warning", ID: id, Text: "commit link without a 40-digit hex sha: " + raw})
			continue
		}
		if l.SHA == "" {
			continue
		}
		fcKey, err := resolve.FixCommitKey(l.Repo, l.SHA)
		if err != nil || seenFix[fcKey] {
			continue
		}
		seenFix[fcKey] = true
		fc := source.Ref{Kind: source.RefFixCommit, Raw: fcKey}
		n.Entities = append(n.Entities, source.Entity{Ref: fc, Props: map[string]any{
			"repoUrl": l.Repo,
			"sha":     strings.ToLower(l.SHA),
			"url":     raw,
		}})
		n.Rels = append(n.Rels,
			source.Rel{From: repo, To: fc, Type: "HAS_FIX_COMMIT"},
			source.Rel{From: fc, To: vref, Type: "FIXES"})
	}
}
