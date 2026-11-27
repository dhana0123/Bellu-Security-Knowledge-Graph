package nvd

import (
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/gitref"
)

// gitLinks maps the reference URLs of one CVE to git entities; see gitref.Append.
func gitLinks(cve string, vref source.Ref, urls []string, n *source.Normalized) {
	gitref.Append(cve, vref, urls, n)
}
