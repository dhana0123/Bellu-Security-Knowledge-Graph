package main

import (
	"os"

	"github.com/bellu/bskg/internal/config"
	"github.com/bellu/bskg/internal/pipeline"
	"github.com/bellu/bskg/internal/source/cwe"
	"github.com/bellu/bskg/internal/source/exploitdb"
	"github.com/bellu/bskg/internal/source/nvd"
)

// version is the product version sent in the NVD User-Agent. Set it with
// -ldflags "-X main.version=...".
var version = "dev"

// registerAdapters registers every Source_Adapter with pipeline.Default. A new
// source is one line here and one row in docs/sources.md. cfg carries the
// settings an adapter needs: cfg.CacheDir, cfg.OSVEcosystems, cfg.GitHubToken
// (a Secret: call Value() only when building the request header, never log
// it), cfg.EPSSChangeThreshold. The adapter name is the job name and the name
// in BSKG_ENABLED_SOURCES (docs/adapter-contract.md).
func registerAdapters(cfg *config.Config) {
	_ = cfg // used by the adapters of the later sources
	_ = pipeline.Default.Register(cwe.New())
	_ = pipeline.Default.Register(nvd.New(nvd.Options{APIKey: os.Getenv(config.EnvNVDAPIKey), Version: version}))
	_ = pipeline.Default.Register(exploitdb.New(storedEIDs))
}
