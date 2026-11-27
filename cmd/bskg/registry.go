package main

import (
	"os"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/config"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/pipeline"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/atlas"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/attack"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/capec"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/cwe"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/epss"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/exploitdb"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/ghsa"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/kev"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/nvd"
	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/internal/source/osv"
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
	_ = pipeline.Default.Register(cwe.New())
	_ = pipeline.Default.Register(nvd.New(nvd.Options{APIKey: os.Getenv(config.EnvNVDAPIKey), Version: version}))
	_ = pipeline.Default.Register(exploitdb.New(storedEIDs))
	_ = pipeline.Default.Register(attack.New(attack.Options{CacheDir: cfg.CacheDir, Version: version}))
	_ = pipeline.Default.Register(atlas.New(atlas.Options{CacheDir: cfg.CacheDir, Version: version}))
	_ = pipeline.Default.Register(capec.New(capec.Options{CacheDir: cfg.CacheDir, Version: version}))
	_ = pipeline.Default.Register(kev.New(kev.Options{CacheDir: cfg.CacheDir, Version: version, Stored: storedKEV}))
	_ = pipeline.Default.Register(epss.New(epss.Options{CacheDir: cfg.CacheDir, Version: version, ChangeThreshold: cfg.EPSSChangeThreshold}))
	_ = pipeline.Default.Register(osv.New(osv.Options{Ecosystems: cfg.OSVEcosystems, CacheDir: cfg.CacheDir, Version: version}))
	_ = pipeline.Default.Register(ghsa.New(ghsa.Options{Token: cfg.GitHubToken.Value(), Version: version}))
}
