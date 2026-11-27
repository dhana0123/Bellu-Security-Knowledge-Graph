package canonical

import (
	"io/fs"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/migrations"
)

func migrationsFS() fs.FS { return migrations.FS }
