package testgen

import (
	"os"
	"testing"

	"github.com/dhana0123/Bellu-Security-Knowledge-Graph/pkg/cve/internal/nettest"
)

func TestMain(m *testing.M) { os.Exit(nettest.Main(m)) }
