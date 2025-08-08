package config

import (
	"github.com/go-faster/sdk/gold"
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	// Explicitly registering flags for golden files.
	gold.Init()

	os.Exit(m.Run())
}
