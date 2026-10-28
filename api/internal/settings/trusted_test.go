package settings

import (
	"slices"
	"testing"

	"api/internal/database"
	"api/internal/helper"
)

// IGNORE_NETWORKS seeds the extras once; after that the saved list (edited in Settings) wins,
// even when it's emptied.
func TestLoadTrustedNetworksSeedsOnce(t *testing.T) {
	if _, err := database.Init(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WG_IP_RANGE", "10.8.0.0/16")
	t.Setenv("HEADSCALE_IP_RANGE", "100.64.0.0/16")
	t.Setenv("IGNORE_NETWORKS", "198.51.100.7, 10.8.0.0/16,203.0.113.9/24")
	t.Cleanup(func() { helper.SetTrustedExtras(nil) })

	LoadTrustedNetworks()
	if got := helper.TrustedExtras(); !slices.Equal(got, []string{"198.51.100.7", "203.0.113.0/24"}) {
		t.Fatalf("seeded %v", got)
	}

	if err := SetTrustedNetworks(nil); err != nil {
		t.Fatal(err)
	}
	LoadTrustedNetworks()
	if got := helper.TrustedExtras(); len(got) != 0 {
		t.Fatalf("an emptied list must stay empty, not reseed: %v", got)
	}
}
