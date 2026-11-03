package nftables

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// nftCheck runs the real `nft -c` on a script; skipped where nft can't run (no nft, not root, or
// a container without CAP_NET_ADMIN), as CI runners usually are.
func nftCheck(t *testing.T, script string) {
	t.Helper()
	nft, err := exec.LookPath("nft")
	if err != nil || os.Geteuid() != 0 {
		t.Skip("nft -c needs nft and root")
	}
	f := filepath.Join(t.TempDir(), "check.nft")
	if err := os.WriteFile(f, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(nft, "-c", "-f", f).CombinedOutput(); err != nil {
		if strings.Contains(string(out), "Operation not permitted") {
			t.Skip("nft -c not permitted here (container without CAP_NET_ADMIN)")
		}
		t.Fatalf("nft -c rejected the script: %v\n%s", err, out)
	}
}
