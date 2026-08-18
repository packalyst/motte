package geolocation

import (
	"math/big"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// mapped16Dec: decimal of the 16-byte ::ffff:v4 form (how IP2Proxy IPv6 CSVs number IPv4).
func mapped16Dec(ip string) string {
	a := netip.MustParseAddr(ip).As16()
	return new(big.Int).SetBytes(a[:]).String()
}

// plain32Dec: plain uint32 numbering (how the LITE ASN CSV numbers IPv4).
func plain32Dec(ip string) string {
	a := netip.MustParseAddr(ip).As4()
	return strconv.FormatUint(uint64(a[0])<<24|uint64(a[1])<<16|uint64(a[2])<<8|uint64(a[3]), 10)
}

func writeCSV(t *testing.T, name, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestASNIndexBuildAndLookup(t *testing.T) {
	csv := `"` + plain32Dec("1.0.0.0") + `","` + plain32Dec("1.0.0.255") + `","1.0.0.0/24","13335","CLOUDFLARENET"
"` + plain32Dec("1.0.1.0") + `","` + plain32Dec("1.0.1.255") + `","1.0.1.0/24","0","-"
"` + plain32Dec("1.1.1.0") + `","` + plain32Dec("1.1.1.255") + `","1.1.1.0/24","13335","CLOUDFLARENET"`
	path := writeCSV(t, "IP2LOCATION-LITE-ASN.CSV", csv)

	tbl := newRangeTable(asnCodec)
	if err := tbl.load(path, parseASNRow(newInterner())); err != nil {
		t.Fatal(err)
	}

	// the .idx / .strings files were compiled next to the CSV
	if !fileExists(swapExt(path, ".idx")) || !fileExists(swapExt(path, ".strings")) {
		t.Fatal("index files not created")
	}
	// row 2 (asn 0, name "-") is dropped → 2 ranges
	if tbl.count() != 2 {
		t.Fatalf("count = %d, want 2", tbl.count())
	}

	// lookups (found via the plain-uint32 second attempt)
	if v, ok := tbl.lookup("1.0.0.50"); !ok || v.asn != 13335 || v.name != "CLOUDFLARENET" {
		t.Fatalf("1.0.0.50 → %+v ok=%v", v, ok)
	}
	if v, ok := tbl.lookup("1.1.1.1"); !ok || v.asn != 13335 {
		t.Fatalf("1.1.1.1 → %+v ok=%v", v, ok)
	}
	if _, ok := tbl.lookup("1.0.1.5"); ok { // dropped range
		t.Fatal("1.0.1.5 should be unknown (asn 0 row dropped)")
	}
	if _, ok := tbl.lookup("8.8.8.8"); ok {
		t.Fatal("8.8.8.8 should be unknown")
	}

	// ASN → CIDR expansion via iterate
	cidrs := asnV4CIDRs(tbl, 13335)
	got := map[string]bool{}
	for _, c := range cidrs {
		got[c] = true
	}
	if !got["1.0.0.0/24"] || !got["1.1.1.0/24"] {
		t.Fatalf("ASN 13335 CIDRs = %v", cidrs)
	}

	// second load must NOT rebuild (idx newer than csv)
	if needBuild(path, swapExt(path, ".idx")) {
		t.Fatal("should not need rebuild when idx is fresh")
	}
	// touch CSV into the future → needs rebuild
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(path, future, future)
	if !needBuild(path, swapExt(path, ".idx")) {
		t.Fatal("should need rebuild after CSV changes")
	}
}

func TestProxyIndexLookup(t *testing.T) {
	csv := `"` + mapped16Dec("5.5.5.0") + `","` + mapped16Dec("5.5.5.255") + `","VPN"
"` + mapped16Dec("6.6.6.0") + `","` + mapped16Dec("6.6.6.255") + `","-"`
	path := writeCSV(t, "IP2PROXY-LITE-PX1.IPV6.CSV", csv)

	tbl := newRangeTable(proxyCodec)
	cols := proxyColumns{usageType: -1, threat: -1, fraud: -1} // PX1: only proxy_type
	if err := tbl.load(path, parseProxyRow(newInterner(), cols)); err != nil {
		t.Fatal(err)
	}
	if tbl.count() != 1 { // the "-" proxy_type row is dropped
		t.Fatalf("count = %d, want 1", tbl.count())
	}
	if v, ok := tbl.lookup("5.5.5.5"); !ok || v.ptype != "VPN" {
		t.Fatalf("5.5.5.5 → %+v ok=%v", v, ok)
	}
	if _, ok := tbl.lookup("6.6.6.6"); ok {
		t.Fatal("6.6.6.6 should be unknown (dropped)")
	}
	if _, ok := tbl.lookup("9.9.9.9"); ok {
		t.Fatal("9.9.9.9 should be unknown")
	}
}

func TestReloadReplacesData(t *testing.T) {
	path := writeCSV(t, "IP2LOCATION-LITE-ASN.CSV",
		`"`+plain32Dec("2.0.0.0")+`","`+plain32Dec("2.0.0.255")+`","2.0.0.0/24","111","OLDNET"`)
	tbl := newRangeTable(asnCodec)
	if err := tbl.load(path, parseASNRow(newInterner())); err != nil {
		t.Fatal(err)
	}
	if v, _ := tbl.lookup("2.0.0.1"); v.asn != 111 {
		t.Fatalf("pre-reload asn = %d", v.asn)
	}
	// rewrite CSV with different data + future mtime, reload
	future := time.Now().Add(time.Hour)
	os.WriteFile(path, []byte(`"`+plain32Dec("2.0.0.0")+`","`+plain32Dec("2.0.0.255")+`","2.0.0.0/24","222","NEWNET"`), 0o644)
	os.Chtimes(path, future, future)
	if err := tbl.load(path, parseASNRow(newInterner())); err != nil {
		t.Fatal(err)
	}
	if v, ok := tbl.lookup("2.0.0.1"); !ok || v.asn != 222 || v.name != "NEWNET" {
		t.Fatalf("post-reload → %+v ok=%v", v, ok)
	}
}
