package helper

import "testing"

func TestNormalizeTags(t *testing.T) {
	got, err := NormalizeTags([]string{" prod ", "prod", "", "db-1"}, "")
	if err != nil || len(got) != 2 || got[0] != "prod" || got[1] != "db-1" {
		t.Fatalf("got %v, %v", got, err)
	}
	if got, err := NormalizeTags([]string{"tag:server"}, "tag:"); err != nil || got[0] != "tag:server" {
		t.Fatalf("headscale tag rejected: %v, %v", got, err)
	}
	for _, bad := range [][]string{{"a,b"}, {"1abc"}, {"has space"}, {"tag:"}, {"server"}} {
		prefix := ""
		if bad[0] == "tag:" || bad[0] == "server" {
			prefix = "tag:"
		}
		if _, err := NormalizeTags(bad, prefix); err == nil {
			t.Errorf("%q (prefix %q) accepted", bad, prefix)
		}
	}
	many := make([]string, MaxTags+1)
	for i := range many {
		many[i] = "t" + string(rune('a'+i))
	}
	if _, err := NormalizeTags(many, ""); err == nil {
		t.Error("more than MaxTags accepted")
	}
}
