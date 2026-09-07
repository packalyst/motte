package server

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

// pkt frames s as a git pkt-line (4-hex length prefix including the 4 length bytes).
func pkt(s string) string { return fmt.Sprintf("%04x%s", len(s)+4, s) }

// TestParseGitRefs parses a realistic git-upload-pack v1 advertisement, including the
// service header, the first ref's NUL-separated capabilities, and the flush packets.
func TestParseGitRefs(t *testing.T) {
	head := "1111111111111111111111111111111111111111"
	main := "2222222222222222222222222222222222222222"
	dev := "3333333333333333333333333333333333333333"

	var b strings.Builder
	b.WriteString(pkt("# service=git-upload-pack\n"))
	b.WriteString("0000") // flush after the service line
	b.WriteString(pkt(head + " HEAD\x00multi_ack symref=HEAD:refs/heads/main agent=git/2.40\n"))
	b.WriteString(pkt(main + " refs/heads/main\n"))
	b.WriteString(pkt(dev + " refs/heads/dev\n"))
	b.WriteString("0000")

	refs := parseGitRefs([]byte(b.String()))
	if refs["HEAD"] != head {
		t.Errorf("HEAD = %q, want %q", refs["HEAD"], head)
	}
	if refs["refs/heads/main"] != main {
		t.Errorf("main = %q, want %q", refs["refs/heads/main"], main)
	}
	if refs["refs/heads/dev"] != dev {
		t.Errorf("dev = %q, want %q", refs["refs/heads/dev"], dev)
	}
}

// TestParseGitRefsMalformed: garbage/truncated input yields no refs and never panics.
func TestParseGitRefsMalformed(t *testing.T) {
	for _, in := range []string{
		"",
		"zzzz",                        // non-hex length
		"0010short",                   // length claims more bytes than present
		pkt("nothexsha refs/heads/x"), // ref line without a 40-hex sha
	} {
		if refs := parseGitRefs([]byte(in)); len(refs) != 0 {
			t.Errorf("parseGitRefs(%q) = %v, want empty", in, refs)
		}
	}
}

// TestFetchRemoteTipRejectsNonHTTPS: only https is ever contacted (blocks ext::/file:///ssh).
func TestFetchRemoteTipRejectsNonHTTPS(t *testing.T) {
	for _, repo := range []string{
		"http://github.com/a/b",
		"ssh://git@github.com/a/b",
		"ext::sh -c whoami",
		"file:///etc/passwd",
		"::bad",
	} {
		if _, err := fetchRemoteTip(context.Background(), repo, "main"); err == nil {
			t.Errorf("fetchRemoteTip(%q) should reject non-https", repo)
		}
	}
}
