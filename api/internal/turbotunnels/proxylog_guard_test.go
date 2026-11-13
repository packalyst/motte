package turbotunnels

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var (
	pyString     = regexp.MustCompile(`"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'`)
	secretIdent  = regexp.MustCompile(`\b(password|auth_data|headers)\b`)
	urlObject    = regexp.MustCompile(`\b_?url\b(\.[a-z_]+)?`)
	authIdent    = regexp.MustCompile(`(\bif )?\bauth\b(\.split\("", 1\)\[0\])?`)
	loggerCallAt = regexp.MustCompile(`utils\.logger\.[a-z]+\(`)
)

// logCalls returns the argument text of every utils.logger call in src, string literals emptied.
func logCalls(src string) []string {
	var out []string
	for _, at := range loggerCallAt.FindAllStringIndex(src, -1) {
		depth, end := 1, at[1]
		for ; end < len(src) && depth > 0; end++ {
			switch src[end] {
			case '(':
				depth++
			case ')':
				depth--
			}
		}
		out = append(out, pyString.ReplaceAllString(src[at[1]:end], `""`))
	}
	return out
}

// leaks reports what in one log call could print a secret: a password, the auth string or
// headers, or a whole URL (it can carry user:pass@). A URL's host/port/address, the tunnel's
// username (auth.split(":", 1)[0]) and testing whether there is a login ("if auth") are fine.
func leaks(call string) []string {
	var bad []string
	bad = append(bad, secretIdent.FindAllString(call, -1)...)
	for _, m := range urlObject.FindAllStringSubmatch(call, -1) {
		if m[1] != ".host" && m[1] != ".port" && m[1] != ".address" {
			bad = append(bad, m[0])
		}
	}
	for _, m := range authIdent.FindAllStringSubmatch(call, -1) {
		if m[1] == "" && m[2] == "" {
			bad = append(bad, m[0])
		}
	}
	return bad
}

// The proxy's log lines end up on disk (Docker's log files): none may print what a client typed
// as a password, the tunnel's credentials, or an upstream URL that can carry a login.
func TestProxyLogsNoSecrets(t *testing.T) {
	dir := filepath.Join("..", "..", "..", "containers", "turbotunnels")
	for _, name := range []string{"https.py", "socks.py", "run.py"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		calls := logCalls(string(b))
		if len(calls) == 0 && name != "run.py" {
			t.Fatalf("%s: no log calls found; the guard is not reading it", name)
		}
		for _, c := range calls {
			if bad := leaks(c); len(bad) > 0 {
				t.Errorf("%s: a log line prints %v: %s", name, bad, strings.Join(strings.Fields(c), " "))
			}
		}
	}
}

// The guard itself catches the shapes that leaked before, and lets the safe ones through.
func TestProxyLogGuardCatchesLeaks(t *testing.T) {
	for _, c := range []struct {
		src  string
		leak bool
	}{
		{`utils.logger.warn("[%s] failed: %s:%s" % (n, req.username, req.password))`, true},
		{`utils.logger.warn("over %s failed" % (self._url,))`, true},
		{`utils.logger.info("x %s" % auth_data)`, true},
		{`utils.logger.info("x %s" % auth)`, true},
		{`utils.logger.warn("[%s] Password verify failed" % self.__class__.__name__)`, false},
		{`utils.logger.warn("over %s:%d" % (self._url.host, self._url.port))`, false},
		{`utils.logger.info("USER=%s" % (address[0], auth.split(":", 1)[0]))`, false},
		{`utils.logger.info("USER=%s" % (auth.split(":", 1)[0] if auth else "-"))`, false},
	} {
		calls := logCalls(c.src)
		if len(calls) != 1 {
			t.Fatalf("%s: %d calls", c.src, len(calls))
		}
		if got := len(leaks(calls[0])) > 0; got != c.leak {
			t.Errorf("%s: leak %v, want %v", c.src, got, c.leak)
		}
	}
}
