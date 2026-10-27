package adguard

import (
	"net/http"
	"strings"
	"testing"
)

// A bad list anywhere in the request stops the whole add before AdGuard is called.
func TestFilterAddRejectsBeforeAdGuard(t *testing.T) {
	good := `{"name":"AdGuard DNS filter","url":"https://adguardteam.github.io/x.txt"}`
	for name, bad := range map[string]string{
		"private address": `{"name":"x","url":"https://192.168.1.1/list.txt"}`,
		"this server":     `{"name":"x","url":"https://localhost:8099/api"}`,
		"vpn address":     `{"name":"x","url":"https://100.64.0.1/list.txt"}`,
		"not https":       `{"name":"x","url":"http://lists.example.com/x.txt"}`,
		"local file":      `{"name":"x","url":"/etc/passwd"}`,
		"login":           `{"name":"x","url":"https://u:p@lists.example.com/x.txt"}`,
		"no name":         `{"name":"  ","url":"https://lists.example.com/x.txt"}`,
		"control char":    `{"name":"a\nb","url":"https://lists.example.com/x.txt"}`,
		"long name":       `{"name":"` + strings.Repeat("a", 101) + `","url":"https://lists.example.com/x.txt"}`,
	} {
		s, calls := rewriteService(t, 0)
		w := httptestFiltering(s, `{"action":"add","filters":[`+good+`,`+bad+`]}`)
		if w.Code != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", name, w.Code)
		}
		if len(*calls) != 0 {
			t.Errorf("%s: %d call(s) reached AdGuard", name, len(*calls))
		}
	}
}

func TestFilterAddSendsCleanValues(t *testing.T) {
	s, calls := rewriteService(t, 0)
	w := httptestFiltering(s, `{"action":"add","filters":[{"name":"  OISD Big ","url":" https://big.oisd.nl "}]}`)
	if w.Code != http.StatusOK || len(*calls) != 1 {
		t.Fatalf("status %d, %d call(s)", w.Code, len(*calls))
	}
	c := (*calls)[0]
	if c.path != "/control/filtering/add_url" || c.body["name"] != "OISD Big" || c.body["url"] != "https://big.oisd.nl" {
		t.Fatalf("call = %s %v", c.path, c.body)
	}
}

// Remove and toggle act on lists AdGuard already has (maybe added there, over http): only a light check.
func TestFilterRemoveToggleChecks(t *testing.T) {
	for body, want := range map[string]int{
		`{"action":"remove","url":"http://old.example.com/list.txt"}`:                     http.StatusOK,
		`{"action":"remove","url":""}`:                                                    http.StatusBadRequest,
		`{"action":"remove","url":"https://a.example/x\n"}`:                               http.StatusBadRequest,
		`{"action":"toggle","url":"https://a.example/x","name":"A","enabled":false}`:      http.StatusOK,
		`{"action":"toggle","url":"https://a.example/x","enabled":false}`:                 http.StatusBadRequest, // no name: set_url would blank it
		`{"action":"toggle","url":"https://a.example/x","name":"A"}`:                      http.StatusBadRequest,
		`{"action":"toggle","url":"https://a.example/x","name":"A\u0007","enabled":true}`: http.StatusBadRequest,
	} {
		s, calls := rewriteService(t, 0)
		w := httptestFiltering(s, body)
		if w.Code != want {
			t.Errorf("%s: status %d, want %d", body, w.Code, want)
		}
		if want != http.StatusOK && len(*calls) != 0 {
			t.Errorf("%s: reached AdGuard", body)
		}
	}
}
