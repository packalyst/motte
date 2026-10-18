package fleet

import (
	"testing"
	"time"

	"api/internal/router"
)

func TestScopeAllows(t *testing.T) {
	m := Machine{ID: "m1", Tags: []string{"prod", "db"}}
	cases := []struct {
		name string
		p    *router.Principal
		want bool
	}{
		{"nil principal", nil, false},
		{"owner", &router.Principal{Role: "owner"}, true},
		{"admin ignores scope", &router.Principal{Role: "admin", ScopeKind: "host", ScopeValues: "other"}, true},
		{"operator scope all", &router.Principal{Role: "operator", ScopeKind: "all"}, true},
		{"operator empty scope = all", &router.Principal{Role: "operator"}, true},
		{"host match", &router.Principal{Role: "operator", ScopeKind: "host", ScopeValues: "m1,m9"}, true},
		{"host no match", &router.Principal{Role: "operator", ScopeKind: "host", ScopeValues: "m9"}, false},
		{"tag match", &router.Principal{Role: "operator", ScopeKind: "tag", ScopeValues: "db,web"}, true},
		{"tag no match", &router.Principal{Role: "viewer", ScopeKind: "tag", ScopeValues: "web"}, false},
	}
	for _, c := range cases {
		if got := scopeAllows(c.p, m); got != c.want {
			t.Errorf("%s: scopeAllows = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestMachineTagsRoundtrip(t *testing.T) {
	svc := newTestService(t)
	if err := svc.registerMachine(Machine{ID: "m1", Name: "web", CertFP: "sha256:x", EnrolledAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	// Input has whitespace, a duplicate and an empty entry — all normalized away.
	if err := svc.SetMachineTags("m1", []string{"prod", " prod ", "db", ""}); err != nil {
		t.Fatal(err)
	}
	tags, err := svc.machineTags("m1")
	if err != nil {
		t.Fatal(err)
	}
	if len(tags) != 2 || tags[0] != "prod" || tags[1] != "db" {
		t.Fatalf("machineTags = %v, want [prod db]", tags)
	}
	ms, err := svc.ListMachines()
	if err != nil {
		t.Fatal(err)
	}
	if len(ms) != 1 || len(ms[0].Tags) != 2 {
		t.Fatalf("ListMachines tags = %v, want 2 tags", ms)
	}
}
