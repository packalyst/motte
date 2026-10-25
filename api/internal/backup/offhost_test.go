package backup

import (
	"context"
	"testing"
	"time"
)

func TestOffhostMaskAndMerge(t *testing.T) {
	stored := OffhostConfig{
		Passphrase: "correct horse battery staple",
		Destinations: []Destination{
			{ID: "d1", Type: "s3", AccessKey: "AK", SecretKey: "SK-secret"},
			{ID: "d2", Type: "sftp", User: "u", Password: "pw-secret", HostKey: "ssh-ed25519 AAAA..."},
		},
	}

	// masked() hides every secret behind the placeholder but keeps non-secrets.
	m := stored.masked()
	if m.Passphrase != redactedSecret {
		t.Errorf("passphrase not masked: %q", m.Passphrase)
	}
	if m.Destinations[0].SecretKey != redactedSecret || m.Destinations[1].Password != redactedSecret {
		t.Error("destination secrets not masked")
	}
	if m.Destinations[0].AccessKey != "AK" || m.Destinations[1].HostKey == "" {
		t.Error("non-secret fields should survive masking")
	}

	// Saving the masked config back must preserve the real secrets (placeholder = keep).
	merged := mergeSecrets(m, stored)
	if merged.Passphrase != stored.Passphrase {
		t.Errorf("merge lost passphrase: %q", merged.Passphrase)
	}
	if merged.Destinations[0].SecretKey != "SK-secret" || merged.Destinations[1].Password != "pw-secret" {
		t.Error("merge lost destination secrets")
	}

	// Explicitly clearing a secret ("") must clear it.
	cleared := m
	cleared.Passphrase = ""
	if got := mergeSecrets(cleared, stored).Passphrase; got != "" {
		t.Errorf("empty passphrase should clear, got %q", got)
	}
}

func TestOffhostValidate(t *testing.T) {
	// Weak/short passphrase rejected (reuses ValidatePassphrase).
	if err := (OffhostConfig{Passphrase: "short", Destinations: []Destination{{Type: "s3"}}}).validate(); err == nil {
		t.Error("expected weak passphrase to fail")
	}
	// Good passphrase but incomplete S3 dest.
	bad := OffhostConfig{Passphrase: "correct horse battery staple!", Destinations: []Destination{{Type: "s3", Endpoint: "s3.x"}}}
	if err := bad.validate(); err == nil {
		t.Error("expected incomplete S3 destination to fail")
	}
	// Fully specified passes.
	ok := OffhostConfig{
		Passphrase:   "correct horse battery staple!",
		Destinations: []Destination{{Type: "s3", Endpoint: "s3.x", Bucket: "b", AccessKey: "AK", SecretKey: "SK"}},
	}
	if err := ok.validate(); err != nil {
		t.Errorf("valid config rejected: %v", err)
	}
}

// fakeBackend records deletions so prune behaviour is testable without a network.
type fakeBackend struct {
	objs    []remoteObject
	removed []string
}

func (f *fakeBackend) put(context.Context, string, string) error { return nil }
func (f *fakeBackend) get(context.Context, string, string) error { return nil }
func (f *fakeBackend) list(context.Context) ([]remoteObject, error) {
	return f.objs, nil
}
func (f *fakeBackend) remove(_ context.Context, name string) error {
	f.removed = append(f.removed, name)
	return nil
}
func (f *fakeBackend) learnedHostKey() string { return "" }
func (f *fakeBackend) close() error           { return nil }

func TestPruneKeepN(t *testing.T) {
	base := time.Now()
	f := &fakeBackend{objs: []remoteObject{
		{Name: "motte-3.wgbackup", ModTime: base.Add(3 * time.Hour)},
		{Name: "motte-1.wgbackup", ModTime: base.Add(1 * time.Hour)},
		{Name: "motte-4.wgbackup", ModTime: base.Add(4 * time.Hour)},
		{Name: "motte-2.wgbackup", ModTime: base.Add(2 * time.Hour)},
	}}
	if err := pruneKeepN(context.Background(), f, 2); err != nil {
		t.Fatal(err)
	}
	// Keeps the 2 newest (4h, 3h); deletes the 2 oldest (2h, 1h).
	if len(f.removed) != 2 {
		t.Fatalf("expected 2 removals, got %v", f.removed)
	}
	for _, name := range f.removed {
		if name != "motte-2.wgbackup" && name != "motte-1.wgbackup" {
			t.Errorf("pruned the wrong archive: %s", name)
		}
	}

	// keepN=0 keeps everything.
	f2 := &fakeBackend{objs: f.objs}
	if err := pruneKeepN(context.Background(), f2, 0); err != nil {
		t.Fatal(err)
	}
	if len(f2.removed) != 0 {
		t.Errorf("keepN=0 should delete nothing, got %v", f2.removed)
	}
}
