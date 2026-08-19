package fleet

import (
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"
)

// archAlias maps `uname -m` values to our release arch suffixes.
var archAlias = map[string]string{
	"x86_64": "amd64", "amd64": "amd64",
	"aarch64": "arm64", "arm64": "arm64",
}

// HandleInstallScript serves a SELF-EXTRACTING install script for a valid token.
// GET /agent/{token}?arch=<uname -m>
//
// The returned script carries the agent binary (for the requested arch), the manifest,
// and the real installer — all base64-embedded — plus panel URL + CA fingerprint +
// token spliced in. It decodes them to a tempdir and runs the bundled installer with
// --binary/--manifest/--panel/--ca-fp/--token, so ALL install logic stays in install.sh
// (no duplication). The assets are pulled from the latest GitHub release and cached on
// the panel (see agentCache) — the repo carries no binaries. On a bad token/arch or a
// cache/fetch failure it returns a runnable error script (the caller is piping to sh),
// so the failure prints cleanly instead of a raw HTTP error.
//
// Registered on the main api router (public, no session — the new box has no cert or
// login yet; the one-time token in the path is the credential) and published over
// Traefik/443 on the panel domain, so the download rides the panel's real cert plus the
// fleet route's rate-limit/blocklist middleware. The token peeked here is consumed later,
// at /enroll on the mTLS listener.
func (s *Service) HandleInstallScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")

	token := r.PathValue("token")
	if !s.tokenIsLive(token) {
		writeErrorScript(w, "enrollment token is invalid, already used, or expired.\nGenerate a fresh one in the panel (Machines -> Add a machine).")
		return
	}
	arch, ok := archAlias[strings.ToLower(strings.TrimSpace(r.URL.Query().Get("arch")))]
	if !ok {
		writeErrorScript(w, fmt.Sprintf("unsupported CPU architecture %q (need x86_64/amd64 or aarch64/arm64).", r.URL.Query().Get("arch")))
		return
	}

	bin, manifest, installer, err := s.agentCache.Get(r.Context(), arch)
	if err != nil {
		writeErrorScript(w, "panel could not fetch the agent from the release — check the panel's internet access and that a release is published.")
		return
	}

	// Where the agent will dial for mTLS (enroll/report/commands). Served via Traefik on
	// 443, so r.Host is the domain WITHOUT the fleet port — build it from the configured
	// domain + the fleet listener port. Fall back to r.Host only if no domain is set
	// (direct :6444 access, e.g. a bare-IP setup).
	panelURL := "https://" + r.Host
	if s.sslDomain != "" {
		panelURL = fmt.Sprintf("https://%s:%d", s.sslDomain, s.effectivePort())
	}

	script := renderInstallScript(installScriptData{
		PanelURL:      panelURL,
		CAFingerprint: s.ca.Fingerprint(),
		Token:         token,
		BinaryB64:     b64(bin),
		ManifestB64:   b64(manifest),
		InstallerB64:  b64(installer),
	})
	_, _ = w.Write([]byte(script))
}

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

type installScriptData struct {
	PanelURL      string
	CAFingerprint string
	Token         string
	BinaryB64     string
	ManifestB64   string
	InstallerB64  string
}

// renderInstallScript builds the self-extracting POSIX-sh script. Payloads are
// base64-embedded (not raw) so the installer's own heredocs can't clash with ours.
func renderInstallScript(d installScriptData) string {
	var b strings.Builder
	b.WriteString("#!/bin/sh\n")
	b.WriteString("# wgscout self-extracting installer — served by the panel, fully self-contained.\n")
	b.WriteString("set -eu\n")
	b.WriteString("TMP=$(mktemp -d)\n")
	b.WriteString(`trap 'rm -rf "$TMP"' EXIT` + "\n")
	b.WriteString("command -v base64 >/dev/null 2>&1 || { echo 'error: base64 not found' >&2; exit 1; }\n\n")

	b.WriteString(`base64 -d > "$TMP/wgscout" <<'__WGSCOUT_BIN__'` + "\n")
	b.WriteString(d.BinaryB64 + "\n__WGSCOUT_BIN__\n\n")

	b.WriteString(`base64 -d > "$TMP/manifest.json" <<'__WGSCOUT_MAN__'` + "\n")
	b.WriteString(d.ManifestB64 + "\n__WGSCOUT_MAN__\n\n")

	b.WriteString(`base64 -d > "$TMP/install.sh" <<'__WGSCOUT_SH__'` + "\n")
	b.WriteString(d.InstallerB64 + "\n__WGSCOUT_SH__\n\n")

	b.WriteString(`chmod +x "$TMP/wgscout"` + "\n")
	// Hand off to the real installer with the binary/manifest local and the enrollment
	// params baked in. "$@" forwards any extra flags the operator appended (e.g. --live).
	fmt.Fprintf(&b, "sh \"$TMP/install.sh\" install \\\n"+
		"  --binary \"$TMP/wgscout\" --manifest \"$TMP/manifest.json\" \\\n"+
		"  --panel %s --ca-fp %s --token %s \"$@\"\n",
		shQuote(d.PanelURL), shQuote(d.CAFingerprint), shQuote(d.Token))
	return b.String()
}

// writeErrorScript returns a tiny script that prints an error and exits non-zero, so a
// `curl … | sudo sh` surfaces the problem instead of silently running nothing.
func writeErrorScript(w http.ResponseWriter, msg string) {
	fmt.Fprintf(w, "#!/bin/sh\n"+
		"echo >&2\n"+
		"echo '  ┌─ wgscout install failed ─────────────────────────────' >&2\n"+
		"printf '  │ %%s\\n' %s >&2\n"+
		"echo '  └──────────────────────────────────────────────────────' >&2\n"+
		"exit 1\n", shQuote(msg))
}

// shQuote single-quotes a value for safe embedding in the generated sh script.
func shQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
