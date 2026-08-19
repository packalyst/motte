package fleet

import "testing"

func TestSanitizeMachineName(t *testing.T) {
	cases := map[string]string{
		"ubuntu24":                       "ubuntu24",
		"web-01.example.com":             "web-01.example.com",
		"  spaced  name  ":               "spaced  name",
		`<img src=x onerror="steal()">`:  "img srcx onerrorsteal", // all HTML metachars stripped
		"a\nb\tc":                        "abc",                    // control chars stripped
		"":                               "",
	}
	for in, want := range cases {
		if got := sanitizeMachineName(in); got != want {
			t.Errorf("sanitizeMachineName(%q) = %q, want %q", in, got, want)
		}
	}
	// length cap
	long := ""
	for i := 0; i < 200; i++ {
		long += "a"
	}
	if got := sanitizeMachineName(long); len(got) > 64 {
		t.Errorf("name not capped: len=%d", len(got))
	}
	// no XSS metacharacters ever survive
	for _, c := range []string{"<", ">", "\"", "'", "&", "\n", "\t"} {
		if got := sanitizeMachineName("x" + c + "y"); got != "xy" {
			t.Errorf("metachar %q survived: %q", c, got)
		}
	}
}
