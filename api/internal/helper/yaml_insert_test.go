package helper

import (
	"reflect"
	"testing"
)

func TestInsertYAMLArrayItem(t *testing.T) {
	doc := "r:\n  m:\n    - a\n    - redirect\n"
	items := func(c string) []string {
		v, err := GetYAMLPath(c, "r.m")
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, x := range v.([]interface{}) {
			out = append(out, x.(string))
		}
		return out
	}
	for _, c := range []struct {
		value, before string
		want          []string
	}{
		{"g", "redirect", []string{"a", "g", "redirect"}},
		{"g", "", []string{"a", "redirect", "g"}},
		{"g", "missing", []string{"a", "redirect", "g"}},
		{"a", "redirect", []string{"a", "redirect"}}, // already there
	} {
		got, err := InsertYAMLArrayItem(doc, "r.m", c.value, c.before)
		if err != nil {
			t.Fatal(err)
		}
		if g := items(got); !reflect.DeepEqual(g, c.want) {
			t.Errorf("insert %q before %q: %v, want %v", c.value, c.before, g, c.want)
		}
	}
}
