// minihelm: renders a Helm chart's templates with Go text/template plus a stdlib-only subset of
// Helm/Sprig functions. Values are passed as JSON (pre-merged). Used only to syntax-check templates
// when the real helm binary is unavailable. toYaml emits JSON (valid YAML).
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"
)

func main() {
	chartDir, valuesFile := os.Args[1], os.Args[2]
	var values map[string]any
	b, _ := os.ReadFile(valuesFile)
	if err := json.Unmarshal(b, &values); err != nil { panic(err) }
	var chart map[string]any
	cb, _ := os.ReadFile(os.Args[3])
	json.Unmarshal(cb, &chart)
	t := template.New("root")
	funcs := template.FuncMap{
		"include": func(name string, data any) (string, error) {
			var buf bytes.Buffer
			err := t.ExecuteTemplate(&buf, name, data)
			return buf.String(), err
		},
		"nindent": func(n int, s string) string {
			pad := strings.Repeat(" ", n)
			return "\n" + pad + strings.ReplaceAll(s, "\n", "\n"+pad)
		},
		"toYaml": func(v any) string { j, _ := json.Marshal(v); return string(j) },
		"toJson": func(v any) string { j, _ := json.Marshal(v); return string(j) },
		"quote":  func(v any) string { return fmt.Sprintf("%q", fmt.Sprint(v)) },
		"sha256sum": func(s string) string { return fmt.Sprintf("%x", sha256.Sum256([]byte(s))) },
		"trunc": func(n int, s string) string { if len(s) > n { return s[:n] }; return s },
		"trimSuffix": func(suf, s string) string { return strings.TrimSuffix(s, suf) },
		"add": func(a, b any) int { return toInt(a) + toInt(b) },
		"fail": func(msg string) (string, error) { return "", errors.New(msg) },
	}
	t.Funcs(funcs)
	files, _ := filepath.Glob(filepath.Join(chartDir, "templates", "*"))
	sort.Strings(files)
	for _, f := range files {
		src, _ := os.ReadFile(f)
		if _, err := t.New(filepath.Base(f)).Parse(string(src)); err != nil { fmt.Fprintln(os.Stderr, "PARSE", err); os.Exit(1) }
	}
	data := map[string]any{
		"Values": values, "Chart": chart,
		"Release": map[string]any{"Name": "qa", "Service": "Helm", "Namespace": "qa"},
	}
	for _, f := range files {
		name := filepath.Base(f)
		if strings.HasPrefix(name, "_") { continue }
		var buf bytes.Buffer
		if err := t.ExecuteTemplate(&buf, name, data); err != nil { fmt.Fprintln(os.Stderr, "EXEC", err); os.Exit(1) }
		out := strings.TrimSpace(buf.String())
		if out != "" { fmt.Printf("---\n# Source: %s\n%s\n", name, out) }
	}
}

func toInt(v any) int {
	switch x := v.(type) {
	case float64: return int(x)
	case int: return x
	}
	return 0
}
