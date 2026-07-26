// Package catalog provides an AWS IAM action dataset and wildcard expansion.
//
// The catalog is intentionally an interface so the diff engine never touches
// the network: the embedded dataset is a curated subset of real AWS actions,
// but any implementation satisfying Catalog (for example one backed by the
// AWS-published action reference) can be substituted in tests or callers.
package catalog

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

//go:embed actions.json
var embedded []byte

// Catalog resolves IAM action patterns to concrete action names.
type Catalog interface {
	// Expand resolves a pattern such as "s3:Get*", "iam:*" or "*" into the
	// sorted set of concrete "service:Action" names it matches. An unknown
	// service yields an empty slice; a pattern with no glob is returned as-is
	// when it names a real action, so callers still see custom/unknown actions.
	Expand(pattern string) []string
	// Actions returns every known action, sorted.
	Actions() []string
	// Services returns every known service, sorted.
	Services() []string
}

type mapCatalog struct {
	byService map[string][]string // service -> sorted "service:Action" names
	all       []string
}

// New returns the catalog backed by the embedded curated dataset.
func New() (Catalog, error) {
	return fromJSON(embedded)
}

// FromJSON builds a catalog from a {"service": ["Action", ...]} document.
// It is exported so callers and tests can supply their own dataset.
func FromJSON(data []byte) (Catalog, error) {
	return fromJSON(data)
}

func fromJSON(data []byte) (Catalog, error) {
	raw := map[string][]string{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse action catalog: %w", err)
	}
	c := &mapCatalog{byService: make(map[string][]string, len(raw))}
	for svc, actions := range raw {
		svc = strings.ToLower(svc)
		names := make([]string, 0, len(actions))
		for _, a := range actions {
			name := svc + ":" + a
			names = append(names, name)
			c.all = append(c.all, name)
		}
		sort.Strings(names)
		c.byService[svc] = names
	}
	sort.Strings(c.all)
	return c, nil
}

func (c *mapCatalog) Actions() []string {
	out := make([]string, len(c.all))
	copy(out, c.all)
	return out
}

func (c *mapCatalog) Services() []string {
	out := make([]string, 0, len(c.byService))
	for s := range c.byService {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func (c *mapCatalog) Expand(pattern string) []string {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return nil
	}
	// Full wildcard: every action across every service.
	if pattern == "*" {
		return c.Actions()
	}
	// IAM patterns are case-insensitive on the action portion.
	svc, action, ok := splitAction(pattern)
	if !ok {
		return nil
	}
	svc = strings.ToLower(svc)
	names, known := c.byService[svc]
	if !known {
		// Unknown service with a concrete action: surface it verbatim so the
		// diff still reports it rather than silently dropping it.
		if !strings.Contains(action, "*") && !strings.Contains(action, "?") {
			return []string{svc + ":" + action}
		}
		return nil
	}
	if action == "*" {
		out := make([]string, len(names))
		copy(out, names)
		return out
	}
	if !strings.ContainsAny(action, "*?") {
		// Concrete action: return it if known, else still surface it verbatim.
		want := svc + ":" + strings.ToLower(action)
		for _, n := range names {
			if strings.EqualFold(n, want) {
				return []string{n}
			}
		}
		return []string{svc + ":" + action}
	}
	var out []string
	for _, n := range names {
		_, act, _ := splitAction(n)
		if globMatch(action, act) {
			out = append(out, n)
		}
	}
	return out
}

func splitAction(s string) (service, action string, ok bool) {
	i := strings.Index(s, ":")
	if i < 0 {
		return "", "", false
	}
	return s[:i], s[i+1:], true
}

// globMatch reports whether name matches an IAM glob pattern (case-insensitive,
// where '*' matches any run and '?' matches a single character).
func globMatch(pattern, name string) bool {
	return globMatchFold(strings.ToLower(pattern), strings.ToLower(name))
}

// globMatchFold is an iterative glob matcher with backtracking, so it stays
// linear-ish without regexp allocation on the hot expansion path.
func globMatchFold(pat, s string) bool {
	var (
		px, sx         int
		starPx, starSx = -1, -1
	)
	for sx < len(s) {
		if px < len(pat) && (pat[px] == '?' || pat[px] == s[sx]) {
			px++
			sx++
			continue
		}
		if px < len(pat) && pat[px] == '*' {
			starPx = px
			starSx = sx
			px++
			continue
		}
		if starPx >= 0 {
			px = starPx + 1
			starSx++
			sx = starSx
			continue
		}
		return false
	}
	for px < len(pat) && pat[px] == '*' {
		px++
	}
	return px == len(pat)
}

// GlobMatch is the exported resource/ARN matcher used across packages.
func GlobMatch(pattern, name string) bool {
	if pattern == name {
		return true
	}
	return globMatchFold(strings.ToLower(pattern), strings.ToLower(name))
}
