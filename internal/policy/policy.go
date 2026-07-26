// Package policy parses AWS IAM policy documents and expands them into the
// concrete set of effective permissions they grant.
package policy

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/moveeeax/iam-policy-diff/internal/catalog"
)

// stringSet is a JSON scalar-or-array: IAM lets a field be a bare string or a
// list of strings. It always unmarshals into a slice.
type stringSet []string

func (s *stringSet) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		*s = nil
		return nil
	}
	if b[0] == '[' {
		var arr []string
		if err := json.Unmarshal(b, &arr); err != nil {
			return err
		}
		*s = arr
		return nil
	}
	var one string
	if err := json.Unmarshal(b, &one); err != nil {
		return err
	}
	*s = []string{one}
	return nil
}

// Statement is a single IAM statement. Condition values may be string or list,
// so the innermost type is stringSet.
type Statement struct {
	Sid         string                          `json:"Sid,omitempty"`
	Effect      string                          `json:"Effect"`
	Action      stringSet                       `json:"Action,omitempty"`
	NotAction   stringSet                       `json:"NotAction,omitempty"`
	Resource    stringSet                       `json:"Resource,omitempty"`
	NotResource stringSet                       `json:"NotResource,omitempty"`
	Condition   map[string]map[string]stringSet `json:"Condition,omitempty"`
}

// Document is an IAM policy document. Statement may be a single object or array.
type Document struct {
	Version   string      `json:"Version,omitempty"`
	ID        string      `json:"Id,omitempty"`
	Statement []Statement `json:"-"`
}

// rawDoc lets us accept Statement as object or array.
type rawDoc struct {
	Version   string          `json:"Version"`
	ID        string          `json:"Id"`
	Statement json.RawMessage `json:"Statement"`
}

// Parse decodes an IAM policy document from JSON.
func Parse(data []byte) (*Document, error) {
	var rd rawDoc
	if err := json.Unmarshal(data, &rd); err != nil {
		return nil, fmt.Errorf("parse policy document: %w", err)
	}
	doc := &Document{Version: rd.Version, ID: rd.ID}
	if len(rd.Statement) == 0 {
		return nil, fmt.Errorf("policy has no Statement block")
	}
	trimmed := strings.TrimSpace(string(rd.Statement))
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(rd.Statement, &doc.Statement); err != nil {
			return nil, fmt.Errorf("parse statements: %w", err)
		}
	} else {
		var one Statement
		if err := json.Unmarshal(rd.Statement, &one); err != nil {
			return nil, fmt.Errorf("parse statement: %w", err)
		}
		doc.Statement = []Statement{one}
	}
	for i := range doc.Statement {
		eff := titleWord(strings.TrimSpace(doc.Statement[i].Effect))
		if eff != "Allow" && eff != "Deny" {
			return nil, fmt.Errorf("statement %d has invalid Effect %q", i, doc.Statement[i].Effect)
		}
		doc.Statement[i].Effect = eff
	}
	return doc, nil
}

// titleWord upper-cases the first rune and lower-cases the rest of a single word.
func titleWord(s string) string {
	if s == "" {
		return s
	}
	s = strings.ToLower(s)
	return strings.ToUpper(s[:1]) + s[1:]
}

// Permission is one concrete effective grant: an expanded action against a
// resource, carrying the canonical condition so that a scoping change registers
// as a distinct permission.
type Permission struct {
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Condition string `json:"condition,omitempty"`
}

// Key is the identity of a permission for set operations.
func (p Permission) Key() string {
	return p.Action + "\x00" + p.Resource + "\x00" + p.Condition
}

func (p Permission) String() string {
	s := p.Action + " on " + p.Resource
	if p.Condition != "" {
		s += " if " + p.Condition
	}
	return s
}

// Effective is the set of permissions a document grants after wildcard
// expansion and explicit-Deny subtraction.
type Effective struct {
	perms map[string]Permission
}

// List returns the permissions sorted deterministically.
func (e *Effective) List() []Permission {
	out := make([]Permission, 0, len(e.perms))
	for _, p := range e.perms {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		if out[i].Resource != out[j].Resource {
			return out[i].Resource < out[j].Resource
		}
		return out[i].Condition < out[j].Condition
	})
	return out
}

// Has reports whether the effective set contains an identical permission.
func (e *Effective) Has(p Permission) bool {
	_, ok := e.perms[p.Key()]
	return ok
}

// Expand computes the effective permission set for the document.
//
// Model: every Allow statement contributes (action x resource) grants tagged
// with its canonical condition. An explicit *unconditional* Deny removes any
// matching (action, resource) grant regardless of condition, mirroring AWS's
// "explicit deny always wins". Conditional denies are left in place because we
// cannot evaluate the request context here.
func (d *Document) Expand(cat catalog.Catalog) *Effective {
	type denyRule struct {
		action   string
		resource string
	}
	var denies []denyRule
	allow := map[string]Permission{}

	for _, st := range d.Statement {
		actions := expandActions(st, cat)
		resources := statementResources(st)
		if st.Effect == "Deny" {
			if len(st.Condition) > 0 {
				continue // conditional deny: cannot evaluate, keep allows
			}
			for _, a := range actions {
				for _, r := range resources {
					denies = append(denies, denyRule{a, r})
				}
			}
			continue
		}
		cond := canonicalCondition(st.Condition)
		for _, a := range actions {
			for _, r := range resources {
				p := Permission{Action: a, Resource: r, Condition: cond}
				allow[p.Key()] = p
			}
		}
	}

	if len(denies) > 0 {
		for key, p := range allow {
			for _, dr := range denies {
				if actionMatch(dr.action, p.Action) && resourceMatch(dr.resource, p.Resource) {
					delete(allow, key)
					break
				}
			}
		}
	}
	return &Effective{perms: allow}
}

func expandActions(st Statement, cat catalog.Catalog) []string {
	if len(st.NotAction) > 0 {
		excluded := map[string]bool{}
		for _, pat := range st.NotAction {
			for _, a := range cat.Expand(pat) {
				excluded[a] = true
			}
		}
		var out []string
		for _, a := range cat.Actions() {
			if !excluded[a] {
				out = append(out, a)
			}
		}
		return out
	}
	seen := map[string]bool{}
	var out []string
	for _, pat := range st.Action {
		for _, a := range cat.Expand(pat) {
			if !seen[a] {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

func statementResources(st Statement) []string {
	if len(st.NotResource) > 0 {
		var out []string
		for _, r := range st.NotResource {
			out = append(out, "NOT("+r+")")
		}
		if len(out) == 0 {
			return []string{"NOT(*)"}
		}
		return out
	}
	if len(st.Resource) == 0 {
		return []string{"*"}
	}
	return append([]string(nil), st.Resource...)
}

func actionMatch(pattern, action string) bool {
	return catalog.GlobMatch(pattern, action)
}

func resourceMatch(pattern, resource string) bool {
	if strings.HasPrefix(pattern, "NOT(") || strings.HasPrefix(resource, "NOT(") {
		return pattern == resource
	}
	return catalog.GlobMatch(pattern, resource)
}

// canonicalCondition renders a Condition block into a stable string so logically
// identical conditions compare equal regardless of key ordering.
func canonicalCondition(c map[string]map[string]stringSet) string {
	if len(c) == 0 {
		return ""
	}
	ops := make([]string, 0, len(c))
	for op := range c {
		ops = append(ops, op)
	}
	sort.Strings(ops)
	var b strings.Builder
	for i, op := range ops {
		if i > 0 {
			b.WriteByte(';')
		}
		b.WriteString(op)
		b.WriteByte('{')
		keys := make([]string, 0, len(c[op]))
		for k := range c[op] {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for j, k := range keys {
			if j > 0 {
				b.WriteByte(',')
			}
			vals := append([]string(nil), c[op][k]...)
			sort.Strings(vals)
			b.WriteString(k)
			b.WriteByte('=')
			b.WriteString(strings.Join(vals, "|"))
		}
		b.WriteByte('}')
	}
	return b.String()
}
