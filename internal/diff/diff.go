// Package diff computes the semantic delta between two IAM policy documents.
package diff

import (
	"github.com/moveeeax/iam-policy-diff/internal/catalog"
	"github.com/moveeeax/iam-policy-diff/internal/policy"
	"github.com/moveeeax/iam-policy-diff/internal/risk"
)

// Result is the semantic diff of two policies.
type Result struct {
	Added   []policy.Permission `json:"added"`
	Removed []policy.Permission `json:"removed"`
	Risks   []risk.Finding      `json:"risks"`
	Summary Summary             `json:"summary"`
}

// Summary holds the headline counts.
type Summary struct {
	Added   int `json:"added"`
	Removed int `json:"removed"`
	Risks   int `json:"risks"`
}

// HasRisks reports whether the new policy introduces any risky permission.
func (r Result) HasRisks() bool { return len(r.Risks) > 0 }

// Compute expands both documents against the catalog and returns the permission
// delta plus risk findings on the added set.
func Compute(oldDoc, newDoc *policy.Document, cat catalog.Catalog) Result {
	oldEff := oldDoc.Expand(cat)
	newEff := newDoc.Expand(cat)

	var added, removed []policy.Permission
	for _, p := range newEff.List() {
		if !oldEff.Has(p) {
			added = append(added, p)
		}
	}
	for _, p := range oldEff.List() {
		if !newEff.Has(p) {
			removed = append(removed, p)
		}
	}
	findings := risk.Analyze(added)
	return Result{
		Added:   added,
		Removed: removed,
		Risks:   findings,
		Summary: Summary{Added: len(added), Removed: len(removed), Risks: len(findings)},
	}
}
