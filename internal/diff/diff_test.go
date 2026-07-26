package diff

import (
	"testing"

	"github.com/moveeeax/iam-policy-diff/internal/catalog"
	"github.com/moveeeax/iam-policy-diff/internal/policy"
)

func mustCat(t *testing.T) catalog.Catalog {
	t.Helper()
	c, err := catalog.New()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return c
}

func parse(t *testing.T, s string) *policy.Document {
	t.Helper()
	d, err := policy.Parse([]byte(s))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return d
}

func TestSemanticNotTextual(t *testing.T) {
	cat := mustCat(t)
	// Same effective grant, different textual form (list order + wildcard).
	oldDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}`)
	newDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:PutObject","s3:GetObject"],"Resource":"*"}]}`)
	r := Compute(oldDoc, newDoc, cat)
	if r.Summary.Added != 0 || r.Summary.Removed != 0 {
		t.Errorf("reordering must be a no-op diff, got +%d -%d", r.Summary.Added, r.Summary.Removed)
	}
}

func TestWildcardExpandsDelta(t *testing.T) {
	cat := mustCat(t)
	oldDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	newDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}`)
	r := Compute(oldDoc, newDoc, cat)
	if r.Summary.Added == 0 {
		t.Fatal("widening s3:GetObject -> s3:* must add permissions")
	}
	if r.Summary.Removed != 0 {
		t.Errorf("nothing should be removed, got %d", r.Summary.Removed)
	}
	// The pre-existing grant is not re-reported as added.
	for _, p := range r.Added {
		if p.Action == "s3:GetObject" {
			t.Error("s3:GetObject already existed and should not be added")
		}
	}
}

func TestRiskFlaggedOnAddition(t *testing.T) {
	cat := mustCat(t)
	oldDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	newDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":["s3:GetObject","iam:PassRole"],"Resource":"*"}]}`)
	r := Compute(oldDoc, newDoc, cat)
	if !r.HasRisks() {
		t.Fatal("adding iam:PassRole must be flagged")
	}
	found := false
	for _, f := range r.Risks {
		if f.Action == "iam:PassRole" {
			found = true
		}
	}
	if !found {
		t.Errorf("iam:PassRole risk not present: %+v", r.Risks)
	}
}

func TestNoRiskOnRemoval(t *testing.T) {
	cat := mustCat(t)
	// Removing a risky permission must NOT be flagged (risk is about additions).
	oldDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"iam:PassRole","Resource":"*"}]}`)
	newDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	r := Compute(oldDoc, newDoc, cat)
	if r.HasRisks() {
		t.Errorf("removing a risky permission should not raise a risk: %+v", r.Risks)
	}
}

func TestResourceScopingChange(t *testing.T) {
	cat := mustCat(t)
	oldDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"arn:aws:s3:::b/*"}]}`)
	newDoc := parse(t, `{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}`)
	r := Compute(oldDoc, newDoc, cat)
	if r.Summary.Added != 1 || r.Summary.Removed != 1 {
		t.Errorf("broadening resource scope should be add+remove, got +%d -%d", r.Summary.Added, r.Summary.Removed)
	}
}
