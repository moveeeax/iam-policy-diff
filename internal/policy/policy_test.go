package policy

import (
	"testing"

	"github.com/moveeeax/iam-policy-diff/internal/catalog"
)

func mustCatalog(t *testing.T) catalog.Catalog {
	t.Helper()
	c, err := catalog.New()
	if err != nil {
		t.Fatalf("catalog: %v", err)
	}
	return c
}

func TestParseScalarAndArray(t *testing.T) {
	// Action as scalar, Resource as scalar, single statement object.
	doc, err := Parse([]byte(`{
		"Version": "2012-10-17",
		"Statement": {"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}
	}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(doc.Statement) != 1 {
		t.Fatalf("want 1 statement, got %d", len(doc.Statement))
	}
	st := doc.Statement[0]
	if len(st.Action) != 1 || st.Action[0] != "s3:GetObject" {
		t.Errorf("scalar action not normalized: %v", st.Action)
	}
	if len(st.Resource) != 1 || st.Resource[0] != "*" {
		t.Errorf("scalar resource not normalized: %v", st.Resource)
	}
}

func TestParseEffectNormalization(t *testing.T) {
	doc, err := Parse([]byte(`{"Statement":[{"Effect":"allow","Action":"s3:GetObject","Resource":"*"}]}`))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if doc.Statement[0].Effect != "Allow" {
		t.Errorf("effect not title-cased: %q", doc.Statement[0].Effect)
	}
}

func TestParseInvalidEffect(t *testing.T) {
	_, err := Parse([]byte(`{"Statement":[{"Effect":"Maybe","Action":"s3:GetObject","Resource":"*"}]}`))
	if err == nil {
		t.Fatal("expected error on invalid effect")
	}
}

func TestExpandWildcard(t *testing.T) {
	cat := mustCatalog(t)
	doc, _ := Parse([]byte(`{"Statement":[{"Effect":"Allow","Action":"s3:Get*","Resource":"arn:aws:s3:::b/*"}]}`))
	eff := doc.Expand(cat)
	if !eff.Has(Permission{Action: "s3:GetObject", Resource: "arn:aws:s3:::b/*"}) {
		t.Errorf("expected s3:GetObject grant, got %v", eff.List())
	}
	if eff.Has(Permission{Action: "s3:PutObject", Resource: "arn:aws:s3:::b/*"}) {
		t.Errorf("s3:Get* must not grant PutObject")
	}
}

func TestExplicitDenyRemoves(t *testing.T) {
	cat := mustCatalog(t)
	doc, _ := Parse([]byte(`{"Statement":[
		{"Effect":"Allow","Action":"s3:*","Resource":"*"},
		{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}
	]}`))
	eff := doc.Expand(cat)
	if eff.Has(Permission{Action: "s3:DeleteObject", Resource: "*"}) {
		t.Error("explicit deny should remove s3:DeleteObject")
	}
	if !eff.Has(Permission{Action: "s3:GetObject", Resource: "*"}) {
		t.Error("unrelated allow should survive the deny")
	}
}

func TestConditionalDenyKeepsAllow(t *testing.T) {
	cat := mustCatalog(t)
	doc, _ := Parse([]byte(`{"Statement":[
		{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"},
		{"Effect":"Deny","Action":"s3:GetObject","Resource":"*","Condition":{"Bool":{"aws:MultiFactorAuthPresent":"false"}}}
	]}`))
	eff := doc.Expand(cat)
	if !eff.Has(Permission{Action: "s3:GetObject", Resource: "*"}) {
		t.Error("conditional deny must not strip the allow")
	}
}

func TestNotAction(t *testing.T) {
	cat := mustCatalog(t)
	doc, _ := Parse([]byte(`{"Statement":[{"Effect":"Allow","NotAction":"iam:*","Resource":"*"}]}`))
	eff := doc.Expand(cat)
	if eff.Has(Permission{Action: "iam:PassRole", Resource: "*"}) {
		t.Error("NotAction iam:* must exclude iam:PassRole")
	}
	if !eff.Has(Permission{Action: "s3:GetObject", Resource: "*"}) {
		t.Error("NotAction iam:* should still allow s3:GetObject")
	}
}

func TestConditionCanonicalStable(t *testing.T) {
	a := canonicalCondition(map[string]map[string]stringSet{
		"StringEquals": {"aws:username": {"bob"}, "s3:prefix": {"x", "y"}},
	})
	b := canonicalCondition(map[string]map[string]stringSet{
		"StringEquals": {"s3:prefix": {"y", "x"}, "aws:username": {"bob"}},
	})
	if a != b {
		t.Errorf("condition canonicalization unstable: %q != %q", a, b)
	}
	if a == "" {
		t.Error("expected non-empty canonical condition")
	}
}
