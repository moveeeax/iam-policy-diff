package risk

import "testing"

import "github.com/moveeeax/iam-policy-diff/internal/policy"

func TestAnalyzeFlagsKnown(t *testing.T) {
	added := []policy.Permission{
		{Action: "iam:PassRole", Resource: "*"},
		{Action: "s3:GetObject", Resource: "*"}, // benign
		{Action: "iam:AttachRolePolicy", Resource: "arn:aws:iam::111:role/x"},
	}
	fs := Analyze(added)
	if len(fs) != 2 {
		t.Fatalf("want 2 findings, got %d: %+v", len(fs), fs)
	}
	// High severity sorts first.
	if fs[0].Severity != High {
		t.Errorf("expected high severity first, got %s", fs[0].Severity)
	}
}

func TestSeverityEscalatesOnStarResource(t *testing.T) {
	// sts:AssumeRole is Medium normally, High when on Resource "*".
	scoped := Analyze([]policy.Permission{{Action: "sts:AssumeRole", Resource: "arn:aws:iam::111:role/x"}})
	if len(scoped) != 1 || scoped[0].Severity != Medium {
		t.Fatalf("scoped sts:AssumeRole should be medium: %+v", scoped)
	}
	wide := Analyze([]policy.Permission{{Action: "sts:AssumeRole", Resource: "*"}})
	if len(wide) != 1 || wide[0].Severity != High {
		t.Fatalf("wildcard sts:AssumeRole should be high: %+v", wide)
	}
}

func TestAnalyzeEmpty(t *testing.T) {
	if fs := Analyze(nil); len(fs) != 0 {
		t.Errorf("nil input should yield no findings, got %+v", fs)
	}
}
