package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/moveeeax/iam-policy-diff/internal/diff"
	"github.com/moveeeax/iam-policy-diff/internal/policy"
	"github.com/moveeeax/iam-policy-diff/internal/risk"
)

func sample() diff.Result {
	return diff.Result{
		Added:   []policy.Permission{{Action: "iam:PassRole", Resource: "*"}},
		Removed: []policy.Permission{{Action: "s3:DeleteObject", Resource: "arn:aws:s3:::b/*"}},
		Risks:   []risk.Finding{{Action: "iam:PassRole", Resource: "*", Severity: risk.High, Reason: "escalation"}},
		Summary: diff.Summary{Added: 1, Removed: 1, Risks: 1},
	}
}

func TestJSONRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample()); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	var back diff.Result
	if err := json.Unmarshal(buf.Bytes(), &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.Summary.Added != 1 || back.Summary.Risks != 1 {
		t.Errorf("summary lost in round trip: %+v", back.Summary)
	}
	if len(back.Added) != 1 || back.Added[0].Action != "iam:PassRole" {
		t.Errorf("added lost in round trip: %+v", back.Added)
	}
}

func TestHumanNoColor(t *testing.T) {
	var buf bytes.Buffer
	if err := Human(&buf, sample(), false); err != nil {
		t.Fatalf("Human: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "\x1b[") {
		t.Error("no-color output must not contain ANSI escapes")
	}
	for _, want := range []string{"+ iam:PassRole", "- s3:DeleteObject", "Privilege risks"} {
		if !strings.Contains(out, want) {
			t.Errorf("human output missing %q\n%s", want, out)
		}
	}
}

func TestHumanEmpty(t *testing.T) {
	var buf bytes.Buffer
	empty := diff.Result{}
	if err := Human(&buf, empty, false); err != nil {
		t.Fatalf("Human: %v", err)
	}
	if !strings.Contains(buf.String(), "No effective permission changes") {
		t.Errorf("empty diff message missing: %q", buf.String())
	}
}
