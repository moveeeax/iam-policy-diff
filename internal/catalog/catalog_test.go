package catalog

import (
	"reflect"
	"testing"
)

func newTest(t *testing.T) Catalog {
	t.Helper()
	c, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

func TestExpandServiceWildcard(t *testing.T) {
	c := newTest(t)
	got := c.Expand("s3:Get*")
	if len(got) == 0 {
		t.Fatal("expected s3:Get* to expand to concrete actions")
	}
	for _, a := range got {
		if a[:3] != "s3:" {
			t.Errorf("unexpected action outside s3: %s", a)
		}
	}
	// GetObject must be present, PutObject must not.
	if !contains(got, "s3:GetObject") {
		t.Errorf("s3:Get* should include s3:GetObject, got %v", got)
	}
	if contains(got, "s3:PutObject") {
		t.Errorf("s3:Get* should not include s3:PutObject")
	}
}

func TestExpandFullWildcard(t *testing.T) {
	c := newTest(t)
	all := c.Expand("*")
	if !reflect.DeepEqual(all, c.Actions()) {
		t.Errorf("* should expand to every action")
	}
	if len(all) < 50 {
		t.Errorf("catalog unexpectedly small: %d", len(all))
	}
}

func TestExpandServiceAll(t *testing.T) {
	c := newTest(t)
	got := c.Expand("iam:*")
	if !contains(got, "iam:PassRole") {
		t.Errorf("iam:* must include iam:PassRole")
	}
}

func TestExpandConcreteAndUnknown(t *testing.T) {
	c := newTest(t)
	if got := c.Expand("s3:GetObject"); !reflect.DeepEqual(got, []string{"s3:GetObject"}) {
		t.Errorf("concrete action mismatch: %v", got)
	}
	// Unknown service, concrete action: surfaced verbatim.
	if got := c.Expand("chime:GetAccount"); !reflect.DeepEqual(got, []string{"chime:GetAccount"}) {
		t.Errorf("unknown concrete action should be surfaced: %v", got)
	}
	// Unknown service with wildcard: nothing to expand against.
	if got := c.Expand("chime:*"); got != nil {
		t.Errorf("unknown wildcard should be empty, got %v", got)
	}
}

func TestGlobMatch(t *testing.T) {
	cases := []struct {
		pat, name string
		want      bool
	}{
		{"Get*", "GetObject", true},
		{"*Object", "GetObject", true},
		{"Get?bject", "GetObject", true},
		{"Get*", "PutObject", false},
		{"*", "anything", true},
		{"Get*Tag*", "GetObjectTagging", true},
	}
	for _, c := range cases {
		if got := globMatch(c.pat, c.name); got != c.want {
			t.Errorf("globMatch(%q,%q)=%v want %v", c.pat, c.name, got, c.want)
		}
	}
}

func TestGlobMatchARN(t *testing.T) {
	if !GlobMatch("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/key.txt") {
		t.Error("ARN prefix glob should match")
	}
	if GlobMatch("arn:aws:s3:::bucket/*", "arn:aws:s3:::other/key") {
		t.Error("ARN glob should not cross bucket")
	}
}

func contains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
