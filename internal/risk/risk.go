// Package risk flags newly added IAM permissions that are known privilege
// escalation or broad-blast-radius vectors.
package risk

import (
	"sort"
	"strings"

	"github.com/moveeeax/iam-policy-diff/internal/policy"
)

// Severity ranks a finding.
type Severity string

const (
	High   Severity = "high"
	Medium Severity = "medium"
)

// Finding is a risky permission surfaced by the diff.
type Finding struct {
	Action   string   `json:"action"`
	Resource string   `json:"resource"`
	Severity Severity `json:"severity"`
	Reason   string   `json:"reason"`
}

// rule matches an action (case-insensitive) to a reason.
type rule struct {
	action   string
	severity Severity
	reason   string
}

// knownRisky is a curated set of privilege-escalation / high-blast-radius
// actions drawn from well-documented AWS IAM escalation paths.
var knownRisky = map[string]rule{
	"iam:passrole":                {severity: High, reason: "Pass a role to a service — classic privilege escalation"},
	"iam:createpolicyversion":     {severity: High, reason: "Set a new default policy version to grant arbitrary access"},
	"iam:setdefaultpolicyversion": {severity: High, reason: "Roll a managed policy to a more permissive version"},
	"iam:attachuserpolicy":        {severity: High, reason: "Attach any managed policy (e.g. AdministratorAccess) to a user"},
	"iam:attachrolepolicy":        {severity: High, reason: "Attach any managed policy to a role"},
	"iam:attachgrouppolicy":       {severity: High, reason: "Attach any managed policy to a group"},
	"iam:putuserpolicy":           {severity: High, reason: "Write an inline policy granting arbitrary access to a user"},
	"iam:putrolepolicy":           {severity: High, reason: "Write an inline policy granting arbitrary access to a role"},
	"iam:putgrouppolicy":          {severity: High, reason: "Write an inline policy granting arbitrary access to a group"},
	"iam:updateassumerolepolicy":  {severity: High, reason: "Rewrite a role's trust policy to assume it"},
	"iam:createaccesskey":         {severity: High, reason: "Mint long-lived credentials for another principal"},
	"iam:createloginprofile":      {severity: High, reason: "Set a console password for another user"},
	"iam:updateloginprofile":      {severity: High, reason: "Reset another user's console password"},
	"iam:addusertogroup":          {severity: High, reason: "Add a user to a privileged group"},
	"sts:assumerole":              {severity: Medium, reason: "Assume another role — lateral movement if trust is broad"},
	"lambda:createfunction":       {severity: Medium, reason: "Run code, often paired with iam:PassRole for escalation"},
	"lambda:updatefunctioncode":   {severity: Medium, reason: "Run arbitrary code in an existing function's role"},
	"ec2:runinstances":            {severity: Medium, reason: "Launch compute with an instance profile role"},
}

// Analyze returns findings for permissions present in added. Full-wildcard
// admin grants (action "*" or "service:*" on resource "*") are reported even if
// the individual expanded action is not in the curated list.
func Analyze(added []policy.Permission) []Finding {
	var out []Finding
	seen := map[string]bool{}
	for _, p := range added {
		key := p.Action + "\x00" + p.Resource
		if seen[key] {
			continue
		}
		lower := strings.ToLower(p.Action)
		if r, ok := knownRisky[lower]; ok {
			sev := r.severity
			if p.Resource == "*" && sev == Medium {
				sev = High
			}
			out = append(out, Finding{
				Action:   p.Action,
				Resource: p.Resource,
				Severity: sev,
				Reason:   r.reason,
			})
			seen[key] = true
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity == High // high first
		}
		if out[i].Action != out[j].Action {
			return out[i].Action < out[j].Action
		}
		return out[i].Resource < out[j].Resource
	})
	return out
}
