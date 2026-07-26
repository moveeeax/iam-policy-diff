// Package render turns a diff result into human or JSON output.
package render

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/moveeeax/iam-policy-diff/internal/diff"
)

// JSON writes the result as indented JSON.
func JSON(w io.Writer, r diff.Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	return enc.Encode(r)
}

// Human writes a colour-free, review-friendly report. It returns the number of
// lines that carry a signal so callers can special-case an empty diff.
func Human(w io.Writer, r diff.Result, color bool) error {
	green, red, yellow, bold, reset := palette(color)

	if r.Summary.Added == 0 && r.Summary.Removed == 0 {
		fmt.Fprintln(w, "No effective permission changes.")
		return nil
	}

	fmt.Fprintf(w, "%sEffective permission diff%s\n", bold, reset)
	fmt.Fprintf(w, "  +%d added  -%d removed  %d risk(s)\n\n",
		r.Summary.Added, r.Summary.Removed, r.Summary.Risks)

	if len(r.Added) > 0 {
		fmt.Fprintf(w, "%sAdded%s\n", bold, reset)
		for _, p := range r.Added {
			fmt.Fprintf(w, "  %s+ %s%s\n", green, p.String(), reset)
		}
		fmt.Fprintln(w)
	}
	if len(r.Removed) > 0 {
		fmt.Fprintf(w, "%sRemoved%s\n", bold, reset)
		for _, p := range r.Removed {
			fmt.Fprintf(w, "  %s- %s%s\n", red, p.String(), reset)
		}
		fmt.Fprintln(w)
	}
	if len(r.Risks) > 0 {
		fmt.Fprintf(w, "%s%s⚠ Privilege risks%s\n", bold, yellow, reset)
		for _, f := range r.Risks {
			fmt.Fprintf(w, "  %s[%s]%s %s on %s — %s\n",
				yellow, f.Severity, reset, f.Action, f.Resource, f.Reason)
		}
	}
	return nil
}

func palette(color bool) (green, red, yellow, bold, reset string) {
	if !color {
		return "", "", "", "", ""
	}
	return "\x1b[32m", "\x1b[31m", "\x1b[33m", "\x1b[1m", "\x1b[0m"
}
