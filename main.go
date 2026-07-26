// Command iam-policy-diff shows the semantic diff between two AWS IAM policy
// documents: what access actually changed, not what text changed.
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/moveeeax/iam-policy-diff/internal/catalog"
	"github.com/moveeeax/iam-policy-diff/internal/diff"
	"github.com/moveeeax/iam-policy-diff/internal/policy"
	"github.com/moveeeax/iam-policy-diff/internal/render"
)

const usage = `iam-policy-diff — semantic diff of two AWS IAM policies

usage:
  iam-policy-diff [flags] OLD.json NEW.json

flags:
  --json          emit machine-readable JSON (for CI gates)
  --fail-on-risk  exit 2 if the new policy adds a risky permission
  --no-color      disable ANSI colour in human output
  -h, --help      show this help

exit codes:
  0  success        1  usage/IO error        2  risk gate tripped (--fail-on-risk)
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	fs := flag.NewFlagSet("iam-policy-diff", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, usage) }
	jsonOut := fs.Bool("json", false, "emit JSON output")
	failOnRisk := fs.Bool("fail-on-risk", false, "exit 2 when a risky permission is added")
	noColor := fs.Bool("no-color", false, "disable ANSI colour")
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() != 2 {
		fmt.Fprint(stderr, usage)
		return 1
	}

	oldDoc, err := load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}
	newDoc, err := load(fs.Arg(1))
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	cat, err := catalog.New()
	if err != nil {
		fmt.Fprintf(stderr, "error: %v\n", err)
		return 1
	}

	result := diff.Compute(oldDoc, newDoc, cat)

	if *jsonOut {
		if err := render.JSON(stdout, result); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	} else {
		color := !*noColor && isTerminal(stdout)
		if err := render.Human(stdout, result, color); err != nil {
			fmt.Fprintf(stderr, "error: %v\n", err)
			return 1
		}
	}

	if *failOnRisk && result.HasRisks() {
		return 2
	}
	return 0
}

func load(path string) (*policy.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	doc, err := policy.Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return doc, nil
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
