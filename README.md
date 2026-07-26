# iam-policy-diff

[![ci](https://github.com/moveeeax/iam-policy-diff/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/iam-policy-diff/actions/workflows/ci.yml)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

Show a **semantic** diff of two AWS IAM policies — what access actually changed,
not what text changed.

A `git diff` on a policy tells you a line moved or a wildcard appeared. It does
*not* tell you that `s3:Get*` quietly became `s3:*`, that the new statement adds
`iam:PassRole` on `*`, or that a resource scope widened from one bucket to every
resource in the account. `iam-policy-diff` expands wildcards against an IAM
action catalog, computes the **effective permission set** of each policy, and
reports the delta — plus the privilege-escalation risks hiding in the additions.

## How it works

1. **Parse** both policy documents, tolerating IAM's scalar-or-array quirk
   (`"Action": "s3:GetObject"` vs a list) and a single-object-or-array
   `Statement`.
2. **Expand** every `Action`/`NotAction` pattern (`s3:Get*`, `iam:*`, `*`)
   against an embedded action catalog into concrete `service:Action` names.
3. **Reduce** to an effective set: each `Allow` contributes
   `(action, resource, condition)` grants; an explicit *unconditional* `Deny`
   subtracts matching grants (explicit deny always wins). A condition change
   registers as remove + add, because the scope really did change.
4. **Diff** the two sets and **flag** additions that match known
   privilege-escalation actions (`iam:PassRole`, `iam:AttachRolePolicy`,
   `sts:AssumeRole`, `lambda:UpdateFunctionCode`, ...).

The catalog sits behind an interface, so the core logic is unit-tested with zero
network access.

## Install

```
go install github.com/moveeeax/iam-policy-diff@latest
```

Or build from source:

```
git clone https://github.com/moveeeax/iam-policy-diff
cd iam-policy-diff
make build
```

## Usage

```
iam-policy-diff [flags] OLD.json NEW.json

flags:
  --json          emit machine-readable JSON (for CI gates)
  --fail-on-risk  exit 2 if the new policy adds a risky permission
  --no-color      disable ANSI colour in human output

exit codes:
  0  success        1  usage/IO error        2  risk gate tripped (--fail-on-risk)
```

Human output:

```
$ iam-policy-diff examples/old.json examples/new.json
Effective permission diff
  +22 added  -0 removed  2 risk(s)

Added
  + iam:PassRole on *
  + lambda:UpdateFunctionCode on *
  + s3:DeleteObject on arn:aws:s3:::my-app-data/*
  ...

⚠ Privilege risks
  [high] iam:PassRole on * — Pass a role to a service — classic privilege escalation
  [high] lambda:UpdateFunctionCode on * — Run arbitrary code in an existing function's role
```

### CI gate

Fail a pull request when a policy change introduces a risky permission:

```yaml
- name: Guard IAM policy changes
  run: iam-policy-diff --json --fail-on-risk policy/old.json policy/new.json
```

`--json` prints a stable document with `added`, `removed`, `risks`, and a
`summary`, so you can also pipe it into `jq` for custom gates.

## Development

```
make fmtcheck   # gofmt -l must be empty
make vet
make race       # go test -race ./...
make build
```

## License

[MIT](LICENSE)
