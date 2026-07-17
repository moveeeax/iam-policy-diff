# iam-policy-diff

> Understand what an IAM change really grants — beyond a text diff.

**Status:** 🚧 In development

## Overview

Show a semantic diff of two AWS IAM policies (what access actually changed).

## Features

- Expands actions (wildcards) and normalizes statements
- Reports added/removed effective permissions
- Highlights privilege escalation risks
- Handles resource and condition scoping
- JSON and human output

## Stack

Go; IAM action/wildcard expansion dataset.

## Usage

```bash
iam-policy-diff old.json new.json
```

## License

MIT
