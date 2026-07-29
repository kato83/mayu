---
title: "License Policy Example"
---
# License Policy Example

This is an example license policy file for use with `mayu audit --license-policy`.

## Usage

```bash
mayu audit --sbom ./sbom.cdx.json --license-policy license-policy.yaml
```

## Policy File Format

```yaml
license_policy:
  # Licenses explicitly allowed (no violation reported)
  allow:
    - MIT
    - Apache-2.0
    - BSD-2-Clause
    - BSD-3-Clause
    - ISC
    - Unlicense
    - CC0-1.0
    - 0BSD
    - BlueOak-1.0.0
    - CC-BY-4.0

  # Licenses explicitly denied (exit code 1)
  deny:
    - GPL-2.0-only
    - GPL-2.0-or-later
    - GPL-3.0-only
    - GPL-3.0-or-later
    - AGPL-3.0-only
    - AGPL-3.0-or-later
    - SSPL-1.0

  # Licenses requiring manual review (reported as warning)
  review:
    - MPL-2.0
    - LGPL-2.1-only
    - LGPL-2.1-or-later
    - LGPL-3.0-only
    - LGPL-3.0-or-later
    - EPL-2.0
    - CDDL-1.0
```

## Behavior

- **Allow list present**: Any license not in `allow`, `deny`, or `review` is implicitly denied.
- **No allow list**: Only licenses explicitly in `deny` or `review` trigger violations.
- **Unknown licenses**: Components without detected license information are treated as denied when an allow list is present.

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No license violations (or only "review" violations) |
| 1 | At least one "deny" violation found |
| 2 | Error (invalid policy file, invalid SBOM, etc.) |
