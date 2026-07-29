package license

import "testing"

func TestPolicyEvaluate_Deny(t *testing.T) {
	p := &Policy{
		Allow: []string{"MIT", "Apache-2.0", "BSD-3-Clause"},
		Deny:  []string{"GPL-3.0-only", "AGPL-3.0-only"},
	}

	components := []ComponentLicense{
		{Name: "safe-pkg", Version: "1.0.0", License: Info{SPDXID: "MIT", Category: Permissive}},
		{Name: "gpl-pkg", Version: "2.0.0", License: Info{SPDXID: "GPL-3.0-only", Category: StrongCopyleft}},
		{Name: "agpl-pkg", Version: "1.0.0", License: Info{SPDXID: "AGPL-3.0-only", Category: StrongCopyleft}},
	}

	violations := p.Evaluate(components)

	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}

	if violations[0].Component.Name != "gpl-pkg" || violations[0].Action != "deny" {
		t.Errorf("violation[0] = %+v, expected gpl-pkg deny", violations[0])
	}
	if violations[1].Component.Name != "agpl-pkg" || violations[1].Action != "deny" {
		t.Errorf("violation[1] = %+v, expected agpl-pkg deny", violations[1])
	}
}

func TestPolicyEvaluate_Review(t *testing.T) {
	p := &Policy{
		Allow:  []string{"MIT", "Apache-2.0"},
		Deny:   []string{"GPL-3.0-only"},
		Review: []string{"MPL-2.0", "LGPL-2.1-only"},
	}

	components := []ComponentLicense{
		{Name: "mpl-pkg", Version: "1.0.0", License: Info{SPDXID: "MPL-2.0", Category: WeakCopyleft}},
		{Name: "lgpl-pkg", Version: "2.0.0", License: Info{SPDXID: "LGPL-2.1-only", Category: WeakCopyleft}},
	}

	violations := p.Evaluate(components)

	if len(violations) != 2 {
		t.Fatalf("expected 2 violations, got %d", len(violations))
	}

	for _, v := range violations {
		if v.Action != "review" {
			t.Errorf("expected review action for %s, got %q", v.Component.Name, v.Action)
		}
	}
}

func TestPolicyEvaluate_ImplicitDeny(t *testing.T) {
	// When allow list is present, unlisted licenses are implicitly denied
	p := &Policy{
		Allow: []string{"MIT", "Apache-2.0"},
	}

	components := []ComponentLicense{
		{Name: "mit-pkg", Version: "1.0.0", License: Info{SPDXID: "MIT"}},
		{Name: "isc-pkg", Version: "1.0.0", License: Info{SPDXID: "ISC"}},
	}

	violations := p.Evaluate(components)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}

	if violations[0].Component.Name != "isc-pkg" {
		t.Errorf("expected isc-pkg violation, got %s", violations[0].Component.Name)
	}
	if violations[0].Action != "deny" {
		t.Errorf("expected deny action, got %q", violations[0].Action)
	}
}

func TestPolicyEvaluate_NoAllowList(t *testing.T) {
	// When no allow list, only explicit deny/review applies
	p := &Policy{
		Deny:   []string{"GPL-3.0-only"},
		Review: []string{"MPL-2.0"},
	}

	components := []ComponentLicense{
		{Name: "mit-pkg", Version: "1.0.0", License: Info{SPDXID: "MIT"}},
		{Name: "isc-pkg", Version: "1.0.0", License: Info{SPDXID: "ISC"}},
		{Name: "gpl-pkg", Version: "1.0.0", License: Info{SPDXID: "GPL-3.0-only"}},
	}

	violations := p.Evaluate(components)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}

	if violations[0].Component.Name != "gpl-pkg" {
		t.Errorf("expected gpl-pkg violation, got %s", violations[0].Component.Name)
	}
}

func TestPolicyEvaluate_UnknownLicense(t *testing.T) {
	p := &Policy{
		Allow: []string{"MIT"},
	}

	components := []ComponentLicense{
		{Name: "no-lic-pkg", Version: "1.0.0", License: Info{SPDXID: "", Category: Unknown}},
	}

	violations := p.Evaluate(components)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
	if violations[0].Action != "deny" {
		t.Errorf("expected deny action for unknown license, got %q", violations[0].Action)
	}
}

func TestPolicyEvaluate_CaseInsensitive(t *testing.T) {
	p := &Policy{
		Deny: []string{"gpl-3.0-only"}, // lowercase in policy
	}

	components := []ComponentLicense{
		{Name: "gpl-pkg", Version: "1.0.0", License: Info{SPDXID: "GPL-3.0-only"}}, // standard case
	}

	violations := p.Evaluate(components)

	if len(violations) != 1 {
		t.Fatalf("expected 1 violation, got %d", len(violations))
	}
}

func TestParsePolicy(t *testing.T) {
	data := []byte(`
license_policy:
  allow:
    - MIT
    - Apache-2.0
  deny:
    - GPL-3.0-only
  review:
    - MPL-2.0
`)
	p, err := ParsePolicy(data)
	if err != nil {
		t.Fatalf("ParsePolicy: %v", err)
	}

	if len(p.Allow) != 2 {
		t.Errorf("expected 2 allow entries, got %d", len(p.Allow))
	}
	if len(p.Deny) != 1 {
		t.Errorf("expected 1 deny entry, got %d", len(p.Deny))
	}
	if len(p.Review) != 1 {
		t.Errorf("expected 1 review entry, got %d", len(p.Review))
	}
}
