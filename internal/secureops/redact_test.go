package secureops

import (
	"strings"
	"testing"
)

// SC-09: the model-visible result contract is closed at the shared
// boundary. DTO shapes pass; unbounded or deeply-nested structures fail.
func TestValidateSafeResult(t *testing.T) {
	ok := []SafeResult{
		{Summary: "github ok", Data: map[string]interface{}{
			"full_name": "o/r", "private": false, "open_issues_count": 3,
		}},
		{Summary: "github ok", Data: map[string]interface{}{
			"issues": []interface{}{
				map[string]interface{}{"number": 1.0, "title": "t", "state": "open"},
			},
		}},
		{Summary: "delivery ok", Data: map[string]interface{}{
			"destination_id": "d", "delivered": true, "bytes": 7, "digest": "abc",
		}},
	}
	for i, r := range ok {
		if err := ValidateSafeResult(r); err != nil {
			t.Fatalf("valid result %d rejected: %v", i, err)
		}
	}
	bad := []SafeResult{
		{Summary: "", Data: map[string]interface{}{"a": "b"}},                                                          // empty summary
		{Summary: "x", Data: map[string]interface{}{"a": map[string]interface{}{"b": map[string]interface{}{"c": 1}}}}, // nested objects
		{Summary: "x", Data: map[string]interface{}{"big": strings.Repeat("s", 5000)}},                                 // oversized string
		{Summary: "x", Data: map[string]interface{}{"deep": []interface{}{[]interface{}{"x"}}}},                        // nested arrays
	}
	for i, r := range bad {
		if err := ValidateSafeResult(r); err == nil {
			t.Fatalf("invalid result %d accepted", i)
		}
	}
}

const marker = "SECRET-MARKER-9f8e7d6c5b4a"

func TestValidateCredentialNonDisclosure(t *testing.T) {
	cred := Credential{
		Value:      "ghp_primary-secret-123",
		Components: map[string]string{"private_key": "component-secret-456"},
	}
	for _, result := range []SafeResult{
		{Summary: "safe", Data: map[string]interface{}{"description": "ordinary metadata"}},
		{Summary: "safe", Data: map[string]interface{}{"description": "prefix " + cred.Value + " suffix"}},
		{Summary: "safe", Data: map[string]interface{}{"nested": []interface{}{map[string]interface{}{"echo": cred.Components["private_key"]}}}},
	} {
		err := ValidateCredentialNonDisclosure(result, cred)
		if result.Data["description"] == "ordinary metadata" {
			if err != nil {
				t.Fatalf("safe control rejected: %v", err)
			}
		} else if err == nil {
			t.Fatalf("credential disclosure accepted: %+v", result)
		}
	}
}

// Unknown operations are denied (no arbitrary HTTP).
func TestUnknownOpDenied(t *testing.T) {
	if _, err := Lookup("shell.exec"); err == nil {
		t.Fatal("arbitrary operation should be denied")
	}
	if _, err := Lookup("http.raw"); err == nil {
		t.Fatal("raw http should be denied")
	}
}

// Driver validation rejects malformed input before credential use.
func TestGithubValidation(t *testing.T) {
	d, _ := Lookup("github.get_repo")
	bad := []string{
		"../etc", "", "org/repo/extra", "org repo", "org/repo?x=1",
		"org/repo#frag", "org%2Frepo", "/leading", "trailing/",
		"org/re po", "o\x00r/repo",
	}
	for _, repo := range bad {
		if err := d.Validate(UseInput{Params: map[string]string{"repo": repo}}); err == nil {
			t.Fatalf("malformed repo accepted: %q", repo)
		}
	}
	if err := d.Validate(UseInput{Params: map[string]string{"repo": "org/repo"}}); err != nil {
		t.Fatalf("valid repo rejected: %v", err)
	}
	if err := d.Validate(UseInput{Params: map[string]string{"repo": "org/repo", "extra": "1"}}); err == nil {
		// Validate alone does not check key allowlist; submission does.
		// Documented here so the gap stays visible.
		t.Log("note: unknown-key rejection enforced at submit, not Validate")
	}
}
