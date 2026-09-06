package deployid

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// The real values for lgoyal6/tollgate. The numeric ids are public repository
// metadata, not secrets; they are what makes the policy survive a rename.
var tollgate = Policy{
	Owner:        "lgoyal6",
	OwnerID:      "238557621",
	Repository:   "tollgate",
	RepositoryID: "1314415571",
	TagPrefix:    "v",
	Environment:  "production",
	WorkflowFile: ".github/workflows/deploy.yml",
}

func inPolicy() Claims {
	return Claims{
		Issuer:            "https://token.actions.githubusercontent.com",
		Subject:           "repo:lgoyal6/tollgate:ref:refs/tags/v1.4.0",
		Repository:        "lgoyal6/tollgate",
		RepositoryID:      "1314415571",
		RepositoryOwner:   "lgoyal6",
		RepositoryOwnerID: "238557621",
		Ref:               "refs/tags/v1.4.0",
		RefType:           "tag",
		Environment:       "production",
		JobWorkflowRef:    "lgoyal6/tollgate/.github/workflows/deploy.yml@refs/tags/v1.4.0",
	}
}

// TestTheDefectThatMotivatedThisPackage pins the bug down. The committed trust
// policy accepted only the immutable subject format, and
// GET /repos/lgoyal6/tollgate/actions/oidc/customization/sub reports
// use_immutable_subject=false, so every deploy presented the default format and
// could never match. The old pattern is written out literally, because a
// regression here is silent until a release fails.
func TestTheDefectThatMotivatedThisPackage(t *testing.T) {
	immutableOnly := []string{"repo:lgoyal6@238557621/tollgate@1314415571:ref:refs/tags/v*"}
	actual := "repo:lgoyal6/tollgate:ref:refs/tags/v1.4.0"

	if MatchesAnyStringLike(immutableOnly, actual) {
		t.Fatal("the immutable-only pattern matched the default subject; the defect cannot be reproduced")
	}
	// Control: the same matcher does admit the format that pattern was written
	// for, so the line above fails for the right reason.
	if !MatchesAnyStringLike(immutableOnly, "repo:lgoyal6@238557621/tollgate@1314415571:ref:refs/tags/v1.4.0") {
		t.Fatal("control failed: the matcher never matches, so the negative result proves nothing")
	}
	// The fix: both formats are accepted.
	if !MatchesAnyStringLike(tollgate.SubjectPatterns(), actual) {
		t.Error("fixed policy still rejects the subject the repository actually emits")
	}
}

func TestInPolicyTokenIsAccepted(t *testing.T) {
	if err := Verify(inPolicy(), tollgate); err != nil {
		t.Fatalf("in-policy token rejected: %v", err)
	}
}

func TestImmutableSubjectFormatIsAlsoAccepted(t *testing.T) {
	c := inPolicy()
	c.Subject = "repo:lgoyal6@238557621/tollgate@1314415571:ref:refs/tags/v1.4.0"
	if err := Verify(c, tollgate); err != nil {
		t.Fatalf("immutable-format subject rejected: %v", err)
	}
}

func TestOutOfPolicyTokensAreRefused(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Claims)
		expect string
	}{
		{"another repository owned by the same account", func(c *Claims) {
			c.Repository = "lgoyal6/leetcode"
			c.RepositoryID = "900000001"
			c.Subject = "repo:lgoyal6/leetcode:ref:refs/tags/v1.4.0"
			c.JobWorkflowRef = "lgoyal6/leetcode/.github/workflows/deploy.yml@refs/tags/v1.4.0"
		}, "repository"},

		{"a branch instead of a tag", func(c *Claims) {
			c.Ref, c.RefType = "refs/heads/main", "branch"
			c.Subject = "repo:lgoyal6/tollgate:ref:refs/heads/main"
			c.JobWorkflowRef = "lgoyal6/tollgate/.github/workflows/deploy.yml@refs/heads/main"
		}, "ref_type"},

		{"a tag that is not a version tag", func(c *Claims) {
			c.Ref = "refs/tags/nightly"
			c.Subject = "repo:lgoyal6/tollgate:ref:refs/tags/nightly"
		}, "version tag"},

		{"a pull request ref", func(c *Claims) {
			c.Ref, c.RefType = "refs/pull/42/merge", "branch"
			c.Subject = "repo:lgoyal6/tollgate:pull_request"
		}, "subject"},

		{"the staging environment", func(c *Claims) {
			c.Environment = "staging"
		}, "environment"},

		{"no environment at all", func(c *Claims) {
			c.Environment = ""
		}, "environment"},

		{"a different workflow in the same repository", func(c *Claims) {
			c.JobWorkflowRef = "lgoyal6/tollgate/.github/workflows/ci.yml@refs/tags/v1.4.0"
		}, "job_workflow_ref"},

		{"an account that took over the owner name", func(c *Claims) {
			c.RepositoryOwner, c.RepositoryOwnerID = "lgoyal6", "999999999"
		}, "repository_owner_id"},

		{"the repository deleted and re-created under the same name", func(c *Claims) {
			c.RepositoryID = "1999999999"
			c.Subject = "repo:lgoyal6@238557621/tollgate@1999999999:ref:refs/tags/v1.4.0"
		}, "repository_id"},

		{"a repository whose name merely starts with the real one", func(c *Claims) {
			c.Repository = "lgoyal6/tollgate-fork"
			c.RepositoryID = "900000002"
			c.Subject = "repo:lgoyal6/tollgate-fork:ref:refs/tags/v1.4.0"
			c.JobWorkflowRef = "lgoyal6/tollgate-fork/.github/workflows/deploy.yml@refs/tags/v1.4.0"
		}, "repository"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := inPolicy()
			tc.mutate(&c)
			err := Verify(c, tollgate)
			if err == nil {
				t.Fatal("accepted an out-of-policy token")
			}
			if !errors.Is(err, ErrOutOfPolicy) {
				t.Errorf("error does not wrap ErrOutOfPolicy: %v", err)
			}
			if !strings.Contains(err.Error(), tc.expect) {
				t.Errorf("error does not name %q, so the message would not point at the cause:\n%v", tc.expect, err)
			}
		})
	}
}

// TestEveryCaseStartsFromAnAcceptedToken is the negative control for the table
// above: without its mutation, each case is a token Verify accepts. That rules
// out the table passing because the base claims were broken all along.
func TestEveryCaseStartsFromAnAcceptedToken(t *testing.T) {
	if err := Verify(inPolicy(), tollgate); err != nil {
		t.Fatalf("the shared base token is not in policy, so every refusal above is meaningless: %v", err)
	}
}

func TestVerifyReportsEveryFailureNotJustTheFirst(t *testing.T) {
	c := inPolicy()
	c.Repository = "attacker/tollgate"
	c.RepositoryOwnerID = "1"
	c.Ref, c.RefType = "refs/heads/main", "branch"
	c.Environment = "staging"
	err := Verify(c, tollgate)
	if err == nil {
		t.Fatal("expected refusal")
	}
	for _, want := range []string{"repository", "repository_owner_id", "ref_type", "environment"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%q missing; the report stops at the first problem: %v", want, err)
		}
	}
}

func TestMatchStringLikeIsAnchoredAndHasNoRegexpMeaning(t *testing.T) {
	cases := []struct {
		pattern, value string
		want           bool
	}{
		{"repo:a/b:ref:refs/tags/v*", "repo:a/b:ref:refs/tags/v1", true},
		{"repo:a/b:ref:refs/tags/v*", "repo:a/b:ref:refs/tags/v", true},
		// Anchored: a matching prefix or suffix is not a match.
		{"repo:a/b:ref:refs/tags/v*", "XXrepo:a/b:ref:refs/tags/v1", false},
		{"repo:a/b", "repo:a/b:ref:refs/tags/v1", false},
		// '.' is a literal dot, not "any character".
		{"a.c", "abc", false},
		{"a.c", "a.c", true},
		// Regexp metacharacters in the value are literal too.
		{"a+c", "a+c", true},
		{"a+c", "ac", false},
		// '?' is exactly one character.
		{"a?c", "abc", true},
		{"a?c", "ac", false},
		{"a?c", "abbc", false},
		// '*' spans separators, which is why the patterns must carry the
		// :ref:refs/tags/ literal rather than ending at the repository.
		{"repo:a/*", "repo:a/b:ref:refs/heads/main", true},
	}
	for _, tc := range cases {
		if got := MatchStringLike(tc.pattern, tc.value); got != tc.want {
			t.Errorf("MatchStringLike(%q, %q) = %v, want %v", tc.pattern, tc.value, got, tc.want)
		}
	}
}

func TestDecodeClaims(t *testing.T) {
	payload := `{"sub":"repo:lgoyal6/tollgate:ref:refs/tags/v1.4.0","repository_id":"1314415571","ref_type":"tag"}`
	tok := "aGVhZGVy." + base64.RawURLEncoding.EncodeToString([]byte(payload)) + ".c2ln"

	c, err := DecodeClaims(tok)
	if err != nil {
		t.Fatalf("DecodeClaims: %v", err)
	}
	if c.Subject != "repo:lgoyal6/tollgate:ref:refs/tags/v1.4.0" || c.RepositoryID != "1314415571" || c.RefType != "tag" {
		t.Errorf("claims not decoded: %+v", c)
	}
}

func TestDecodeClaimsRejectsMalformedTokens(t *testing.T) {
	for _, tok := range []string{"", "onlyonepart", "two.parts", "a.b.c.d", "a.!!!notbase64!!!.c", "a." + base64.RawURLEncoding.EncodeToString([]byte("not json")) + ".c"} {
		if _, err := DecodeClaims(tok); err == nil {
			t.Errorf("accepted malformed token %q", tok)
		}
	}
}

// TestPolicyAgreesWithTerraform reads the trust policy out of
// deploy/terraform/aws/main.tf and checks that the patterns this package
// accepts are exactly the ones the role will accept. The two are written in
// different languages in different files, and the defect this package exists
// to catch was precisely a disagreement between a policy and the thing it was
// supposed to describe.
func TestPolicyAgreesWithTerraform(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "..", "deploy", "terraform", "aws", "main.tf"))
	if err != nil {
		t.Fatalf("reading the trust policy: %v", err)
	}
	tf := string(src)

	// The condition must be StringLike over the shared local, not a single
	// inlined string: a single string is how the immutable-only pattern got in.
	if !strings.Contains(tf, `"token.actions.githubusercontent.com:sub" = local.github_oidc_subjects`) {
		t.Error("the sub condition no longer reads local.github_oidc_subjects")
	}

	// Every format() call in the github_oidc_subjects local, rendered.
	start := strings.Index(tf, "github_oidc_subjects = [")
	if start < 0 {
		t.Fatal("github_oidc_subjects is gone from main.tf")
	}
	end := strings.Index(tf[start:], "\n  ]")
	if end < 0 {
		t.Fatal("could not find the end of github_oidc_subjects")
	}
	block := tf[start : start+end]

	rendered := map[string]bool{}
	for _, m := range regexp.MustCompile(`"([^"]*%s[^"]*)"`).FindAllStringSubmatch(block, -1) {
		spec := m[1]
		n := strings.Count(spec, "%s")
		args := map[int][]any{
			2: {tollgate.Owner, tollgate.Repository},
			4: {tollgate.Owner, tollgate.OwnerID, tollgate.Repository, tollgate.RepositoryID},
		}[n]
		if args == nil {
			t.Fatalf("unexpected format spec in main.tf with %d verbs: %q", n, spec)
		}
		rendered[fmt.Sprintf(spec, args...)] = true
	}

	for _, want := range tollgate.SubjectPatterns() {
		if !rendered[want] {
			t.Errorf("Terraform does not accept %q; the trust policy and this package disagree", want)
		}
		delete(rendered, want)
	}
	for extra := range rendered {
		t.Errorf("Terraform accepts %q, which this package would refuse", extra)
	}
}
