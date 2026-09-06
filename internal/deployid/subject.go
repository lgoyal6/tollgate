// Package deployid checks, before a deployment tries to assume its cloud role,
// that the GitHub OIDC token in hand actually satisfies the trust policy that
// was installed for it.
//
// Without this check the failure mode is an opaque STS error at the moment of
// the assume, which names neither the claim that did not match nor the pattern
// it was compared against. That is how the trust policy in
// deploy/terraform/aws/main.tf came to pin a subject format the repository
// does not emit: nothing ever compared the two.
package deployid

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// Claims is the subset of a GitHub Actions OIDC token this package reads.
type Claims struct {
	Subject           string `json:"sub"`
	Audience          any    `json:"aud"`
	Issuer            string `json:"iss"`
	Repository        string `json:"repository"`
	RepositoryID      string `json:"repository_id"`
	RepositoryOwner   string `json:"repository_owner"`
	RepositoryOwnerID string `json:"repository_owner_id"`
	Ref               string `json:"ref"`
	RefType           string `json:"ref_type"`
	Environment       string `json:"environment"`
	JobWorkflowRef    string `json:"job_workflow_ref"`
}

// Policy is the deployment identity restriction, stated once so the preflight
// and the Terraform trust policy can be read against each other.
type Policy struct {
	Owner        string // "lgoyal6"
	OwnerID      string // immutable numeric account id
	Repository   string // "tollgate"
	RepositoryID string // immutable numeric repository id
	TagPrefix    string // "v"
	Environment  string // required GitHub environment, "" to not require one
	WorkflowFile string // ".github/workflows/deploy.yml", "" to not require one
}

// ErrOutOfPolicy is returned by Verify for any token the policy does not admit.
var ErrOutOfPolicy = errors.New("deployment identity is out of policy")

// SubjectPatterns returns the subject patterns the trust policy accepts, in the
// same order and with the same meaning as local.github_oidc_subjects in
// deploy/terraform/aws/main.tf.
//
// Two patterns, because GitHub mints the second form only for repositories
// that have opted into immutable subject identifiers, and that is a repository
// setting rather than something the deployment stack chooses.
func (p Policy) SubjectPatterns() []string {
	return []string{
		fmt.Sprintf("repo:%s/%s:ref:refs/tags/%s*", p.Owner, p.Repository, p.TagPrefix),
		fmt.Sprintf("repo:%s@%s/%s@%s:ref:refs/tags/%s*",
			p.Owner, p.OwnerID, p.Repository, p.RepositoryID, p.TagPrefix),
	}
}

// MatchStringLike reports whether value matches pattern under AWS IAM
// StringLike semantics: '*' stands for any sequence including empty, '?' for
// exactly one character, everything else is literal, and the match is anchored
// to the whole string. There are no character classes, so a pattern is not a
// regular expression and must not be treated as one.
func MatchStringLike(pattern, value string) bool {
	var b strings.Builder
	b.WriteString(`\A`)
	for _, r := range pattern {
		switch r {
		case '*':
			b.WriteString(`(?s:.)*`)
		case '?':
			b.WriteString(`(?s:.)`)
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	b.WriteString(`\z`)
	re, err := regexp.Compile(b.String())
	if err != nil {
		return false
	}
	return re.MatchString(value)
}

// MatchesAnyStringLike reports whether value matches at least one pattern.
func MatchesAnyStringLike(patterns []string, value string) bool {
	for _, p := range patterns {
		if MatchStringLike(p, value) {
			return true
		}
	}
	return false
}

// Verify reports every way the token fails the policy, rather than the first,
// so a misconfiguration is diagnosed in one run instead of one deploy each.
//
// The subject is checked because that is what the cloud trust policy compares.
// The individual claims are checked as well: they are the ones that carry the
// immutable identity, they are unaffected by the repository's subject-format
// setting, and checking them catches a rename or a re-creation that a subject
// pattern built from names alone would still admit.
func Verify(c Claims, p Policy) error {
	var bad []string

	if !MatchesAnyStringLike(p.SubjectPatterns(), c.Subject) {
		bad = append(bad, fmt.Sprintf(
			"subject %q matches none of the accepted patterns %v", c.Subject, p.SubjectPatterns()))
	}
	if want := p.Owner + "/" + p.Repository; c.Repository != want {
		bad = append(bad, fmt.Sprintf("repository is %q, policy allows only %q", c.Repository, want))
	}
	if c.RepositoryOwnerID != p.OwnerID {
		bad = append(bad, fmt.Sprintf(
			"repository_owner_id is %q, policy allows only %q; an account that took over the owner name would carry a different id",
			c.RepositoryOwnerID, p.OwnerID))
	}
	if c.RepositoryID != p.RepositoryID {
		bad = append(bad, fmt.Sprintf(
			"repository_id is %q, policy allows only %q; a deleted and re-created repository keeps the name but not the id",
			c.RepositoryID, p.RepositoryID))
	}
	if c.RefType != "tag" {
		bad = append(bad, fmt.Sprintf("ref_type is %q, deployment runs only from a tag", c.RefType))
	}
	if !strings.HasPrefix(c.Ref, "refs/tags/"+p.TagPrefix) {
		bad = append(bad, fmt.Sprintf("ref %q is not a refs/tags/%s* version tag", c.Ref, p.TagPrefix))
	}
	if p.Environment != "" && c.Environment != p.Environment {
		bad = append(bad, fmt.Sprintf(
			"environment is %q, policy requires %q; a job without an environment carries no environment claim at all",
			c.Environment, p.Environment))
	}
	if p.WorkflowFile != "" {
		want := fmt.Sprintf("%s/%s/%s@", p.Owner, p.Repository, p.WorkflowFile)
		if !strings.HasPrefix(c.JobWorkflowRef, want) {
			bad = append(bad, fmt.Sprintf(
				"job_workflow_ref %q does not start with %q; another workflow in the same repository is not the deploy workflow",
				c.JobWorkflowRef, want))
		}
	}

	if len(bad) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  - %s", ErrOutOfPolicy, strings.Join(bad, "\n  - "))
}

// DecodeClaims reads the claim set out of a JWT without verifying its
// signature. That is correct here and only here: this runs inside the job that
// GitHub just minted the token for, to compare the token against the policy
// before spending a round trip on STS. The signature check is STS's job, and
// nothing in this package grants anything.
func DecodeClaims(token string) (Claims, error) {
	var c Claims
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return c, fmt.Errorf("not a JWT: found %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return c, fmt.Errorf("claim segment is not base64url: %w", err)
	}
	if err := json.Unmarshal(payload, &c); err != nil {
		return c, fmt.Errorf("claim segment is not JSON: %w", err)
	}
	return c, nil
}
