// Command tollgate-oidc-preflight checks the GitHub Actions OIDC token a
// deployment job is holding against the trust policy that was installed for
// it, before the job spends a round trip on sts:AssumeRoleWithWebIdentity.
//
// A trust policy mismatch otherwise surfaces as "Not authorized to perform
// sts:AssumeRoleWithWebIdentity", which names neither the claim that did not
// match nor the pattern it was compared against.
//
// The token is a credential and is never printed, logged, or written to a
// file. Only its claims are, and the claims are public repository metadata.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/lgoyal6/tollgate/internal/deployid"
)

func main() {
	var (
		policy  deployid.Policy
		fromEnv = flag.Bool("from-actions", true,
			"request the token from the Actions token service; false reads a token on stdin")
		audience = flag.String("audience", "sts.amazonaws.com", "OIDC audience to request")
	)
	flag.StringVar(&policy.Owner, "owner", "lgoyal6", "repository owner login")
	flag.StringVar(&policy.OwnerID, "owner-id", "238557621", "immutable owner id")
	flag.StringVar(&policy.Repository, "repo", "tollgate", "repository name")
	flag.StringVar(&policy.RepositoryID, "repo-id", "1314415571", "immutable repository id")
	flag.StringVar(&policy.TagPrefix, "tag-prefix", "v", "required tag prefix")
	flag.StringVar(&policy.Environment, "environment", "production", "required GitHub environment")
	flag.StringVar(&policy.WorkflowFile, "workflow", ".github/workflows/deploy.yml",
		"workflow file allowed to deploy")
	flag.Parse()

	if err := run(policy, *fromEnv, *audience); err != nil {
		fmt.Fprintf(os.Stderr, "\noidc preflight failed: %v\n", err)
		if errors.Is(err, deployid.ErrOutOfPolicy) {
			fmt.Fprintf(os.Stderr, `
The token this job holds does not satisfy the deployment trust policy, so the
role assumption would have been refused. Accepted subject patterns:
  - %s

Check that the tag is a v* tag, that the job declares environment: %s, and that
deploy/terraform/aws/main.tf still names this repository's numeric ids. Those
ids change if the repository is deleted and re-created.
`, strings.Join(policy.SubjectPatterns(), "\n  - "), policy.Environment)
		}
		os.Exit(1)
	}
}

func run(policy deployid.Policy, fromActions bool, audience string) error {
	var raw string
	var err error
	if fromActions {
		raw, err = tokenFromActions(audience)
	} else {
		raw, err = tokenFromStdin()
	}
	if err != nil {
		return err
	}

	claims, err := deployid.DecodeClaims(raw)
	if err != nil {
		return err
	}

	// Claims only. The token itself stays in memory.
	pretty, _ := json.MarshalIndent(claims, "", "  ")
	fmt.Println("deployment identity claims:")
	fmt.Println(string(pretty))

	if err := deployid.Verify(claims, policy); err != nil {
		return err
	}
	fmt.Printf("\nin policy: %s may deploy %s from %s as %s\n",
		claims.JobWorkflowRef, claims.Repository, claims.Ref, claims.Environment)
	return nil
}

func tokenFromStdin() (string, error) {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		return "", fmt.Errorf("reading token from stdin: %w", err)
	}
	tok := strings.TrimSpace(string(b))
	if tok == "" {
		return "", errors.New("no token on stdin")
	}
	return tok, nil
}

// tokenFromActions calls the per-job token service GitHub injects into a
// workflow that declares id-token: write.
func tokenFromActions(audience string) (string, error) {
	endpoint := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL")
	bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if endpoint == "" || bearer == "" {
		return "", errors.New(
			"ACTIONS_ID_TOKEN_REQUEST_URL/TOKEN are unset: run this inside a job with permissions: id-token: write, " +
				"or pass -from-actions=false and supply a token on stdin")
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", fmt.Errorf("ACTIONS_ID_TOKEN_REQUEST_URL is not a URL: %w", err)
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("requesting an id token: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// Status only. The body of a failed token request can echo the request.
		return "", fmt.Errorf("token service returned %s", resp.Status)
	}
	var body struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", fmt.Errorf("decoding the token response: %w", err)
	}
	if body.Value == "" {
		return "", errors.New("token service returned an empty token")
	}
	return body.Value, nil
}
