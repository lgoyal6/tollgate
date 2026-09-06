# Federated deployment identity and runtime least privilege

The GCP counterpart to the GitHub OIDC role in `../aws`. Same three layers,
different provider:

1. A **trust policy** decides which workflow runs get a token at all.
2. A **separate binding** decides which identity such a run may become.
3. The **identity it becomes** can do its job and nothing else.

No service account keys exist anywhere in this stack. The deployment presents a
token GitHub mints for one workflow run; the runtime authenticates as the
service account attached to it.

## Apply

```bash
terraform -chdir=deploy/terraform/gcp-identity init
terraform -chdir=deploy/terraform/gcp-identity apply \
  -var project_id=YOUR_PROJECT \
  -var project_number=YOUR_PROJECT_NUMBER \
  -var state_bucket_suffix=$(openssl rand -hex 4)
```

`terraform output workload_identity_provider` is the value for
`google-github-actions/auth`. It is a resource name, not a credential.

## The trust policy

```
assertion.repository_owner_id == '238557621' &&
assertion.repository_id      == '1314415571' &&
assertion.ref_type           == 'tag' &&
assertion.ref.startsWith('refs/tags/v') &&
assertion.environment        == 'production' &&
assertion.job_workflow_ref.startsWith('lgoyal6/tollgate/.github/workflows/deploy.yml@')
```

It is written against the numeric identity claims rather than the `sub` string.
`sub` has two formats and which one a repository emits is a repository setting;
`repository_id` and `repository_owner_id` are always present, always numeric,
and cannot be obtained by taking over a name. A repository deleted and
re-created under the same name gets a new `repository_id` and stops matching.

## Verifying it

Four harnesses, each stating its expectation per case and exiting non-zero if
any case lands somewhere else.

```bash
cd deploy/terraform/gcp-identity
export PROJECT=YOUR_PROJECT BUCKET_SUFFIX=the-suffix-you-applied

./verify-trust-policy.sh          # which tokens are refused, and why
./verify-impersonation-binding.sh # the second layer, independently
./verify-least-privilege.sh       # what each runtime identity cannot do
./verify-token-expiry.sh 60       # the credential stops working when it expires
```

`verify-trust-policy.sh` reads the live condition off the Terraform-managed
GitHub provider and applies it verbatim to a probe provider whose signing key it
generates locally. That is what makes out-of-policy claims presentable: GitHub
will not mint a token claiming to be a different repository, so the condition is
exercised through an issuer whose claims can be chosen, against the real
`sts.googleapis.com` endpoint. The condition under test is the production one,
read from the live provider rather than retyped.

`PROV=c10-probe-loose ./verify-trust-policy.sh` runs the same matrix against a
provider whose condition is only `repository_owner_id`, which is the shape a
trust policy takes when it is scoped to an account rather than to a repository.
It admits most of the matrix. That is the point of running it: it is the control
that shows the tight condition is doing work, and it gives
`verify-impersonation-binding.sh` a token that clears the trust policy so the
service account binding can be seen refusing it on its own.

The throwaway probe keypair is generated on first run and is gitignored.

## Runtime identities

`c10-tollgate-rt` and `c10-argus-rt` each hold `secretAccessor` on their own
secrets and nothing else. Neither can list the project's secrets, add a version,
destroy one, or read the other's. Rotation is therefore something done to a
workload, never by it.

`c10-tollgate-rt` additionally holds `objectAdmin` on the state bucket under an
IAM condition restricting it to the `tollgate/` prefix. The trailing slash
matters: without it the condition also admits `tollgate-anything`. Note that an
object-name condition can never satisfy `storage.objects.list`, which is
evaluated against the bucket, so a client that lists before writing will fail
where one that writes the object directly succeeds.

`c10-deployer` has no `secretAccessor` grant at all. A deployment identity that
can read runtime secrets turns every release into an opportunity to exfiltrate
them, and it does not need them: the runtime reads its own.
