# AWS verification infrastructure

This stack creates the resources used for the committed in-cluster benchmark:

- one standard-support Amazon EKS cluster in `us-east-1`;
- two on-demand `m7i-flex.large` workers across `us-east-1a` and `us-east-1b`;
- public subnets and an internet gateway, with no NAT Gateway or load balancer;
- two private ECR repositories;
- the EBS CSI driver for the in-cluster Postgres PVC;
- a tag-restricted GitHub OIDC deployment role.

Redis and Postgres are not AWS managed services. Apply the existing Kubernetes
Terraform after EKS is ready:

```bash
terraform -chdir=deploy/terraform/aws init
terraform -chdir=deploy/terraform/aws apply

aws eks update-kubeconfig \
  --region us-east-1 \
  --name tollgate \
  --alias tollgate-benchmark

terraform -chdir=deploy/terraform init
terraform -chdir=deploy/terraform apply \
  -state="$(pwd)/deploy/terraform/aws/backing-stores.tfstate" \
  -var-file="$(pwd)/deploy/terraform/aws/backing-stores.tfvars"
```

Store the `github_actions_role_arn` Terraform output as the repository secret
`AWS_ROLE_ARN`. It is an IAM role identifier, not a credential. Do not commit the
output, an AWS account ID, access keys, Terraform state, or kubeconfig content.

## The deployment identity

The role trust policy reads GitHub's public repository metadata at apply time
and accepts two subject patterns, both pinned to this repository and to
`refs/tags/v*`:

    repo:OWNER/REPO:ref:refs/tags/v*
    repo:OWNER@OWNER_ID/REPO@REPO_ID:ref:refs/tags/v*

Two, because GitHub emits the second form only for repositories that have opted
into immutable subject identifiers, and that is a repository setting rather than
something this stack can read or set. `internal/deployid` holds the same
patterns and a test that fails if the two definitions drift apart.

`cmd/tollgate-oidc-preflight` runs in the deploy workflow before the role
assumption and compares the token in hand against that policy, so a mismatch
arrives as the claim that did not match rather than as an opaque STS error.

## Teardown

From the repository root, with the same AWS identity used to create the stack:

```bash
./deploy/terraform/aws/teardown.sh
```

The EKS control plane, EC2 workers, public IPv4 addresses, and EBS volumes bill
until deletion finishes. Confirm that the script succeeds before leaving the
cluster idle.
