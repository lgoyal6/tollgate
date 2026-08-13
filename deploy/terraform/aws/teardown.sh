#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
BACKING_DIR=$(cd -- "${SCRIPT_DIR}/.." && pwd)
BACKING_STATE="${SCRIPT_DIR}/backing-stores.tfstate"
BACKING_VARS="${SCRIPT_DIR}/backing-stores.tfvars"
KUBE_CONTEXT="tollgate-teardown"

aws sts get-caller-identity >/dev/null

terraform -chdir="${SCRIPT_DIR}" init -input=false
CLUSTER_NAME=$(terraform -chdir="${SCRIPT_DIR}" output -raw cluster_name)
AWS_REGION=$(terraform -chdir="${SCRIPT_DIR}" output -raw region)

echo "Deleting in-cluster workloads and their EBS volumes first."
aws eks update-kubeconfig \
  --region "${AWS_REGION}" \
  --name "${CLUSTER_NAME}" \
  --alias "${KUBE_CONTEXT}"

helm uninstall tollgate --namespace tollgate --ignore-not-found
helm uninstall prometheus-adapter --namespace monitoring --ignore-not-found
helm uninstall prometheus --namespace monitoring --ignore-not-found

if [[ -f "${BACKING_STATE}" ]]; then
  terraform -chdir="${BACKING_DIR}" init -input=false
  terraform -chdir="${BACKING_DIR}" destroy \
    -input=false \
    -auto-approve \
    -state="${BACKING_STATE}" \
    -var-file="${BACKING_VARS}" \
    -var="kube_context=${KUBE_CONTEXT}"
fi

echo "Destroying EKS, EC2 workers, ECR repositories, IAM roles, and VPC networking."
terraform -chdir="${SCRIPT_DIR}" state list
terraform -chdir="${SCRIPT_DIR}" destroy -input=false -auto-approve "$@"

echo "Teardown complete. Confirm that the tollgate EKS cluster and EC2 workers are absent."
