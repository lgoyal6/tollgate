# Federated deployment identity and least-privilege runtime identities on GCP.
#
# This is the GCP counterpart to the GitHub OIDC role in
# deploy/terraform/aws/main.tf, and it is the stack the identity restrictions
# were actually exercised against: see verify-identity.sh, which drives real
# token exchanges through sts.googleapis.com and records which ones are refused.
#
# The shape is the same on both clouds:
#
#   1. A trust policy decides which workflow runs get a token at all.
#   2. A separate binding decides which identity such a run may become.
#   3. The identity it becomes can do its job and nothing else.
#
# Nothing here creates or holds a service account key. The deployment
# authenticates with a token GitHub mints for one workflow run, and the runtime
# authenticates as the service account attached to it.

locals {
  pool_id = "${var.name_prefix}-deploy-pool"

  # The trust policy. Written against the dedicated identity claims rather than
  # against the `sub` string, because `sub` has two formats and which one a
  # repository emits is a repository setting: see the comment on
  # local.github_oidc_subjects in ../aws/main.tf for what that cost.
  # repository_id and repository_owner_id are always present and always
  # numeric, so they cannot be spoofed by taking over a name.
  trust_conditions = compact([
    "assertion.repository_owner_id == '${var.github_owner_id}'",
    "assertion.repository_id == '${var.github_repository_id}'",
    "assertion.ref_type == 'tag'",
    "assertion.ref.startsWith('refs/tags/${var.tag_prefix}')",
    var.deploy_environment == "" ? "" : "assertion.environment == '${var.deploy_environment}'",
    "assertion.job_workflow_ref.startsWith('${var.github_owner}/${var.github_repository}/${var.deploy_workflow}@')",
  ])

  attribute_condition = join(" && ", local.trust_conditions)

  attribute_mapping = {
    "google.subject"          = "assertion.sub"
    "attribute.repository"    = "assertion.repository"
    "attribute.repository_id" = "assertion.repository_id"
    "attribute.ref"           = "assertion.ref"
    "attribute.environment"   = "assertion.environment"
    "attribute.workflow_ref"  = "assertion.job_workflow_ref"
  }

  pool_name    = "projects/${var.project_number}/locations/global/workloadIdentityPools/${local.pool_id}"
  state_bucket = "${var.name_prefix}-tollgate-state-${var.state_bucket_suffix}"
  state_prefix = "tollgate/"
  other_bucket = "${var.name_prefix}-argus-state-${var.state_bucket_suffix}"
}

resource "google_iam_workload_identity_pool" "deploy" {
  workload_identity_pool_id = local.pool_id
  display_name              = "C10 deploy pool"
  description               = "Short-lived federated deployment identity. No service account keys."
}

resource "google_iam_workload_identity_pool_provider" "github" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.deploy.workload_identity_pool_id
  workload_identity_pool_provider_id = "${var.name_prefix}-github"
  display_name                       = "GitHub Actions deploy"

  attribute_mapping   = local.attribute_mapping
  attribute_condition = local.attribute_condition

  oidc {
    issuer_uri = "https://token.actions.githubusercontent.com"
  }
}

# ---------------------------------------------------------------------------
# Identities
# ---------------------------------------------------------------------------

resource "google_service_account" "deployer" {
  account_id   = "${var.name_prefix}-deployer"
  display_name = "C10 deployment identity (federated, no keys)"
}

resource "google_service_account" "tollgate_runtime" {
  account_id   = "${var.name_prefix}-tollgate-rt"
  display_name = "C10 Tollgate runtime workload identity"
}

resource "google_service_account" "argus_runtime" {
  account_id   = "${var.name_prefix}-argus-rt"
  display_name = "C10 Argus runtime workload identity"
}

# Which federated identities may become the deployer. Scoped to one value of
# one attribute.
#
# The anti-pattern this replaces is a principalSet ending in /* , which admits
# every identity in the pool. That is not a restriction: it is the trust policy
# doing all the work with no second opinion. verify-identity.sh demonstrates
# the difference by putting a token from a different repository through a
# deliberately loose provider and showing this binding refuse it anyway.
resource "google_service_account_iam_member" "deployer_federation" {
  service_account_id = google_service_account.deployer.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principalSet://iam.googleapis.com/${local.pool_name}/attribute.repository/${var.github_owner}/${var.github_repository}"
}

# ---------------------------------------------------------------------------
# What the deployment identity may do
# ---------------------------------------------------------------------------

resource "google_artifact_registry_repository" "tollgate" {
  location      = var.region
  repository_id = "${var.name_prefix}-tollgate"
  format        = "DOCKER"
  description   = "The one repository the deployment identity may push to."
}

# A second repository the deployer has no grant on, so "cannot push elsewhere"
# is a claim with something to test it against rather than an absence.
resource "google_artifact_registry_repository" "out_of_scope" {
  location      = var.region
  repository_id = "${var.name_prefix}-other"
  format        = "DOCKER"
  description   = "Out of scope for the deployment identity. Exists so the denial is testable."
}

resource "google_artifact_registry_repository_iam_member" "deployer_push" {
  location   = google_artifact_registry_repository.tollgate.location
  repository = google_artifact_registry_repository.tollgate.name
  role       = "roles/artifactregistry.writer"
  member     = "serviceAccount:${google_service_account.deployer.email}"
}

# There is deliberately no secretAccessor grant for the deployer. A deployment
# identity that can read runtime secrets turns every release into a chance to
# exfiltrate them, and it does not need them: the runtime reads its own.

# ---------------------------------------------------------------------------
# Runtime secrets, granted one at a time
# ---------------------------------------------------------------------------

locals {
  secrets = {
    "${var.name_prefix}-tollgate-upstream-key" = google_service_account.tollgate_runtime.email
    "${var.name_prefix}-argus-model-key"       = google_service_account.argus_runtime.email
    "${var.name_prefix}-argus-supabase-key"    = google_service_account.argus_runtime.email
  }
}

resource "google_secret_manager_secret" "runtime" {
  for_each  = local.secrets
  secret_id = each.key
  labels    = { owner = var.name_prefix }

  replication {
    auto {}
  }
}

# secretAccessor on one secret, not secretmanager.admin and not a project-level
# role. The holder can read the current version of that one secret; it cannot
# list the project's secrets, add a version, or destroy one. Rotation is
# therefore something done to the workload, never by it.
resource "google_secret_manager_secret_iam_member" "runtime_access" {
  for_each  = local.secrets
  secret_id = google_secret_manager_secret.runtime[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${each.value}"
}

# ---------------------------------------------------------------------------
# Runtime state, bounded to one key prefix
# ---------------------------------------------------------------------------

resource "google_storage_bucket" "tollgate_state" {
  name                        = local.state_bucket
  location                    = var.region
  uniform_bucket_level_access = true # required for IAM conditions
  force_destroy               = true
}

resource "google_storage_bucket" "argus_state" {
  name                        = local.other_bucket
  location                    = var.region
  uniform_bucket_level_access = true
  force_destroy               = true
}

# objectAdmin, but only on names under tollgate/. The trailing slash is
# load-bearing: without it the condition also admits tollgate-anything.
#
# Note that this grant cannot satisfy storage.objects.list, which is evaluated
# against the bucket and so never matches an object-name condition. A client
# that lists before it writes will fail; a client that writes the object
# directly, which is what the SDKs do, will not.
resource "google_storage_bucket_iam_member" "tollgate_own_prefix" {
  bucket = google_storage_bucket.tollgate_state.name
  role   = "roles/storage.objectAdmin"
  member = "serviceAccount:${google_service_account.tollgate_runtime.email}"

  condition {
    title       = "only-tollgate-prefix"
    description = "Runtime may touch only its own key prefix"
    expression  = "resource.name.startsWith('projects/_/buckets/${local.state_bucket}/objects/${local.state_prefix}')"
  }
}
