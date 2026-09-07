output "workload_identity_provider" {
  description = "Value for google-github-actions/auth workload_identity_provider. A resource name, not a credential."
  value       = google_iam_workload_identity_pool_provider.github.name
}

output "deploy_service_account" {
  description = "Service account a permitted workflow run may impersonate."
  value       = google_service_account.deployer.email
}

output "runtime_service_accounts" {
  description = "Attach these to the deployed workloads. Each reads only its own secrets."
  value = {
    tollgate = google_service_account.tollgate_runtime.email
    argus    = google_service_account.argus_runtime.email
  }
}

output "trust_condition" {
  description = "The attribute condition installed on the GitHub provider, for reading against verify-identity.sh."
  value       = google_iam_workload_identity_pool_provider.github.attribute_condition
}

output "github_actions_variables" {
  description = "Non-secret repository variables consumed by the live GitHub OIDC verification job."
  value = {
    GCP_PROJECT                    = var.project_id
    GCP_REGION                     = var.region
    GCP_WORKLOAD_IDENTITY_PROVIDER = google_iam_workload_identity_pool_provider.github.name
    GCP_DEPLOY_SERVICE_ACCOUNT     = google_service_account.deployer.email
    GCP_REPOSITORY                 = google_artifact_registry_repository.tollgate.repository_id
    GCP_DENIED_REPOSITORY          = google_artifact_registry_repository.out_of_scope.repository_id
    GCP_RUNTIME_SECRET             = google_secret_manager_secret.runtime["${var.name_prefix}-tollgate-upstream-key"].secret_id
  }
}
