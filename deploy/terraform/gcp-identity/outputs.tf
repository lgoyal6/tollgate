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
