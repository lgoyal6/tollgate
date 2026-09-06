output "gateway_urls" {
  description = "Public HTTPS endpoint of each environment's gateway."
  value       = { for e, s in google_cloud_run_v2_service.gateway : e => s.uri }
}

output "argus_urls" {
  description = "HTTPS endpoint of each environment's Argus backend. Invoking one needs a Google identity token."
  value       = { for e, s in google_cloud_run_v2_service.argus : e => s.uri }
}

output "upstream_url" {
  description = "Public HTTPS endpoint of the demo upstream, used as the route target when seeding."
  value       = google_cloud_run_v2_service.upstream.uri
}

output "admin_tokens" {
  description = "Bearer token for each environment's management API."
  value       = { for e in local.envs : e => random_password.admin_token[e].result }
  sensitive   = true
}

output "operator_database_urls" {
  description = "Per-environment Postgres DSNs over the instance's public IP, reachable only from operator_cidr."
  value       = local.operator_database_url
  sensitive   = true
}

output "gateway_service_accounts" {
  value = { for e, sa in google_service_account.gateway : e => sa.email }
}

output "argus_service_accounts" {
  value = { for e, sa in google_service_account.argus : e => sa.email }
}

output "sql_connection_name" {
  value = google_sql_database_instance.tollgate.connection_name
}

output "artifact_registry" {
  description = "Docker repository images are pushed to before apply."
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.c16.repository_id}"
}

output "operator_admin_database_url" {
  description = "Superuser DSN over the public IP, for the grants that have no API. Never handed to a running service."
  value       = "postgres://postgres:${random_password.pg_admin.result}@${google_sql_database_instance.tollgate.public_ip_address}:5432/postgres?sslmode=require"
  sensitive   = true
}
