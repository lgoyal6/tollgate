# Values the services must not carry as plain Cloud Run environment variables,
# because `gcloud run services describe` prints those to anyone with read access
# to the project: the database URL (it contains the password), the admin token
# (it mints tenant API keys), and Argus's backing-store credentials.
resource "random_password" "admin_token" {
  for_each = local.envs

  length  = 48
  special = false
}

locals {
  # Unix socket rather than an address: Cloud Run mounts the Cloud SQL connector
  # at /cloudsql/<connection name>, and pgx takes the socket directory as the
  # host query parameter. Nothing about this path is reachable from outside the
  # revision.
  database_url = {
    for e in local.envs :
    e => "postgres://tollgate_${e}:${random_password.db[e].result}@/tollgate_${e}?host=/cloudsql/${google_sql_database_instance.tollgate.connection_name}&sslmode=disable"
  }

  # The same role over the instance's public IP, for the operator only. Used to
  # seed tenants and budgets and to run the cross-environment negative control.
  operator_database_url = {
    for e in local.envs :
    e => "postgres://tollgate_${e}:${random_password.db[e].result}@${google_sql_database_instance.tollgate.public_ip_address}:5432/tollgate_${e}?sslmode=require"
  }

  # One map per environment, flattened into secret ids of the form
  # <app>-<env>-<name>. Every secret below belongs to exactly one environment;
  # there is deliberately no shared secret in this project.
  gateway_secrets = merge([
    for e in local.envs : {
      "tollgate-${e}-database-url" = { env = e, app = "tollgate", value = local.database_url[e] }
      "tollgate-${e}-admin-token"  = { env = e, app = "tollgate", value = random_password.admin_token[e].result }
    }
  ]...)

  # Argus's backend reads SUPABASE_URL and SUPABASE_KEY. These are per-environment
  # placeholders, not the repository's real values: the point being demonstrated is
  # that the environments hold different credentials and cannot read each other's,
  # and putting a live third-party key on a Cloud Run service to demonstrate that
  # would be the opposite of the lesson.
  argus_secrets = merge([
    for e in local.envs : {
      "argus-${e}-supabase-url" = { env = e, app = "argus", value = "https://argus-${e}.invalid.supabase.co" }
      "argus-${e}-supabase-key" = { env = e, app = "argus", value = "placeholder-${e}-${random_password.admin_token[e].result}" }
    }
  ]...)

  all_secrets = merge(local.gateway_secrets, local.argus_secrets)
}

resource "google_secret_manager_secret" "all" {
  for_each = local.all_secrets

  secret_id = each.key

  replication {
    auto {}
  }

  depends_on = [google_project_service.enabled]
}

resource "google_secret_manager_secret_version" "all" {
  for_each = local.all_secrets

  secret      = google_secret_manager_secret.all[each.key].id
  secret_data = each.value.value
}

# The whole environment boundary, in one binding: accessor is granted on the
# secret itself, to the single runtime account of the environment that secret
# belongs to. Not project-level, and not to a group that spans environments.
resource "google_secret_manager_secret_iam_member" "accessor" {
  for_each = local.all_secrets

  secret_id = google_secret_manager_secret.all[each.key].id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value.app == "tollgate" ? "serviceAccount:${google_service_account.gateway[each.value.env].email}" : "serviceAccount:${google_service_account.argus[each.value.env].email}"
}
