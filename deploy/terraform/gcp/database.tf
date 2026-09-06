# One instance, because a second db-f1-micro would double the only line on this
# bill that does not scale to zero. Separation between environments is carried by
# the database and the login role, not by the machine: tollgate_prod and
# tollgate_stage are separate databases, each with a role that is the only role
# allowed to connect to it. The REVOKE that makes that true is applied by the
# seeder, since Terraform's postgres provider is not in play here.
resource "random_password" "db" {
  for_each = local.envs

  length = 32
  # The password is carried inside a postgres:// URL. Restricting it to the
  # unreserved set means the URL never needs percent-encoding, which is the class
  # of bug where a deploy works until the day a "/" is generated.
  special = false
}

resource "google_sql_database_instance" "tollgate" {
  name             = "tollgate-pg"
  database_version = "POSTGRES_16"
  region           = var.region

  deletion_protection = false

  settings {
    tier              = var.db_tier
    edition           = "ENTERPRISE"
    availability_type = "ZONAL"
    disk_size         = 10
    disk_type         = "PD_HDD"
    disk_autoresize   = false

    deletion_protection_enabled = false

    backup_configuration {
      enabled = false
    }

    ip_configuration {
      ipv4_enabled = true
      ssl_mode     = "ENCRYPTED_ONLY"

      # Cloud Run does NOT come in this way. It uses the Cloud SQL connector,
      # which authenticates with IAM and needs no address on this list. The one
      # entry is the operator's machine.
      authorized_networks {
        name  = "operator"
        value = var.operator_cidr
      }
    }
  }

  depends_on = [google_project_service.enabled]
}

resource "google_sql_database" "env" {
  for_each = local.envs

  name     = "tollgate_${each.key}"
  instance = google_sql_database_instance.tollgate.name
}

resource "google_sql_user" "env" {
  for_each = local.envs

  name     = "tollgate_${each.key}"
  instance = google_sql_database_instance.tollgate.name
  password = random_password.db[each.key].result
}

# The built-in Cloud SQL admin role. Its password is set here rather than left
# unset because the per-environment boundary below has to be applied by somebody
# with cloudsqlsuperuser: REVOKE CONNECT ON DATABASE ... FROM PUBLIC is what
# turns "each environment has its own login role" from a naming convention into
# something a connection attempt is refused by. No service ever uses this role.
resource "random_password" "pg_admin" {
  length  = 32
  special = false
}

resource "google_sql_user" "postgres" {
  name     = "postgres"
  instance = google_sql_database_instance.tollgate.name
  password = random_password.pg_admin.result
}
