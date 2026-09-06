# The demo backend the gateway proxies to. It is an echo server: it holds no
# data and no credential, which is why it is the one component that is shared
# between environments rather than duplicated.
resource "google_cloud_run_v2_service" "upstream" {
  name     = "tollgate-upstream"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  deletion_protection = false

  template {
    service_account = google_service_account.upstream.email

    scaling {
      min_instance_count = 0
      max_instance_count = 2
    }

    containers {
      image = var.upstream_image

      ports {
        container_port = 9000
      }

      env {
        name  = "LISTEN_ADDR"
        value = ":9000"
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [google_project_service.enabled]
}

resource "google_cloud_run_v2_service" "gateway" {
  for_each = local.envs

  name     = "tollgate-gateway-${each.key}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  deletion_protection = false

  # Traffic on this service is what the rollout moves: a canary split and a
  # rollback are changes to this field made by the deploy process, not by an
  # apply. Terraform still creates the service and its first revision; it just
  # does not get to decide afterwards who is serving.
  lifecycle {
    ignore_changes = [traffic, client, client_version]
  }

  template {
    service_account = google_service_account.gateway[each.key].email

    scaling {
      # Zero, deliberately. An idle demonstration should cost nothing, and the
      # cold start this buys is the honest trade for that.
      min_instance_count = 0
      max_instance_count = var.gateway_max_instances
    }

    volumes {
      name = "cloudsql"

      cloud_sql_instance {
        instances = [google_sql_database_instance.tollgate.connection_name]
      }
    }

    # Container order is load-bearing, which nothing in the API documents.
    # The Cloud SQL socket volume is attached to the FIRST container in this
    # list and to no other, whichever container declares the mount. Measured:
    # with redis declared first, the gateway's mount was silently dropped and
    # every revision died on
    #   dial unix /cloudsql/<instance>/.s.PGSQL.5432: no such file or directory
    # after a 90s retry loop; declaring the mount on both containers did not
    # change it. Moving the gateway to the front fixed it, with no other edit.
    # dependsOn is unaffected and still names redis correctly below.
    containers {
      name       = "gateway"
      image      = var.gateway_image
      depends_on = ["redis"]

      ports {
        container_port = 8080
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      # The schema has to be applied by something, and this image is distroless:
      # there is no shell in it and Cloud Run has no exec. The gateway applying
      # its own migrations at boot is the only thing left that can, which is the
      # case AUTO_MIGRATE was added for.
      env {
        name  = "AUTO_MIGRATE"
        value = "true"
      }

      env {
        name  = "RATE_LIMITER"
        value = "redis"
      }

      # Not a secret: the sidecar has no address outside this instance's own
      # network namespace, so there is no credential here to protect.
      env {
        name  = "REDIS_URL"
        value = "redis://localhost:6379/0"
      }

      # A limiter that fails open turns a Redis outage into an unmetered gateway,
      # and a ledger that fails open turns a database outage into free spend.
      # This deployment exists to demonstrate that the limits hold, so both refuse.
      env {
        name  = "RATE_LIMIT_FAIL_OPEN"
        value = "false"
      }

      env {
        name  = "BUDGET_FAIL_OPEN"
        value = "false"
      }

      env {
        name  = "LOG_LEVEL"
        value = "info"
      }

      env {
        name  = "TOLLGATE_ENV"
        value = each.key
      }

      dynamic "env" {
        for_each = {
          DATABASE_URL = "tollgate-${each.key}-database-url"
          ADMIN_TOKEN  = "tollgate-${each.key}-admin-token"
        }

        content {
          name = env.key

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.all[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      startup_probe {
        tcp_socket {
          port = 8080
        }

        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 20
      }
    }

    # Redis as a sidecar rather than Memorystore. Memorystore's floor is a basic
    # 1GB instance at roughly 35 USD a month and it cannot scale to zero, so
    # leaving a preserved baseline standing would have cost that every month for
    # a demonstration that is idle almost all of the time. A sidecar is billed
    # with the revision, which is billed only while a request is in flight.
    #
    # The cost of the choice, stated rather than hidden: this Redis is per
    # instance, so the limiter is shared between concurrent requests on one
    # instance but not between instances. The Lua script, the token bucket and
    # the fail-closed path are all genuinely exercised; a cross-instance shared
    # counter is not. max_instance_count is small for that reason.
    containers {
      name  = "redis"
      image = var.redis_image

      args = ["--save", "", "--appendonly", "no"]

      # Declared, and dropped by the API: see the note on the gateway container
      # above. Only the first container in the list is given the Cloud SQL
      # socket, so this block has no effect and is kept only so that the two
      # containers read the same and the next person does not "fix" the order.
      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      startup_probe {
        tcp_socket {
          port = 6379
        }

        initial_delay_seconds = 1
        period_seconds        = 2
        failure_threshold     = 10
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_version.all,
    google_secret_manager_secret_iam_member.accessor,
    google_project_iam_member.gateway_sql,
    google_sql_user.env,
    google_sql_database.env,
  ]
}

# Argus's backend. Unlike the gateway it has no authentication of its own, so it
# is not published to allUsers: reaching it needs a Google identity token, which
# is the correct default for a service whose front door has not been written yet.
resource "google_cloud_run_v2_service" "argus" {
  for_each = local.envs

  name     = "argus-backend-${each.key}"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  deletion_protection = false

  template {
    service_account = google_service_account.argus[each.key].email

    scaling {
      min_instance_count = 0
      max_instance_count = 1
    }

    containers {
      image = var.argus_image

      ports {
        container_port = 8000
      }

      env {
        name  = "ARGUS_ENV"
        value = each.key
      }

      dynamic "env" {
        for_each = {
          SUPABASE_URL = "argus-${each.key}-supabase-url"
          SUPABASE_KEY = "argus-${each.key}-supabase-key"
        }

        content {
          name = env.key

          value_source {
            secret_key_ref {
              secret  = google_secret_manager_secret.all[env.value].secret_id
              version = "latest"
            }
          }
        }
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }
    }
  }

  depends_on = [
    google_secret_manager_secret_version.all,
    google_secret_manager_secret_iam_member.accessor,
  ]
}

# The gateways answer unauthenticated requests because that is their job: the
# front door does its own authentication with tenant API keys, and putting Cloud
# Run IAM in front of it would consume the Authorization header the tenant key
# travels in. The upstream is public because the gateway reaches it over the
# public run.app name holding no Google credential to sign with. Argus is on
# neither list.
resource "google_cloud_run_v2_service_iam_member" "public" {
  for_each = merge(
    { for e in local.envs : "gateway-${e}" => google_cloud_run_v2_service.gateway[e].name },
    { "upstream" = google_cloud_run_v2_service.upstream.name },
  )

  location = var.region
  name     = each.value
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# The operator, and only the operator, may invoke Argus.
resource "google_cloud_run_v2_service_iam_member" "argus_operator" {
  for_each = local.envs

  location = var.region
  name     = google_cloud_run_v2_service.argus[each.key].name
  role     = "roles/run.invoker"
  member   = var.operator_principal
}
