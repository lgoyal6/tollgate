# Postgres holds the gateway's control plane: tenants, routes, api keys.
# StatefulSet with a PVC so config survives pod restarts; credentials are
# generated here and handed to the app through a Secret it mounts by name.

resource "random_password" "postgres" {
  length  = 24
  special = false
}

resource "kubernetes_secret_v1" "postgres_credentials" {
  metadata {
    name      = "postgres-credentials"
    namespace = kubernetes_namespace_v1.tollgate.metadata[0].name
  }
  data = {
    username     = "tollgate"
    password     = random_password.postgres.result
    database_url = "postgres://tollgate:${random_password.postgres.result}@postgres.${var.namespace}.svc.cluster.local:5432/tollgate"
  }
}

resource "kubernetes_stateful_set_v1" "postgres" {
  metadata {
    name      = "postgres"
    namespace = kubernetes_namespace_v1.tollgate.metadata[0].name
    labels    = { app = "postgres" }
  }
  spec {
    service_name = "postgres"
    replicas     = 1
    selector {
      match_labels = { app = "postgres" }
    }
    template {
      metadata {
        labels = { app = "postgres" }
      }
      spec {
        container {
          name  = "postgres"
          image = "postgres:16-alpine"
          env {
            name  = "POSTGRES_USER"
            value = "tollgate"
          }
          env {
            name = "POSTGRES_PASSWORD"
            value_from {
              secret_key_ref {
                name = kubernetes_secret_v1.postgres_credentials.metadata[0].name
                key  = "password"
              }
            }
          }
          env {
            name  = "POSTGRES_DB"
            value = "tollgate"
          }
          env {
            name  = "PGDATA"
            value = "/var/lib/postgresql/data/pgdata"
          }
          port {
            container_port = 5432
          }
          resources {
            requests = { cpu = "250m", memory = "256Mi" }
            limits   = { cpu = "1", memory = "512Mi" }
          }
          volume_mount {
            name       = "data"
            mount_path = "/var/lib/postgresql/data"
          }
          readiness_probe {
            exec {
              command = ["pg_isready", "-U", "tollgate"]
            }
            period_seconds = 3
          }
        }
      }
    }
    volume_claim_template {
      metadata {
        name = "data"
      }
      spec {
        access_modes = ["ReadWriteOnce"]
        resources {
          requests = { storage = "1Gi" }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "postgres" {
  metadata {
    name      = "postgres"
    namespace = kubernetes_namespace_v1.tollgate.metadata[0].name
  }
  spec {
    selector = { app = "postgres" }
    port {
      port        = 5432
      target_port = 5432
    }
  }
}

output "database_url_secret" {
  value       = "${kubernetes_secret_v1.postgres_credentials.metadata[0].name} (key: database_url)"
  description = "The gateway reads DATABASE_URL from this secret"
}
