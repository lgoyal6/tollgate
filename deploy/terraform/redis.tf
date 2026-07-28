# Redis holds only rate-limit counters: small, hot, and reconstructible, so
# a single unreplicated instance with no persistence is the right shape.
# Losing it means at worst one refilled bucket per tenant, and the gateway
# fails open (with an alertable error metric) while it is gone.

resource "kubernetes_deployment_v1" "redis" {
  metadata {
    name      = "redis"
    namespace = kubernetes_namespace_v1.tollgate.metadata[0].name
    labels    = { app = "redis" }
  }
  spec {
    replicas = 1
    selector {
      match_labels = { app = "redis" }
    }
    template {
      metadata {
        labels = { app = "redis" }
      }
      spec {
        container {
          name  = "redis"
          image = "redis:7-alpine"
          args  = ["redis-server", "--maxmemory", "128mb", "--maxmemory-policy", "allkeys-lru", "--save", ""]
          port {
            container_port = 6379
          }
          resources {
            requests = { cpu = "100m", memory = "64Mi" }
            limits   = { cpu = "500m", memory = "160Mi" }
          }
          readiness_probe {
            exec {
              command = ["redis-cli", "ping"]
            }
            period_seconds = 3
          }
          liveness_probe {
            tcp_socket {
              port = 6379
            }
            period_seconds = 10
          }
        }
      }
    }
  }
}

resource "kubernetes_service_v1" "redis" {
  metadata {
    name      = "redis"
    namespace = kubernetes_namespace_v1.tollgate.metadata[0].name
  }
  spec {
    selector = { app = "redis" }
    port {
      port        = 6379
      target_port = 6379
    }
  }
}

output "redis_addr" {
  value = "${kubernetes_service_v1.redis.metadata[0].name}.${var.namespace}.svc.cluster.local:6379"
}
