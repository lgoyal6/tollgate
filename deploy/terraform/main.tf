# Provisions the gateway's backing stores — Redis and Postgres — into the
# kind cluster. In a cloud deployment this file would target ElastiCache and
# RDS instead; the interface the app sees (an address and a DSN in a secret)
# stays the same, which is the point of keeping it in Terraform.

terraform {
  required_version = ">= 1.5"
  required_providers {
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

variable "kubeconfig_path" {
  description = "Path to kubeconfig"
  type        = string
  default     = "~/.kube/config"
}

variable "kube_context" {
  description = "Kubeconfig context for the target cluster"
  type        = string
  default     = "kind-tollgate"
}

variable "namespace" {
  type    = string
  default = "tollgate"
}

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context
}

resource "kubernetes_namespace_v1" "tollgate" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}
