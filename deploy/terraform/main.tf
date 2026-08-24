# Provisions the gateway's backing stores, Redis and Postgres, inside the
# selected Kubernetes cluster. Cloud verification deliberately uses these
# same in-cluster resources rather than managed database services.

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

variable "postgres_storage_size" {
  description = "Postgres PVC size. Cloud runs use 10Gi; local kind keeps the 1Gi default."
  type        = string
  default     = "1Gi"
}

variable "postgres_storage_class" {
  description = "Optional Kubernetes storage class for the Postgres PVC."
  type        = string
  default     = null
  nullable    = true
}

provider "kubernetes" {
  config_path    = var.kubeconfig_path
  config_context = var.kube_context
}

resource "kubernetes_storage_class_v1" "postgres" {
  count = var.postgres_storage_class == "gp3" ? 1 : 0

  metadata {
    name = "gp3"
  }

  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Delete"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type      = "gp3"
    encrypted = "true"
  }
}

resource "kubernetes_namespace_v1" "tollgate" {
  metadata {
    name = var.namespace
    labels = {
      "app.kubernetes.io/managed-by" = "terraform"
    }
  }
}
