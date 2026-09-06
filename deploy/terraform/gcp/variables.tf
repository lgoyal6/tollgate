variable "project_id" {
  description = "Existing GCP project that owns every resource here."
  type        = string
}

variable "region" {
  description = "Region for Cloud Run, Cloud SQL and Artifact Registry."
  type        = string
  default     = "us-central1"
}

variable "gateway_image" {
  description = "Artifact Registry image for the tollgate gateway. Built and pushed before apply, because Terraform does not build containers."
  type        = string
}

variable "upstream_image" {
  description = "Artifact Registry image for the demo upstream the gateway proxies to."
  type        = string
}

variable "redis_image" {
  description = "Artifact Registry image for the per-revision Redis sidecar. Cloud Run cannot pull from Docker Hub, so upstream redis is mirrored into this project's registry."
  type        = string
}

variable "argus_image" {
  description = "Artifact Registry image for the Argus FastAPI backend, built from the working tree only."
  type        = string
}

variable "operator_cidr" {
  description = "The single address allowed to reach Cloud SQL over its public IP, in CIDR form. This is the operator's own machine: budget rows and per-environment GRANTs have no HTTP surface. Cloud Run does not use this path; it connects over the Cloud SQL connector."
  type        = string

  validation {
    condition     = can(cidrnetmask(var.operator_cidr))
    error_message = "operator_cidr must be CIDR, e.g. 203.0.113.7/32."
  }
}

variable "operator_principal" {
  description = "The human principal running this, as an IAM member string (user:someone@example.com). Granted token-creator on each per-environment service account so that a cross-environment access attempt can actually be executed as that environment, rather than asserted."
  type        = string
}

variable "db_tier" {
  description = "Cloud SQL machine type. The default is the smallest Postgres tier there is."
  type        = string
  default     = "db-f1-micro"
}

variable "gateway_max_instances" {
  description = "Cloud Run ceiling for a gateway. Minimum is fixed at zero so an idle deployment costs nothing."
  type        = number
  default     = 2
}
