variable "project_id" {
  description = "Existing GCP project that holds the federated identities and runtime secrets."
  type        = string
}

variable "project_number" {
  description = "Numeric project number, used to build workload identity principal sets."
  type        = string
}

variable "region" {
  description = "Region for the artifact repository and the runtime state bucket."
  type        = string
  default     = "us-central1"
}

variable "name_prefix" {
  description = "Prefix for every resource this stack owns, so it never collides with other work in the project."
  type        = string
  default     = "c10"
}

variable "github_owner" {
  description = "GitHub account that owns the deploying repository."
  type        = string
  default     = "lgoyal6"
}

variable "github_owner_id" {
  description = "Immutable numeric GitHub account id. Survives a rename; a squatter on the same login has a different one."
  type        = string
  default     = "238557621"
}

variable "github_repository" {
  description = "Repository name allowed to deploy."
  type        = string
  default     = "tollgate"
}

variable "github_repository_id" {
  description = "Immutable numeric repository id. Changes if the repository is deleted and re-created."
  type        = string
  default     = "1314415571"
}

variable "deploy_workflow" {
  description = "The one workflow file allowed to assume the deployment identity."
  type        = string
  default     = ".github/workflows/deploy.yml"
}

variable "deploy_environment" {
  description = "GitHub Environment a deploy must run in. Empty removes the requirement."
  type        = string
  default     = "production"
}

variable "tag_prefix" {
  description = "Only tags starting with this may deploy."
  type        = string
  default     = "v"
}

variable "state_bucket_suffix" {
  description = "Suffix that makes the runtime state bucket name globally unique."
  type        = string
}
