variable "region" {
  description = "AWS region for EKS, ECR, VPC, and EBS resources."
  type        = string
  default     = "us-east-1"

  validation {
    condition     = var.region == "us-east-1"
    error_message = "The benchmark stack is fixed to us-east-1."
  }
}

variable "availability_zones" {
  description = "Two availability zones used by the public benchmark subnets."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]

  validation {
    condition = (
      length(var.availability_zones) == 2 &&
      var.availability_zones[0] == "us-east-1a" &&
      var.availability_zones[1] == "us-east-1b"
    )
    error_message = "The benchmark stack is fixed to us-east-1a and us-east-1b."
  }
}

variable "cluster_name" {
  description = "EKS cluster name used by Terraform and GitHub Actions."
  type        = string
  default     = "tollgate"
}

variable "kubernetes_version" {
  description = "Optional EKS Kubernetes version. Null selects AWS's current default under standard support."
  type        = string
  default     = null
  nullable    = true
}

variable "worker_instance_type" {
  description = "On-demand EC2 instance type for each benchmark worker."
  type        = string
  default     = "m7i-flex.large"

  validation {
    condition     = var.worker_instance_type == "m7i-flex.large"
    error_message = "The benchmark methodology is fixed to m7i-flex.large workers."
  }
}

variable "worker_count" {
  description = "Fixed size of the EKS managed node group."
  type        = number
  default     = 2

  validation {
    condition     = var.worker_count == 2
    error_message = "The benchmark methodology is fixed to two workers."
  }
}

variable "github_repository" {
  description = "GitHub owner/repository allowed to deploy version tags through OIDC."
  type        = string
  default     = "lgoyal6/tollgate"
}
