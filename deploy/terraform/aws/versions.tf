terraform {
  required_version = ">= 1.9"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 6.59.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= 4.3.0"
    }
    http = {
      source  = "hashicorp/http"
      version = "= 3.5.0"
    }
  }
}

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "tollgate"
      Purpose = "cloud-verification"
    }
  }
}
