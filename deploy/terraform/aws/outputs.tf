output "cluster_name" {
  value       = aws_eks_cluster.tollgate.name
  description = "EKS cluster used by the deployment workflow."
}

output "region" {
  value       = var.region
  description = "AWS region containing the verification stack."
}

output "gateway_repository_url" {
  value       = aws_ecr_repository.gateway.repository_url
  description = "ECR repository for the Tollgate gateway."
}

output "upstream_repository_url" {
  value       = aws_ecr_repository.upstream.repository_url
  description = "ECR repository for the mock upstream."
}

output "github_actions_role_arn" {
  value       = aws_iam_role.github_actions.arn
  description = "Store this runtime value as the AWS_ROLE_ARN GitHub Actions secret."
}

output "cluster_shape" {
  value = {
    availability_zones = var.availability_zones
    instance_type      = var.worker_instance_type
    node_count         = var.worker_count
    node_disk_gib      = aws_eks_node_group.tollgate.disk_size
  }
  description = "Fixed worker shape to record in the benchmark methodology."
}

output "teardown_command" {
  value       = "./deploy/terraform/aws/teardown.sh"
  description = "Run from the repository root as soon as verification is complete."
}
