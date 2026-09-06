# One bounded environment per entry. The point of the list is that nothing below
# is written twice: every service account, every secret, every database and every
# Cloud Run service is produced per environment, so "prod" and "stage" cannot end
# up sharing an identity by an oversight in one resource.
locals {
  envs = toset(["prod", "stage"])

  services = [
    "artifactregistry.googleapis.com",
    "cloudbuild.googleapis.com",
    "iamcredentials.googleapis.com",
    "logging.googleapis.com",
    "monitoring.googleapis.com",
    "run.googleapis.com",
    "secretmanager.googleapis.com",
    "sqladmin.googleapis.com",
  ]
}

# disable_on_destroy is off everywhere: turning an API off is a project-wide act,
# and this stack shares its project with whatever else the owner runs there.
resource "google_project_service" "enabled" {
  for_each = toset(local.services)

  project            = var.project_id
  service            = each.value
  disable_on_destroy = false
}

resource "google_artifact_registry_repository" "c16" {
  location      = var.region
  repository_id = "c16"
  format        = "DOCKER"
  description   = "Gateway, demo upstream, mirrored Redis and Argus backend images."

  depends_on = [google_project_service.enabled]
}
