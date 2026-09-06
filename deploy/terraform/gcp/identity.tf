# ---------------------------------------------------------------- identity ---
# The requirement this file exists for: an environment's credential is that
# environment's, and carries no reach into another. There are three separate
# identity systems in play and each is split per environment, because splitting
# only one of them leaves a way across.
#
#   1. Google service accounts   - tollgate-prod is not tollgate-stage.
#   2. Secret Manager grants     - a secret names exactly one accessor.
#   3. Postgres login roles      - a role connects to one database.
#
# Argus gets the same treatment with its own accounts, so that a compromise of
# the gateway's runtime identity does not read Argus's configuration either.

resource "google_service_account" "gateway" {
  for_each = local.envs

  account_id   = "tollgate-${each.key}"
  display_name = "tollgate gateway runtime (${each.key})"

  depends_on = [google_project_service.enabled]
}

# The echo upstream holds no credential, so it is given an identity with no
# role at all rather than being left on the project's default compute account.
# That account carries roles/editor, which this project's `gcloud projects
# get-iam-policy` confirms, and the upstream is the one service published to
# allUsers: leaving the two facts stacked means a public container runs as
# project editor for no reason anyone chose.
resource "google_service_account" "upstream" {
  account_id   = "tollgate-upstream"
  display_name = "tollgate demo upstream runtime (no roles)"

  depends_on = [google_project_service.enabled]
}

resource "google_service_account" "argus" {
  for_each = local.envs

  account_id   = "argus-${each.key}"
  display_name = "argus backend runtime (${each.key})"

  depends_on = [google_project_service.enabled]
}

# The Cloud SQL connector authenticates as the gateway's account, which is why
# the instance's authorized-network list holds no Cloud Run entry.
#
# Note what this role does and does not do: roles/cloudsql.client is granted on
# the project, so it lets either gateway account open a connection to the one
# instance. It is not the environment boundary and is not claimed to be. The
# boundary is that each account can only read its own DSN out of Secret Manager,
# and that the role inside that DSN is refused CONNECT on the other database.
resource "google_project_iam_member" "gateway_sql" {
  for_each = local.envs

  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${google_service_account.gateway[each.key].email}"
}

# Lets the operator mint a token *as* an environment's runtime account. Without
# this, "stage cannot read prod's secret" would be an assertion about an IAM
# policy document; with it, the claim is a command that returns PERMISSION_DENIED.
resource "google_service_account_iam_member" "operator_impersonation" {
  for_each = merge(
    { for e in local.envs : "gateway-${e}" => google_service_account.gateway[e].name },
    { for e in local.envs : "argus-${e}" => google_service_account.argus[e].name },
  )

  service_account_id = each.value
  role               = "roles/iam.serviceAccountTokenCreator"
  member             = var.operator_principal
}
