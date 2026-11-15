# BankShield — simulated bank landing zone on GCP.
#
# Creates four projects under a folder, enables audit logging + asset inventory, wires a
# Pub/Sub log sink that the BankShield ingester consumes, and (deliberately) plants a few
# misconfigurations that the posture rules are expected to catch. Apply with care: the
# planted misconfigs are real misconfigs. Use a sandbox org.

terraform {
  required_version = ">= 1.6"
  required_providers {
    google = { source = "hashicorp/google", version = "~> 5.0" }
  }
}

provider "google" {
  region = var.region
}

locals {
  projects = {
    core-banking-prod = { sensitivity = "restricted" }
    payments-prod     = { sensitivity = "restricted" }
    data-lake         = { sensitivity = "restricted" }
    shared-services   = { sensitivity = "internal" }
  }
}

resource "google_folder" "bank" {
  display_name = "bankshield-sim"
  parent       = "organizations/${var.org_id}"
}

resource "google_project" "p" {
  for_each        = local.projects
  name            = each.key
  project_id      = "${var.prefix}-${each.key}"
  folder_id       = google_folder.bank.name
  billing_account = var.billing_account
  labels          = { sensitivity = each.value.sensitivity, managed_by = "bankshield" }
}

resource "google_project_service" "apis" {
  for_each = { for pair in setproduct(keys(local.projects), var.apis) : "${pair[0]}/${pair[1]}" => pair }
  project  = google_project.p[each.value[0]].project_id
  service  = each.value[1]
}

# ---- Audit logs: Data Access logging on everything (LOG-1.1)
resource "google_project_iam_audit_config" "all" {
  for_each = google_project.p
  project  = each.value.project_id
  service  = "allServices"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }
}

# ---- Central log sink -> Pub/Sub -> BankShield ingester (LOG-1.2)
resource "google_pubsub_topic" "audit" {
  project = google_project.p["shared-services"].project_id
  name    = "bankshield-audit-logs"
}

resource "google_logging_project_sink" "to_pubsub" {
  for_each               = google_project.p
  project                = each.value.project_id
  name                   = "bankshield-sink"
  destination            = "pubsub.googleapis.com/${google_pubsub_topic.audit.id}"
  filter                 = "logName:\"cloudaudit.googleapis.com\""
  unique_writer_identity = true
}

resource "google_pubsub_topic_iam_member" "sink_writers" {
  for_each = google_logging_project_sink.to_pubsub
  project  = google_project.p["shared-services"].project_id
  topic    = google_pubsub_topic.audit.name
  role     = "roles/pubsub.publisher"
  member   = each.value.writer_identity
}

# ---- Locked central log bucket, 400-day retention (LOG-1.3)
resource "google_storage_bucket" "central_logs" {
  project                     = google_project.p["shared-services"].project_id
  name                        = "${var.prefix}-central-audit-logs"
  location                    = var.region
  uniform_bucket_level_access = true
  versioning { enabled = true }
  retention_policy {
    retention_period = 400 * 86400
    is_locked        = false # set true in a real deployment; locking is irreversible
  }
}

# ---- Org policy: resource location restriction (DRS-2.1)
resource "google_folder_organization_policy" "locations" {
  folder     = google_folder.bank.name
  constraint = "gcp.resourceLocations"
  list_policy {
    allow { values = ["in:asia-south1-locations", "in:asia-south2-locations"] }
  }
}
