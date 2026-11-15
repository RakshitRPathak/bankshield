# Deliberately planted misconfigurations for the posture rules to catch.
# Guarded by var.plant_misconfigs so a clean estate can be built with the same module.

resource "google_storage_bucket" "merchant_exports" {
  count                       = var.plant_misconfigs ? 1 : 0
  project                     = google_project.p["payments-prod"].project_id
  name                        = "${var.prefix}-merchant-exports"
  location                    = var.region
  uniform_bucket_level_access = false # BS-002
  labels                      = { sensitivity = "restricted" }
}

resource "google_storage_bucket_iam_member" "merchant_exports_public" {
  count  = var.plant_misconfigs ? 1 : 0
  bucket = google_storage_bucket.merchant_exports[0].name
  role   = "roles/storage.objectViewer"
  member = "allUsers" # BS-001  — real public exposure; sandbox org only
}

resource "google_compute_firewall" "ssh_any" {
  count   = var.plant_misconfigs ? 1 : 0
  project = google_project.p["payments-prod"].project_id
  name    = "allow-ssh-any"
  network = "default"
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
  source_ranges = ["0.0.0.0/0"] # BS-030
}

resource "google_service_account" "ci_deployer" {
  count        = var.plant_misconfigs ? 1 : 0
  project      = google_project.p["payments-prod"].project_id
  account_id   = "ci-deployer-sa"
  display_name = "CI deployer (over-privileged on purpose)"
}

resource "google_project_iam_member" "ci_editor" {
  count   = var.plant_misconfigs ? 1 : 0
  project = google_project.p["payments-prod"].project_id
  role    = "roles/editor" # BS-020
  member  = "serviceAccount:${google_service_account.ci_deployer[0].email}"
}

resource "google_storage_bucket" "ml_feature_store" {
  count    = var.plant_misconfigs ? 1 : 0
  project  = google_project.p["data-lake"].project_id
  name     = "${var.prefix}-ml-feature-store"
  location = "US" # BS-005 — will be blocked by the org policy above unless exempted; that's the point
  uniform_bucket_level_access = true
  labels   = { sensitivity = "restricted" }
}
