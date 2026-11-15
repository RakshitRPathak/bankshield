variable "org_id" { type = string }
variable "billing_account" { type = string }
variable "prefix" {
  type    = string
  default = "bsh"
}
variable "region" {
  type    = string
  default = "asia-south1"
}
variable "plant_misconfigs" {
  type    = bool
  default = true
}
variable "apis" {
  type = list(string)
  default = [
    "compute.googleapis.com", "sqladmin.googleapis.com", "storage.googleapis.com",
    "bigquery.googleapis.com", "cloudkms.googleapis.com", "secretmanager.googleapis.com",
    "logging.googleapis.com", "pubsub.googleapis.com", "cloudasset.googleapis.com",
    "iam.googleapis.com", "container.googleapis.com", "accesscontextmanager.googleapis.com",
  ]
}
