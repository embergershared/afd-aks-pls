# Subscription to deploy to
variable "tenant_id" {}
variable "subsc_id" {}
variable "client_id" {}
variable "client_secret" {}
variable "aks_admins_group" {}

# Subscription with the connectivity resource(s) (Public DNS Zone)
variable "conn_tenant_id" {}
variable "conn_subsc_id" {}
variable "conn_client_id" {}
variable "conn_client_secret" {}
variable "public_dns_zone_id" {}


# 2 steps deployment control
variable "is_ready_to_deploy_origins" {
  type    = bool
  default = false
}

# Base settings
variable "res_suffix" {}
variable "loc_sub" {}
variable "location" {}

# TLS Certificate
variable "pfx_cert_name" {}
variable "pfx_cert_password" {}

