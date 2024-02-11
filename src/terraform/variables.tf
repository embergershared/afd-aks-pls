# Azure subscription access
variable "tenant_id" {}
variable "subsc_id" {}
variable "conn_subsc_id" {}
variable "client_id" {}
variable "client_secret" {}
variable "aks_admins_group" {}

# Base settings
variable "res_suffix" {}
variable "loc_sub" {}
variable "location" {}

# TLS Certificate
variable "pfx_cert_name" {}
variable "pfx_cert_password" {}

variable "dns_zone_id" {}
