# Azure subscription access
variable "tenant_id" {}
variable "subsc_id" {}
variable "conn_subsc_id" {}
variable "client_id" {}
variable "client_secret" {}

# Base settings
variable "app_prefix" {}
variable "location" {}

# TLS Certificate
variable "pfx_cert_name" {}
variable "pfx_cert_password" {}

variable "dns_zone_id" {}
variable "aks_managed_rg_name" {}
