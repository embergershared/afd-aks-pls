# Get public IP
# https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
data "http" "icanhazip" {
  url = "http://icanhazip.com"
}
# Get the Azure Public DNS Zone to create the AFD Endpoints CNAME records
data "azurerm_dns_zone" "public_dns_zone" {
  provider = azurerm.s2-connectivity

  name                = split("/", var.public_dns_zone_id)[8]
  resource_group_name = split("/", var.public_dns_zone_id)[4]
}

# Gather the Diagnostic categories for the selected resources
data "azurerm_monitor_diagnostic_categories" "diag_cat_afd" {
  resource_id = azurerm_cdn_frontdoor_profile.this.id
}
data "azurerm_monitor_diagnostic_categories" "diag_cat_aks" {
  depends_on = [azurerm_kubernetes_cluster.this]
  count      = local.deploy_aks ? 1 : 0

  resource_id = azurerm_kubernetes_cluster.this.0.id
}


# Allows to get the Public IP of the Public Ingress controller
data "kubernetes_service_v1" "public_ingress_svc" {
  depends_on = [helm_release.public_ingress_controller]

  count = local.deploy_option1 ? 1 : 0

  metadata {
    name      = "${local.public_ingress_name}-ingress-nginx-controller"
    namespace = local.public_ingress_name
  }
}

# Allows to get the Private IP of the Internal Ingress controller on the ilb-subnet
data "kubernetes_service_v1" "internal_ingress_svc" {
  depends_on = [helm_release.internal_ingress_controller]

  count = local.deploy_option2 ? 1 : 0

  metadata {
    name      = "${local.internal_ingress_name}-ingress-nginx-controller"
    namespace = local.internal_ingress_name
  }
}
