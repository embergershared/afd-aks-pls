data "azurerm_dns_zone" "public_dnz_zone" {
  provider = azurerm.s2-connectivity

  name                = split("/", var.dns_zone_id)[8]
  resource_group_name = split("/", var.dns_zone_id)[4]
}

# data "azurerm_resources" "aks_managed_plss" {
#   resource_group_name = var.aks_managed_rg_name
#   type                = "Microsoft.Network/privateLinkServices"
# }

# data "azurerm_private_link_service" "priv_ing_pls" {
#   name                = data.azurerm_resources.aks_managed_plss.resources[0].name
#   resource_group_name = var.aks_managed_rg_name
# }

# Get public IP
# https://registry.terraform.io/providers/hashicorp/http/latest/docs/data-sources/http
data "http" "icanhazip" {
  url = "http://icanhazip.com"
}


data "kubernetes_service" "ingress_public" {
  depends_on = [helm_release.ing_ctrl_public]

  metadata {
    name      = "${local.ing_public_name}-ingress-nginx-controller"
    namespace = local.ing_public_name
  }
}

# data "kubernetes_service" "ingress_internal" {
#   depends_on = [helm_release.ing_ctrl_internal]

#   metadata {
#     name      = "${local.ing_internal_name}-ingress-nginx-controller"
#     namespace = local.ing_internal_name
#   }
# }
