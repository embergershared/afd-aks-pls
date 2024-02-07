data "azurerm_dns_zone" "public_dnz_zone" {
  provider = azurerm.s2-connectivity

  name                = split("/", var.dns_zone_id)[8]
  resource_group_name = split("/", var.dns_zone_id)[4]
}

data "azurerm_resources" "aks_managed_plss" {
  resource_group_name = var.aks_managed_rg_name
  type                = "Microsoft.Network/privateLinkServices"
}

data "azurerm_private_link_service" "priv_ing_pls" {
  name                = data.azurerm_resources.aks_managed_plss.resources[0].name
  resource_group_name = var.aks_managed_rg_name
}
