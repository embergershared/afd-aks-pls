resource "azurerm_resource_group" "this" {
  name     = "rg-${var.app_prefix}"
  location = var.location
}

resource "azurerm_storage_account" "this" {
  name                     = "stlogsdiagsaksafd"
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public  = false
  cross_tenant_replication_enabled = false
}

resource "azurerm_key_vault" "this" {
  name                = "kv-use2-446692-s4-aksfdp"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  tenant_id           = var.tenant_id
  sku_name            = "standard"

  enable_rbac_authorization       = true
  enabled_for_deployment          = false
  enabled_for_disk_encryption     = false
  enabled_for_template_deployment = false
}

resource "azurerm_key_vault_certificate" "this" {
  name         = "extended-star-ebdemos-info"
  key_vault_id = azurerm_key_vault.this.id
  certificate {
    contents = filebase64(var.pfx_cert_name)
    password = var.pfx_cert_password
  }
  lifecycle {
    ignore_changes = [certificate]
  }
}

resource "azurerm_virtual_network" "this" {
  name                = "vnet-${var.app_prefix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = ["10.0.0.0/19"]
}
resource "azurerm_subnet" "user_np_nodes" {
  name                 = "aks-userpool-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.2.0/24"]
}
resource "azurerm_subnet" "pods" {
  name                 = "aks-pod-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.8.0/21"]
  delegation {
    name = "Microsoft.ContainerService.managedClusters"
    service_delegation {
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
      name = "Microsoft.ContainerService/managedClusters"
    }
  }
}
resource "azurerm_subnet" "system_np_nodes" {
  name                 = "aks-systempool-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.1.0/24"]
}
resource "azurerm_subnet" "ilb" {
  name                 = "aks-ilb-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["10.0.3.0/24"]
}

resource "azurerm_private_dns_zone" "this" {
  name                = "ebdemos.info"
  resource_group_name = azurerm_resource_group.this.name
}
resource "azurerm_private_dns_a_record" "azvote" {
  name                = "azvote.int"
  zone_name           = azurerm_private_dns_zone.this.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 60
  records             = ["10.0.1.6"]
}
resource "azurerm_private_dns_a_record" "httpbin" {
  name                = "httpbin.int"
  zone_name           = azurerm_private_dns_zone.this.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 60
  records             = ["10.0.1.6"]
}
resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  name                  = "link-to-vnet"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.this.name
  virtual_network_id    = azurerm_virtual_network.this.id
  registration_enabled  = false
}


##### Azure Front Door
resource "azurerm_cdn_frontdoor_profile" "this" {
  name                     = "afd-use2-446692-s4-aks-fd-pls-02"
  resource_group_name      = azurerm_resource_group.this.name
  sku_name                 = "Premium_AzureFrontDoor"
  response_timeout_seconds = 60
}

# Endpoints
resource "azurerm_cdn_frontdoor_endpoint" "ep_1" {
  # https://aksafdpls-g2dqh6dvctcmgdfb.b01.azurefd.net/

  name                     = "aksafdpls1"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}
resource "azurerm_cdn_frontdoor_endpoint" "ep_2" {
  # https://aksafdpls-g2dqh6dvctcmgdfb.b01.azurefd.net/

  name                     = "aksafdpls2"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}

# Internal/Private-ingress Origin group
resource "azurerm_cdn_frontdoor_origin_group" "int_ing" {
  name                     = "internal-ingresses"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled = false

  health_probe {
    interval_in_seconds = 100
    path                = "/"
    protocol            = "Https"
    request_type        = "GET"
  }

  load_balancing {
    additional_latency_in_milliseconds = 50
    sample_size                        = 4
    successful_samples_required        = 3
  }

  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}
resource "azurerm_cdn_frontdoor_origin" "int_azvote" {
  name                          = "azvote-int"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = "azvote.int.ebdemos.info"
  origin_host_header             = "azvote.int.ebdemos.info"
  priority                       = 1
  weight                         = 1000

  private_link {
    request_message        = "Please approve"
    location               = azurerm_resource_group.this.location
    private_link_target_id = data.azurerm_private_link_service.priv_ing_pls.id
  }
}
resource "azurerm_cdn_frontdoor_origin" "int_httpbin" {
  name                          = "httpbin-int"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.id

  enabled                        = false
  certificate_name_check_enabled = true
  host_name                      = "httpbin.int.ebdemos.info"
  origin_host_header             = "httpbin.int.ebdemos.info"
  priority                       = 1
  weight                         = 1000

  private_link {
    request_message        = "Please approve"
    location               = azurerm_resource_group.this.location
    private_link_target_id = data.azurerm_private_link_service.priv_ing_pls.id
  }
}

# External/Public-ingress Origin group
resource "azurerm_cdn_frontdoor_origin_group" "ext_ing" {
  name                     = "external-ingresses"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  session_affinity_enabled = false

  health_probe {
    interval_in_seconds = 100
    path                = "/"
    protocol            = "Https"
    request_type        = "GET"
  }

  load_balancing {
    additional_latency_in_milliseconds = 50
    sample_size                        = 4
    successful_samples_required        = 3
  }

  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}
resource "azurerm_cdn_frontdoor_origin" "ext_azvote" {
  name                          = "azvote-ext"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.ext_ing.id

  enabled                        = false
  certificate_name_check_enabled = true
  host_name                      = "azvote.ebdemos.info"
  origin_host_header             = "azvote.ebdemos.info"
  priority                       = 1
  weight                         = 1000
}
resource "azurerm_cdn_frontdoor_origin" "ext_httpbin" {
  name                          = "httpbin-ext"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.ext_ing.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = "httpbin.ebdemos.info"
  origin_host_header             = "httpbin.ebdemos.info"
  priority                       = 1
  weight                         = 1000
}

# TLS certificate for AFD endpoint
resource "azurerm_cdn_frontdoor_secret" "tls_cert" {
  name                     = "test-ebdemos-info"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  secret {
    customer_certificate {
      key_vault_certificate_id = azurerm_key_vault_certificate.this.id
    }
  }
  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}

# To Internal ingress
resource "azurerm_dns_cname_record" "testint_ebdemos_info" {
  provider = azurerm.s2-connectivity

  name                = "testint"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  record              = azurerm_cdn_frontdoor_endpoint.ep_1.host_name
}
resource "azurerm_cdn_frontdoor_custom_domain" "testint_ebdemos_info" {
  name                     = "${azurerm_dns_cname_record.testint_ebdemos_info.name}-${replace(data.azurerm_dns_zone.public_dnz_zone.name, ".", "-")}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  dns_zone_id              = data.azurerm_dns_zone.public_dnz_zone.id
  host_name                = "${azurerm_dns_cname_record.testint_ebdemos_info.name}.${data.azurerm_dns_zone.public_dnz_zone.name}"
  # https://testext.ebdemos.info

  tls {
    certificate_type        = "CustomerCertificate"
    minimum_tls_version     = "TLS12"
    cdn_frontdoor_secret_id = azurerm_cdn_frontdoor_secret.tls_cert.id
  }
  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}
resource "azurerm_cdn_frontdoor_route" "int_route" {
  name                      = "rt-to-int-origins"
  cdn_frontdoor_endpoint_id = azurerm_cdn_frontdoor_endpoint.ep_1.id
  enabled                   = true

  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.id
  cdn_frontdoor_origin_ids = [
    azurerm_cdn_frontdoor_origin.int_azvote.id,
    azurerm_cdn_frontdoor_origin.int_httpbin.id,
  ]

  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = false
  patterns_to_match      = ["/*"]
  supported_protocols    = ["Https"]

  cdn_frontdoor_custom_domain_ids = [
    azurerm_cdn_frontdoor_custom_domain.testint_ebdemos_info.id,
  ]
  # link_to_default_domain = true
}
# https://testint.ebdemos.info

# To Public ingress
resource "azurerm_dns_cname_record" "testext_ebdemos_info" {
  provider = azurerm.s2-connectivity

  name                = "testext"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  record              = azurerm_cdn_frontdoor_endpoint.ep_2.host_name
}
resource "azurerm_cdn_frontdoor_custom_domain" "testext_ebdemos_info" {
  name                     = "${azurerm_dns_cname_record.testext_ebdemos_info.name}-${replace(data.azurerm_dns_zone.public_dnz_zone.name, ".", "-")}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  dns_zone_id              = data.azurerm_dns_zone.public_dnz_zone.id
  host_name                = "${azurerm_dns_cname_record.testext_ebdemos_info.name}.${data.azurerm_dns_zone.public_dnz_zone.name}"
  # https://testext.ebdemos.info

  tls {
    certificate_type        = "CustomerCertificate"
    minimum_tls_version     = "TLS12"
    cdn_frontdoor_secret_id = azurerm_cdn_frontdoor_secret.tls_cert.id
  }
  lifecycle {
    ignore_changes = [cdn_frontdoor_profile_id]
  }
}
resource "azurerm_cdn_frontdoor_route" "ext_route" {
  name                      = "rt-to-ext-origins"
  cdn_frontdoor_endpoint_id = azurerm_cdn_frontdoor_endpoint.ep_2.id
  enabled                   = true

  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.ext_ing.id
  cdn_frontdoor_origin_ids = [
    azurerm_cdn_frontdoor_origin.ext_azvote.id,
    azurerm_cdn_frontdoor_origin.ext_httpbin.id,
  ]

  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = false
  patterns_to_match      = ["/*"]
  supported_protocols    = ["Https"]

  cdn_frontdoor_custom_domain_ids = [
    azurerm_cdn_frontdoor_custom_domain.testext_ebdemos_info.id,
  ]
  # link_to_default_domain = true
}
# https://testext.ebdemos.info
