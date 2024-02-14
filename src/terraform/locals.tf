locals {
  public_ip                  = chomp(data.http.icanhazip.response_body)
  ing_internal_name          = "ingress-internal"
  ing_public_name            = "ingress-public"
  secret_provider_class_name = "${azurerm_key_vault.this.name}-aks-msi-ing-tls"
}
