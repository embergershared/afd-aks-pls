locals {
  public_ip = chomp(data.http.icanhazip.response_body)

  secret_provider_class_name = "${azurerm_key_vault.this.name}-aks-msi-ing-tls"

  # Namespaces to use
  ing_internal_name = "ingress-internal"
  ing_public_name   = "ingress-public"
  azure_vote        = "azure-vote"
  httpbin           = "httpbin"
  hello_aks         = "hello-aks"

  namespaces = toset([
    local.ing_internal_name,
    local.ing_public_name,
    local.azure_vote,
    local.httpbin,
    local.hello_aks
  ])
}
