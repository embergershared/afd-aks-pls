locals {
  public_ip = chomp(data.http.icanhazip.response_body)

  secret_provider_class_name = "${azurerm_key_vault.this.name}-aks-msi-ing-tls"


  # Namespaces to use
  ing_internal_name = "ingress-internal"
  ing_public_name   = "ingress-public"
  azure_vote        = "azure-vote"
  httpbin           = "httpbin"
  hello_aks         = "hello-aks"

  apps_namespaces = [
    local.azure_vote,
    local.httpbin,
    local.hello_aks
  ]
  ns_w_opt1   = local.deploy_option1 ? concat(local.apps_namespaces, [local.ing_public_name]) : local.apps_namespaces
  ns_w_opt2   = local.deploy_option2 ? concat(local.ns_w_opt1, [local.ing_internal_name]) : local.ns_w_opt1
  ns_full_set = toset(local.ns_w_opt2)


  # Resource ID of the Internal Load Balancer bound Private Link Service
  ilb_pls_name = "pls-${local.ing_internal_name}"
  ilb_pls_id = replace(
    azurerm_virtual_network.this.id,
    "/virtualNetworks/${azurerm_virtual_network.this.name}",
    "/privateLinkServices/${local.ilb_pls_name}/"
  )

  ########  Deployment control  ########

  # Deployment steps:
  # 1. All locals below to "false", run terraform apply to deploy:
  #    - RG, KV, AFD, VNet and Storage Account.
  #
  # 2. Set "deploy_aks" to "true", run terraform apply to deploy:
  #    - the AKS cluster,
  #    - the namespaces.
  #
  # 3. Set "kubernetes_manifest_ready" to "true", run terraform apply to deploy:
  #    - all the kubernetes_manifest based resources:
  #      - the CSI driver for Key vault,
  #      - the 3 applications resources (deployments & services).
  #
  # 4a. Set "deploy_option1" to "true", run terraform apply to deploy:
  #    - the Public ingress controller,
  #    - the Public Ingress resources for the 3 applications,
  #    - the Public DNS record,
  #    - the Azure Front Door Endpoint,
  #    - the Azure Front Door Origin group & origins to the public ingresses,
  #    - the Azure Front Door routing rule.
  #
  # 4b. Set "deploy_option2" to "true", run terraform apply to deploy:
  #    - the Internal ingress controller on a kubernetes-internal load balancer,
  #    - the Internal ingress resources for the 3 applications,
  #    - the Private DNS record,
  #    - the Azure Front Door Endpoint,
  #    - the Azure Front Door Origin group & origins to the internal ingresses,
  #    - the Azure Front Door routing rule.
  #
  # 4c. Set "deploy_option3" to "true", run terraform apply to deploy:
  #    - the 3 services on kubernetes-internal load balancer with PLS for the 3 applications,
  #    - the Azure Front Door Endpoint,
  #    - the Azure Front Door Origin group & origins to the services PLSs,
  #    - the Azure Front Door routing rule.

  # Deployment contol variables
  deploy_aks = true
  # Required to manage the fact resources of type kubernetes_manifest will query the cluster, even if not created
  kubernetes_manifest_ready = true

  # Azure Front Door to Azure Kubernetes Service Options
  deploy_option1 = false # Front Door to Public kubernetes Ingresses
  deploy_option2 = false # Front Door to Internal kubernetes Ingresses through Private Link Service on the Internal Load Balancer
  deploy_option3 = false # Front Door to kubernetes Services through Private Link Service on the Internal Load Balancer
}
