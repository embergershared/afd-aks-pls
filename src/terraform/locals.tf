locals {
  public_ip                  = chomp(data.http.icanhazip.response_body)
  secret_provider_class_name = "${azurerm_key_vault.this.name}-aks-msi-ing-tls"


  # Base resources Tags
  UTC_to_TZ      = "-5h" # Careful to factor DST
  TZ_suffix      = "EST"
  created_TZtime = timeadd(local.created_now, local.UTC_to_TZ)
  created_now    = time_static.this.rfc3339
  created_nowTZ  = "${formatdate("YYYY-MM-DD hh:mm", local.created_TZtime)} ${local.TZ_suffix}" # 2020-06-16 14:44 EST

  base_tags = tomap({
    "Created_with"    = "Terraform v1.7.2 on windows_amd64",
    "Created_on"      = "${local.created_nowTZ}",
    "Initiated_by"    = "Manually",
    "GiHub_repo"      = "https://github.com/embergershared/aks-afd-pls",
    "Subscription"    = "s4",
    "Terraform_state" = "tfstates-s4-spokes/aks-afd-pls"
  })


  # Namespaces to use
  internal_ingress_name = "ingress-internal"
  public_ingress_name   = "ingress-public"
  azure_vote            = "azure-vote"
  httpbin               = "httpbin"
  hello_aks             = "hello-aks"
  whoami                = "whoami"

  apps_namespaces = [
    local.azure_vote,
    local.httpbin,
    local.hello_aks,
    local.whoami
  ]
  ns_full_set = toset(concat(
    local.apps_namespaces,
    local.deploy_option1 ? [local.public_ingress_name] : [],
    local.deploy_option2 ? [local.internal_ingress_name] : []
  ))

  # Resource ID of the Public Load Balancer bound Private Link Service
  public_lb_pls_name = "pls-${local.public_ingress_name}"
  public_lb_pls_id = replace(
    azurerm_virtual_network.this.id,
    "/virtualNetworks/${azurerm_virtual_network.this.name}",
    "/privateLinkServices/${local.public_lb_pls_name}/"
  )


  # Resource ID of the Internal Load Balancer bound Private Link Service
  ilb_pls_name = "pls-${local.internal_ingress_name}"
  ilb_pls_id = replace(
    azurerm_virtual_network.this.id,
    "/virtualNetworks/${azurerm_virtual_network.this.name}",
    "/privateLinkServices/${local.ilb_pls_name}/"
  )

  ########  Deployment control  ########

  # Deployment steps:
  # 1. Set all controls variables below to "false", run terraform apply to deploy:
  #    - RG, KV, AFD, VNet, Storage Account, Log Analytics Workspace,
  #    - AFD Diagnostic settings.
  #
  # 2. Set "deploy_aks" to "true", run terraform apply to deploy:
  # Note: It is possible to start at this stage, skipping terraform apply of step 1.
  #    - the AKS cluster,
  #    - the namespaces,
  #    - AKS Diagnostic settings.
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

  # Deployment control variables
  deploy_aks                = true
  kubernetes_manifest_ready = true  # Required to manage that resources of type kubernetes_manifest will query the cluster, even if not created
  deploy_option1            = true  # Front Door to Public kubernetes Ingresses
  deploy_option2            = false # Front Door to Internal kubernetes Ingresses through Private Link Service on the Internal Load Balancer
  deploy_option3            = false # Front Door to kubernetes Services through Private Link Service on the Internal Load Balancer
}
