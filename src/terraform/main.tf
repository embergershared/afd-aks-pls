resource "azurerm_resource_group" "this" {
  name     = "rg-${var.loc_sub}-${var.res_suffix}"
  location = var.location
}

resource "azurerm_storage_account" "this" {
  name                     = substr(replace("st-${var.res_suffix}", "-", ""), 0, 24)
  resource_group_name      = azurerm_resource_group.this.name
  location                 = azurerm_resource_group.this.location
  account_tier             = "Standard"
  account_replication_type = "LRS"

  allow_nested_items_to_be_public  = false
  cross_tenant_replication_enabled = false
}
#   / Main location storage account Networking rules
resource "azurerm_storage_account_network_rules" "this" {
  # Prevents locking the Storage Account before all resources are created
  depends_on = [
    azurerm_storage_account.this
  ]

  storage_account_id         = azurerm_storage_account.this.id
  default_action             = "Deny"
  ip_rules                   = [local.public_ip]
  virtual_network_subnet_ids = []
  bypass                     = ["AzureServices"]
}

resource "azurerm_key_vault" "this" {
  name                = substr(lower("kv-${var.res_suffix}"), 0, 24)
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
  name                = "vnet-${var.res_suffix}"
  location            = azurerm_resource_group.this.location
  resource_group_name = azurerm_resource_group.this.name
  address_space       = ["192.168.0.0/22"]
}

resource "azurerm_subnet" "ilb" {
  name                 = "aks-ilb-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["192.168.0.0/27"]
}
resource "azurerm_subnet" "syspool1" {
  name                 = "aks-syspool1-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["192.168.1.0/26"]

  private_endpoint_network_policies_enabled     = false
  private_link_service_network_policies_enabled = false
  service_endpoint_policy_ids                   = null
  service_endpoints                             = null
}
resource "azurerm_subnet" "userpool1" {
  name                 = "aks-userpool1-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["192.168.1.64/26"]
}
resource "azurerm_subnet" "jobspool1" {
  name                 = "aks-jobspool1-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["192.168.1.128/26"]

  private_endpoint_network_policies_enabled     = false
  private_link_service_network_policies_enabled = false
  service_endpoint_policy_ids                   = null
  service_endpoints                             = null
}
resource "azurerm_subnet" "pods" {
  name                 = "aks-pod-snet"
  resource_group_name  = azurerm_resource_group.this.name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = ["192.168.2.0/24"]
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


resource "azurerm_private_dns_zone" "this" {
  count = local.deploy_option1 || local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                = "ebdemos.info"
  resource_group_name = azurerm_resource_group.this.name
}
resource "azurerm_private_dns_zone_virtual_network_link" "this" {
  count = local.deploy_option1 || local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                  = "link-to-aks-vnet"
  resource_group_name   = azurerm_resource_group.this.name
  private_dns_zone_name = azurerm_private_dns_zone.this.0.name
  virtual_network_id    = azurerm_virtual_network.this.id
  registration_enabled  = false
}


##### AKS
resource "azurerm_kubernetes_cluster" "this" {
  count = local.deploy_aks ? 1 : 0

  name                             = "aks-${var.res_suffix}"
  location                         = azurerm_resource_group.this.location
  resource_group_name              = azurerm_resource_group.this.name
  node_resource_group              = "${azurerm_resource_group.this.name}-managed"
  kubernetes_version               = "1.27.7"
  private_cluster_enabled          = false
  dns_prefix                       = "aks-${var.res_suffix}-dns"
  oidc_issuer_enabled              = true
  workload_identity_enabled        = true
  open_service_mesh_enabled        = false
  http_application_routing_enabled = false
  automatic_channel_upgrade        = "node-image"
  local_account_disabled           = true
  image_cleaner_enabled            = true
  image_cleaner_interval_hours     = 48

  api_server_access_profile {
    authorized_ip_ranges     = ["${local.public_ip}/32"]
    vnet_integration_enabled = false
  }
  azure_active_directory_role_based_access_control {
    admin_group_object_ids = [
      var.aks_admins_group,
    ]
    azure_rbac_enabled = true
    managed            = true
    tenant_id          = var.tenant_id
  }
  identity {
    type = "SystemAssigned"
  }
  network_profile {
    network_plugin = "azure"
  }
  default_node_pool {
    name                 = "syspool1"
    node_count           = 2
    vm_size              = "Standard_B2s"
    max_pods             = 150
    kubelet_disk_type    = "OS"
    orchestrator_version = "1.27.7"
    os_disk_size_gb      = 128
    os_sku               = "Ubuntu"
    # os_disk_type         = "Ephemeral"
    vnet_subnet_id   = azurerm_subnet.syspool1.id
    pod_subnet_id    = azurerm_subnet.pods.id
    workload_runtime = "OCIContainer"
    zones            = []
  }

  key_vault_secrets_provider {
    secret_rotation_enabled  = false
    secret_rotation_interval = "2m"
  }
}
resource "azurerm_kubernetes_cluster_node_pool" "userpool1" {
  count = local.deploy_aks ? 1 : 0

  name                  = "userpool1"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.this.0.id
  mode                  = "User"
  node_count            = 2
  vm_size               = "Standard_B2s"
  max_pods              = 150
  kubelet_disk_type     = "OS"
  orchestrator_version  = "1.27.7"
  os_disk_size_gb       = 128
  os_sku                = "Ubuntu"
  # os_disk_type         = "Ephemeral"
  vnet_subnet_id   = azurerm_subnet.userpool1.id
  pod_subnet_id    = azurerm_subnet.pods.id
  workload_runtime = "OCIContainer"
  zones            = []
}

##### Create all the namespaces to deploy the CSI secret provider in them
resource "kubernetes_namespace" "this" {
  for_each = local.deploy_aks ? local.ns_full_set : []
  metadata {
    name = each.value
  }
}

##### Create the CSI drivers in all namespaces for Key vault integration
resource "azurerm_role_assignment" "aks_kv_rassignment" {
  count = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  principal_id         = azurerm_kubernetes_cluster.this.0.key_vault_secrets_provider[0].secret_identity[0].object_id
  role_definition_name = "Key Vault Secrets User"
  scope                = azurerm_key_vault.this.id
}
resource "kubernetes_manifest" "kv_csi_secret_providers" {
  depends_on = [
    azurerm_kubernetes_cluster.this,
    kubernetes_namespace.this,
    azurerm_role_assignment.aks_kv_rassignment
  ]

  for_each = local.deploy_aks && local.kubernetes_manifest_ready ? local.ns_full_set : []

  manifest = yamldecode(
    <<-EOF
    # This is a SecretProviderClass example using user-assigned identity to access your key vault
    apiVersion: secrets-store.csi.x-k8s.io/v1
    kind: SecretProviderClass
    metadata:
      name: ${local.secret_provider_class_name}
      namespace: ${each.value}
    spec:
      provider: azure
      secretObjects:                            # secretObjects defines the desired state of synced K8s secret objects
        - secretName: "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
          type: kubernetes.io/tls
          data:
            - objectName: ${azurerm_key_vault_certificate.this.name}
              key: tls.key
            - objectName: ${azurerm_key_vault_certificate.this.name}
              key: tls.crt
      parameters:
        usePodIdentity: "false"
        useVMManagedIdentity: "true"                                                                                          # Set to true for using managed identity
        userAssignedIdentityID: ${azurerm_kubernetes_cluster.this.0.key_vault_secrets_provider[0].secret_identity[0].client_id} # Set the clientID of the user-assigned managed identity to use
        keyvaultName: ${azurerm_key_vault.this.name}                                                                          # Set to the name of your key vault
        objects:  |
          array:
            - |
              objectName: ${azurerm_key_vault_certificate.this.name}  # object names or secrets
              objectType: secret              # object types: secret, key, or cert
        tenantId: ${var.tenant_id}            # The tenant ID of the key vault
        EOF
  )
}

##### Deploy the 3 Apps for the tests
# / Httpbin
resource "kubernetes_manifest" "httpbin_dep" {
  depends_on = [kubernetes_namespace.this]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("httpbin/2.httpbin-dep.yaml"))
}
resource "kubernetes_manifest" "httpbin_svc" {
  depends_on = [kubernetes_manifest.httpbin_dep]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("httpbin/3.httpbin-svc-clusip.yaml"))
}

# / Azure vote
resource "kubernetes_manifest" "azvote_back_dep" {
  depends_on = [kubernetes_namespace.this]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("azure-vote/2.az-vote-back-dep.yaml"))
}
resource "kubernetes_manifest" "azvote_back_svc" {
  depends_on = [kubernetes_manifest.azvote_back_dep]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("azure-vote/3.az-vote-back-svc-clusip.yaml"))
}
resource "kubernetes_manifest" "azvote_front_dep" {
  depends_on = [kubernetes_namespace.this]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("azure-vote/4.az-vote-front-dep.yaml"))
}
resource "kubernetes_manifest" "azvote_front_svc" {
  depends_on = [kubernetes_manifest.azvote_front_dep]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("azure-vote/5.az-vote-front-svc-clusip.yaml"))
}

# / Hello AKS
resource "kubernetes_manifest" "helloaks_dep" {
  depends_on = [kubernetes_namespace.this]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("hello-aks/2.hello-aks-dep.yaml"))
}
resource "kubernetes_manifest" "helloaks_svc" {
  depends_on = [kubernetes_manifest.helloaks_dep]
  count      = local.deploy_aks && local.kubernetes_manifest_ready ? 1 : 0

  manifest = yamldecode(file("hello-aks/3.hello-aks-svc-clusip.yaml"))
}


##### Azure Front Door Common configuration
resource "azurerm_cdn_frontdoor_profile" "this" {
  name                     = "afd-${var.res_suffix}"
  resource_group_name      = azurerm_resource_group.this.name
  sku_name                 = "Premium_AzureFrontDoor"
  response_timeout_seconds = 60
}
resource "azapi_update_resource" "frontdoor_profile_system_identity" {
  type        = "Microsoft.Cdn/profiles@2023-02-01-preview"
  resource_id = azurerm_cdn_frontdoor_profile.this.id
  body = jsonencode({
    "identity" : {
      "type" : "SystemAssigned"
    }
  })
  response_export_values = ["identity.principalId", "identity.tenantId"]
}
resource "azurerm_role_assignment" "frontdoor_profile_system_identity" {
  depends_on = [azapi_update_resource.frontdoor_profile_system_identity]

  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = jsondecode(azapi_update_resource.frontdoor_profile_system_identity.output).identity.principalId
}

# TLS certificate for AFD endpoint + custom domain
resource "azurerm_cdn_frontdoor_secret" "tls_cert" {
  depends_on = [azurerm_role_assignment.frontdoor_profile_system_identity]

  name                     = "test-ebdemos-info"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id

  secret {
    customer_certificate {
      key_vault_certificate_id = azurerm_key_vault_certificate.this.id
    }
  }
}


##### Prepare Helm based AKS ingress controllers deployments
# helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx
resource "null_resource" "helm_add_repo" {
  count = local.deploy_option1 || local.deploy_option1 ? 1 : 0

  provisioner "local-exec" {
    command = "helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx"
  }
}
# helm repo update
resource "null_resource" "helm_update" {
  depends_on = [null_resource.helm_add_repo]

  count = local.deploy_option1 || local.deploy_option1 ? 1 : 0

  provisioner "local-exec" {
    command = "helm repo update"
  }
}

##### OPTION 1: Expose the 3 Applications with Ingresses on the Public Load Balancer #####
# Public Ingress controller
resource "helm_release" "ing_ctrl_public" {
  depends_on = [
    null_resource.helm_update,
    kubernetes_namespace.this,
  ]

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name             = local.ing_public_name
  namespace        = local.ing_public_name
  create_namespace = false

  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  version    = "4.9.1"

  # values = [ "${file("ing-public-values.yaml")}" ]

  values = [
    <<-EOF
    controller:
      ingressClassResource:
        name: "${local.ing_public_name}"
      config:
        enable-modsecurity: true
        enable-owasp-modsecurity-crs: true
      replicaCount: 2
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.azure.com/mode: system
      service:
        annotations:
          service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path: "/healthz"
      extraVolumes:
        - name: secrets-store-inline
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: "${local.secret_provider_class_name}"
      extraVolumeMounts:
        - name: secrets-store-inline
          mountPath: "/mnt/secrets-store"
          readOnly: true
    defaultBackend:
      enabled: true
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.azure.com/mode: system
    EOF
  ]
}

# HTTPBIN
resource "azurerm_dns_a_record" "httpbin_ing_public_ebdemos_info" {
  provider = azurerm.s2-connectivity

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                = "${local.httpbin}-ing"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  records             = [data.kubernetes_service_v1.ingress_public.0.status.0.load_balancer.0.ingress.0.ip]
}
resource "kubernetes_ingress_v1" "httpbin_ing_public" {
  depends_on = [azurerm_dns_a_record.httpbin_ing_public_ebdemos_info]

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  wait_for_load_balancer = true
  metadata {
    name      = "${local.httpbin}-ing-public"
    namespace = local.httpbin
  }

  spec {
    ingress_class_name = local.ing_public_name
    rule {
      host = trimsuffix(azurerm_dns_a_record.httpbin_ing_public_ebdemos_info.0.fqdn, ".")
      http {
        path {
          backend {
            service {
              name = "httpbin-svc-clusip"
              port { number = 80 }
            }
          }
          path_type = "Prefix"
          path      = "/"
        }
      }
    }

    tls {
      secret_name = "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
    }
  }
}

# Azure Vote
resource "azurerm_dns_a_record" "azvote_ing_public_ebdemos_info" {
  provider = azurerm.s2-connectivity

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                = "${local.azure_vote}-ing"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  records             = [data.kubernetes_service_v1.ingress_public.0.status.0.load_balancer.0.ingress.0.ip]
}
resource "kubernetes_ingress_v1" "azvote_ing_public" {
  depends_on = [azurerm_dns_a_record.azvote_ing_public_ebdemos_info]
  metadata {
    name      = "${local.azure_vote}-ing-public"
    namespace = local.azure_vote
  }

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  spec {
    ingress_class_name = local.ing_public_name
    rule {
      host = trimsuffix(azurerm_dns_a_record.azvote_ing_public_ebdemos_info.0.fqdn, ".")
      http {
        path {
          backend {
            service {
              name = "azure-vote-front-svc-clusip"
              port {
                number = 80
              }
            }
          }
          path      = "/"
          path_type = "Prefix"
        }
      }
    }
    tls {
      secret_name = "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
    }
  }
}

# Hello AKS
resource "azurerm_dns_a_record" "helloaks_ing_public_ebdemos_info" {
  provider = azurerm.s2-connectivity

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                = "${local.hello_aks}-ing"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  records             = [data.kubernetes_service_v1.ingress_public.0.status.0.load_balancer.0.ingress.0.ip]
}
resource "kubernetes_ingress_v1" "helloaks_ing_public" {
  depends_on = [azurerm_dns_a_record.helloaks_ing_public_ebdemos_info]
  metadata {
    name      = "${local.hello_aks}-ing-public"
    namespace = local.hello_aks
  }

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  spec {
    ingress_class_name = local.ing_public_name
    rule {
      host = trimsuffix(azurerm_dns_a_record.helloaks_ing_public_ebdemos_info.0.fqdn, ".")
      http {
        path {
          backend {
            service {
              name = "hello-aks-svc-clusip"
              port {
                number = 80
              }
            }
          }

          path      = "/"
          path_type = "Prefix"
        }
      }
    }

    tls {
      secret_name = "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
    }
  }
}

# External/Public-ingress Origin group (Option 1)
resource "azurerm_cdn_frontdoor_endpoint" "ep_for_option_1" {
  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                     = "aksafdpls1"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
}
resource "azurerm_cdn_frontdoor_origin_group" "pub_ing" {
  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                     = "public-ingresses"
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
}
resource "azurerm_cdn_frontdoor_origin" "pub_ing_httpbin" {
  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                          = "httpbin-pub-ing"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.pub_ing.0.id

  enabled                        = false
  certificate_name_check_enabled = true
  host_name                      = kubernetes_ingress_v1.httpbin_ing_public.0.spec.0.rule.0.host
  origin_host_header             = kubernetes_ingress_v1.httpbin_ing_public.0.spec.0.rule.0.host
  priority                       = 1
  weight                         = 1000
}
resource "azurerm_cdn_frontdoor_origin" "pub_ing_azvote" {
  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                          = "azvote-pub-ing"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.pub_ing.0.id

  enabled                        = false
  certificate_name_check_enabled = true
  host_name                      = kubernetes_ingress_v1.azvote_ing_public.0.spec.0.rule.0.host
  origin_host_header             = kubernetes_ingress_v1.azvote_ing_public.0.spec.0.rule.0.host
  priority                       = 1
  weight                         = 1000
}
resource "azurerm_cdn_frontdoor_origin" "pub_ing_helloaks" {
  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                          = "helloaks-pub-ing"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.pub_ing.0.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = kubernetes_ingress_v1.helloaks_ing_public.0.spec.0.rule.0.host
  origin_host_header             = kubernetes_ingress_v1.helloaks_ing_public.0.spec.0.rule.0.host
  priority                       = 1
  weight                         = 1000
}

resource "azurerm_dns_cname_record" "pub_ing_ebdemos_info" {
  provider = azurerm.s2-connectivity

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                = "aksafd-pub-ing"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  record              = azurerm_cdn_frontdoor_endpoint.ep_for_option_1.0.host_name
}
resource "azurerm_cdn_frontdoor_custom_domain" "pub_ing_ebdemos_info" {
  depends_on = [azurerm_cdn_frontdoor_secret.tls_cert]

  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                     = "${azurerm_dns_cname_record.pub_ing_ebdemos_info.0.name}-${replace(data.azurerm_dns_zone.public_dnz_zone.name, ".", "-")}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  dns_zone_id              = data.azurerm_dns_zone.public_dnz_zone.id
  host_name                = "${azurerm_dns_cname_record.pub_ing_ebdemos_info.0.name}.${data.azurerm_dns_zone.public_dnz_zone.name}"
  tls {
    certificate_type        = "CustomerCertificate"
    minimum_tls_version     = "TLS12"
    cdn_frontdoor_secret_id = azurerm_cdn_frontdoor_secret.tls_cert.id
  }
}
resource "azurerm_cdn_frontdoor_route" "pub_ing_route" {
  count = local.deploy_aks && local.deploy_option1 ? 1 : 0

  name                      = "route-to-public-ingresses-origins"
  cdn_frontdoor_endpoint_id = azurerm_cdn_frontdoor_endpoint.ep_for_option_1.0.id
  enabled                   = true

  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.pub_ing.0.id
  cdn_frontdoor_origin_ids = [
    azurerm_cdn_frontdoor_origin.pub_ing_httpbin.0.id,
    azurerm_cdn_frontdoor_origin.pub_ing_azvote.0.id,
    azurerm_cdn_frontdoor_origin.pub_ing_helloaks.0.id,
  ]

  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = false
  patterns_to_match      = ["/*"]
  supported_protocols    = ["Https"]

  cdn_frontdoor_custom_domain_ids = [
    azurerm_cdn_frontdoor_custom_domain.pub_ing_ebdemos_info.0.id,
  ]
  link_to_default_domain = false
}
# Be patient, AFD is slow, up to 10 minutes, then:
# Visit endpoint at: https://aksafd-pub-ing.ebdemos.info


##### OPTION 2: Expose the 3 Applications with Ingresses on the Internal Load Balancer #####

# Internal Ingress controller
resource "azurerm_role_assignment" "aks_vnet_rassignment" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  principal_id         = azurerm_kubernetes_cluster.this.0.identity[0].principal_id
  role_definition_name = "Network Contributor"
  scope                = azurerm_resource_group.this.id
  # Note: only VNet scope is requried for ILB, but to create the PLS, scope must be at the RG level.
}
resource "helm_release" "ing_ctrl_internal" {
  depends_on = [
    null_resource.helm_update,
    kubernetes_namespace.this,
    kubernetes_manifest.kv_csi_secret_providers,
  ]

  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name             = local.ing_internal_name
  namespace        = local.ing_internal_name
  create_namespace = false

  repository = "https://kubernetes.github.io/ingress-nginx"
  chart      = "ingress-nginx"
  version    = "4.9.1"

  values = [
    <<-EOF
    controller:
      ingressClassResource:
        name: "${local.ing_internal_name}"
      config:
        enable-modsecurity: true
        enable-owasp-modsecurity-crs: true
      replicaCount: 2
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.azure.com/mode: system
      service:
        annotations:
          # Refs: https://learn.microsoft.com/en-us/azure/aks/internal-lb?tabs=set-service-annotations
          #       https://cloud-provider-azure.sigs.k8s.io/topics/pls-integration/#privatelinkservice-annotations
          # AKS Internal Load Balancer
          service.beta.kubernetes.io/azure-load-balancer-internal: "true"
          service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path: "/healthz"
          service.beta.kubernetes.io/azure-load-balancer-internal-subnet: "${azurerm_subnet.ilb.name}"
          # AKS ILB Private Link Service
          service.beta.kubernetes.io/azure-pls-create: "true"
          service.beta.kubernetes.io/azure-pls-resource-group: "${azurerm_resource_group.this.name}"
          service.beta.kubernetes.io/azure-pls-ip-configuration-subnet: "${azurerm_subnet.ilb.name}"
          service.beta.kubernetes.io/azure-pls-name: "${local.ilb_pls_name}"
          service.beta.kubernetes.io/azure-pls-ip-configuration-ip-address-count: 2
          service.beta.kubernetes.io/azure-pls-proxy-protocol: "true"
          service.beta.kubernetes.io/azure-pls-visibility: "*"
          service.beta.kubernetes.io/azure-pls-auto-approval: "${var.subsc_id}"
      extraVolumes:
        - name: secrets-store-inline
          csi:
            driver: secrets-store.csi.k8s.io
            readOnly: true
            volumeAttributes:
              secretProviderClass: "${local.secret_provider_class_name}"
      extraVolumeMounts:
        - name: secrets-store-inline
          mountPath: "/mnt/secrets-store"
          readOnly: true
    defaultBackend:
      enabled: true
      nodeSelector:
        kubernetes.io/os: linux
        kubernetes.azure.com/mode: system
    EOF
  ]
}

# Internal Ingresses on the ILB
resource "azurerm_private_dns_a_record" "httpbin_ing_internal_ebdemos_info" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                = "${local.httpbin}-ing.int"
  zone_name           = azurerm_private_dns_zone.this.0.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 60
  records             = [data.kubernetes_service_v1.ingress_internal.0.status.0.load_balancer.0.ingress.0.ip]
}
resource "kubernetes_ingress_v1" "httpbin_ing_internal" {
  depends_on = [azurerm_dns_a_record.httpbin_ing_public_ebdemos_info]

  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  metadata {
    name      = "${local.httpbin}-ing-internal"
    namespace = local.httpbin
  }

  spec {
    ingress_class_name = local.ing_internal_name
    rule {
      host = trimsuffix(azurerm_private_dns_a_record.httpbin_ing_internal_ebdemos_info.0.fqdn, ".")
      http {
        path {
          backend {
            service {
              name = "httpbin-svc-clusip"
              port {
                number = 80
              }
            }
          }

          path      = "/"
          path_type = "Prefix"
        }
      }
    }
    tls {
      secret_name = "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
    }
  }
}
resource "azurerm_private_dns_a_record" "azvote_ing_internal_ebdemos_info" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                = "${local.azure_vote}-ing.int"
  zone_name           = azurerm_private_dns_zone.this.0.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 60
  records             = [data.kubernetes_service_v1.ingress_internal.0.status.0.load_balancer.0.ingress.0.ip]
}
resource "kubernetes_ingress_v1" "azvote_ing_internal" {
  depends_on = [azurerm_private_dns_a_record.azvote_ing_internal_ebdemos_info]

  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  metadata {
    name      = "${local.azure_vote}-ing-internal"
    namespace = local.azure_vote
  }

  spec {
    ingress_class_name = local.ing_internal_name
    rule {
      host = trimsuffix(azurerm_private_dns_a_record.azvote_ing_internal_ebdemos_info.0.fqdn, ".")
      http {
        path {
          backend {
            service {
              name = "azure-vote-front-svc-clusip"
              port {
                number = 80
              }
            }
          }

          path      = "/"
          path_type = "Prefix"
        }
      }
    }
    tls {
      secret_name = "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
    }
  }
}
resource "azurerm_private_dns_a_record" "helloaks_ing_internal_ebdemos_info" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                = "${local.hello_aks}-ing.int"
  zone_name           = azurerm_private_dns_zone.this.0.name
  resource_group_name = azurerm_resource_group.this.name
  ttl                 = 60
  records             = [data.kubernetes_service_v1.ingress_internal.0.status.0.load_balancer.0.ingress.0.ip]
}
resource "kubernetes_ingress_v1" "helloaks_ing_internal" {
  depends_on = [azurerm_private_dns_a_record.helloaks_ing_internal_ebdemos_info]

  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  metadata {
    name      = "${local.hello_aks}-ing-internal"
    namespace = local.hello_aks
  }

  spec {
    ingress_class_name = local.ing_internal_name
    rule {
      host = trimsuffix(azurerm_private_dns_a_record.helloaks_ing_internal_ebdemos_info.0.fqdn, ".")
      http {
        path {
          backend {
            service {
              name = "${local.hello_aks}-svc-clusip"
              port {
                number = 80
              }
            }
          }

          path      = "/"
          path_type = "Prefix"
        }
      }
    }
    tls {
      secret_name = "kv-${azurerm_key_vault_certificate.this.name}-tls-csi"
    }
  }
}

# Internal/Private-ingress Origin group (Option 2)
resource "azurerm_cdn_frontdoor_endpoint" "ep_for_option_2" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                     = "aksafdpls2"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
}
resource "azurerm_cdn_frontdoor_origin_group" "int_ing" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                     = "ilb-ingresses"
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
}
resource "azurerm_cdn_frontdoor_origin" "int_ing_httpbin" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                          = "httpbin-int-ing"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.0.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = kubernetes_ingress_v1.httpbin_ing_internal.0.spec.0.rule.0.host
  origin_host_header             = kubernetes_ingress_v1.httpbin_ing_internal.0.spec.0.rule.0.host
  priority                       = 1
  weight                         = 1000

  private_link {
    request_message        = "Please approve AFD to ILB PLS connection"
    location               = azurerm_resource_group.this.location
    private_link_target_id = local.ilb_pls_id
  }
}
########   APPROVE THE Private Endpoint Connection   ######## on pls-ingress-internal

resource "azurerm_cdn_frontdoor_origin" "int_ing_azvote" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                          = "azvote-int-ing"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.0.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = kubernetes_ingress_v1.azvote_ing_internal.0.spec.0.rule.0.host
  origin_host_header             = kubernetes_ingress_v1.azvote_ing_internal.0.spec.0.rule.0.host
  priority                       = 1
  weight                         = 1000

  private_link {
    request_message        = "Please approve AFD to ILB PLS connection"
    location               = azurerm_resource_group.this.location
    private_link_target_id = local.ilb_pls_id
  }
}
resource "azurerm_cdn_frontdoor_origin" "int_ing_helloaks" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                          = "helloaks-int-ing"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.0.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = kubernetes_ingress_v1.helloaks_ing_internal.0.spec.0.rule.0.host
  origin_host_header             = kubernetes_ingress_v1.helloaks_ing_internal.0.spec.0.rule.0.host
  priority                       = 1
  weight                         = 1000

  private_link {
    request_message        = "Please approve AFD to ILB PLS connection"
    location               = azurerm_resource_group.this.location
    private_link_target_id = local.ilb_pls_id
  }
}
resource "azurerm_dns_cname_record" "int_ing_ebdemos_info" {
  provider = azurerm.s2-connectivity

  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                = "aksafd-pub-ing"
  zone_name           = data.azurerm_dns_zone.public_dnz_zone.name
  resource_group_name = data.azurerm_dns_zone.public_dnz_zone.resource_group_name
  ttl                 = 60
  record              = azurerm_cdn_frontdoor_endpoint.ep_for_option_2.0.host_name
}
resource "azurerm_cdn_frontdoor_custom_domain" "int_ing_ebdemos_info" {
  depends_on = [azurerm_cdn_frontdoor_secret.tls_cert]

  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                     = "${azurerm_dns_cname_record.pub_ing_ebdemos_info.0.name}-${replace(data.azurerm_dns_zone.public_dnz_zone.name, ".", "-")}"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
  dns_zone_id              = data.azurerm_dns_zone.public_dnz_zone.id
  host_name                = "${azurerm_dns_cname_record.pub_ing_ebdemos_info.0.name}.${data.azurerm_dns_zone.public_dnz_zone.name}"
  # https://testext.ebdemos.info

  tls {
    certificate_type        = "CustomerCertificate"
    minimum_tls_version     = "TLS12"
    cdn_frontdoor_secret_id = azurerm_cdn_frontdoor_secret.tls_cert.id
  }
}
resource "azurerm_cdn_frontdoor_route" "int_ing_route" {
  count = local.deploy_aks && local.deploy_option2 ? 1 : 0

  name                      = "route-to-internal-ingresses"
  cdn_frontdoor_endpoint_id = azurerm_cdn_frontdoor_endpoint.ep_for_option_2.0.id
  enabled                   = true

  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.0.id
  cdn_frontdoor_origin_ids = [
    azurerm_cdn_frontdoor_origin.int_ing_httpbin.0.id,
    azurerm_cdn_frontdoor_origin.int_ing_azvote.0.id,
    azurerm_cdn_frontdoor_origin.int_ing_helloaks.0.id,
  ]

  forwarding_protocol    = "HttpsOnly"
  https_redirect_enabled = false
  patterns_to_match      = ["/*"]
  supported_protocols    = ["Https"]

  cdn_frontdoor_custom_domain_ids = [
    azurerm_cdn_frontdoor_custom_domain.int_ing_ebdemos_info.0.id,
  ]
  link_to_default_domain = false
}
#*/

/*
##### OPTION 3: Expose the 3 Applications with a LoadBalancer Service type on the Internal Load Balancer and a PLS #####
# AKS: Kubernetes Services with ILB and PLS
resource "kubernetes_service_v1" "httpbin_svc_ilb" {
  count = local.deploy_aks && local.deploy_option3 ? 1 : 0

  metadata {
    name      = "httpbin-svc-ilb"
    namespace = "httpbin"
    annotations = {
      "service.beta.kubernetes.io/azure-load-balancer-internal"                  = "true"
      "service.beta.kubernetes.io/azure-load-balancer-internal-subnet"           = azurerm_subnet.ilb.name
      "service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path" = "/healthz"

      "service.beta.kubernetes.io/azure-pls-create"                            = "true"
      "service.beta.kubernetes.io/azure-pls-resource-group"                    = azurerm_resource_group.this.name
      "service.beta.kubernetes.io/azure-pls-ip-configuration-subnet"           = azurerm_subnet.ilb.name
      "service.beta.kubernetes.io/azure-pls-name"                              = "pls-httpbin"
      "service.beta.kubernetes.io/azure-pls-ip-configuration-ip-address-count" = "1"
      "service.beta.kubernetes.io/azure-pls-proxy-protocol"                    = "true"
      "service.beta.kubernetes.io/azure-pls-visibility"                        = "*"
      "service.beta.kubernetes.io/azure-pls-auto-approval"                     = var.subsc_id
    }
  }
  spec {
    selector = {
      app = "httpbin"
    }
    type = "LoadBalancer"
    port {
      port        = 80
      target_port = 80
    }
  }
}
resource "kubernetes_service_v1" "azvote_svc_ilb" {
  count = local.deploy_aks && local.deploy_option3 ? 1 : 0

  metadata {
    name      = "azure-vote-front-svc-ilb"
    namespace = "azure-vote"
    annotations = {
      "service.beta.kubernetes.io/azure-load-balancer-internal"                  = "true"
      "service.beta.kubernetes.io/azure-load-balancer-internal-subnet"           = azurerm_subnet.ilb.name
      "service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path" = "/healthz"

      "service.beta.kubernetes.io/azure-pls-create"                            = "true"
      "service.beta.kubernetes.io/azure-pls-resource-group"                    = azurerm_resource_group.this.name
      "service.beta.kubernetes.io/azure-pls-ip-configuration-subnet"           = azurerm_subnet.ilb.name
      "service.beta.kubernetes.io/azure-pls-name"                              = "pls-azure-vote"
      "service.beta.kubernetes.io/azure-pls-ip-configuration-ip-address-count" = "1"
      "service.beta.kubernetes.io/azure-pls-proxy-protocol"                    = "true"
      "service.beta.kubernetes.io/azure-pls-visibility"                        = "*"
      "service.beta.kubernetes.io/azure-pls-auto-approval"                     = var.subsc_id
    }
  }
  spec {
    selector = {
      app = "azure-vote-front"
    }
    type = "LoadBalancer"
    port {
      port        = 80
      target_port = 80
    }
  }
}
resource "kubernetes_service_v1" "helloaks_svc_ilb" {
  count = local.deploy_aks && local.deploy_option3 ? 1 : 0

  metadata {
    name      = "hello-aks-svc-ilb"
    namespace = "hello-aks"
    annotations = {
      "service.beta.kubernetes.io/azure-load-balancer-internal"                  = "true"
      "service.beta.kubernetes.io/azure-load-balancer-internal-subnet"           = azurerm_subnet.ilb.name
      "service.beta.kubernetes.io/azure-load-balancer-health-probe-request-path" = "/healthz"

      "service.beta.kubernetes.io/azure-pls-create"                            = "true"
      "service.beta.kubernetes.io/azure-pls-resource-group"                    = azurerm_resource_group.this.name
      "service.beta.kubernetes.io/azure-pls-ip-configuration-subnet"           = azurerm_subnet.ilb.name
      "service.beta.kubernetes.io/azure-pls-name"                              = "pls-hello-aks"
      "service.beta.kubernetes.io/azure-pls-ip-configuration-ip-address-count" = "1"
      "service.beta.kubernetes.io/azure-pls-proxy-protocol"                    = "true"
      "service.beta.kubernetes.io/azure-pls-visibility"                        = "*"
      "service.beta.kubernetes.io/azure-pls-auto-approval"                     = var.subsc_id
    }
  }
  spec {
    selector = {
      app = "hello-aks"
    }
    type = "LoadBalancer"
    port {
      port        = 80
      target_port = 80
    }
  }
}


# AFD: Endpoint for Option 3
resource "azurerm_cdn_frontdoor_endpoint" "ep_for_option_3" {
  # https://aksafdpls-g2dqh6dvctcmgdfb.b01.azurefd.net/
  count = local.deploy_aks && local.deploy_option3 ? 1 : 0

  name                     = "aksafdpls3"
  cdn_frontdoor_profile_id = azurerm_cdn_frontdoor_profile.this.id
}

# AFD: Internal/PLS services Origin group + origins
resource "azurerm_cdn_frontdoor_origin_group" "pls_svc" {
  name                     = "pls-services"
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
}
resource "azurerm_cdn_frontdoor_origin" "pls_azvote" {
  name                          = "azvote-int"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.id

  enabled                        = true
  certificate_name_check_enabled = true
  host_name                      = "azvote.int.ebdemos.info"
  origin_host_header             = "azvote.int.ebdemos.info"
  priority                       = 1
  weight                         = 1000

  # private_link {
  #   request_message        = "Please approve"
  #   location               = azurerm_resource_group.this.location
  #   private_link_target_id = data.azurerm_private_link_service.priv_ing_pls.id
  # }
}
resource "azurerm_cdn_frontdoor_origin" "pls_httpbin" {
  name                          = "httpbin-int"
  cdn_frontdoor_origin_group_id = azurerm_cdn_frontdoor_origin_group.int_ing.id

  enabled                        = false
  certificate_name_check_enabled = true
  host_name                      = "httpbin.int.ebdemos.info"
  origin_host_header             = "httpbin.int.ebdemos.info"
  priority                       = 1
  weight                         = 1000

  # private_link {
  #   request_message        = "Please approve"
  #   location               = azurerm_resource_group.this.location
  #   private_link_target_id = data.azurerm_private_link_service.priv_ing_pls.id
  # }
}

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

#*/
