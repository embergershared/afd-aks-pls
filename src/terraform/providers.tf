provider "azurerm" {
  tenant_id       = var.tenant_id
  subscription_id = var.subsc_id
  client_id       = var.client_id
  client_secret   = var.client_secret

  skip_provider_registration = true
  storage_use_azuread        = true

  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azurerm" {
  alias = "s2-connectivity"

  tenant_id       = var.tenant_id
  subscription_id = var.conn_subsc_id
  client_id       = var.client_id
  client_secret   = var.client_secret

  skip_provider_registration = true

  features {
    resource_group {
      prevent_deletion_if_contains_resources = false
    }
  }
}

provider "azapi" {}

provider "helm" {
  # Ref: https://registry.terraform.io/providers/hashicorp/helm/latest/docs
  #      https://registry.terraform.io/providers/hashicorp/helm/latest/docs/resources/release
  kubernetes {
    host                   = azurerm_kubernetes_cluster.this.kube_config.0.host
    cluster_ca_certificate = base64decode(azurerm_kubernetes_cluster.this.kube_config.0.cluster_ca_certificate)
    exec {
      api_version = "client.authentication.k8s.io/v1beta1"
      command     = "kubelogin"
      args = [
        "get-token",
        "--login",
        "azurecli",
        "--server-id",
        "6dae42f8-4368-4678-94ff-3960e28e3630"
      ]
    }
  }
}
