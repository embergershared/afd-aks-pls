terraform {
  required_version = ">=1.7"

  required_providers {
    azurerm = {
      # https://registry.terraform.io/providers/hashicorp/azurerm/latest
      source  = "hashicorp/azurerm"
      version = ">=3.90"
    }
    azapi = {
      source  = "Azure/azapi"
      version = "~> 1.0"
    }
    helm = {
      # https://registry.terraform.io/providers/hashicorp/helm/latest
      source  = "hashicorp/helm"
      version = ">=2.10"
    }
    kubernetes = {
      # https://registry.terraform.io/providers/hashicorp/kubernetes/latest
      source  = "hashicorp/kubernetes"
      version = ">=2.25"
    }
  }
}
