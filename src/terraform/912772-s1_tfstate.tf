#--------------------------------------------------------------
#   Backend TF State, Specific Locals
#--------------------------------------------------------------
#
# NOTE:
#   Terraform states are in Management subscription (s1)
#

terraform {
  backend "azurerm" {
    subscription_id      = "a73ced30-c712-4405-8828-67a833b1e39a"
    resource_group_name  = "rg-cac-912772-s1-hub-terraform-01"
    storage_account_name = "stcac912772s1tfstates"
    container_name       = "tfstates-912772-s1-spokes"
    key                  = "aks-afd-pls-05"
  }
}
