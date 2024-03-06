#--------------------------------------------------------------
#   Backend TF State, Specific Locals
#--------------------------------------------------------------
#
# NOTE:
#   Terraform states are in Management subscription (s1)
#

terraform {
  backend "azurerm" {
    subscription_id      = "33855627-4730-446e-b4c8-9f49bad5f089"
    resource_group_name  = "rg-use2-446692-s1-hub-terraform-01"
    storage_account_name = "stuse2446692s1tfstates"
    container_name       = "tfstates-446692-s1-s4-spokes"
    key                  = "aks-afd-pls"
  }
}
