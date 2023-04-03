provider "azurerm" {
  features {
    key_vault {
      purge_soft_delete_on_destroy = true
    }
    resource_group {
      prevent_deletion_if_contains_resources = false
    }  
  }
  version = "~> 2.0"
  environment = "china_cloud"
  skip_provider_registration = true
}

provider "azuread" {
  environment = "china"
}
