# Launch an Aviatrix Controller in Azure China with High Availability

## Description

### Note:

This Terraform module includes the required modifications to module [Azure-Controller-HA](https://github.com/AviatrixSystems/Azure_Controller_HA) to deploy the artifacts in Azure China Cloud. In addition to that, this module doesn't deploy a service principal; it requires the Service Principal to be created before using this module. It automatically adds the IP Address of the system that runs this code to the NSG of the Aviatrix Controller. It also adds logic to the null_resource that deploys the Azure Function to try deploying up to 5 times, this is needed because in the original code the script results in error *"Timed out waiting for SCM to update Environment Settings"* and requires to run `Terraform apply` twice. See <https://github.com/Azure/azure-functions-core-tools/issues/1863> for more details on this issue

Module [terraform-aviatrix-azure-controller](https://github.com/AviatrixSystems/terraform-aviatrix-azure-controller) has been modified to allow initializing a controller deployed in Azure China Cloud. The modified code is included in this Github repository.

This Terraform module:

- Is limited to deployments in Azure China.
- Supports Azure controller deployment with only 6.5 and above versions.
- Creates an Aviatrix Controller in Azure using scale set and load balancer.
- Creates an access account on the controller.
- Creates storage account and container required for backup/function logs.
- Enables backup to an Azure storage account in the controller.
- Creates a KeyVault to safeguard secrets. 
- Creates an Alert to check the loadbalancer health probes.
- Creates an Azure funtion to manage failover event along with periodic backup if needed.
- Creates a log analytics workspace required for Application Insights

## Prerequisites

1. [Terraform v0.13+](https://www.terraform.io/downloads.html) - execute terraform files
2. [Python3.9](https://www.python.org/downloads/)
3. [Azure Functions Core Tools](https://docs.microsoft.com/en-us/azure/azure-functions/functions-run-local?tabs=v4%2Cwindows%2Ccsharp%2Cportal%2Cbash)
4. [Resource Providers](https://docs.microsoft.com/en-us/azure/azure-resource-manager/management/resource-providers-and-types#register-resource-provider-1) mentioned below should be registered in the subscription:
  ``` shell
      Microsoft.Compute
      Microsoft.Storage
      Microsoft.Network
      Microsoft.KeyVault
      Microsoft.ManagedIdentity
      Microsoft.insights
      Microsoft.OperationalInsights
      Microsoft.Web
  ```

## Providers

| Name | Version |
|------|---------|
| <a name="provider_azuread"></a> [azuread](#provider\_azuread) | ~> 2.36 |
| <a name="provider_azurerm"></a> [azurerm](#provider\_azurerm) | ~> 3.49 |
| <a name="provider_null"></a> [null](#provider\_null) | \>= 2.0 |
| <a name="provider_random"></a> [random](#provider\_random) | 3.4.3 |
| <a name="provider_http"></a> [http](#provider\_http) | 3.2.1 |

## Available Modules

Module  | Description |
| ------- | ----------- |
|[aviatrix_controller_initialize](https://github.com/jocortems/azure_china_controller_ha/tree/main/aviatrix_controller_initialize) | Initializes the Aviatrix Controller in Azure China (setting admin email, setting admin password, upgrading controller version, and setting up access account, setting up backup to an azure storage account) |

## Procedures for Building and Initializing a Controller in Azure

### 1. Create the Python virtual environment and install required dependencies

Install Python3.9 virtual environment.

``` shell
sudo apt install python3.9-venv
```

Create the virtual environment.

``` shell
python3.9 -m venv venv
```

Activate the virtual environment.

``` shell
source venv/bin/activate
```

Install Python3.9-pip

``` shell
sudo apt install python3.9-distutils
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python3.9 get-pip.py
```

Install required dependencies.

``` shell
pip install -r requirements.txt
```

### 2. Authenticating to Azure

Set the environment in Azure CLI to Azure China:

```shell
az cloud set -n AzureChinaCloud
```

Login to the Azure CLI using:

```shell
az login --use-device-code
````
*Note: Please refer to the [documentation](https://registry.terraform.io/providers/hashicorp/azuread/latest/docs#authenticating-to-azure-active-directory) for different methods of authentication to Azure, incase above command is not applicable.*

Pick the subscription you want and use it in the command below.

```shell
az account set --subscription <subscription_id>
```

Set environment variables ARM_ENDPOINT and ARM_ENVIRONMENT to use Azure China endpoints:

  ``` shell
  export ARM_ENDPOINT=https://management.chinacloudapi.cn
  export ARM_ENVIRONMENT=china
  ```

If executing this code from a CI/CD pipeline, the following environment variables are required. The service principal used to authenticate the CI/CD tool into Azure must either have subscription owner role or a custom role that has `Microsoft.Authorization/roleAssignments/write` to be able to succesfully create the role assignments required

``` shell
export ARM_CLIENT_ID="00000000-0000-0000-0000-000000000000"
export ARM_CLIENT_SECRET="00000000-0000-0000-0000-000000000000"
export ARM_SUBSCRIPTION_ID="00000000-0000-0000-0000-000000000000"
export ARM_TENANT_ID="00000000-0000-0000-0000-000000000000"
```

### 3. Applying Terraform configuration

```hcl
module "aviatrix_controller_azure" {
    source                                         = "github.com/jocortems/azure_china_controller_ha"
    resource_group_name                            = "<RESOURCE GROUP NAME>"                 # Required; Creates a Resource Group with this name.
    location                                       = "<AZURE REGION>"                        # Required; Creates all resources in this region/location.
    avtx_service_principal_secret                  = var.avtx_service_principal_secret       # Required; Azure AD SP object secret to be used to onboard Azure to Aviatrix Controller. Sensitive
    avtx_service_principal_appid	      	         = var.avtx_service_principal_appid        # Required; Azure AD SP object AppId to be used to onboard Azure to Aviatrix Controller. Sensitive
    icp_certificate_domain                         = "yourdomain.net"                        # Optional; Registered ICP Domain. If not provided it must be manually configured later on before any gateway deployment
    storage_account_name                           = "aviatrixstorage<random hex value>"     # Optional; Creates Storage account with this name. Default = "aviatrixstorage<random hex value>"
    key_vault_name                                 = "aviatrix-key-vault-<random hex value>" # Optional; Creates Key vault with this name. Default = "aviatrix-key-vault-<random hex value>"
    virtual_network_name                           = "aviatrix-vnet"                         # Optional; Creates Virtual Network with this name. Default = "aviatrix-vnet"
    virtual_network_cidr                           = "<VNET CIDR>"                           # Optional; Creates Virtual Network with this address space. Default = "10.0.0.0/23"
    subnet_name                                    = "controller-subnet"                     # Optional; Creates Subnet with this name. Default = "aviatrix-subnet"
    subnet_cidr                                    = "<SUBNET CIDR>"                         # Optional; Creates Subnet with this cidr. Default = "10.0.0.0/24"
    load_balancer_frontend_public_ip_name          = "aviatrix-lb-public-ip"                 # Optional; Creates LoadBalancer Frontend IP with this name. Default = "aviatrix-lb-public-ip"
    load_balancer_name                             = "aviatrix-lb"                           # Optional; Creates LoadBalancer with this name. Default = "aviatrix-lb"
    load_balancer_frontend_name                    = "aviatrix-lb-frontend"                  # Optional; Creates LoadBalancer Frontend Configurations with this name. Default = "aviatrix-lb-frontend"
    load_balancer_controller_backend_pool_name     = "aviatrix-controller-backend"           # Optional; Creates LoadBalancer Backend Pool with this name. Default = "aviatrix-controller-backend"
    load_balancer_controller_health_probe_name     = "aviatrix-controller-probe"             # Optional; Creates LoadBalancer Health Probe with this name. Default = "aviatrix-controller-probe"
    load_balancer_controller_rule_name             = "aviatrix-controller-lb-rule"           # Optional; Creates LoadBalancer Rule with this name. Default = "aviatrix-controller-lb-rule"
    network_security_group_controller_name         = "aviatrix-controller-nsg"               # Optional; Creates Network Security Group with this name. Default = "aviatrix-controller-nsg"
    aviatrix_controller_security_group_allowed_ips = []                                      # Optional; The IP address of the machine that runs this code doesn't need to be added to this variable, it is automatically retrieved using Terraform http provider
    controller_virtual_machine_size                = "Standard_A4_v2"                        # Optional; Creates Scale Set with this size Virtual Machine. Default = "Standard_A4_v2"
    scale_set_controller_name                      = "aviatrix-controller-scale-set"         # Optional; Creates Scale Set with this name. Default = "aviatrix-controller-scale-set"
    avx_access_account_name                        = "azure-account"                         # Required; Creates an access account with this name in the Aviatrix Controller.
    avx_account_email                              = "john@doe.com"                          # Required; Creates an access account with this email address in the Aviatrix Controller.
    avx_controller_admin_email                     = "john@doe.com"                          # Required; Adds this email address to admin account in the Aviatrix Controller.
    avx_aviatrix_customer_id			   = var.avx_aviatrix_customer_id                          # Required; Aviatrix Controller License Sensitive
    avx_controller_admin_password                  = var.avx_controller_admin_password       # Optional; Changes admin password to this password. Default = "<autogenerated value>". Sensitive
    avx_controller_version                         = "latest"                                # Optional; Upgrades the controller to this version. Default = "latest"    
    log_analytics_workspace_id                     = "/subscriptions/<SUBSCRIPTION ID>/resourceGroups/<RG NAME>/providers/Microsoft.OperationalInsights/workspaces/<WORKSPACE NAME>"   # Optional; if not specified a workspace is created. Log Analytics Workspace is required for Application Insights in Azure China    
    log_analytics_workspace_retention_in_days      = 30                                      # Optional; Valid values are 30-730. Defaults to 30. Only used if log_analytics_workspace is not specified
    log_analytics_workspace_daily_quota_gb         = 1                                       # Optional; Defaults to 1GB/day. Only used if log_analytics_workspace is not specified
    application_insights_name                      = "controllerha-appinsights"              # Optional; Creates Application Insights with this name. Default = "aviatrix-function-app-insights"
    app_service_plan_name                          = "controllerha-appplan"                  # Optional; Creates App Service Plan with this name. Default = "aviatrix-function-app-sp"
    function_app_name                              = "controllerha-functionapp"              # Optional; Creates Function App with this name. Default = "aviatrix-controller-app-<random hex value>"
    user_assigned_identity_name                    = "contorllerha-functionapp-identity"     # Optional; Creates a User Assigned Identity with this name. Default = "aviatrix-function-identity"
    aviatrix_function_app_custom_role_name         = "controllerha-functionapp-role"         # Optional; Creates a Custom Role with permissions for the User Assigned Identity. Default = "aviatrix-function-custom-role"
    function_action_group_name                     = "controllerha-functionapp-ag"           # Optional; Creates an Action Group for triggering the Function App with this name. Default = "aviatrix-function-action-group"
    notification_action_group_name                 = "controllerha-functionapp-ng"           # Optional; Creates an Action Group for notifying email with Function App results. Default = "aviatrix-notify-action-group"
    enable_function_app_alerts                     = true/false                              # Optional; Enable Function App Notifications for success, failure, exception. Default = false
    az_support                                     = true/false                              # Required; Set to true if the Azure region supports AZ's.
    enable_backup                                  = true/false                              # Optional; Default true. Set to false if you plan to restore the Controller from an existing backup
    enable_multiple_backup                         = true/false                              # Optional; Default true; whether to enable multiple backups for Aviatrix Controller
    disable_periodic_backup                        = true/false                              # Optional; Enable Periodic backup function. Default = true
    schedule                                       = "0 0 * * * *"                           # Optional; Creates a backup every hour by default when disable_periodic_backup is set to false. Default = "0 0 * * * *"
}

```

### Execute

```shell
terraform init
terraform apply --var-file=<terraform.tfvars>
````

Additional Information:

1. Total expected time for failover ~20 mins
    - ~5 min for azure alert to get fired as controller unhealthy.
    - ~15 min to deploy, initialize, restore the new controller.

2. Make sure to enable the backup on the healthy controller prior to triggering the failover.

3. Failover logs can be viewed in function monitor logs.

4. [List](https://github.com/MicrosoftDocs/azure-docs/blob/main/articles/availability-zones/includes/availability-zone-regions-include.md) of regions that support availability zones for the az_support var.
5. Formatted names of the region for location var, can also be gathered using command below
    ```shell
    az account list-locations -o table
    ````

6. Cron Timer [examples](https://docs.microsoft.com/en-us/azure/azure-functions/functions-bindings-timer?tabs=csharp#ncrontab-examples)

Known Caveat :

1. Function Timeout error can occur during the restore process. In case of this error please login to the new controller to validate if the backup has been restored successfully. 
![ScreenShot](./Restore-error.png)

2. Failover may or may not be triggered when instance is stopped manually. As per azure, this inconsistent behavior is technically by design when manual auto scale feature is used in azure virtual machine scale set.

3. Run ``` python -m pip install -–upgrade pip```, if below error occurs during dependencies installation.
![ScreenShot](./Pip-error.png)

Note:

Alert will not be triggered when instance is deleted. It will only be triggered when loadbalancer health checks are failed.
To test the failover, insert a deny rule on controller SG by blocking https traffic from Azure load balancer(sevice tag).

## **Disclaimer**:

The material embodied in this software/code is provided to you "as-is" and without warranty of any kind, express, implied or otherwise, including without limitation, any warranty of fitness for a particular purpose. In no event shall the Aviatrix Inc. be liable to you or anyone else for any direct, special, incidental, indirect or consequential damages of any kind, or any damages whatsoever, including without limitation, loss of profit, loss of use, savings or revenue, or the claims of third parties, whether or not Aviatrix Inc. has been advised of the possibility of such loss, however caused and on any theory of liability, arising out of or in connection with the possession, use or performance of this software/code.
