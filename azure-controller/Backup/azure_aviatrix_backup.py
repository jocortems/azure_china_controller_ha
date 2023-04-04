import json
import logging
import os
import time
import datetime
import requests
import urllib3
import azure.functions as func
from . import version
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.resource import SubscriptionClient
from urllib3.exceptions import InsecureRequestWarning
from opencensus.ext.azure.log_exporter import AzureLogHandler
from opencensus.ext.azure import metrics_exporter
from opencensus.ext.azure.trace_exporter import AzureExporter
from opencensus.trace import config_integration
from opencensus.trace.samplers import ProbabilitySampler

urllib3.disable_warnings(InsecureRequestWarning)

# Initialize Azure Monitor Exporter for logs
connection_string = os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING')
if connection_string:
    logger = logging.getLogger(__name__)
    logger.setLevel(logger.info)
    handler = AzureLogHandler(connection_string=connection_string)
    logger.addHandler(handler)

# Initialize Azure Monitor Exporter for exceptions
connection_string = os.environ.get('APPLICATIONINSIGHTS_CONNECTION_STRING')
if connection_string:
    exporter = AzureExporter(connection_string=connection_string)
    config_integration.trace_integrations(['requests'])
    sampler = ProbabilitySampler(rate=1.0)
    exporter = AzureExporter(connection_string=connection_string)


class AviatrixException(Exception):
    def __init__(self, message="Aviatrix Error Message: ..."):
        super(AviatrixException, self).__init__(message)


def function_handler(event):
    aviatrix_api_version = event["aviatrix_api_version"]
    aviatrix_api_route = event["aviatrix_api_route"]
    vault_uri = event["vault_uri"]
    vault_secret = event["vault_secret"]
    func_client_id = event["func_client_id"]
    lb_name = event["lb_name"]
    rg = event["rg"]

    credentials = DefaultAzureCredential(authority="login.chinacloudapi.cn", managed_identity_client_id=func_client_id)
    subscription_client = SubscriptionClient(credentials, base_url='https://management.chinacloudapi.cn')
    subscription = next(subscription_client.subscriptions.list())
    subscription_id = subscription.subscription_id    
    network_client = NetworkManagementClient(credentials, subscription_id, base_url='https://management.chinacloudapi.cn')

    secret_client = SecretClient(vault_url=f"https://{vault_uri}.vault.azure.cn", credential=credentials)
    retrieved_secret = secret_client.get_secret(vault_secret)

    lb_res_client = network_client.load_balancers
    lb_res_client.base_url = "https://management.chinacloudapi.cn"
    lb = LbConf(lb_res_client, rg, network_client, lb_name)
    hostname = lb.lb_public_ip_prefix
    api_endpoint_url = (
        f"https://{hostname}/{aviatrix_api_version}/{aviatrix_api_route}"
    )
    logger.info(
        "START: Login Aviatrix Controller as admin")
    response = login(
        api_endpoint_url=api_endpoint_url,
        username="admin",
        password=retrieved_secret.value,
        hide_password=True,
    )

    verify_aviatrix_api_response_login(response=response)
    CID = response.json()["CID"]
    logger.info(
        "END: Login Aviatrix Controller as admin")

    logger.info("START: Starting Backup")
    try:
        enable_backup(
            api_endpoint_url=api_endpoint_url,
            CID=CID)
    except Exception as err:
        logger.warning(str(err))
        logger.info("END: Starting Backup")


def verify_aviatrix_api_response_login(response=None):
    # if successfully login
    # response_code == 200
    # api_return_boolean == true
    # response_message = "authorized successfully"

    py_dict = response.json()
    if 'CID' in py_dict:
        py_dict["CID"] = "*********"
    logger.info(f"Aviatrix API response is {str(py_dict)}")

    response_code = response.status_code
    if response_code != 200:
        err_msg = (
            f"Fail to login Aviatrix Controller. The response code is "
            f"{response_code}"
        )
        raise AviatrixException(message=err_msg)

    api_return_boolean = py_dict["return"]
    if api_return_boolean is not True:
        err_msg = (
            f"Fail to Login Aviatrix Controller. The Response is "
            f"{str(py_dict)}"
        )
        raise AviatrixException(
            message=err_msg,
        )

    api_return_msg = py_dict["results"]
    expected_string = "authorized successfully"
    if (expected_string in api_return_msg) is not True:
        err_msg = (
            f"Fail to Login Aviatrix Controller. The Response is "
            f"{str(py_dict)}"
        )
        raise AviatrixException(
            message=err_msg,
        )


# End def verify_aviatrix_api_response_login()

def login(
    api_endpoint_url="https://123.123.123.123/v1/api",
    username="admin",
    password="********",
    hide_password=True,
):
    request_method = "POST"
    data = {"action": "login", "username": username, "password": password}
    logger.info(f"API endpoint url is : {api_endpoint_url}")

    # handle if the hide_password is selected
    if hide_password:
        payload_with_hidden_password = dict(data)
        payload_with_hidden_password["password"] = "************"
        logger.info(
            f"Request payload: "
            f"{str(json.dumps(obj=payload_with_hidden_password, indent=4))}")
    else:
        logger.info(f"Request payload: "
                     f"{str(json.dumps(obj=data, indent=4))}")

    # send post request to the api endpoint
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
    )
    return response


# End def login()

def send_aviatrix_api(
    api_endpoint_url="https://123.123.123.123/v1/api",
    request_method="POST",
    payload=dict(),
    retry_count=5,
    timeout=None,
):
    response = None
    responses = list()
    request_type = request_method.upper()
    response_status_code = -1

    for i in range(retry_count):
        try:
            if request_type == "GET":
                response = requests.get(
                    url=api_endpoint_url, params=payload, verify=False
                )
                response_status_code = response.status_code
            elif request_type == "POST":
                response = requests.post(
                    url=api_endpoint_url, data=payload,
                    verify=False, timeout=timeout
                )
                response_status_code = response.status_code
            else:
                failure_reason = (f"ERROR : Bad HTTPS request type: "
                                  f"{request_type}")
                logger.error(failure_reason)
        except requests.exceptions.Timeout as e:
            logger.warning(f"WARNING: Request timeout... {str(e)}")
            responses.append(str(e))
        except requests.exceptions.ConnectionError as e:
            logger.warning(f"WARNING: Server is not responding... {str(e)}")
            responses.append(str(e))
        except Exception as e:
            logger.warning(f"HTTP request failed {str(e)}")
            # For error message/debugging purposes

        finally:
            if response_status_code == 200:
                return response
            elif response_status_code == 404:
                failure_reason = "ERROR: 404 Not Found"
                logger.error(failure_reason)

            # if the response code is neither 200 nor 404, retry process
            # the default retry count is 5, the wait for each retry is i
            # i           =  0  1  2  3  4
            # wait time   =     1  2  4  8

            if i + 1 < retry_count:
                logger.info("START: retry")
                logger.info("i == %d", i)
                wait_time_before_retry = pow(2, i)
                logger.info("Wait for: %ds for the next retry",
                             wait_time_before_retry)
                time.sleep(wait_time_before_retry)
                logger.info("ENDED: Wait until retry")
                # continue next iteration
            else:
                failure_reason = (
                    f"ERROR: Failed to invoke Aviatrix API. Exceed the max "
                    f"retry times. All responses are listed as follows: "
                    f"{str(responses)}"
                )
                raise AviatrixException(
                    message=failure_reason,
                )
            # END
    return response


# End def send_aviatrix_api()

class LbConf():
    def __init__(self, lb_client, resource_group, network_client, lb_name):
        self.resource_group = resource_group
        self.lb_name = lb_name
        self.network_client = network_client
        self.lb_client_get = lb_client.get(self.resource_group, self.lb_name)
        self.location = self.lb_client_get.location
        self.lb_fe_name = self.lb_client_get.frontend_ip_configurations[0].name
        self.lb_be_name = self.lb_client_get.backend_address_pools[0].name
        self.lb_be_id = self.lb_client_get.backend_address_pools[0].id
        self.lb_be_rules = (
            self.lb_client_get.backend_address_pools[0].load_balancing_rules)
        self.lb_be_type = self.lb_client_get.backend_address_pools[0].type
        self.lb_frontend_ip_config = (
            self.lb_client_get.frontend_ip_configurations[0])
        self.lb_public_ip_name = (
            self.lb_frontend_ip_config.public_ip_address.id.split(
                '/')[-1])
        self.lb_public_ip = self.network_client.public_ip_addresses.get(
            self.resource_group, self.lb_public_ip_name)
        self.lb_public_ip_prefix = self.lb_public_ip.ip_address
        self.lb_be_conf = (
            self.network_client.load_balancer_backend_address_pools.get(
                self.resource_group, self.lb_name, self.lb_be_name))


def enable_backup(
    api_endpoint_url="123.123.123.123/v1/api",
    CID="ABCD1234",
):
    request_method = "GET"
    data = {"action": "get_cloudn_backup_config", "CID": CID}
    logger.info(f"API endpoint url is : {api_endpoint_url}")
    logger.info(f"Request method is : {request_method}")
    payload_with_hidden_password = dict(data)
    payload_with_hidden_password["CID"] = "********"
    formatted_payload = json.dumps(obj=payload_with_hidden_password, indent=4)
    logger.info(f"Request method is : {str(formatted_payload)}")
    response = send_aviatrix_api(
        api_endpoint_url=api_endpoint_url,
        request_method=request_method,
        payload=data,
    )

    py_dict = response.json()
    logger.info("Aviatrix API response is: %s", str(py_dict))
    if (py_dict["return"] is True) and (
            py_dict["results"]["enabled"] == "yes"):
        config = {}
        config["account_name"] = py_dict["results"]["acct_name"]
        config["storage_name"] = py_dict["results"]["storage_name"]
        config["container_name"] = py_dict["results"]["container_name"]
        config["cloud_type"] = py_dict["results"]["cloud_type"]
        config["multiple"] = py_dict["results"]["multiple_bkup"]
        config["region"] = py_dict["results"]["region"]
        config["now"] = "true"
        try:
            request_method = "POST"
            data = {"action": "enable_cloudn_backup_config", "CID": CID}
            data.update(config)
            payload_with_hidden_password = dict(data)
            payload_with_hidden_password["CID"] = "********"
            logger.info(f"API endpoint url is : {api_endpoint_url}")
            formatted_payload = json.dumps(obj=payload_with_hidden_password,
                                           indent=4)
            logger.info(f"Request method is : {str(formatted_payload)}")

            response = send_aviatrix_api(
                api_endpoint_url=api_endpoint_url,
                request_method=request_method,
                payload=data,
            )
            py_dict = response.json()
            logger.info("Aviatrix API response is: %s", str(py_dict))
        except Exception as e:
            logger.info(e)
    else:
        output = {"return": False, "reason": "Backup is not enabled"}
        logger.warning(output)
        return output


def main(mytimer: func.TimerRequest) -> None:
    # Initialize Azure Monitor Exporter for logs
    if connection_string:
        logger.addHandler(handler)

    # Initialize Azure Monitor Exporter for exceptions
    if connection_string:
        tracer = Tracer(exporter=exporter, sampler=sampler)
        requests.Session().mount('http://', requests.adapters.HTTPAdapter(max_retries=3))

    utc_timestamp = datetime.datetime.utcnow().replace(
        tzinfo=datetime.timezone.utc).isoformat()
    logging.basicConfig(
        format="%(asctime)s aviatrix-azure-function--- %(message)s",
        level=logger.info
    )
    logger.info(
        f"Version : {version.VERSION} Backup triggered at {utc_timestamp}")
    event = {
        "aviatrix_api_version": "v1",
        "aviatrix_api_route": "api",
        "vault_uri": os.environ["keyvault_uri"],
        "vault_secret": "aviatrix-controller-key",
        "func_client_id": os.environ["func_client_id"],
        "lb_name": os.environ["lb_name"],
        "rg": os.environ["resource_group_name"]
    }

    try:
        function_handler(event)
    except Exception as err:
        logger.error(f"Error has occurred: {str(err)}")
