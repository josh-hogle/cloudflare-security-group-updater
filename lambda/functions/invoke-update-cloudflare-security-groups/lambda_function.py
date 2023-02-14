# Python imports
import json
import logging
import os
import pprint
import sys
sys.path.insert(0, "{}/package".format(os.environ.get("LAMBDA_TASK_ROOT", sys.path[0])))

# 3rd party imports
import boto3
import requests

# local imports

# global variables / defaults
log = logging.getLogger()
org_client = boto3.client("organizations")
defaults = {
    "account_state_tag": {
        "env_var": "ACCOUNT_STATE_TAG",
        "default": "fn.aws.joshhogle.com/update-cloudflare-security-groups/account/state",
    },
    "account_enabled_values": {
        "env_var": "ACCOUNT_ENABLED_VALUES",
        "default": "enabled",
    },
    "iam_role_tag": {
        "env_var": "IAM_ROLE_TAG",
        "default": "fn.aws.joshhogle.com/update-cloudflare-security-groups/iam/role",
    },
    "default_iam_role": {
        "env_var": "DEFAULT_IAM_ROLE",
        "default": "STS-UpdateCloudflareSecurityGroupsRole",
    },
    "sg_tag_name_account_tag": {
        "env_var": "SG_TAG_NAME_ACCOUNT_TAG",
        "default": "fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/tag_name",
    },
    "sg_managed_values_account_tag": {
        "env_var": "SG_MANAGED_VALUES_ACCOUNT_TAG",
        "default": "fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/managed_values",
    },
    "default_sg_tag_name": {
        "env_var": "DEFAULT_SG_TAG_NAME",
        "default": "fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/state",
    },
    "default_sg_managed_values": {
        "env_var": "DEFAULT_SG_MANAGED_VALUES",
        "default": "managed",
    },
    "sg_regions_account_tag": {
        "env_var": "SG_REGIONS_ACCOUNT_TAG",
        "default": "fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/regions",
    },
    "default_sg_regions": {
        "env_var": "DEFAULT_SG_REGIONS",
        "default": "us-west-2"
    },
    "invoke_function_name": {
        "env_var": "INVOKE_FUNCTION_NAME",
        "default": "update-cloudflare-security-groups",
    },
}


def get_cloudflare_ip_list():
  """Retrieves the current list of IPv4 and IPv6 CIDR blocks for Cloudflare using its API.
  
  Returns:
    (list, list): A tuple of 2 lists, the first of which is the list of IPv4 CIDR blocks and the second of which is
                  a list of IPv6 CIDR blocks.
  
  Raises:
    Exception:  If a request or response error occurs when retrieving the list of IPs.
  """
  try:
    response = requests.get("https://api.cloudflare.com/client/v4/ips")
    data = response.json()
  except Exception as e:
    msg = "Cloudflare request error: {}".format(e)
    log.fatal(msg)
    raise Exception(msg)
  if "result" in data and "ipv4_cidrs" in data["result"] and "ipv6_cidrs" in data["result"]:
    return data["result"]["ipv4_cidrs"], data["result"]["ipv6_cidrs"]
  msg = "Cloudflare response error: {}".format(data)
  log.fatal(msg)
  raise Exception(msg)


def get_setting(setting):
  """Retrieves the value of a setting from the environment.

  Parameters:
    setting (str):  The name of the setting to retrieve.
  
  Returns:
    object: The value of the setting.
  """
  value = os.environ.get(defaults[setting]["env_var"], None)
  if value is None:
    return defaults[setting]["default"]
  return value


def tags_to_dict(tags):
  """Takes the list of tags and converts it to a regular Python dict object.

  If a tag has no "Key" or "Value" or "Values" key, it is ignored.

  Parameters:
    tags (list):    A list of tags to convert.

  Returns:
    dict: The converted dictionary representation of the tags.
  """
  result = {}
  for t in tags:
    key = t.get("Key", None)
    if key is None:
      continue
    values = t.get("Values", t.get("Value", None))
    if values is None:
      continue
    result[key] = values
  return result


def lambda_handler(event, context):
  """AWS Lambda main entrypoint.
  
  Parameters:
    event (dict):   Event data that triggered the function.
    context (dict): Additional function context.
  """
  # initialize logging
  log.setLevel(logging.INFO)
  log.info("=== Starting invoke-update-cloudflare-security-groups ===")
  log.info("sys.path: {}".format(sys.path))
  log.info("boto3 version: {}\n".format(boto3.__version__))

  # retrieve Cloudflare IPs and a list of Organization accounts
  cloudflare_v4_ips, cloudflare_v6_ips = get_cloudflare_ip_list()
  accounts = org_client.list_accounts().get("Accounts", [])

  # configure settings
  log.info("--- VARIABLE SETTINGS ---")
  account_state_tag = get_setting("account_state_tag")
  log.info("account_state_tag: {}".format(account_state_tag))

  account_enabled_values = [v.strip() for v in get_setting("account_enabled_values").split(":")]
  log.info("account_enabled_values: {}".format(account_enabled_values))

  iam_role_tag = get_setting("iam_role_tag")
  log.info("iam_role_tag: {}".format(iam_role_tag))
  default_iam_role = get_setting("default_iam_role")
  log.info("default_iam_role: {}".format(default_iam_role))

  sg_tag_name_account_tag = get_setting("sg_tag_name_account_tag")
  log.info("sg_tag_name_account_tag: {}".format(sg_tag_name_account_tag))
  default_sg_tag_name = get_setting("default_sg_tag_name")
  log.info("default_sg_tag_name: {}".format(default_sg_tag_name))

  sg_managed_values_account_tag = get_setting("sg_managed_values_account_tag")
  log.info("sg_managed_values_account_tag: {}".format(sg_managed_values_account_tag))
  default_sg_managed_values = get_setting("default_sg_managed_values")
  log.info("default_sg_managed_values: {}".format(default_sg_managed_values))

  sg_regions_account_tag = get_setting("sg_regions_account_tag")
  log.info("sg_regions_account_tag: {}".format(sg_regions_account_tag))
  default_sg_regions = get_setting("default_sg_regions")
  log.info("default_sg_regions: {}".format(default_sg_regions))

  invoke_function_name = get_setting("invoke_function_name")
  log.info("invoke_function_name: {}\n".format(invoke_function_name))

  # find accounts with the function enabled and asynchronously invoke Lambda function
  for account in accounts:
    # get account ID, name and tags - if no ID is set, skip it
    id = account.get("Id", None)
    name = account.get("Name", id)
    if id is None:
      log.warn("account has no 'Id' - skipping")
      continue
    tags = tags_to_dict(org_client.list_tags_for_resource(ResourceId=id).get("Tags", []))

    # skip the account if it is not enabled
    if account_state_tag not in tags or tags[account_state_tag] not in account_enabled_values:
      log.info("skipping disabled account: {} ({})".format(name, id))
      continue
    log.info("updating account: {} ({})".format(name, id))

    # configure the IAM role
    iam_role = tags.get(iam_role_tag, None)
    if iam_role is None:
      iam_role = default_iam_role
    arn = "arn:aws:iam::{}:role/{}".format(id, iam_role)
    log.info("   arn: {}".format(arn))

    # configure the security group settings
    sg_tag_name = tags.get(sg_tag_name_account_tag, default_sg_tag_name)
    sg_managed_values = [
        v.strip() for v in tags.get(sg_managed_values_account_tag, default_sg_managed_values).split(":")
    ]
    sg_regions = [v.strip() for v in tags.get(sg_regions_account_tag, default_sg_regions).split(":")]

    # create the event and invoke the Lambda function
    event = {
        "arn": arn,
        "cf_ipv4_blocks": cloudflare_v4_ips,
        "cf_ipv6_blocks": cloudflare_v6_ips,
        "sg_regions": sg_regions,
        "sg_tag_name": sg_tag_name,
        "sg_managed_values": sg_managed_values
    }
    log.info("   invoking function '{}' with event:\n{}".format(invoke_function_name,
                                                                json.dumps(event, sort_keys=True, indent=4)))
    if context is not None:
      response = boto3.client("lambda").invoke(FunctionName=invoke_function_name,
                                               InvocationType="Event",
                                               LogType="Tail",
                                               Payload=json.dumps(event))
      log.info(response)
  log.info("=== Finished invoke-update-cloudflare-security-groups ===\n")


# invocation for debugging purposes
if __name__ == "__main__":
  ch = logging.StreamHandler()
  log.addHandler(ch)
  try:
    lambda_handler({}, None)
  except Exception as e:
    log.error(e)
