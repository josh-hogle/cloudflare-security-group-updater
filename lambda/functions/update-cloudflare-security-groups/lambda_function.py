# Python imports
import json
import logging
import os
import sys
sys.path.insert(0, "{}/package".format(os.environ.get("LAMBDA_TASK_ROOT", sys.path[0])))

# 3rd party imports
import boto3

# local imports

# global variables
log = logging.getLogger()
sts_client = boto3.client("sts")


def add_rule(ec2_client, group_id, version, pair):
  """Adds a security group ingress rule.
  
  Parameters:
    ec2_client (object):  The EC2 client object.
    group_id (str):       The ID of the Security Group to modify.
    version (str):        The IP version: v4 or v6.
    pair (str):           The "CIDR start_port-end_port" pair to add.
  """
  perms = pair_to_permission(pair, version)
  ec2_client.authorize_security_group_ingress(GroupId=group_id, IpPermissions=[perms])
  log.info("added {} ingress rule: {}".format(version, pair))


def get_event_value(event, key):
  """Gets a value from the event and raises an Exception if it is missing.

  Parameters:
    event (dict):   Dictionary containing event information.
    key (str):      The event key to retrieve the value for.
  
  Returns:
    value (object): The value of the key.

  Raises:
    Exception:  If the value missing from the event.
  """
  value = event.get(key, None)
  if value is None:
    msg = "'{}' is missing from the event".format(key)
    log.fatal(msg)
    raise Exception(msg)
  return value


def pair_to_permission(pair, version):
  """Parses the IP/port pair into an IPPermissions entry.

  Parameters:
    version (str):  The IP version: v4 or v6.
    pair (str):     The "CIDR start_port-end_port" pair to convert.
  
  Returns:
    dict: Dictionary containing the proper settings for modifying the IPPermissions field of an ingress or egress rule.
  """
  parts = pair.split(" ")
  ip_addr = parts[0]
  ports = parts[1].split("-")
  perms = {
      "IpProtocol": "tcp",
      "FromPort": int(ports[0]),
      "ToPort": int(ports[1]),
  }
  if version == "v4":
    perms["IpRanges"] = [{"CidrIp": ip_addr}]
  else:
    perms["Ipv6Ranges"] = [{"CidrIpv6": ip_addr}]
  return perms


def remove_rule(ec2_client, group_id, version, pair):
  """Removes a security group ingress rule.
  
  Parameters:
    ec2_client (object):  The EC2 client object.
    group_id (str):       The ID of the Security Group to modify.
    version (str):        The IP version: v4 or v6.
    pair (str):           The "CIDR start_port-end_port" pair to remove.
  """
  perms = pair_to_permission(pair, version)
  ec2_client.revoke_security_group_ingress(GroupId=group_id, IpPermissions=[perms])
  log.info("removed {} ingress rule: {}".format(version, pair))


def lambda_handler(event, context):
  """AWS Lambda main entrypoint.
  
  Parameters:
    event (dict):   Event data that triggered the function.
    context (dict): Additional function context.
  """
  # initialize logging
  log.setLevel(logging.INFO)
  log.info("=== Starting update-cloudflare-security-groups ===")
  log.info("sys.path: {}".format(sys.path))
  log.info("boto3 version: {}\n".format(boto3.__version__))

  # get settings from event
  ports = [v.strip() for v in os.environ.get("CLOUDFLARE_PORTS", "80,443").split(",")]
  role_arn = get_event_value(event, "arn")
  cloudflare_v4_ips = get_event_value(event, "cf_ipv4_blocks")
  cloudflare_v6_ips = get_event_value(event, "cf_ipv6_blocks")
  sg_regions = get_event_value(event, "sg_regions")
  sg_tag_name = get_event_value(event, "sg_tag_name")
  sg_managed_values = get_event_value(event, "sg_managed_values")

  # build CIDR/port pairs for Cloudflare to be used for comparison later
  cloudflare_v4_pairs = []
  cloudflare_v6_pairs = []
  for port in ports:
    for ip in cloudflare_v4_ips:
      cloudflare_v4_pairs.append("{} {}-{}".format(ip, port, port))
    for ip in cloudflare_v6_ips:
      cloudflare_v6_pairs.append("{} {}-{}".format(ip, port, port))

  # initiate a session using ARN of the IAM role
  role = sts_client.assume_role(RoleArn=role_arn, RoleSessionName="awsaccount_session")
  log.info("assumed role: {}".format(role_arn))

  # -----------------------------------------------------------------------
  # enumerate tagged security groups in regions
  # -----------------------------------------------------------------------
  for region in sg_regions:
    log.info("checking region: {}".format(region))
    ec2_client = boto3.client("ec2",
                       region_name=region,
                       aws_access_key_id=role["Credentials"]["AccessKeyId"],
                       aws_secret_access_key=role["Credentials"]["SecretAccessKey"],
                       aws_session_token=role["Credentials"]["SessionToken"])

    # enumerate security groups that match the given tag and values
    groups = ec2_client.describe_security_groups(Filters=[{"Name": "tag:{}".format(sg_tag_name), "Values": sg_managed_values}])
    for group in groups.get("SecurityGroups", []):
      id = group.get("GroupId", None)
      name = group.get("GroupName", id)
      if id is None:
        continue
      log.info("found matching security group: {} ({})".format(name, id))

      # build pairs for comparison
      permissions = group.get("IpPermissions", [])
      group_v4_pairs = []
      group_v6_pairs = []
      for perm in permissions:
        for r in perm.get("IpRanges", []):
          group_v4_pairs.append("{} {}-{}".format(r.get("CidrIp"), perm.get("FromPort", 0), perm.get("ToPort", 0)))
        for r in perm.get("Ipv6Ranges", []):
          group_v6_pairs.append("{} {}-{}".format(r.get("CidrIpv6"), perm.get("FromPort", 0), perm.get("ToPort", 0)))

      # update permissions
      v4_add_pairs = list(set(cloudflare_v4_pairs) - set(group_v4_pairs))
      log.info("missing IPv4 addresses: {}".format(v4_add_pairs))
      v4_remove_pairs = list(set(group_v4_pairs) - set(cloudflare_v4_pairs))
      log.info("extra IPv4 addresses: {}".format(v4_remove_pairs))
      v6_add_pairs = list(set(cloudflare_v6_pairs) - set(group_v6_pairs))
      log.info("missing IPv6 addresses: {}".format(v6_add_pairs))
      v6_remove_pairs = list(set(group_v6_pairs) - set(cloudflare_v6_pairs))
      log.info("extra IPv6 addresses: {}".format(v6_remove_pairs))
      for pair in v4_add_pairs:
        add_rule(ec2_client, id, "v4", pair)
      for pair in v6_add_pairs:
        add_rule(ec2_client, id, "v6", pair)
      for pair in v4_remove_pairs:
        remove_rule(ec2_client, id, "v4", pair)
      for pair in v6_remove_pairs:
        remove_rule(ec2_client, id, "v6", pair)
  log.info("=== Finished update-cloudflare-security-groups ===\n")


# invocation for debugging purposes
if __name__ == "__main__":
  if len(sys.argv) == 1:
    print("USAGE: {} <JSON event file>".format(sys.argv[0]))
    sys.exit(1)
  ch = logging.StreamHandler()
  log.addHandler(ch)
  try:
    with open(sys.argv[1], "r") as event_file:
      event = json.load(event_file)
    lambda_handler(event, None)
  except Exception as e:
    log.error(e)
