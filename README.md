# Cloudflare Security Group Updater

This tool consists of Lamba functions that automatically update tagged Security Groups belonging to accounts within the organization that be updated with the most current list of IP address blocks from Cloudflare.  The Security Group(s) will have rules allowing **only** Cloudflare IP blocks to access the associated resources over ports 80 and 443.

The tool consists of 2 Lambda functions which are explained in greater detail below.

Note that colon-delimited rather than colon-delimited values are required in Account tag values because those values do not allow the comma character.

## invoke-update-cloudflare-security-groups

This function is responsible for enumerating the list of accounts in the organization and determining whether or not to run the **update-cloudflare-security-groups** function on those accounts.  The steps performed by this function are described below.

### 1. Determine if an Account is enabled

The following steps are used to determine whether or not to run the **update-cloudflare-security-groups** function on a member account:

- If the **ACCOUNT_STATE_TAG** environment variable is set, this tag on the account will be used to determine whether or not the function should be run.  If the variable is not set, the default tag **fn.aws.joshhogle.com/update-cloudflare-security-groups/account/state** will be used instead.

- If the **ACCOUNT_ENABLED_VALUES** environment variable is set, this should be a colon-delimited list of values.  If the value of the tag is set to one of the values in this list, the account is considered to be "enabled".  If the variable is not set, the tag's value value must be set to the default value of **enabled** to be considered "enabled".

### 2. Determine the IAM Role name

If the account is enabled, the next step is to determine the name of the role to assume on the target account.  The following steps are used to determine the name of this role:

- If the **IAM_ROLE_TAG** environment variable is set, this tag on the account will be used to determine the name of the IAM role to use.  If the variable is not set, the default tag **fn.aws.joshhogle.com/update-cloudflare-security-groups/iam/role** is used instead.

- If the previously determined tag name exists on the account, its value is used for the IAM role name.  If the tag does not exist, use the value of the **DEFAULT_IAM_ROLE** environment variable as the name of the role.  If the variable is not set, the default value **STS-UpdateCloudflareSecurityGroupsRole** is used instead.

### 3. Determine Security Group regions, managed tag and values

If the account is enabled, the final step is to determine the name of the tag to search for on Security Groups in the target account.  If the tag exists on a Security group and its value matches one of the values in the supplied colon-delimited list of values to the **update-cloudflare-security-groups** function, it will consider the security group as being "managed", thus allowing it to make changes to the IP permissions list in the group.  

The following steps are used to determine the name of the tag to search for on the Security Group:

- If the **SG_TAG_NAME_ACCOUNT_TAG** environment variable is set, this tag on the account will be used to determine the name of the Security Group tag to search for.  If the variable is not set, the default tag **fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/name** on the account will be used instead.

- If the account contains a tag matching the previously determined value, its value will be used as the name of the Security Group tag to search for.  If no tag exists on the account, use the value of the **DEFAULT_SG_TAG_NAME** environment variable as the name of the Security Group tag.  If the variable is not set, search for the default **fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/state** tag on Security Groups instead.

The following steps are used to determine the list of values to supply to the **update-cloudflare-security-groups** function for the tag:

- If the **SG_MANAGED_VALUES_ACCOUNT_TAG** environment variable is set, this tag on the account will be used to determine the list of values to supply.  If the variable is not set, the default tag **fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/managed_values** on the account will be used instead.

- If the account contains a tag matching the previously determined value, its colon-delimited list of values will be supplied.  If no tag exists on the account, use the value of the **DEFAULT_SG_MANAGED_VALUES** environment variable as the list of values.  If the variable is not set, use the default value of **managed** instead.

The following steps are used to determine the list of regions to supply to the **update-cloudflare-security-groups** function:

- If the **SG_REGIONS_ACCOUNT_TAG** environment variable is set, this tag on the account will be used to determine the list of regions to supply.  If the variable is not set, the default tag **fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/regions** on the account will be used instead.

- If the account contains a tag matching the previously determined value, its colon-delimited list of values will be supplied.  If no tag exists on the account, use the value of the **DEFAULT_SG_REGIONS** environment variable as the list of values.  If the variable is not set, use the default value of **us-west-2** instead.

### 5. Update Security Groups across Accounts

The final step is for the function to asynchronously invoke the **update-cloudflare-security-groups** function for each account sending it the following event as input:

```json
{
  "arn": "Amazon Resource Name for the IAM Role being used",
  "cf_ipv4_blocks": [ "list of Cloudflare IPv4 CIDR blocks" ],
  "cf_ipv6_blocks": [ "list of Cloudflare IPv6 CIDR blocks" ],
  "sg_regions": [ "list of regions in which to enumerate SGs" ],
  "sg_tag": "name of the Security Group tag to search for",
  "sg_managed_values": "list of values to indicate the SG is managed"
}
```

Note that, if desired, the name of the function invoked can be overridden by specifying a value for the **INVOKE_FUNCTION_NAME** environment variable.

### Debugging and Logging

By default, all output from the function is sent to CloudWatch Logs and placed into the **/aws/lambda/invoke-update-cloudflare-security-groups** Log Group.

The function can be invoked from Lambda by simply executing the function with an empty event or it can be run from the command-line directly.  When running directly from the command-line, the function will log to stdout instead of CloudWatch and will **not** invoke the same Lambda function as outlined in step 4.  Instead only the function name and related event that would have invoked are logged.

## update-cloudflare-security-groups

This function is responsible for enumerating the Security Groups within the account and updating any that are tagged as "managed" with the current list of Cloudflare IP blocks.  The steps performed by this function are described below.

1. Retrieve settings from the event.  The event passed to the function is expected to contain the values described previously.  If any are missing, an exception is raised and the function exits.
2. Create a new AWS session by assuming the IAM role that was sent in the event.
3. For each region that was sent in the event, enumerate Security Groups and return those that have a matching tag and one of the given values to indicate that the group is "managed".
4. Compare the list of IP permissions attached to the Security Group with the list of Cloudflare CIDR blocks sent and add any missing rules and remove any extra rules.  By default rules for ports 80 and 443 are added.  However, this can be overridden by specifying a different comma-delimited set of ports for the **CLOUDFLARE_PORTS** environment variable.

### Debugging and Logging

By default, all output from the function is sent to CloudWatch Logs and placed into the **/aws/lambda/update-cloudflare-security-groups** Log Group.

The function can be invoked from Lambda by executing the function with a sample event in the previously described format or it can be run from the command-line directly.  When running directly from the command-line, the function will log to stdout instead of CloudWatch.

## IAM Role Configuration

IAM roles are required to run each of the functions within the context of Lambda as is a role required when the actual **update-cloudflare-security-groups** function is run.  The `iam/roles` folder contains JSON files for each of the roles that is required.  Each policy document can be used to create a custom policy that is attached to the role or used as an inline policy directly on the role.

### Lambda-InvokeUpdateCloudflareSecurityGroupsRole

This role should be created as a Lambda-trusted entity role and assigned to the **invoke-update-cloudflare-security-groups** Lambda function.

If you wish to tighten restrictions on what this role can do for additional security, use the `Lambda-InvokeUpdateCloudflareSecurityGroupsRole-restricted.json` file instead.  If you use this policy instead, you will need change the **REGION** and **ACCOUNT_ID** placeholders to match the region in which the Lambda function is running as well as your account ID, respectively, and pre-create the Log Group in CloudWatch.  If you do not use the standard **invoke-update-cloudflare-security-groups** and **update-cloudflare-security-groups** function names in Lambda, you must update those strings in this policy as well.

### Lambda-UpdateCloudflareSecurityGroupsRole

This role should be created as a Lambda-trusted entity role and assigned to the **update-cloudflare-security-groups** Lambda function.

If you do not use the default role named **STS-UpdateCloudflareSecurityGroupsRole**, you will need to update the name of the role in the policy as well.

If you wish to tighten restrictions on what this role can do for additional security, use the `Lambda-UpdateCloudflareSecurityGroupsRole-restricted.json` file instead.  If you use this policy instead, you will need change the **REGION** and **ACCOUNT_ID**/**ACCOUNTx_ID** placeholders to match the region in which the Lambda function is running as well as your account ID, respectively, and pre-create the Log Group in CloudWatch.  If you do not use the standard **update-cloudflare-security-groups** function name in Lambda, you must update that string in this policy as well.  As in the default file, update the **STS-UpdateCloudflareSecurityGroupsRole** string if you choose to use a non-standard role name.

### STS-UpdateCloudflareSecurityGroupsRole

This role should be created in each account in which the **update-cloudflare-security-groups** function will search for Security Groups.  It must be created as an **Another AWS account** trusted entity role specifying the ID of the account in which the **update-cloudflare-security-groups** Lambda function is located.  It gives the function permission to enumerate the security groups and only update those that are tagged as being "managed".

If you do not use the default Security Group tag named **fn.aws.joshhogle.com/update-cloudflare-security-groups/sg/state**, you will need to update the name of the resource tag in the policy.  Update any "managed" values as well if you do not simply use the **managed** value.

## Additional Help or Questions

If you have questions about this project, find a bug or wish to submit a feature request, please [submit an issue](https://github.com/josh-hogle/cloudflare-security-group-updated/issues).
