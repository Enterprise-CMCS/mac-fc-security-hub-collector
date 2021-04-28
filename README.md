# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for
consumption by visualization tools. In order to use this tool, you will
need to have valid AWS credentials in your environment (or provide a
profile for the tool to use).

## Installation

```sh
go get -u github.com/CMSGov/security-hub-collector
```

## Usage

```sh
security-hub-collector is an application for retrieving Security Hub findings for visualization

Usage:
  security-hub-collector [OPTIONS]

Application Options:
  -o, --output=  File to direct output to. (default: SecurityHub-Findings.csv)
  -p, --profile= The AWS profile to use. [$AWS_PROFILE]
  -r, --region=  The AWS region to use. [$AWS_REGION]
  -m, --teammap= JSON file containing team to account mappings.

Help Options:
  -h, --help     Show this help message

```

You will need to create a team map file with a JSON object that describes
your teams based on account numbers. For example:

```json
{
  "teams": [
    {
      "accounts": [
        "000000000001",
        "000000000011"
      ],
      "name": "My Team"
    }
  ]
}
```

If you want to be able to query multiple accounts using a cross account role, you can specify the AWS profiles in the map as well. You will need to make sure that your AWS CLI configuration has each a profile for each account properly defined, and want to use `-p` option to the app to specify the `source_profile` that is used for each cross account profile. Keep in mind that you will also need to have `~/.aws/credentials` with a matching profile for the primary account.

**NOTE**: If you are using MFA, each time the application moves on to the next account, it will ask for a new token. **DO NOT RE-USE TOKENS**. You have to wait for the next token for each account accessed.

For example, if our `~/.aws/config` looks like:

```
[profile primary-account]
mfa_serial=arn:aws:iam::111111111111:mfa/SERIAL
region=us-east-1
output=json

[profile cross-account-1]
source_profile=primary-account
mfa_serial=arn:aws:iam::111111111111:mfa/SERIAL
region=us-east-1
output=json
role_arn=arn:aws:iam::000000000001:role/crossacct-role

[profile cross-account-11]
source_profile=primary-account
mfa_serial=arn:aws:iam::111111111111:mfa/SERIAL
region=us-east-1
output=json
role_arn=arn:aws:iam::000000000011:role/crossacct-role
```

Then our team map looks like:
```json
{
  "teams": [
    {
      "accounts": [
        "000000000001",
        "000000000011"
      ],
      "profiles": [
        "cross-account-1",
        "cross-account-11"
      ],
      "name": "My Team"
    }
  ]
}
```

## Examples

Run the command like this:

```sh
security-hub-collector -m teammap.json -p primary-account
```
