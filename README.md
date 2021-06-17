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
  -a, --assumedrole= Role name to assume when collecting across all accounts
  -o, --output=      File to direct output to. (default: SecurityHub-Findings.csv)
  -s, --s3bucket=    S3 bucket where you would like to have the output file uploaded
  -k, --s3key=       The S3 key (path/filename) to use (defaults to --output, will have timestamp inserted in name)
  -p, --profile=     The AWS profile to use. [$AWS_PROFILE]
  -r, --region=      The AWS region to use. [$AWS_REGION]
  -m, --teammap=     JSON file containing team to account mappings.
  -u, --upload-only= Use this flag to upload results to S3

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

If you want to be able to query multiple accounts using a cross account role, you can specify the AWS profiles in the map as well. You will need to make sure that your AWS CLI configuration has a profile defined for each account with the `role_arn`, and need to use the `-p` option to the app to specify the same profile that is used for the `source_profile` in each cross account profile. Keep in mind that you will also need to have `~/.aws/credentials` with a matching profile name and proper credentials (`aws_access_key_id` and `aws_secret_access_key`) for the primary account.

**NOTE**: If you are using MFA like in the following examples, each time the application moves on to the next account, it will ask for a new MFA token. **DO NOT RE-USE TOKENS**. You have to wait for the next token for each account accessed.

For example, if our `~/.aws/config` looks like:

```ini
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

and our `~/.aws/credentials` looks like:

```ini
[profile primary-account]
aws_access_key_id=AKXXXXXXXXXXXXXXXXXX
aws_secret_access_key=xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
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
