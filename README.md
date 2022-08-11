# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for
consumption by visualization tools. To use this tool, you will
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
      "accounts": ["000000000001", "000000000011"],
      "name": "My Team"
    }
  ]
}
```

If you want to be able to query multiple accounts using a cross-account role, you can specify the AWS profiles in the map as well. You will need to make sure that your AWS CLI configuration has a profile defined for each account with the `role_arn`, and need to use the `-p` option to the app to specify the same profile that is used for the `source_profile` in each cross-account profile. Keep in mind that you will also need to have `~/.aws/credentials` with a matching profile name and proper credentials (`aws_access_key_id` and `aws_secret_access_key`) for the primary account.

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

then our team map looks like:

```json
{
  "teams": [
    {
      "accounts": ["000000000001", "000000000011"],
      "profiles": ["cross-account-1", "cross-account-11"],
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

## Terraform

The repo contains a Terraform module that deploys:

- an ECR repo to host the Collector image
- a service user with permissions to push images to the ECR repo

Note that the name of the ECR repo in the module, `security-hub-collector`, is coupled to the `reusable-build-and-push` GitHub Action workflow below, and should only be changed in concert with that workflow.

Example usage:

```terraform
  module "security_hub_collector_ecr" {
    source = "github.com/CMSgov/security-hub-collector"
    allowed_read_principals = local.allowed_read_principals
    scan_on_push = // optional, defaults to true
    tags = // optional, defaults to {}
    lifecycle_policy = // optional, defaults to "".  When empty, defaults to keep the last 500 images
  }
```

## GitHub Action Workflows

### reusable-build-and-push

This is a [reusable workflow](https://docs.github.com/en/actions/using-workflows/reusing-workflows) that can be called to build the Docker image and push it to an ECR repo. It uses [GitHub environments](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment) to select the right AWS credentials for the calling workflow.

To set up a new deployment environment (e.g. 'test'):

1. Deploy the Terraform module contained in this repo to create an ECR repo and a service user in the test AWS account
2. Using the AWS console or CLI, get AWS credentials (access key ID and secret access key) for the service user
3. [Create a GitHub environment](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#creating-an-environment) called 'test'. Optionally, [configure deployment branches](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#deployment-branches) for the environment to limit which branches are allowed to deploy to the environment
4. Store the AWS credentials as [environment secrets](https://docs.github.com/en/actions/deployment/targeting-different-environments/using-environments-for-deployment#environment-secrets) for the 'test' environment, using the values from step 2 and the following keys:
   - AWS_ACCESS_KEY_ID
   - AWS_SECRET_ACCESS_KEY
5. Create a new workflow for the environment that calls the `reusable-build-and-push` workflow, passing the `environment` and `secrets`. The `branches` workflow trigger should match any deployment branches that you configured for the GitHub environment in step 3.

   ```yml
   name: build-and-push-test

   on:
     push:
       branches: ["*build-and-push"]

   jobs:
     build:
       uses: ./.github/workflows/reusable-build-and-push.yml
       with:
         environment: test
       secrets:
         AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID}}
         AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
   ```

### validate

This workflow runs pre-commit, Go tests, and a Docker build upon pull requests

## Testing

If you'd like to test a deployed version of the Collector Docker image, add `build-and-push` to the end of your feature branch name (e.g. `my-feature-build-and-push`). This will trigger the `build-and-push-test` workflow that builds a Docker image and pushes it to the ECR repo for the test environment. For configuration steps, see the `reusable-build-and-push` workflow documentation in this README.
