# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for consumption by visualization tools. To use this tool, you need a cross-account role ARN that is valid for all accounts listed in the team map provided to the tool. You can also specify custom role ARNs for specific accounts if the role name is not consistent across accounts.

## Installation

```sh
go get -u github.com/Enterprise-CMCS/mac-fc-security-hub-collector
```

## Usage

`security-hub-collector` is a CLI for retrieving Security Hub findings for visualization.

To display a full list of CLI options, build the application and run `security-hub-collector -h`.


You will need to create a team map file with a JSON object that describes
your teams based on account numbers, environments and optional role ARN overrides. For example:

```json
{
  "teams": [
    {
      "accounts": [
        { "id": "000000000001", "environment": "dev" },
        { "id": "000000000011", "environment": "test", "roleArnOverride": "arn:aws:iam::000000000011:role/CustomRole" }
      ],
      "name":"My Team"
    }
  ]
}
```

The roleArnOverride field is optional. If specified, it will be used instead of the default role ARN provided in the command line arguments for that specific account.

## Run Docker Image Locally

To run the Docker image locally for testing, do the following:

1. create a local `team_map.json` file based on the example above
2. `export TEAM_MAP=$(cat team_map.json | base64)`
3. set AWS creds in the environment (`AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID, AWS_SESSION_TOKEN`)
4. `docker build . -t local-collector-test`
5. run the image:

```bash
docker run \
-e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_ACCESS_KEY_ID -e TEAM_MAP \
-e AWS_REGION={region}
-e ASSUME_ROLE={full role ARN} \
-e S3_BUCKET_PATH={bucket name} \
local-collector-test
```

## Terraform

The repo contains Terraform for:

- an ECR repo that hosts the Collector image, which is deployed in the `MACBIS Shared DSO Dev` account. A team's AWS account ID must be on the access list to have permission to pull the Collector image. The access list is maintained via the `ecr_read_account_ids` variable in `terraform/dev/account/terraform.tfvars`. To request access, please open a Jira ticket in the `CMCS-MACBIS-DSO` project
- those IAM resources needed for the `build-and-push-dev` workflow

## GitHub Actions Workflows

### build-and-push

This workflow builds and pushes the Collector image to a private ECR registry in MACBIS Shared DSO dev. It tags the image with the SHA and the value `v2`, to signify a breaking change in the team map schema from the previous release tag, `latest`. We have deprecated the `latest` tag, but the image with this tag should not be removed from the repo because it is in use.

### validate

This workflow runs pre-commit, Go tests, and a Docker build upon pull requests


