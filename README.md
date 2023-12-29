# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for consumption by visualization tools. To use this tool, you need a cross-account role that is valid for all accounts listed in the team map provided to the tool.

## Installation

```sh
go get -u github.com/CMSgov/security-hub-collector
```

## Usage

`security-hub-collector` is a CLI for retrieving Security Hub findings for visualization.

To display a full list of CLI options, build the application and run `security-hub-collector -h`.


You will need to create a team map file with a JSON object that describes
your teams based on account numbers and environments. For example:

```json
{
  "teams": [
    {
      "accounts": [
        { "id": "000000000001", "environment": "dev" },
        { "id": "000000000011", "environment": "test" }
      ],
      "name":"My Team"
    }
  ]
}
```

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
-e ASSUME_ROLE={role name} \
-e S3_BUCKET_PATH={bucket name} \
local-collector-test
```

## Terraform

The repo contains Terraform for:

- an ECR repo that hosts the Collector images, which is deployed in the MACBIS Shared DSO dev account. Teams that want to pull this image have their AWS account IDs whitelisted in the `ecr_read_account_ids` list variable in `terraform/dev/account/terraform.tfvars`. Terraform must be applied if this list is updated
- those IAM resources needed for the `build-and-push-dev` workflow

## GitHub Action Workflows

### build-and-push

This workflow builds and pushes the Collector image to a private ECR registry in MACBIS Shared DSO dev. It tags the image with the SHA and the value `v2`, to signify a breaking change in the team map schema from the previous release tag, `latest`. We have deprecated the `latest` tag, but the image with this tag should not be removed from the repo because it is in use.

### validate

This workflow runs pre-commit, Go tests, and a Docker build upon pull requests


