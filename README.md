# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for consumption by visualization tools. To use this tool, you need one of the following, depending on whether you provide team data via the Teams API or a JSON file:

To configure with the Teams API:

- an API key for the Teams API
- a single IAM role that is valid for all of the accounts in the Teams API

To configure with a JSON team map:

- one or more IAM roles that are valid for each account listed in the map of accounts to teams provided to the tool

## Installation

```sh
go get -u github.com/Enterprise-CMCS/mac-fc-security-hub-collector
```

## Usage

`security-hub-collector` is a CLI for retrieving Security Hub findings for visualization.

To display a full list of CLI options, build the application and run `security-hub-collector -h`.

## Run Docker Image Locally

To run the Docker image locally for testing, do the following:

1. Create a file at the top level called `docker-gitconfig` with the following content:

   ```bash
   [url "https://<username>:<personal access token>@github.com/Enterprise-CMCS/"]
     insteadOf = https://github.com/Enterprise-CMCS/
   ```

2. `docker build . -t local-collector-test`
3. set AWS creds in the environment (`AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID, AWS_SESSION_TOKEN`)
4. run the image:
   - using the Teams API

   ```bash
   docker run \
   -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_ACCESS_KEY_ID \
   -e TEAMS_API_KEY \
   -e TEAMS_API_BASE_URL=https://vshjmodi2c.execute-api.us-east-1.amazonaws.com/teams-api-prod \
   -e COLLECTOR_ROLE_PATH=delegatedadmin/developer/ct-cmcs-mac-fc-cost-usage-role \
   -e AWS_REGION=us-east-1 \
   -e S3_BUCKET=securityhub-collector-results-037370603820s \
   local-collector-test
   ```

   - using a team map

   ```bash
   export BASE64_TEAM_MAP=$(cat team_map.json | base64)
   docker run \
   -e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_ACCESS_KEY_ID \
   -e BASE64_TEAM_MAP \
   -e AWS_REGION=us-east-1 \
   -e S3_BUCKET=securityhub-collector-results-037370603820s \
   local-collector-test
   ```

## Terraform

The repo contains Terraform for:

- an ECR repo that hosts the Collector image, which is deployed in the `MACBIS Shared DSO Dev` account. A team's AWS account ID must be on the access list to have permission to pull the Collector image. The access list is maintained via the `ecr_read_account_ids` variable in `terraform/dev/account/terraform.tfvars`. To request access, please open a Jira ticket in the `CMCS-MACBIS-DSO` project
- those IAM resources needed for the `build-and-push-dev` workflow

## GitHub Actions Workflows

### build-and-push

This workflow builds and pushes the Collector image to a private ECR registry in MACBIS Shared DSO dev. It tags the image with the SHA. We have deprecated the `latest` tag, but the image with this tag should not be removed from the ECR registry because it is in use.

### validate

This workflow runs pre-commit, Go tests, and a Docker build upon pull requests

## QuickSight dataset

QuickSight requires a [manifest file](https://docs.aws.amazon.com/quicksight/latest/user/supported-manifest-file-format.html) to ingest data from S3. Since there's a dependency between the CSV delimiter and the manifest file, `manifest.json` is included here. This file must be manually uploaded when a new dataset is created that uses the Collector data as a data source. We use tab delimiters because we were seeing some errors with unescaped commas in some fields.
