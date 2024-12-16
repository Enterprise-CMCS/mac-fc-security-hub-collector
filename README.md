# Security Hub Collector

## Description

This tool pulls findings from AWS Security Hub and outputs them for consumption by visualization tools. To use this tool, you need
- an Athena table of teams to accounts that follows the [format expected by the Athena library](https://github.com/Enterprise-CMCS/mac-fc-macbis-cost-analysis/blob/250739e71c9617344a584aab82d5785334c37bba/pkg/athenalib)
- an S3 bucket for Athena query outputs
- a role that is valid for each account listed in the map of accounts to teams provided to the tool

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
   ```
   [url "https://<username>:<personal access token>@github.com/Enterprise-CMCS/"]
	  insteadOf = https://github.com/Enterprise-CMCS/
   ```
2. set AWS creds in the environment (`AWS_SECRET_ACCESS_KEY, AWS_ACCESS_KEY_ID, AWS_SESSION_TOKEN`)
3. `docker build . -t local-collector-test`
4. run the image:

```bash
docker run \
-e AWS_SECRET_ACCESS_KEY -e AWS_SESSION_TOKEN -e AWS_ACCESS_KEY_ID \
-e ATHENA_TEAMS_TABLE=athenacurcfn_cms_cloud_cur_monthly.teams \
-e QUERY_OUTPUT_LOCATION=s3://cms-macbis-cost-analysis/professor-mac/teams-query/ \
-e COLLECTOR_ROLE_ARN=arn:aws:iam::037370603820:role/delegatedadmin/developer/security-hub-collector \
-e AWS_REGION=us-east-1 \
-e S3_BUCKET=bharvey-test-distro \
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


