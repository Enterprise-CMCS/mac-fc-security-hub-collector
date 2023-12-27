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

The repo contains a Terraform module that deploys:

- an ECR repo to host the Collector image
- a service user with permissions to push images to the ECR repo

Note that the name of the ECR repo in the module, `security-hub-collector`, is coupled to the `reusable-build-and-push` GitHub Action workflow below, and should only be changed in concert with that workflow.

Example usage:

```terraform
  module "security_hub_collector_ecr" {
    source = "github.com/CMSgov/security-hub-collector"
    ecr_read_aws_accounts = local.ecr_read_aws_accounts
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
