########## Building in us-east-1 ##########
provider "aws" {
  region              = "us-east-1"
  allowed_account_ids = ["037370603820"]

  default_tags {
    tags = {
      Maintainer  = "cms-macfc+archive@corbalt.com"
      Owner       = "cms-macfc+archive@corbalt.com"
      Environment = "dev"
      Application = "mac-fc-security-hub-collector"
      Business    = "MACBIS"
      Automated   = "Terraform"
      stack       = "dev"
    }
  }
}

terraform {
  required_version = "= 1.5.2"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.58.0"
    }
  }

  backend "s3" {
    region         = "us-east-1"
    bucket         = "security-hub-collector-dev-tfstate"
    key            = "app/state"
    dynamodb_table = "security-hub-collector-dev-lock-table"
    encrypt        = true
  }
}

########## Create a test assume role ########

data "aws_iam_policy" "security_hub_read_only" {
  name = "AWSSecurityHubReadOnlyAccess"
}

resource "aws_iam_role" "security_hub_collector" {
  name                 = "security-hub-collector"
  path                 = "/delegatedadmin/developer/"
  permissions_boundary = "arn:aws:iam::037370603820:policy/cms-cloud-admin/developer-boundary-policy"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = ["arn:aws:iam::037370603820:root"]
        }
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "security_hub_read_only" {
  role       = aws_iam_role.security_hub_collector.name
  policy_arn = data.aws_iam_policy.security_hub_read_only.arn
}

########## Create s3 bucket for storing the collected findings ##########
resource "aws_s3_bucket" "security_hub_collector" {
  bucket = var.security_hub_collector_results_bucket_name
}

resource "aws_s3_bucket_server_side_encryption_configuration" "security_hub_collector" {
  bucket = aws_s3_bucket.security_hub_collector.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "security_hub_collector" {
  bucket = aws_s3_bucket.security_hub_collector.id

  rule {
    id     = "security-hub-collector"
    status = "Enabled"

    expiration {
      days = 90
    }
  }
}

resource "aws_s3_bucket_public_access_block" "security_hub_collector" {
  bucket = aws_s3_bucket.security_hub_collector.id

  # Block new public ACLs and uploading public objects
  block_public_acls = true

  # Retroactively remove public access granted through public ACLs
  ignore_public_acls = true

  # Block new public bucket policies
  block_public_policy = true

  # Retroactively block public and cross-account access if bucket has public policies
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "security_hub_collector_bucket_policy" {
  bucket = aws_s3_bucket.security_hub_collector.id
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "var.security_hub_collector_results_bucket_name"
    Statement = [
      {
        Sid       = "write-only"
        Effect    = "Allow"
        Principal = { AWS : [module.security_hub_collector_runner.task_execution_role_arn] }
        Action    = ["s3:PutObject"]
        Resource = [
          aws_s3_bucket.security_hub_collector.arn,
          "${aws_s3_bucket.security_hub_collector.arn}/*",
        ]
      },
      {
        Action = "s3:*"
        Condition = {
          Bool = {
            "aws:SecureTransport" = "false",
          }
        }
        Effect    = "Deny"
        Principal = "*"
        Resource = [
          aws_s3_bucket.security_hub_collector.arn,
          "${aws_s3_bucket.security_hub_collector.arn}/*",
        ]
        Sid = "AllowSSLRequestsOnly"
      }
    ]
  })
}


##########Create cloudwatch log group and ecs cluster ##########
resource "aws_cloudwatch_log_group" "aws-scanner-inspec" {
  name = var.aws_cloudwatch_log_group_name
}

resource "aws_ecs_cluster" "security_hub_collector_runner" {
  name = "security-hub-collector"
}

########## Use the securityhub collector runner module ##########
module "security_hub_collector_runner" {
  source                    = "github.com/CMSgov/security-hub-collector-ecs-runner?ref=e120cc3cdd19aa192a75473051e5bdd0a439be69"
  app_name                  = "security-hub"
  environment               = "dev"
  task_name                 = "scheduled-collector"
  repo_arn                  = "arn:aws:ecr:us-east-1:037370603820:repository/security-hub-collector"
  repo_url                  = "037370603820.dkr.ecr.us-east-1.amazonaws.com/security-hub-collector"
  repo_tag                  = var.repo_tag
  ecs_vpc_id                = var.ecs_vpc_id
  ecs_subnet_ids            = var.ecs_subnet_ids
  schedule_task_expression  = var.schedule_task_expression
  logs_cloudwatch_group_arn = aws_cloudwatch_log_group.aws-scanner-inspec.arn
  ecs_cluster_arn           = aws_ecs_cluster.security_hub_collector_runner.arn
  s3_results_bucket         = var.security_hub_collector_results_bucket_name
  assign_public_ip          = var.assign_public_ip
  role_path                 = "/delegatedadmin/developer/"
  permissions_boundary      = "arn:aws:iam::037370603820:policy/cms-cloud-admin/developer-boundary-policy"
  scheduled_task_state      = "ENABLED" #Set to DISABLED to stop scheduled execution

  team_config = {
    teams_api : {
      base_url : "https://vshjmodi2c.execute-api.us-east-1.amazonaws.com/teams-api-prod",
      api_key_param : aws_ssm_parameter.teams_api_key.name,
      collector_role_path : "delegatedadmin/developer/ct-cmcs-mac-fc-cost-usage-role"
    }
  }
}

resource "aws_ssm_parameter" "teams_api_key" {
  name  = "security-hub-dev-teams-api-key" # must match `{app_name}-{environment}*` per task execution role policy
  type  = "SecureString"
  value = "replace with real value"

  lifecycle {
    ignore_changes = [value]
  }
}

resource "aws_security_group_rule" "allow_security_hub_collector_to_execute_api" {
  description              = "HTTPS from Security Hub Collector"
  type                     = "ingress"
  from_port                = 443
  to_port                  = 443
  protocol                 = "tcp"
  security_group_id        = var.execute_api_vpc_endpoint_security_group_id
  source_security_group_id = module.security_hub_collector_runner.task_security_group_id
}
