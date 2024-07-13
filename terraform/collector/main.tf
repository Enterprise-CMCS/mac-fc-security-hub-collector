########## Building in us-east-1 ##########
provider "aws" {
  region = "us-east-1"
}

#terraform {
#  backend "s3" {
#    region  = "us-east-1"
#  }
#}

########## Create s3 bucket for storing the collected findings ##########
resource "aws_s3_bucket" "security_hub_collector" {
  bucket = var.security_hub_collector_results_bucket_name
  #acl    = "private"

  #lifecycle_rule {
  #  enabled = true

   # expiration {
   #   days = 10
   # }
  #}

  tags = {
    Automation  = "Terraform"
    Environment = "dev"
  }
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
        Action    = "s3:*"
        Condition = {
            Bool = {
              "aws:SecureTransport" = "false",
            }
        }
        Effect    = "Deny"
        Principal = "*"
        Resource  = [
              aws_s3_bucket.security_hub_collector.arn,
            "${aws_s3_bucket.security_hub_collector.arn}/*",
        ]
        Sid       = "AllowSSLRequestsOnly"
      }
    ]
  })
}


##########Create cloudwatch log group and ecs cluster ##########
resource "aws_cloudwatch_log_group" "aws-scanner-inspec" {
  name = var.aws_cloudwatch_log_group_name
}

resource "aws_ecs_cluster" "security_hub_collector_runner" {
  name = "security_hub_collector"
    }

########## Use the securityhub collector runner module ##########
module "security_hub_collector_runner" {
  source      = "github.com/CMSgov/security-hub-collector-ecs-runner?ref=9b76aea273ce9c27c50257c10b23ae921ab99416"
  app_name    = "security-hub"
  environment = "dev"
  task_name      = "scheduled-collector"
  repo_arn       = "arn:aws:ecr:us-east-1:037370603820:repository/security-hub-collector"
  repo_url       = "037370603820.dkr.ecr.us-east-1.amazonaws.com/security-hub-collector"
  repo_tag       = "latest"
  ecs_vpc_id     = var.ecs_vpc_id
  ecs_subnet_ids = var.ecs_subnet_ids
  schedule_task_expression  = var.schedule_task_expression
  logs_cloudwatch_group_arn = aws_cloudwatch_log_group.aws-scanner-inspec.arn
  ecs_cluster_arn           = aws_ecs_cluster.security_hub_collector_runner.arn
  output_path       = var.output_path  //optional
  s3_results_bucket = var.security_hub_collector_results_bucket_name
  s3_key            = var.s3_key //optional
  assume_role       = var.assume_role    // the role to assume if collecting security hub results across accounts
  assign_public_ip  = var.assign_public_ip
  role_path         = "/delegatedadmin/developer/"
  permissions_boundary = "arn:aws:iam::037370603820:policy/cms-cloud-admin/developer-boundary-policy"
  scheduled_task_enabled = false
  team_map = base64encode(jsonencode({
    teams = [
      {
        accounts = [
          { id = "116229642442", environment = "dev" }
        ],
        name = "My Team"
      }
    ]
  }))
}
