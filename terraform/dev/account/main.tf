locals {
  # Using our standard lifecycle policy
  policy = var.lifecycle_policy == "" ? file("${path.module}/lifecycle-policy.json") : var.lifecycle_policy
  tags = {
    Automation = "Terraform"
  }
}

data "aws_caller_identity" "current" {}

resource "aws_ecr_repository" "main" {
  name = "security-hub-collector"
  tags = merge(local.tags, var.tags)
  image_scanning_configuration {
    scan_on_push = var.scan_on_push
  }
}

resource "aws_ecr_lifecycle_policy" "main" {
  repository = aws_ecr_repository.main.name
  policy     = local.policy
}

resource "aws_ecr_repository_policy" "main" {
  repository = aws_ecr_repository.main.name
  policy     = data.aws_iam_policy_document.ecr_perms_ro_cross_account.json
}

data "aws_iam_policy_document" "ecr_perms_ro_cross_account" {

  statement {
    sid = "CrossAccountReadOnly"

    effect = "Allow"

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:GetAuthorizationToken",
      "ecr:GetDownloadUrlForLayer",
      "ecr:ListImages",
      "ecr:DescribeImages",
      "ecr:BatchGetImage",
    ]

    principals {
      identifiers = var.allowed_read_principals
      type        = "AWS"
    }
  }

  statement {
    sid = ""

    effect = "Allow"

    actions = ["ecr:GetAuthorizationToken"]

    principals {
      identifiers = var.allowed_read_principals
      type        = "AWS"
    }
  }
}

resource "aws_iam_user" "security_hub_collector_service_user" {
  name          = "security-hub-collector-service-user"
  force_destroy = true
}

resource "aws_iam_user_policy" "security_hub_collector_ecr_access" {
  name   = "security-hub-collector-ecr-access"
  user   = aws_iam_user.security_hub_collector_service_user.name
  policy = data.aws_iam_policy_document.security_hub_collector_ecr_access.json
}

data "aws_iam_policy_document" "security_hub_collector_ecr_access" {
  statement {
    sid = ""

    effect = "Allow"

    actions = ["ecr:GetAuthorizationToken"]

    resources = ["*"]
  }
  statement {
    sid = "ECRAccess"

    effect = "Allow"

    actions = [
      "ecr:UploadLayerPart",
      "ecr:PutImage",
      "ecr:ListImages",
      "ecr:InitiateLayerUpload",
      "ecr:GetRepositoryPolicy",
      "ecr:GetDownloadUrlForLayer",
      "ecr:DescribeRepositories",
      "ecr:DescribeImages",
      "ecr:CompleteLayerUpload",
      "ecr:BatchGetImage",
      "ecr:BatchCheckLayerAvailability"
    ]

    resources = [aws_ecr_repository.main.arn]
  }
}
