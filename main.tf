locals {
  # Using our standard lifecycle policy
  policy = var.lifecycle_policy == "" ? file("${path.module}/lifecycle-policy.json") : var.lifecycle_policy
  tags = {
    Automation = "Terraform"
  }
}

resource "aws_ecr_repository" "main" {
  name = var.container_name
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
      identifiers = concat([var.ci_user_arn], var.allowed_read_principals)
      type        = "AWS"
    }
  }

  statement {
    sid = "githubCIPermissions"

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
      "ecr:BatchCheckLayerAvailability",
    ]

    principals {
      identifiers = [var.ci_user_arn]
      type        = "AWS"
    }
  }
}