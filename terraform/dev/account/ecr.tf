locals {
  principal_arns = [for item in var.ecr_read_aws_accounts : format("arn:aws:iam::%s:root", item)]
}

resource "aws_ecr_repository" "this" {
  name = "security-hub-collector"
  image_scanning_configuration {
    scan_on_push = true
  }
}

resource "aws_ecr_lifecycle_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy     = <<EOF
{
  "rules": [
    {
      "action": {
        "type": "expire"
      },
      "description": "Keep last 500 images",
      "rulePriority": 10,
      "selection": {
        "countNumber": 500,
        "countType": "imageCountMoreThan",
        "tagStatus": "any"
      }
    }
  ]
}
EOF
}

resource "aws_ecr_repository_policy" "this" {
  repository = aws_ecr_repository.this.name
  policy     = data.aws_iam_policy_document.cross_account_readonly.json
}

data "aws_iam_policy_document" "cross_account_readonly" {
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
      identifiers = local.principal_arns
      type        = "AWS"
    }
  }

  statement {
    sid = ""

    effect = "Allow"

    actions = ["ecr:GetAuthorizationToken"]

    principals {
      identifiers = local.principal_arns
      type        = "AWS"
    }
  }
}
