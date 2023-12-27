data "aws_caller_identity" "current" {}

data "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}

module "iam_github_oidc_role_github_actions_runner" {
  source = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"

  name = "security-hub-collector-github-oidc"

  path                     = "/delegatedadmin/developer/"
  permissions_boundary_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/cms-cloud-admin/developer-boundary-policy"

  subjects = [
    "Enterprise-CMCS/mac-fc-security-hub-collector:*",
  ]

  policies = {
    github_actions_runner = aws_iam_policy.github_actions_permissions.arn
  }
}

# GHA needs permission to push to ECR
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push.html
data "aws_iam_policy_document" "github_actions_permissions" {
  statement {
    actions = [
      "ecr:GetAuthorizationToken"
    ]
    resources = ["*"]
  }

  statement {
    actions = [
      "ecr:CompleteLayerUpload",
      "ecr:UploadLayerPart",
      "ecr:InitiateLayerUpload",
      "ecr:BatchCheckLayerAvailability",
      "ecr:PutImage",
    ]
    resources = ["arn:aws:ecr:us-east-1:${data.aws_caller_identity.current.account_id}:repository/security-hub-collector"]
  }
}

resource "aws_iam_policy" "github_actions_permissions" {
  name        = "github-actions-permissions"
  policy      = data.aws_iam_policy_document.github_actions_permissions.json
  path        = "/delegatedadmin/developer/"
  description = "Permissions for GitHub Actions OIDC"
}

