data "aws_caller_identity" "current" {}

# this resource is managed here: https://github.com/Enterprise-CMCS/mac-fc-github-actions-runner-aws/blob/4e431b665a8627deccc0de24d21b40e3b8db1b24/terraform/dev/account/github-oidc.tf
data "aws_iam_openid_connect_provider" "github_actions" {
  url = "https://token.actions.githubusercontent.com"
}

module "iam_github_oidc_role_security_hub_collector" {
  source = "terraform-aws-modules/iam/aws//modules/iam-github-oidc-role"

  name = "security-hub-collector-github-oidc"

  path                     = "/delegatedadmin/developer/"
  permissions_boundary_arn = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:policy/cms-cloud-admin/developer-boundary-policy"

  subjects = [
    "Enterprise-CMCS/mac-fc-security-hub-collector:*",
  ]

  policies = {
    security_hub_collector = aws_iam_policy.push_to_ecr.arn
  }
}

# GHA needs permission to push to ECR
# https://docs.aws.amazon.com/AmazonECR/latest/userguide/image-push.html
data "aws_iam_policy_document" "push_to_ecr" {
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

resource "aws_iam_policy" "push_to_ecr" {
  name        = "github-actions-permissions"
  policy      = data.aws_iam_policy_document.push_to_ecr.json
  path        = "/delegatedadmin/developer/"
  description = "Permissions to push to ECR"
}

