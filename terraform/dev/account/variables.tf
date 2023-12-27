variable "ecr_read_aws_accounts" {
  type        = list(any)
  description = "AWS accounts that are allowed to read from the ECR repository"
}
