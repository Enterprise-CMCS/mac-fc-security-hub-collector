variable "ecr_read_aws_accounts" {
  type        = list(string)
  description = "AWS accounts that are allowed to read from the ECR repository"
}
