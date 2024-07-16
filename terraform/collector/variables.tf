variable "ecs_vpc_id" {
  description = "The ID of the VPC where the ECS tasks will run"
  type        = string
}

variable "ecs_subnet_ids" {
  description = "A list of subnet IDs where the ECS tasks will be placed"
  type        = list(string)
}

variable "security_hub_collector_results_bucket_name" {
  description = "The name of the S3 bucket where Security Hub collector results will be stored"
  type        = string
}

variable "schedule_task_expression" {
  description = "The schedule expression for when the ECS task should run (e.g., cron or rate expression)"
  type        = string
}

variable "output_path" {
  description = "The path where output files will be saved"
  type        = string
}

variable "s3_key" {
  description = "The S3 key (path) where files will be stored in the S3 bucket"
  type        = string
}

variable "aws_cloudwatch_log_group_name" {
  description = "The name of the CloudWatch log group where ECS task logs will be sent"
  type        = string
}

variable "assign_public_ip" {
  description = "Whether to assign a public IP address to the ECS task"
  type        = bool
}
