ecs_vpc_id                                 = "vpc-07f4de56f6970729d"
ecs_subnet_ids                             = ["subnet-06bbdc0b680091dd1", "subnet-02d08271e8ac413b0"]
security_hub_collector_results_bucket_name = "securityhub-collector-results-037370603820s"
schedule_task_expression                   = "cron(35 * ? * * *)"
aws_cloudwatch_log_group_name              = "security_hub_collector"
assign_public_ip                           = true
repo_tag                                   = "b6f8272"
