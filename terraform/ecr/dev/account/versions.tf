terraform {
  required_version = "= 1.5.2"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~>5.30.0"
    }
  }
  backend "s3" {
    bucket         = "security-hub-collector-dev-tfstate"
    key            = "account/state"
    region         = "us-east-1"
    dynamodb_table = "security-hub-collector-dev-lock-table"
    encrypt        = true
  }
}

provider "aws" {
  allowed_account_ids = ["037370603820"]

  default_tags {
    tags = {
      Maintainer  = "cms-macfc+archive@corbalt.com"
      Owner       = "cms-macfc+archive@corbalt.com"
      Environment = "dev"
      Application = "mac-fc-security-hub-collector"
      Business    = "MACBIS"
      Automated   = "Terraform"
      stack       = "dev"
    }
  }
}