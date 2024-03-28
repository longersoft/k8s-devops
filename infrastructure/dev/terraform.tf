terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0.0"
    }

    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.26.0"
    }

    tls = {
      source  = "hashicorp/tls"
      version = "~> 4.0"
    }
  }

  required_version = ">= 1.4.0"

  backend "s3" {
    bucket         = "test-terraform-state-240328"
    key            = "dev/terraform.tfstate"
    region         = "us-east-2"
    dynamodb_table = "test-terraform-state-lock-240328"
    encrypt        = true
  }
}

provider "aws" {
  region = "us-east-2"

  # assume_role {
  #   role_arn = "arn:aws:iam::905418377632:role/terraform-execution-role"
  # }

  default_tags {
    tags = {
      Environment = "dev"
      Application = "test"
      ManageBy    = "devops/infrastructure"
    }
  }
}
