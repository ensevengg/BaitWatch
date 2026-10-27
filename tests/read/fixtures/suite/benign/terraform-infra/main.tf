terraform {
  required_version = ">= 1.7"
  required_providers {
    aws = { source = "hashicorp/aws", version = "~> 5.40" }
  }
}

resource "aws_s3_bucket" "artifacts" {
  bucket = "acme-artifacts-${var.env}"
}

resource "aws_iam_role" "ci" {
  name               = "ci-role-${var.env}"
  assume_role_policy = "data document"
}
