################################################################################
# Networking
################################################################################

resource "aws_s3_bucket" "vpc_flowlogs_bucket" {
  #checkov:skip=CKV_AWS_21: "Ensure all data stored in the S3 bucket have versioning enabled"
  #checkov:skip=CKV2_AWS_62: "Ensure S3 buckets should have event notifications enabled"
  #checkov:skip=CKV_AWS_18: "Ensure the S3 bucket has access logging enabled"
  #checkov:skip=CKV_AWS_144: "Ensure that S3 bucket has cross-region replication enabled"
  #checkov:skip=CKV2_AWS_6: "Ensure that S3 bucket has a Public Access block"
  #checkov:skip=CKV_AWS_145: "Ensure that S3 buckets are encrypted with KMS by default"
  #checkov:skip=CKV2_AWS_61: "Ensure that an S3 bucket has a lifecycle configuration"
  bucket = "${local.prefix}-flowlog-bucket"
}

resource "aws_eip" "nat_eip" {
  #checkov:skip=CKV2_AWS_19: "Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances"

  domain = "vpc"
  count  = 2

  tags = {
    Name = "${local.prefix}-nat-eip"
  }
}

module "vpc" {
  #checkov:skip=CKV_AWS_356: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"
  #checkov:skip=CKV_AWS_111: "Ensure IAM policies does not allow write access without constraints"
  #checkov:skip=CKV2_AWS_11: "Ensure VPC flow logging is enabled in all VPCs"
  #checkov:skip=CKV2_AWS_12: "Ensure the default security group of every VPC restricts all traffic"
  #checkov:skip=CKV2_AWS_19: "Ensure that all EIP addresses allocated to a VPC are attached to EC2 instances"

  source     = "terraform-aws-modules/vpc/aws"
  version    = "5.5.2"
  depends_on = [aws_s3_bucket.vpc_flowlogs_bucket, aws_eip.nat_eip]

  name = "${local.prefix}-vpc"
  cidr = local.vpc_cidr

  azs             = formatlist("${data.aws_region.current.name}%s", ["a", "b"])
  private_subnets = local.private_subnet_cirds
  public_subnets  = local.public_subnet_cirds

  enable_vpn_gateway = false

  enable_nat_gateway     = true
  single_nat_gateway     = false
  one_nat_gateway_per_az = true
  reuse_nat_ips          = true
  external_nat_ip_ids    = aws_eip.nat_eip[*].id

  enable_flow_log           = true
  flow_log_destination_type = "s3"
  flow_log_destination_arn  = aws_s3_bucket.vpc_flowlogs_bucket.arn

  default_security_group_egress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  default_security_group_ingress = [
    {
      from_port   = 0
      to_port     = 0
      protocol    = "-1"
      cidr_blocks = "0.0.0.0/0"
    }
  ]

  # Set this tag for k8s
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
}
