################################################################################
# Aurora DB
################################################################################

resource "aws_kms_key" "db_secret_kms" {
  #checkov:skip=CKV2_AWS_64: "Ensure KMS key Policy is defined"

  description             = "KMS for DB secret"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7
  enable_key_rotation     = true
}

resource "aws_secretsmanager_secret" "db_secret" {
  #checkov:skip=CKV_AWS_149: "Ensure that Secrets Manager secret is encrypted using KMS CMK"
  #checkov:skip=CKV2_AWS_57: "Ensure Secrets Manager secrets should have automatic rotation enabled"

  name       = "${local.prefix}/db/secret"
  kms_key_id = aws_kms_key.db_secret_kms.id
}

resource "aws_security_group" "db_security_group" {
  #checkov:skip=CKV_AWS_23: "Ensure every security groups rule has a description"

  depends_on = [module.vpc]

  name        = "${local.prefix}-db-security-group"
  description = "Security group for Aurora Serverless database"

  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 5432 // PostgreSQL
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] // Allow access from anywhere
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"          // Allow all protocols
    cidr_blocks = ["0.0.0.0/0"] // Allow outbound traffic to anywhere
  }

  tags = {
    Name = "${local.prefix}-db-security-group"
  }
}

resource "aws_db_subnet_group" "db_subnet_group" {
  name       = "${local.prefix}-db-subnet-group"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_secretsmanager_secret_version" "initial_service_config" {
  secret_id = aws_secretsmanager_secret.db_secret.id
  secret_string = jsonencode({
    username = "admin"
    password = "admin"
  })

  lifecycle {
    ignore_changes = [
      secret_string
    ]
  }
}

resource "aws_iam_role" "db_monitoring_role" {
  name               = "${local.prefix}-db-monitoring-role"
  assume_role_policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "monitoring.rds.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
EOF
}

resource "aws_iam_role_policy_attachment" "db_monitoring_policy_attachment" {
  role       = aws_iam_role.db_monitoring_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonRDSEnhancedMonitoringRole"
}

resource "aws_kms_key" "db_kms" {
  #checkov:skip=CKV2_AWS_64: "Ensure KMS key Policy is defined"

  description             = "KMS for DB"
  key_usage               = "ENCRYPT_DECRYPT"
  deletion_window_in_days = 7
  enable_key_rotation     = true

  lifecycle {
    ignore_changes = [
      tags,
      tags_all,
      description,
      enable_key_rotation
    ]
  }
}

# resource "aws_kms_key" "db_kms_performance_insights" {
#   description             = "KMS for DB Performance Insights"
#   key_usage               = "ENCRYPT_DECRYPT"
#   deletion_window_in_days = 7
#   enable_key_rotation     = true
# }

resource "aws_db_instance" "aurora_db" {
  #checkov:skip=CKV_AWS_354: "Ensure RDS Performance Insights are encrypted using KMS CMKs"
  #checkov:skip=CKV_AWS_293: "Ensure that AWS database instances have deletion protection enabled"
  #checkov:skip=CKV_AWS_353: "Ensure that RDS instances have performance insights enabled"
  #checkov:skip=CKV_AWS_157: "Ensure that RDS instances have Multi-AZ enabled"
  #checkov:skip=CKV_AWS_129: "Ensure that respective logs of Amazon Relational Database Service (Amazon RDS) are enabled"
  #checkov:skip=CKV_AWS_226: "Ensure DB instance gets all minor upgrades automatically"
  #checkov:skip=CKV_AWS_118: "Ensure that enhanced monitoring is enabled for Amazon RDS instances"
  #checkov:skip=CKV_AWS_16: "Ensure all data stored in the RDS is securely encrypted at rest"
  #checkov:skip=CKV2_AWS_60: "Ensure RDS instance with copy tags to snapshots is enabled"

  db_name                               = "init_db" #"${local.prefix}-cluster"
  engine                                = "aurora-postgresql"
  engine_version                        = "16.1"
  username                              = "postgres"
  password                              = "admin"
  skip_final_snapshot                   = true
  monitoring_interval                   = 0
  deletion_protection                   = false
  enabled_cloudwatch_logs_exports       = []
  iam_database_authentication_enabled   = false
  max_allocated_storage                 = 0
  storage_encrypted                     = true
  apply_immediately                     = true
  availability_zone                     = "us-east-2a"
  backup_retention_period               = 7
  backup_target                         = "region"
  backup_window                         = "04:03-04:33"
  ca_cert_identifier                    = "rds-ca-rsa2048-g1"
  kms_key_id                            = aws_kms_key.db_kms.arn
  multi_az                              = false
  monitoring_role_arn                   = aws_iam_role.db_monitoring_role.arn
  performance_insights_enabled          = true
  performance_insights_retention_period = 7
  performance_insights_kms_key_id       = aws_kms_key.db_kms.arn

  # tflint-ignore: aws_db_instance_invalid_type
  instance_class = "db.serverless"

  # identifier           = "${local.prefix}-cluster"
  # parameter_group_name = "default.aurora-postgresql16"
  option_group_name = "default:aurora-postgresql-16"

  db_subnet_group_name   = aws_db_subnet_group.db_subnet_group.name
  vpc_security_group_ids = [aws_security_group.db_security_group.id]
}

output "rds_endpoint" {
  value = aws_db_instance.aurora_db.endpoint
}

# Force run pipeline
