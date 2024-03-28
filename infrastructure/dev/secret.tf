resource "aws_kms_key" "secret_key" {
  #checkov:skip=CKV2_AWS_64: "Ensure KMS key Policy is defined"
  description         = "${local.prefix}-secret_key"
  enable_key_rotation = true
}

resource "aws_secretsmanager_secret" "dev_secret" {
  #checkov:skip=CKV2_AWS_57: "Ensure Secrets Manager secrets should have automatic rotation enabled"
  name       = "${local.prefix}/dev/application"
  kms_key_id = aws_kms_key.secret_key.id
}
