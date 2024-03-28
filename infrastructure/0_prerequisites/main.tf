resource "aws_s3_bucket" "terraform_state" {
  bucket = "test-terraform-state-240328"
}

resource "aws_dynamodb_table" "terraform_state_lock" {
  name         = "test-terraform-state-lock-240328"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "LockID"
  attribute {
    name = "LockID"
    type = "S"
  }
}
