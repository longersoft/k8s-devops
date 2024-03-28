config {
  format = "compact"
  plugin_dir = "~/.tflint.d/plugins"

  module = false
  force = false
  disabled_by_default = false

  ignore_module = {
    "terraform-aws-modules/vpc/aws"            = true
    "terraform-aws-modules/security-group/aws" = true
  }

  varfile = []
  variables = []
}

plugin "aws" {
  enabled = true
  version = "0.27.0"
  source  = "github.com/terraform-linters/tflint-ruleset-aws"
}

rule "aws_instance_invalid_type" {
  enabled = false
}

plugin "terraform" {
  enabled = true
  preset  = "recommended"
}
