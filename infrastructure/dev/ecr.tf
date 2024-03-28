################################################################################
# ECR
################################################################################

resource "aws_ecr_repository" "repositories" {
  #checkov:skip=CKV_AWS_136: "Ensure that ECR repositories are encrypted using KMS"

  for_each             = toset(local.ecr_list_repos)
  name                 = each.value
  image_tag_mutability = local.ecr_image_tag_mutability

  encryption_configuration {
    encryption_type = "AES256"
  }

  image_scanning_configuration {
    scan_on_push = local.ecr_scan_images_on_push
  }

  tags = {
    Name = "${local.env}-ecr-${each.value}"
  }

  lifecycle {
    ignore_changes = [
      tags # ECR Repository only support Name tag, this is to prevent Terraform to show diff on every apply
    ]
  }
}

resource "aws_ecr_lifecycle_policy" "name" {
  for_each   = toset(local.ecr_list_repos)
  repository = aws_ecr_repository.repositories[each.value].name

  policy = jsonencode({
    rules = concat(local.ecr_untagged_image_rule, local.ecr_remove_old_image_rule)
  })
}

data "aws_iam_policy_document" "resource_readonly_access" {
  statement {
    sid    = "ReadonlyAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = local.ecr_principals_read_only_access
    }

    actions = [
      "ecr:BatchCheckLayerAvailability",
      "ecr:BatchGetImage",
      "ecr:DescribeImageScanFindings",
      "ecr:DescribeImages",
      "ecr:DescribeRepositories",
      "ecr:GetDownloadUrlForLayer",
      "ecr:GetLifecyclePolicy",
      "ecr:GetLifecyclePolicyPreview",
      "ecr:GetRepositoryPolicy",
      "ecr:ListImages",
      "ecr:ListTagsForResource",
    ]
  }
}

data "aws_iam_policy_document" "resource_full_access" {
  statement {
    sid    = "FullAccess"
    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = local.ecr_principals_full_access
    }

    actions = ["ecr:*"]
  }
}

data "aws_iam_policy_document" "resource" {
  source_policy_documents   = [data.aws_iam_policy_document.resource_readonly_access.json]
  override_policy_documents = [data.aws_iam_policy_document.resource_full_access.json]
}

resource "aws_ecr_repository_policy" "ecr_policies" {
  for_each   = toset(local.ecr_list_repos)
  repository = aws_ecr_repository.repositories[each.value].name
  policy     = join("", data.aws_iam_policy_document.resource[*].json)
}
