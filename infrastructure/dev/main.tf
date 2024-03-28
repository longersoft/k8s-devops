data "aws_region" "current" {}

locals {
  env        = basename(abspath(path.module))
  account_id = "012345678910"

  region_codes = {
    "us-east-1" : "ue1",
    "us-east-2" : "ue2",
  }
  region_code = lookup(local.region_codes, data.aws_region.current.name, "unknown")

  app_name = "test"
  prefix   = "${local.env}-${local.region_code}-${local.app_name}"

  vpc_cidr             = "172.16.0.0/16"
  private_subnet_cirds = ["172.16.1.0/24", "172.16.2.0/24"]
  public_subnet_cirds  = ["172.16.101.0/24", "172.16.102.0/24"]

  eks_cluster_name                     = "${local.prefix}-eks-cluster-v2"
  eks_cluster_version                  = "1.29"
  eks_nw_conf_service_ipv4_cidr        = "10.100.0.0/16"
  eks_addon_coredns_name               = "${local.prefix}-eks-addon-coredns"
  eks_addon_coredns_version            = "v1.11.1-eksbuild.6"
  eks_addon_vpc_cni_name               = "${local.prefix}-eks-addon-vpc-cni"
  eks_addon_vpc_cni_version            = "v1.16.4-eksbuild.2"
  eks_addon_kube_proxy_name            = "${local.prefix}-eks-addon-kube-proxy"
  eks_addon_kube_proxy_version         = "v1.29.1-eksbuild.2"
  eks_addon_pod_identify_agent_name    = "${local.prefix}-eks-addon-pod-identity-agent"
  eks_addon_pod_identify_agent_version = "v1.2.0-eksbuild.1"
  eks_addon_ebs_csi_driver_name        = "${local.prefix}-eks-addon-ebs-csi-driver"
  eks_addon_ebs_csi_driver_version     = "v1.28.0-eksbuild.1"
  eks_serviceaccount_alb               = "system:serviceaccount:kube-system:aws-load-balancer-controller"
  eks_serviceaccount_configserver_dev  = "system:serviceaccount:dev:dev-application-configserver"
  eks_serviceaccount_configserver_qa   = "system:serviceaccount:qa:qa-application-configserver"

  ecr_list_repos = [
    "frontend",
    "backend",
  ]
  ecr_read_only_accounts = {
    "test-dev" = "012345678910"
  }
  ecr_full_access_accounts = {
    "admin-dev" = "012345678910"
  }
  ecr_principals_full_access      = [for key, value in local.ecr_full_access_accounts : "arn:aws:iam::${value}:root"]
  ecr_principals_read_only_access = [for key, value in local.ecr_read_only_accounts : "arn:aws:iam::${value}:root"]
  ecr_scan_images_on_push         = true
  ecr_image_tag_mutability        = "IMMUTABLE"
  ecr_untagged_image_rule = [
    {
      rulePriority = 1
      description  = "Remove untagged images"
      selection = {
        tagStatus   = "untagged"
        countType   = "imageCountMoreThan"
        countNumber = 5
      }
      action = {
        type = "expire"
      }
    }
  ]
  ecr_remove_old_image_rule = [
    {
      rulePriority = 2
      description  = "Expire images older than 1 year",
      selection = {
        tagStatus   = "any"
        countType   = "sinceImagePushed"
        countUnit   = "days"
        countNumber = 365
      }
      action = {
        type = "expire"
      }
    }
  ]
}
