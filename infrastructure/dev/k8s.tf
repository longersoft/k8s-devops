################################################################################
# K8s Cluster
################################################################################

resource "aws_eks_cluster" "eks_cluster" {
  #checkov:skip=CKV_AWS_58: "Ensure EKS Cluster has Secrets Encryption Enabled"
  #checkov:skip=CKV_AWS_339: "Ensure EKS clusters run on a supported Kubernetes version"
  #checkov:skip=CKV_AWS_39: "Ensure Amazon EKS public endpoint disabled"
  #checkov:skip=CKV_AWS_38: "Ensure Amazon EKS public endpoint not accessible to 0.0.0.0/0"

  depends_on = [module.vpc, aws_iam_role.eks_cluster_role, aws_security_group.eks_cluster_sg]

  name     = local.eks_cluster_name
  version  = local.eks_cluster_version
  role_arn = aws_iam_role.eks_cluster_role.arn

  vpc_config {
    subnet_ids         = module.vpc.private_subnets
    security_group_ids = [aws_security_group.eks_cluster_sg.id]

    endpoint_private_access = true
    endpoint_public_access  = true
  }

  enabled_cluster_log_types = [
    "api",
    "audit",
    "authenticator",
    "controllerManager",
    "scheduler"
  ]

  access_config {
    authentication_mode                         = "API_AND_CONFIG_MAP"
    bootstrap_cluster_creator_admin_permissions = false
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = local.eks_nw_conf_service_ipv4_cidr
  }

  tags = {
    Name = local.eks_cluster_name
  }
}

# Define IAM policy for CoreDNS
resource "aws_iam_policy" "coredns_policy" {
  name        = "${local.prefix}-eks-addon-coredns-policy"
  description = "IAM policy for CoreDNS"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ],
        Resource = "*",
      }
    ],
  })
}

# Create IAM role for CoreDNS service account
resource "aws_iam_role" "coredns_role" {
  name = "${local.prefix}-eks-addon-coredns-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "sts:ExternalId" : "eks.amazonaws.com"
        }
      }
    }]
  })
}

# Attach IAM policy to the role
resource "aws_iam_policy_attachment" "coredns_policy_attachment" {
  name       = "${local.prefix}-eks-addon-coredns-policy-attachment"
  policy_arn = aws_iam_policy.coredns_policy.arn
  roles      = [aws_iam_role.coredns_role.name]
}

resource "aws_eks_addon" "eks_addon_coredns" {
  cluster_name                = aws_eks_cluster.eks_cluster.name
  addon_name                  = local.eks_addon_coredns_name
  addon_version               = local.eks_addon_coredns_version
  resolve_conflicts_on_update = "PRESERVE"
}

# Define IAM policy for VPC CNI
resource "aws_iam_policy" "vpc_cni_policy" {
  #checkov:skip=CKV_AWS_290: "Ensure IAM policies does not allow write access without constraints"
  #checkov:skip=CKV_AWS_355: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"

  name        = "${local.prefix}-eks-addon-vpc-cni-policy"
  description = "IAM policy for VPC CNI add-on"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:Describe*",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:AssignPrivateIpAddresses"
        ],
        Resource = "*",
      }
    ],
  })
}

# Create IAM role for VPC CNI service account
resource "aws_iam_role" "vpc_cni_role" {
  name = "${local.prefix}-eks-addon-vpc-cni-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "sts:ExternalId" : "eks.amazonaws.com"
        }
      }
    }]
  })
}

# Attach IAM policy to the role
resource "aws_iam_policy_attachment" "vpc_cni_policy_attachment" {
  name       = "${local.prefix}-eks-addon-vpc-cni-policy-attachment"
  policy_arn = aws_iam_policy.vpc_cni_policy.arn
  roles      = [aws_iam_role.vpc_cni_role.name]
}

resource "aws_eks_addon" "eks_addon_vpc_cni" {
  cluster_name                = aws_eks_cluster.eks_cluster.name
  addon_name                  = local.eks_addon_vpc_cni_name
  addon_version               = local.eks_addon_vpc_cni_version
  resolve_conflicts_on_update = "OVERWRITE"
}

# Define IAM policy for kube-proxy
resource "aws_iam_policy" "kube_proxy_policy" {
  name        = "${local.prefix}-eks-addon-kube-proxy-policy"
  description = "IAM policy for kube-proxy"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "ec2:DescribeInstances",
          "ec2:DescribeTags"
        ],
        Resource = "*",
      }
    ],
  })
}

# Create IAM role for kube-proxy service account
resource "aws_iam_role" "kube_proxy_role" {
  name = "${local.prefix}-eks-addon-kube-proxy-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      },
      Action = "sts:AssumeRoleWithWebIdentity",
      Condition = {
        StringEquals = {
          "sts:ExternalId" : "eks.amazonaws.com"
        }
      }
    }]
  })
}

# Attach IAM policy to the role
resource "aws_iam_policy_attachment" "kube_proxy_policy_attachment" {
  name       = "${local.prefix}-eks-addon-kube-proxy-policy-attachment"
  policy_arn = aws_iam_policy.kube_proxy_policy.arn
  roles      = [aws_iam_role.kube_proxy_role.name]
}

resource "aws_eks_addon" "eks_addon_kube_proxy" {
  cluster_name                = aws_eks_cluster.eks_cluster.name
  addon_name                  = local.eks_addon_kube_proxy_name
  addon_version               = local.eks_addon_kube_proxy_version
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "eks_addon_pod_identify_agent" {
  cluster_name                = aws_eks_cluster.eks_cluster.name
  addon_name                  = local.eks_addon_pod_identify_agent_name
  addon_version               = local.eks_addon_pod_identify_agent_version
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_eks_addon" "eks_addon_ebs_csi_driver" {
  cluster_name                = aws_eks_cluster.eks_cluster.name
  addon_name                  = local.eks_addon_ebs_csi_driver_name
  addon_version               = local.eks_addon_ebs_csi_driver_version
  resolve_conflicts_on_update = "OVERWRITE"
}

resource "aws_security_group" "eks_cluster_sg" {
  #checkov:skip=CKV_AWS_260: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 80"
  #checkov:skip=CKV_AWS_24: "Ensure no security groups allow ingress from 0.0.0.0:0 to port 22"

  name        = "${local.prefix}-eks-cluster-sg"
  description = "EKS Cluster Connection"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP"
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS"
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
    description = "Allows all outbound traffic from any port to any destination IP address using any protocol."
  }

  tags = {
    Name = "${local.prefix}-eks-cluster-sg"
  }
}

# Define IAM roles for the EKS cluster and node group
resource "aws_iam_role" "eks_cluster_role" {
  name = "${local.prefix}-eks-cluster-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "eks.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

data "aws_ami" "eks_node_ami" {
  most_recent = true

  filter {
    name   = "name"
    values = ["amazon-eks-node-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  filter {
    name   = "architecture"
    values = ["x86_64"]
  }

  owners = ["602401143452"] # Canonical
}

resource "aws_launch_template" "eks_node_launch_template" {
  name_prefix   = "${local.prefix}-eks-node-launch-template"
  image_id      = data.aws_ami.eks_node_ami.id
  instance_type = "c6a.2xlarge"

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  # lifecycle {
  #   ignore_changes = [
  #     image_id,
  #     latest_version
  #   ]
  # }
}

# This resource can be removed, it should be attached to aws_eks_node_group
resource "aws_autoscaling_group" "eks_autoscaling_group" {
  #checkov:skip=CKV_AWS_315: "Ensure EC2 Auto Scaling groups use EC2 launch templates"

  name     = "${local.prefix}-eks-autoscaling-group"
  max_size = 2
  min_size = 1

  # launch_template {
  #   id      = aws_launch_template.eks_node_launch_template.id
  #   version = aws_launch_template.eks_node_launch_template.latest_version
  # }

  mixed_instances_policy {
    launch_template {
      launch_template_specification {
        launch_template_id = aws_launch_template.eks_node_launch_template.id
        version            = aws_launch_template.eks_node_launch_template.latest_version
      }
      override {
        instance_type     = "c6a.2xlarge"
        weighted_capacity = "3"
      }
      override {
        instance_type     = "t3.micro"
        weighted_capacity = "2"
      }
    }
    instances_distribution {
      on_demand_allocation_strategy            = "prioritized"
      on_demand_base_capacity                  = 0
      on_demand_percentage_above_base_capacity = 100
      spot_allocation_strategy                 = "lowest-price"
      spot_instance_pools                      = 2
    }
  }

  max_instance_lifetime   = 0
  capacity_rebalance      = true
  default_instance_warmup = 0
  enabled_metrics         = []
  suspended_processes     = []
  termination_policies = [
    "AllocationStrategy",
    "OldestLaunchTemplate",
    "OldestInstance",
  ]
  vpc_zone_identifier = module.vpc.private_subnets

  tag {
    key                 = "eks:clustername"
    propagate_at_launch = true
    value               = aws_eks_cluster.eks_cluster.name
  }
  tag {
    key                 = "eks:cluster-name"
    propagate_at_launch = true
    value               = aws_eks_cluster.eks_cluster.name
  }
  tag {
    key                 = "eks:nodegroup-name"
    propagate_at_launch = true
    value               = "${local.prefix}-eks-nodegroup"
  }
  tag {
    key                 = "k8s.io/cluster-autoscaler/${aws_eks_cluster.eks_cluster.name}"
    propagate_at_launch = true
    value               = "owned"
  }
  tag {
    key                 = "k8s.io/cluster-autoscaler/enabled"
    propagate_at_launch = true
    value               = "true"
  }
  tag {
    key                 = "kubernetes.io/cluster/${aws_eks_cluster.eks_cluster.name}"
    propagate_at_launch = true
    value               = "owned"
  }
  tag {
    key                 = "Environment"
    propagate_at_launch = true
    value               = local.env
  }
  tag {
    key                 = "Environment"
    propagate_at_launch = true
    value               = local.env
  }
  tag {
    key                 = "Application"
    propagate_at_launch = true
    value               = "test"
  }
}

# Create a node group for the EKS cluster
resource "aws_eks_node_group" "eks_node_group" {
  cluster_name  = aws_eks_cluster.eks_cluster.name
  node_role_arn = aws_iam_role.eks_node_group_role.arn
  subnet_ids    = module.vpc.private_subnets

  scaling_config {
    min_size     = 1
    max_size     = 2
    desired_size = 1
  }

  node_group_name = "${local.prefix}-eks-nodegroup"

  # https://docs.aws.amazon.com/eks/latest/userguide/launch-templates.html#launch-template-custom-ami
  ami_type       = "AL2_x86_64"
  capacity_type  = "ON_DEMAND"
  disk_size      = 100
  instance_types = ["c6a.2xlarge"]
  labels = {
    "Name" = "${local.prefix}-eks-nodegroup"
  }

  update_config {
    max_unavailable = 1
  }

  tags = {
    Name = "${local.prefix}-eks-nodegroup"
  }
}

# Attach necessary policies to IAM roles
resource "aws_iam_role_policy_attachment" "eks_cluster_policy_attachment" {
  role       = aws_iam_role.eks_cluster_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
}

resource "aws_iam_role" "eks_node_group_role" {
  name = "${local.prefix}-eks-node-group-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [{
      Effect = "Allow",
      Principal = {
        Service = "ec2.amazonaws.com"
      },
      Action = "sts:AssumeRole"
    }]
  })
}

resource "aws_iam_role_policy_attachment" "eks_node_group_policy_attachment" {
  role       = aws_iam_role.eks_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy"
}

resource "aws_iam_role_policy_attachment" "eks_node_group_cni_policy_attachment" {
  role       = aws_iam_role.eks_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy"
}

resource "aws_iam_role_policy_attachment" "eks_node_group_ecr_policy_attachment" {
  role       = aws_iam_role.eks_node_group_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly"
}

data "tls_certificate" "eks_tls_certificate" {
  url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "eks_oidc" {
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.eks_tls_certificate.certificates[0].sha1_fingerprint]
  url             = data.tls_certificate.eks_tls_certificate.url
}

resource "aws_iam_policy" "eks_alb_controller_iam_policy" {
  #checkov:skip=CKV_AWS_290: "Ensure IAM policies does not allow write access without constraints"
  #checkov:skip=CKV_AWS_355: "Ensure no IAM policies documents allow "*" as a statement's resource for restrictable actions"

  name        = "${local.prefix}-eks-alb-controller-iam-policy"
  description = "IAM policy for AWS Load Balancer Controller"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = ["iam:CreateServiceLinkedRole"]
        Resource = "*"
        Condition = {
          StringEquals = {
            "iam:AWSServiceName" = "elasticloadbalancing.amazonaws.com"
          }
        }
      },
      {
        Effect = "Allow"
        Action = [
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAddresses",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeInternetGateways",
          "ec2:DescribeVpcs",
          "ec2:DescribeVpcPeeringConnections",
          "ec2:DescribeSubnets",
          "ec2:DescribeSecurityGroups",
          "ec2:DescribeInstances",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribeTags",
          "ec2:GetCoipPoolUsage",
          "ec2:DescribeCoipPools",
          "elasticloadbalancing:DescribeLoadBalancers",
          "elasticloadbalancing:DescribeLoadBalancerAttributes",
          "elasticloadbalancing:DescribeListeners",
          "elasticloadbalancing:DescribeListenerCertificates",
          "elasticloadbalancing:DescribeSSLPolicies",
          "elasticloadbalancing:DescribeRules",
          "elasticloadbalancing:DescribeTargetGroups",
          "elasticloadbalancing:DescribeTargetGroupAttributes",
          "elasticloadbalancing:DescribeTargetHealth",
          "elasticloadbalancing:DescribeTags",
          "cognito-idp:DescribeUserPoolClient",
          "acm:ListCertificates",
          "acm:DescribeCertificate",
          "iam:ListServerCertificates",
          "iam:GetServerCertificate",
          "waf-regional:GetWebACL",
          "waf-regional:GetWebACLForResource",
          "waf-regional:AssociateWebACL",
          "waf-regional:DisassociateWebACL",
          "wafv2:GetWebACL",
          "wafv2:GetWebACLForResource",
          "wafv2:AssociateWebACL",
          "wafv2:DisassociateWebACL",
          "shield:GetSubscriptionState",
          "shield:DescribeProtection",
          "shield:CreateProtection",
          "shield:DeleteProtection",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DeleteSecurityGroup",
          "elasticloadbalancing:CreateLoadBalancer",
          "elasticloadbalancing:CreateTargetGroup",
          "elasticloadbalancing:CreateListener",
          "elasticloadbalancing:DeleteListener",
          "elasticloadbalancing:CreateRule",
          "elasticloadbalancing:DeleteRule",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:RemoveTags",
          "elasticloadbalancing:AddTags",
          "elasticloadbalancing:ModifyLoadBalancerAttributes",
          "elasticloadbalancing:SetIpAddressType",
          "elasticloadbalancing:SetSecurityGroups",
          "elasticloadbalancing:SetSubnets",
          "elasticloadbalancing:DeleteLoadBalancer",
          "elasticloadbalancing:ModifyTargetGroup",
          "elasticloadbalancing:ModifyTargetGroupAttributes",
          "elasticloadbalancing:DeleteTargetGroup",
          "elasticloadbalancing:RegisterTargets",
          "elasticloadbalancing:DeregisterTargets",
          "elasticloadbalancing:SetWebAcl",
          "elasticloadbalancing:ModifyListener",
          "elasticloadbalancing:AddListenerCertificates",
          "elasticloadbalancing:RemoveListenerCertificates",
          "elasticloadbalancing:ModifyRule"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role" "eks_lb_controller_role" {
  name = "${local.prefix}-eks-alb-controller-iam-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${local.account_id}:oidc-provider/${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:sub" = local.eks_serviceaccount_alb
          }
        }
      },
    ]
  })
}

resource "aws_iam_policy_attachment" "lb_controller_policy_attachment" {
  name       = "${local.prefix}-eks-alb-controller-iam-policy-attachment"
  policy_arn = aws_iam_policy.eks_alb_controller_iam_policy.arn
  roles      = [aws_iam_role.eks_lb_controller_role.name]
}

resource "aws_iam_policy" "eks_configserver_policy" {
  name        = "${local.prefix}-eks-configserver-policy"
  description = "IAM policy for Config Server"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret",
          "kms:Decrypt"
        ],
        Resource = [
          aws_secretsmanager_secret.dev_secret.arn,
          aws_kms_key.secret_key.arn
        ]
      }
    ]
  })
}

resource "aws_iam_role" "eks_configserver_role" {
  name = "${local.prefix}-eks-configserver-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${local.account_id}:oidc-provider/${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:sub" = local.eks_serviceaccount_configserver_dev
          }
        }
      },
      {
        Effect = "Allow"
        Principal = {
          Federated = "arn:aws:iam::${local.account_id}:oidc-provider/${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:aud" = "sts.amazonaws.com"
            "${replace(aws_iam_openid_connect_provider.eks_oidc.url, "https://", "")}:sub" = local.eks_serviceaccount_configserver_test
          }
        }
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "configserver_policy_attachment" {
  name       = "${local.prefix}-eks-configserver-iam-policy-attachment"
  policy_arn = aws_iam_policy.eks_configserver_policy.arn
  roles      = [aws_iam_role.eks_configserver_role.name]
}

# data "tls_certificate" "eks_tls_certificate" {
#   url = aws_eks_cluster.eks_cluster.identity[0].oidc[0].issuer
# }

# resource "aws_iam_openid_connect_provider" "eks_oidc" {
#   client_id_list  = ["sts.amazonaws.com"]
#   thumbprint_list = [data.tls_certificate.eks_tls_certificate.certificates[0].sha1_fingerprint]
#   url             = data.tls_certificate.eks_tls_certificate.url
# }

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.eks_oidc.arn
}


# resource "aws_cognito_identity_provider" "eks_oidc_provider" {
#   provider_name = "YourOIDCProviderName"
#   provider_type = "OIDC"
#   provider_details {
#     client_id                 = "YourClientID"
#     client_secret             = "YourClientSecret"
#     authorize_scopes          = ["openid", "email", "profile"] # Define required scopes
#     attributes_request_method = "POST"
#     oidc_issuer               = "YourOIDCIssuerURL"
#     token_endpoint            = "YourTokenEndpointURL"
#     auth_endpoint             = "YourAuthEndpointURL"
#     jwk_url                   = "YourJWKsURL"
#     response_type             = "code"
#     response_mode             = "query"
#   }
# }
