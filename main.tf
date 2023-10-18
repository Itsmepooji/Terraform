locals {
  vpc_id              = data.tfe_outputs.data_platform_infra.values.vpc_id
  vpc_cidr            = data.tfe_outputs.data_platform_infra.values.vpc_cidr_block
  private_subnet_1_id = data.tfe_outputs.data_platform_infra.values.private_subnet_1_id
  private_subnet_2_id = data.tfe_outputs.data_platform_infra.values.private_subnet_2_id
}

# Create Security Group for Airflow
module "airflow_sg" {
  source      = "app.terraform.io/koho/security-group/aws"
  version     = "0.0.4"
  description = "Airflow Security Group"
  vpc_id      = local.vpc_id
  security_group_self_rules = [{
    type      = "ingress"
    from_port = 0
    to_port   = 0
    protocol  = -1
    self      = true
  }]
  security_group_cidr_block_rules = [{
    type             = "egress"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
    },
    {
    type             = "ingress"
    from_port        = 443
    to_port          = 443
    protocol         = "-1"
    cidr_blocks      = [local.vpc_cidr]
    ipv6_cidr_blocks = []
    }
  ]
  name       = var.airflow_security_group_name
  env        = var.env
  aws_region = var.aws_region
  owner      = var.owner
}

# Creating S3 bucket to store dags code
module "airflow_s3_bucket" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~>2.15.0"

  bucket = var.airflow_bucket_name
  acl    = "private"
  versioning = {
    enabled = true
  }
  logging = {
    target_bucket = module.airflow_bucket_access_logs.s3_bucket_id
    target_prefix = "logs/"
  }
  # S3 bucket-level Public Access Block configuration
  block_public_acls                     = true
  block_public_policy                   = true
  ignore_public_acls                    = true
  restrict_public_buckets               = true
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = module.airflow_kms_key.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
  tags = {
    Name        = var.airflow_bucket_name
    Owner       = var.owner
    Environment = var.env
    Region      = var.aws_region
  }
}

# Attaching Bucket Policy to Airflow S3 bucket
resource "aws_s3_bucket_policy" "airflow_s3_bucket_policy" {
  bucket = module.airflow_s3_bucket.s3_bucket_id
  policy = data.aws_iam_policy_document.airflow_s3_bucket_policy.json
}

# Bucket policy with one statement denying deletion action for everyone except Sysadmin role,
# and the second statement requires requests to use Secure Socket Layer
data "aws_iam_policy_document" "airflow_s3_bucket_policy" {
  statement {
    sid = "S3PreventDeletion"
    effect = "Deny"
    principals {
      type = "AWS"
      identifiers = [
        "*"
      ]
    }
    actions = [
      "s3:DeleteBucket"
    ]
    resources = [
      module.airflow_s3_bucket.s3_bucket_arn
    ]
  }
  statement {
    sid    = "AllowSSLRequestsOnly_accesslogs"
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    actions = [
      "s3:*"
    ]
    resources = [
      module.airflow_s3_bucket.s3_bucket_arn,
      "${module.airflow_s3_bucket.s3_bucket_arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values = [
        false
      ]
    }
  }
}

# Creating S3 bucket to store access logs 
module "airflow_bucket_access_logs" {
  source  = "terraform-aws-modules/s3-bucket/aws"
  version = "~>2.15.0"

  bucket = var.airflow_bucket_access_logs_name
  acl    = "log-delivery-write"
  versioning = {
    enabled = true
  }
  # S3 bucket-level Public Access Block configuration
  block_public_acls                     = true
  block_public_policy                   = true
  ignore_public_acls                    = true
  restrict_public_buckets               = true
  server_side_encryption_configuration = {
    rule = {
      apply_server_side_encryption_by_default = {
        kms_master_key_id = module.airflow_kms_key.arn
        sse_algorithm     = "aws:kms"
      }
      bucket_key_enabled = true
    }
  }
  tags = {
    Name        = var.airflow_bucket_name
    Owner       = var.owner
    Environment = var.env
    Region      = var.aws_region
  }
}

# Attaching Bucket Policy to Airflow Acees Log S3 bucket
resource "aws_s3_bucket_policy" "airflow_access_logs_bucket_policy" {
  bucket = module.airflow_bucket_access_logs.s3_bucket_id
  policy = data.aws_iam_policy_document.airflow_access_logs_bucket_policy.json
}

# Bucket policy for Access logs S3 bucket
data "aws_iam_policy_document" "airflow_access_logs_bucket_policy" {
  statement {
    sid    = "AWSLogDeliveryWrite"
    effect = "Allow"
    principals {
      identifiers = [
        "logging.s3.amazonaws.com"
      ]
      type = "Service"
    }
    actions = [
      "s3:PutObject"
    ]
    resources = [
      "${module.airflow_bucket_access_logs.s3_bucket_arn}/*"
    ]
  }
  statement {
    sid = "S3PreventDeletion"
    effect = "Deny"
    principals {
      type = "AWS"
      identifiers = [
        "*"
      ]
    }
    actions = [
      "s3:DeleteBucket"
    ]
    resources = [
      module.airflow_bucket_access_logs.s3_bucket_arn
    ]
  }
  statement {
    sid    = "AllowSSLRequestsOnly_accesslogs"
    effect = "Deny"
    principals {
      identifiers = [
        "*"
      ]
      type = "AWS"
    }
    actions = [
      "s3:*"
    ]
    resources = [
      module.airflow_bucket_access_logs.s3_bucket_arn,
      "${module.airflow_bucket_access_logs.s3_bucket_arn}/*"
    ]
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values = [
        false
      ]
    }
  }
}


#create KMS used for the bucket encryption
module "airflow_kms_key" {
  source                   = "app.terraform.io/koho/kms/aws"
  version                  = "0.0.12"
  alias_name               = var.kms_key_alias_name
  description              = "KMS key used for AWS Managed Airflow and S3 bucket encryption"
  enable_key_rotation      = true
  kms_key_admin_principals = var.kms_key_admin_principals
  kms_key_usage_services   = var.kms_key_usage_services
  kms_key_usage_principals = var.kms_key_usage_principals
  env                      = var.env
  name                     = var.kms_key_alias_name
  owner                    = var.owner
}

#This script is used to create airflow environment , it uses IAM role and Bucket for storing dag_processing_logs
resource "aws_mwaa_environment" "airflow_environment" {
  name                           = var.airflow_name
  min_workers                    = var.airflow_min_workers
  max_workers                    = var.airflow_max_workers
  environment_class              = var.airflow_environment_class
  airflow_version                = var.airflow_version
  webserver_access_mode          = var.airflow_webserver_access_mode
  execution_role_arn             = aws_iam_role.airflow_iam_role.arn
  kms_key                        = module.airflow_kms_key.arn
  source_bucket_arn              = module.airflow_s3_bucket.s3_bucket_arn
  dag_s3_path                    = var.dag_s3_path
  plugins_s3_path                = var.plugins_s3_path
  plugins_s3_object_version      = var.plugins_s3_object_version
  requirements_s3_path           = var.requirements_s3_path
  requirements_s3_object_version = var.requirements_s3_object_version
  airflow_configuration_options  = var.airflow_configuration_options
  logging_configuration {
    dag_processing_logs {
      enabled   = true
      log_level = "ERROR"
    }
    scheduler_logs {
      enabled   = true
      log_level = "ERROR"
    }
    task_logs {
      enabled   = true
      log_level = "INFO"
    }
    webserver_logs {
      enabled   = true
      log_level = "ERROR"
    }
    worker_logs {
      enabled   = true
      log_level = "ERROR"
    }
  }
  network_configuration {
    security_group_ids = [module.airflow_sg.id]
    subnet_ids         = [local.private_subnet_1_id, local.private_subnet_2_id]
  }
  tags = {
    Name        = var.airflow_bucket_name
    Owner       = var.owner
    Environment = var.env
    Region      = var.aws_region
  }
}
