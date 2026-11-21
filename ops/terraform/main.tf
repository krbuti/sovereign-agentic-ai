############################################################
# Variables with EU-only validation (fail at plan time)
############################################################
variable "environment" {
  type = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging or prod."
  }
}

variable "aws_region" {
  type    = string
  default = "eu-central-1"
  validation {
    # EU member-state regions only (London eu-west-2 and Zurich eu-central-2 are non-EU).
    condition     = contains(["eu-central-1", "eu-west-1", "eu-west-3", "eu-north-1", "eu-south-1", "eu-south-2"], var.aws_region)
    error_message = "Only EU-member-state AWS regions are allowed."
  }
}

variable "aws_account_id" {
  type = string
}

variable "allowed_regions" {
  type    = list(string)
  default = ["eu-central-1", "eu-west-1"]
}

variable "break_glass_role_arn" {
  type        = string
  description = "Role exempted from the region-deny SCP for org-level emergencies."
}

variable "workloads_ou_id" {
  type = string
}

variable "gcp_org_id" {
  type = string
}

variable "gcp_kms_project" {
  type = string
}

############################################################
# Providers: region pinned, account pinned, tags enforced
############################################################
provider "aws" {
  region              = var.aws_region
  allowed_account_ids = [var.aws_account_id]
  default_tags {
    tags = {
      system         = "eng-knowledge-qa"
      environment    = var.environment
      data_residency = "eu"
      managed_by     = "terraform"
    }
  }
}

provider "google" {
  region = "europe-west3"
}

data "aws_caller_identity" "current" {}

############################################################
# KMS customer-managed key (CMK) with rotation
############################################################
resource "aws_kms_key" "data" {
  description             = "CMK for QA platform data (S3 corpus, vector index snapshots, audit logs)"
  key_usage               = "ENCRYPT_DECRYPT"
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = 30
  multi_region            = false # keep key material in one EU region

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AccountAdmin"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        # A KMS key is regional, so region conditions are redundant here; instead restrict
        # data-plane use to approved in-region AWS services (S3, OpenSearch, CloudWatch Logs).
        Sid       = "DenyUseExceptViaApprovedServices"
        Effect    = "Deny"
        Principal = { AWS = "*" }
        Action    = ["kms:Decrypt", "kms:GenerateDataKey*", "kms:ReEncrypt*"]
        Resource  = "*"
        Condition = {
          StringNotEquals = {
            "kms:ViaService" = [
              "s3.${var.aws_region}.amazonaws.com",
              "es.${var.aws_region}.amazonaws.com",
              "logs.${var.aws_region}.amazonaws.com"
            ]
          }
          Bool = { "aws:PrincipalIsAWSService" = "false" }
        }
      }
    ]
  })
}

resource "aws_kms_alias" "data" {
  name          = "alias/qa-${var.environment}-data"
  target_key_id = aws_kms_key.data.key_id
}

############################################################
# S3 corpus bucket: CMK encryption, no public access, TLS only
############################################################
resource "aws_s3_bucket" "corpus" {
  bucket        = "acme-qa-${var.environment}-corpus-${var.aws_region}"
  force_destroy = false
}

resource "aws_s3_bucket_public_access_block" "corpus" {
  bucket                  = aws_s3_bucket.corpus.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.data.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_policy" "corpus" {
  bucket = aws_s3_bucket.corpus.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.corpus.arn, "${aws_s3_bucket.corpus.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      },
      {
        Sid       = "DenyWrongKmsKey"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.corpus.arn}/*"
        Condition = {
          StringNotEqualsIfExists = { "s3:x-amz-server-side-encryption-aws-kms-key-id" = aws_kms_key.data.arn }
        }
      }
    ]
  })
}

############################################################
# AWS Organizations SCP: deny non-EU regions (attach to workload OU)
# Based on the AWS IAM "deny based on requested Region" example; global services
# (single us-east-1 endpoint) must be exempted or they break.
############################################################
resource "aws_organizations_policy" "eu_region_deny" {
  name        = "deny-non-eu-regions"
  description = "Deny all actions outside allowed EU regions except global services"
  type        = "SERVICE_CONTROL_POLICY"
  content = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid    = "DenyAllOutsideEU"
      Effect = "Deny"
      NotAction = [
        "cloudfront:*", "iam:*", "organizations:*", "route53:*", "support:*",
        "sts:*", "budgets:*", "waf:*"
      ]
      Resource = "*"
      Condition = {
        StringNotEquals = { "aws:RequestedRegion" = var.allowed_regions }
        ArnNotLike      = { "aws:PrincipalARN" = [var.break_glass_role_arn] }
      }
    }]
  })
}

resource "aws_organizations_policy_attachment" "eu_region_deny" {
  policy_id = aws_organizations_policy.eu_region_deny.id
  target_id = var.workloads_ou_id
}

############################################################
# Google Cloud equivalents: org policies
############################################################
# Resource location restriction: EU value group (excludes CH and UK; use in:europe-locations to include them).
resource "google_org_policy_policy" "resource_locations" {
  name   = "organizations/${var.gcp_org_id}/policies/gcp.resourceLocations"
  parent = "organizations/${var.gcp_org_id}"
  spec {
    rules {
      values {
        allowed_values = ["in:eu-locations"]
      }
    }
  }
}

# Require CMEK for listed services (deny list of services that may run without CMEK).
resource "google_org_policy_policy" "restrict_non_cmek" {
  name   = "organizations/${var.gcp_org_id}/policies/gcp.restrictNonCmekServices"
  parent = "organizations/${var.gcp_org_id}"
  spec {
    rules {
      values {
        denied_values = ["storage.googleapis.com", "aiplatform.googleapis.com", "bigquery.googleapis.com"]
      }
    }
  }
}

# Only keys from the customer's KMS project may be used for CMEK.
resource "google_org_policy_policy" "cmek_key_projects" {
  name   = "organizations/${var.gcp_org_id}/policies/gcp.restrictCmekCryptoKeyProjects"
  parent = "organizations/${var.gcp_org_id}"
  spec {
    rules {
      values {
        allowed_values = ["under:projects/${var.gcp_kms_project}"]
      }
    }
  }
}

output "corpus_bucket" {
  value = aws_s3_bucket.corpus.bucket
}

output "data_kms_key_arn" {
  value = aws_kms_key.data.arn
}
