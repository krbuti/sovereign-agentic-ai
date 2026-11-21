# Per-environment state: one key per env, separate state bucket per account in production.
# Init with: terraform init -backend-config=env/prod.s3.tfbackend
terraform {
  backend "s3" {
    bucket       = "acme-tfstate-eu-central-1"
    key          = "qa-platform/prod/terraform.tfstate"
    region       = "eu-central-1"
    encrypt      = true
    kms_key_id   = "alias/tfstate-cmk" # state encrypted with a customer-managed key
    use_lockfile = true                # S3-native lock file; DynamoDB locking is deprecated
  }
}
