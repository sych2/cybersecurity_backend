package main

# Deny if public access block is missing or turned off
deny[msg] {
    # Look for the resource type in the terraform files
    resource := input.resource.aws_s3_bucket_public_access_block[name]
    
    # Check if any of these are false
    fields := ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
    val := resource[fields[_]]
    val == false

    msg = sprintf("Security Violation: Resource '%v' has public access enabled. All blocks must be true.", [name])
}