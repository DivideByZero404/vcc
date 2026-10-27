"""
S3 Bucket Manager — Component 3: Amazon S3 Bucket Creation and Management.
Handles bucket creation, listing objects, deleting objects, and bucket deletion.
"""

import re
import time
import boto3
from botocore.exceptions import ClientError


def get_s3_client(region="us-east-1"):
    return boto3.client("s3", region_name=region)


def validate_bucket_name(bucket_name: str) -> tuple[bool, str]:
    """Validate S3 bucket naming rules according to AWS specifications."""
    if not bucket_name:
        return False, "Bucket name cannot be empty."
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        return False, f"Bucket name must be between 3 and 63 characters long (currently {len(bucket_name)} characters)."
    if any(c.isupper() for c in bucket_name):
        return False, "Bucket names cannot contain uppercase letters. AWS S3 requires all lowercase characters (e.g., 'my-bucket-name' instead of 'BuCket1')."
    if not re.match(r"^[a-z0-9][a-z0-9.-]*[a-z0-9]$", bucket_name):
        return False, "Bucket name must start and end with a lowercase letter or number, and can only contain lowercase letters, numbers, and hyphens."
    if ".." in bucket_name:
        return False, "Bucket name cannot contain consecutive periods."
    return True, ""


def create_bucket(bucket_name, region="us-east-1"):
    """Create an S3 bucket. Returns (success: bool, message: str)."""
    valid, err_msg = validate_bucket_name(bucket_name)
    if not valid:
        return False, err_msg

    s3 = get_s3_client(region)
    try:
        if region == "us-east-1":
            s3.create_bucket(Bucket=bucket_name)
        else:
            s3.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={"LocationConstraint": region}
            )
        # Block all public access
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True
            }
        )
        # Enable versioning
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={"Status": "Enabled"}
        )
        return True, f"Bucket '{bucket_name}' created in {region} with versioning enabled."
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "InvalidBucketName":
            return False, "Invalid bucket name: AWS S3 names must be 3-63 chars, lowercase letters, numbers, and hyphens only (no uppercase)."
        elif code == "BucketAlreadyExists":
            return False, f"Bucket name '{bucket_name}' is already taken globally. Choose a more unique name (e.g., '{bucket_name}-{int(time.time())}')."
        elif code == "BucketAlreadyOwnedByYou":
            return True, f"Bucket '{bucket_name}' already exists and is owned by your account."
        elif code == "AccessDenied":
            return False, "Access Denied: The IAM role (aws-elasticbeanstalk-ec2-role) lacks 's3:CreateBucket' permissions. Attach 'AmazonS3FullAccess' in AWS IAM Console."
        return False, str(e)



def list_buckets():
    """List all S3 buckets. Returns (buckets: list, message: str)."""
    s3 = get_s3_client()
    try:
        response = s3.list_buckets()
        buckets = [
            {"name": b["Name"], "created": b["CreationDate"].strftime("%Y-%m-%d %H:%M:%S")}
            for b in response.get("Buckets", [])
        ]
        return buckets, f"{len(buckets)} bucket(s) found."
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AccessDenied":
            return [], "Access Denied: The IAM role (aws-elasticbeanstalk-ec2-role) lacks 's3:ListAllMyBuckets' permissions. Attach 'AmazonS3FullAccess' to the role in AWS IAM Console."
        return [], str(e)


def list_objects(bucket_name):
    """List all objects in a bucket. Returns (objects: list, message: str)."""
    s3 = get_s3_client()
    try:
        response = s3.list_objects_v2(Bucket=bucket_name)
        objects = [
            {
                "key": obj["Key"],
                "size": obj["Size"],
                "last_modified": obj["LastModified"].strftime("%Y-%m-%d %H:%M:%S")
            }
            for obj in response.get("Contents", [])
        ]
        return objects, f"{len(objects)} object(s) in '{bucket_name}'."
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code == "AccessDenied":
            return [], "Access Denied: The IAM role (aws-elasticbeanstalk-ec2-role) lacks 's3:ListAllMyBuckets' permissions. Attach 'AmazonS3FullAccess' to the role in AWS IAM Console."
        return [], str(e)


def delete_object(bucket_name, key):
    """Delete a single object from a bucket. Returns (success: bool, message: str)."""
    s3 = get_s3_client()
    try:
        s3.delete_object(Bucket=bucket_name, Key=key)
        return True, f"Object '{key}' deleted from '{bucket_name}'."
    except ClientError as e:
        return False, str(e)


def delete_bucket(bucket_name):
    """Empty and delete a bucket. Returns (success: bool, message: str)."""
    s3 = get_s3_client()
    try:
        # Empty bucket first
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket_name):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket_name, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket_name)
        return True, f"Bucket '{bucket_name}' emptied and deleted."
    except ClientError as e:
        return False, str(e)


def get_bucket_info(bucket_name):
    """Get bucket region and versioning status."""
    s3 = get_s3_client()
    try:
        location = s3.get_bucket_location(Bucket=bucket_name)
        versioning = s3.get_bucket_versioning(Bucket=bucket_name)
        region = location.get("LocationConstraint") or "us-east-1"
        ver_status = versioning.get("Status", "Disabled")
        return {
            "bucket": bucket_name,
            "region": region,
            "versioning": ver_status
        }, "OK"
    except ClientError as e:
        return {}, str(e)
