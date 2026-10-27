#!/usr/bin/env python3
"""
VCC Full Deployment Script
Deploys all 5 components automatically using your AWS credentials.

Usage:
    python3 deploy.py

Requirements:
    - AWS credentials configured (run: aws configure)
    - boto3 installed (pip3 install boto3)
"""

import boto3
import json
import os
import subprocess
import sys
import time
import zipfile
import io

REGION = "us-east-1"
APP_NAME = "cryptographic-arp"
ENV_NAME = "cryptoarp-env"
BUCKET_NAME = f"cryptoarp-secure-{int(time.time())}"   # globally unique
EC2_KEY_NAME = "cryptoarp-key"                          # will be created
SG_NAME = "cryptoarp-sg"

DIVIDER = "=" * 60


def banner(title):
    print(f"\n{DIVIDER}\n  {title}\n{DIVIDER}")


# ─────────────────────────────────────────────────────────────
# STEP 0: Verify credentials
# ─────────────────────────────────────────────────────────────
def verify_credentials():
    banner("STEP 0: Verifying AWS Credentials")
    try:
        sts = boto3.client("sts", region_name=REGION)
        identity = sts.get_caller_identity()
        print(f"  Account : {identity['Account']}")
        print(f"  User ARN: {identity['Arn']}")
        print("  [✓] Credentials valid.")
        return identity["Account"]
    except Exception as e:
        print(f"  [✗] Credentials error: {e}")
        print("\n  Run:  aws configure")
        print("  Then enter your Access Key ID, Secret Access Key, region: us-east-1\n")
        sys.exit(1)


# ─────────────────────────────────────────────────────────────
# COMPONENT 3: S3 Bucket Creation and Management
# ─────────────────────────────────────────────────────────────
def deploy_s3(account_id):
    banner("COMPONENT 3: S3 Bucket Creation & Management")
    s3 = boto3.client("s3", region_name=REGION)

    print(f"  Creating bucket: {BUCKET_NAME}")
    try:
        s3.create_bucket(Bucket=BUCKET_NAME)
        # Block public access
        s3.put_public_access_block(
            Bucket=BUCKET_NAME,
            PublicAccessBlockConfiguration={
                "BlockPublicAcls": True, "IgnorePublicAcls": True,
                "BlockPublicPolicy": True, "RestrictPublicBuckets": True
            }
        )
        # Enable versioning
        s3.put_bucket_versioning(
            Bucket=BUCKET_NAME,
            VersioningConfiguration={"Status": "Enabled"}
        )
        print(f"  [✓] Bucket '{BUCKET_NAME}' created with versioning + public access blocked.")
    except Exception as e:
        print(f"  [!] Bucket creation: {e}")

    # List all buckets
    resp = s3.list_buckets()
    print(f"  [✓] Total buckets in account: {len(resp['Buckets'])}")
    for b in resp["Buckets"]:
        print(f"       - {b['Name']}")

    return BUCKET_NAME


# ─────────────────────────────────────────────────────────────
# COMPONENT 4: Secure File Upload (AES-256-GCM + SHA-256)
# ─────────────────────────────────────────────────────────────
def deploy_secure_upload(bucket_name):
    banner("COMPONENT 4: Secure File Upload to S3")
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from aws.secure_upload import secure_upload, list_secure_files

    # Upload the README.md as a demo file
    demo_file = os.path.join(os.path.dirname(__file__), "README.md")
    with open(demo_file, "rb") as f:
        file_bytes = f.read()

    password = "VCC-AES256-Demo-Key-2024"
    success, msg, meta = secure_upload(bucket_name, file_bytes, "README.md", password, REGION)
    if success:
        print(f"  [✓] {msg}")
        print(f"       SHA-256 : {meta['sha256_original']}")
        print(f"       S3 Key  : {meta['s3_key']}")
        print(f"       Cipher  : {meta['encryption']}")
    else:
        print(f"  [✗] Upload failed: {msg}")

    # List encrypted files
    files, list_msg = list_secure_files(bucket_name, REGION)
    print(f"  [✓] Encrypted files in bucket: {len(files)}")
    for f in files:
        print(f"       - {f['original_filename']} | SHA-256: {f['sha256'][:20]}...")


# ─────────────────────────────────────────────────────────────
# COMPONENT 2: EC2 Instance Creation & Deployment
# ─────────────────────────────────────────────────────────────
def deploy_ec2():
    banner("COMPONENT 2: Amazon EC2 Instance Creation & Deployment")
    ec2 = boto3.client("ec2", region_name=REGION)

    # Get latest Amazon Linux 2023 AMI
    print("  Finding latest Amazon Linux 2023 AMI...")
    images = ec2.describe_images(
        Owners=["amazon"],
        Filters=[
            {"Name": "name", "Values": ["al2023-ami-*-x86_64"]},
            {"Name": "state", "Values": ["available"]}
        ]
    )
    ami = sorted(images["Images"], key=lambda x: x["CreationDate"], reverse=True)[0]
    ami_id = ami["ImageId"]
    print(f"  AMI: {ami_id} ({ami['Name'][:50]})")

    # Create key pair
    print(f"  Creating key pair: {EC2_KEY_NAME}")
    try:
        kp = ec2.create_key_pair(KeyName=EC2_KEY_NAME)
        key_path = os.path.expanduser(f"~/{EC2_KEY_NAME}.pem")
        with open(key_path, "w") as f:
            f.write(kp["KeyMaterial"])
        os.chmod(key_path, 0o400)
        print(f"  [✓] Key saved to {key_path}")
    except ec2.exceptions.ClientError as e:
        if "InvalidKeyPair.Duplicate" in str(e):
            print(f"  [!] Key pair '{EC2_KEY_NAME}' already exists, reusing.")
        else:
            raise

    # Create security group
    print(f"  Creating security group: {SG_NAME}")
    try:
        sg = ec2.create_security_group(
            GroupName=SG_NAME,
            Description="Cryptographic ARP Web UI"
        )
        sg_id = sg["GroupId"]
        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {"IpProtocol": "tcp", "FromPort": 8080, "ToPort": 8080,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "Web UI"}]},
                {"IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
                 "IpRanges": [{"CidrIp": "0.0.0.0/0", "Description": "SSH"}]}
            ]
        )
        print(f"  [✓] Security group {sg_id} created (ports 22, 8080 open).")
    except Exception as e:
        if "InvalidGroup.Duplicate" in str(e):
            sgs = ec2.describe_security_groups(Filters=[{"Name": "group-name", "Values": [SG_NAME]}])
            sg_id = sgs["SecurityGroups"][0]["GroupId"]
            print(f"  [!] Security group already exists: {sg_id}")
        else:
            raise

    # Read userdata script
    userdata_path = os.path.join(os.path.dirname(__file__), "aws", "ec2_userdata.sh")
    with open(userdata_path) as f:
        userdata = f.read()

    # Launch EC2 instance
    print("  Launching EC2 t3.micro instance...")
    instances = ec2.run_instances(
        ImageId=ami_id,
        InstanceType="t3.micro",
        KeyName=EC2_KEY_NAME,
        SecurityGroupIds=[sg_id],
        MinCount=1,
        MaxCount=1,
        UserData=userdata,
        TagSpecifications=[{
            "ResourceType": "instance",
            "Tags": [{"Key": "Name", "Value": "CryptoARP-WebUI"}]
        }]
    )
    instance_id = instances["Instances"][0]["InstanceId"]
    print(f"  [✓] Instance launched: {instance_id}")
    print("  Waiting for instance to get a public IP (this takes ~30s)...")

    # Wait for running state
    waiter = ec2.get_waiter("instance_running")
    waiter.wait(InstanceIds=[instance_id])

    desc = ec2.describe_instances(InstanceIds=[instance_id])
    public_ip = desc["Reservations"][0]["Instances"][0].get("PublicIpAddress", "N/A")
    print(f"\n  [✓] EC2 Instance running!")
    print(f"       Instance ID : {instance_id}")
    print(f"       Public IP   : {public_ip}")
    print(f"       App URL     : http://{public_ip}:8080  (ready in ~2 min after boot)")
    print(f"       SSH Access  : ssh -i ~/{EC2_KEY_NAME}.pem ec2-user@{public_ip}")

    return instance_id, public_ip


# ─────────────────────────────────────────────────────────────
# COMPONENT 1: PaaS — Elastic Beanstalk Deployment
# ─────────────────────────────────────────────────────────────
def deploy_paas():
    banner("COMPONENT 1: PaaS Deployment (AWS Elastic Beanstalk)")
    project_dir = os.path.dirname(os.path.abspath(__file__))

    # Create deployment zip (exclude venv, __pycache__, .git, keys/*.pem)
    zip_path = "/tmp/cryptoarp_deploy.zip"
    print(f"  Packaging application to {zip_path}...")
    exclude_dirs = {"venv", "__pycache__", ".git", "node_modules", ".ebextensions"}
    exclude_exts = {".pyc"}

    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        for root, dirs, files in os.walk(project_dir):
            dirs[:] = [d for d in dirs if d not in exclude_dirs]
            for file in files:
                if any(file.endswith(e) for e in exclude_exts):
                    continue
                full_path = os.path.join(root, file)
                arcname = os.path.relpath(full_path, project_dir)
                zf.write(full_path, arcname)

    zip_size = os.path.getsize(zip_path) / 1024
    print(f"  [✓] Package created: {zip_size:.1f} KB")

    # Upload to S3 for EB source bundle
    s3 = boto3.client("s3", region_name=REGION)
    eb = boto3.client("elasticbeanstalk", region_name=REGION)

    # Create EB S3 bucket for source bundles
    eb_bucket = f"elasticbeanstalk-{REGION}-{boto3.client('sts').get_caller_identity()['Account']}"
    try:
        s3.create_bucket(Bucket=eb_bucket)
    except Exception:
        pass  # already exists

    version_label = f"v-{int(time.time())}"
    s3_key = f"{APP_NAME}/{version_label}.zip"

    print(f"  Uploading source bundle to S3...")
    s3.upload_file(zip_path, eb_bucket, s3_key)
    print(f"  [✓] Uploaded: s3://{eb_bucket}/{s3_key}")

    # Create EB Application
    print(f"  Creating Elastic Beanstalk application: {APP_NAME}")
    try:
        eb.create_application(
            ApplicationName=APP_NAME,
            Description="Cryptographically Authenticated ARP Security Workbench"
        )
        print(f"  [✓] Application '{APP_NAME}' created.")
    except eb.exceptions.TooManyApplicationsException:
        print(f"  [!] Application already exists, reusing.")

    # Create Application Version
    eb.create_application_version(
        ApplicationName=APP_NAME,
        VersionLabel=version_label,
        SourceBundle={"S3Bucket": eb_bucket, "S3Key": s3_key},
        AutoCreateApplication=False
    )
    print(f"  [✓] Application version '{version_label}' registered.")

    # Create or update environment
    print(f"  Creating environment '{ENV_NAME}' (Python 3.11 on t3.micro)...")
    print("  This takes 3-5 minutes...")
    try:
        eb.create_environment(
            ApplicationName=APP_NAME,
            EnvironmentName=ENV_NAME,
            VersionLabel=version_label,
            SolutionStackName="64bit Amazon Linux 2023 v4.3.0 running Python 3.11",
            OptionSettings=[
                {"Namespace": "aws:autoscaling:launchconfiguration",
                 "OptionName": "InstanceType", "Value": "t3.micro"},
                {"Namespace": "aws:elasticbeanstalk:environment",
                 "OptionName": "EnvironmentType", "Value": "SingleInstance"},
                {"Namespace": "aws:elasticbeanstalk:container:python",
                 "OptionName": "WSGIPath", "Value": "web_ui:app"},
                {"Namespace": "aws:elasticbeanstalk:application:environment",
                 "OptionName": "FLASK_ENV", "Value": "production"},
                {"Namespace": "aws:elasticbeanstalk:application:environment",
                 "OptionName": "PORT", "Value": "8080"}
            ]
        )
    except Exception as e:
        if "already exists" in str(e).lower():
            print(f"  [!] Environment exists, updating version...")
            eb.update_environment(
                ApplicationName=APP_NAME,
                EnvironmentName=ENV_NAME,
                VersionLabel=version_label
            )
        else:
            print(f"  [!] EB environment error: {e}")
            return None

    # Wait for environment to be ready
    print("  Waiting for environment to become Ready...")
    for _ in range(40):
        time.sleep(15)
        envs = eb.describe_environments(
            ApplicationName=APP_NAME,
            EnvironmentNames=[ENV_NAME]
        )
        status = envs["Environments"][0]["Status"]
        health = envs["Environments"][0].get("Health", "")
        print(f"    Status: {status} | Health: {health}")
        if status == "Ready":
            break

    envs = eb.describe_environments(ApplicationName=APP_NAME, EnvironmentNames=[ENV_NAME])
    env = envs["Environments"][0]
    eb_url = env.get("CNAME", "N/A")
    print(f"\n  [✓] Elastic Beanstalk environment READY!")
    print(f"       URL: http://{eb_url}")
    return eb_url


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────
def main():
    print("\n" + DIVIDER)
    print("  VCC FULL DEPLOYMENT — Cryptographic ARP Project")
    print(DIVIDER)

    account_id = verify_credentials()

    # Component 3: S3 bucket
    bucket_name = deploy_s3(account_id)

    # Component 4: Secure upload demo
    deploy_secure_upload(bucket_name)

    # Component 2: EC2
    instance_id, public_ip = deploy_ec2()

    # Component 1: Elastic Beanstalk PaaS
    eb_url = deploy_paas()

    # Final summary
    banner("DEPLOYMENT COMPLETE — SUMMARY")
    print(f"  Component 1 (PaaS)  : http://{eb_url}")
    print(f"  Component 2 (EC2)   : http://{public_ip}:8080  (ready in ~2 min)")
    print(f"  Component 3 (S3)    : Bucket '{bucket_name}' created & managed")
    print(f"  Component 4 (Upload): README.md encrypted (AES-256-GCM) & uploaded")
    print(f"\n  S3 Dashboard        : Open the web UI → AWS S3 panel")
    print(DIVIDER + "\n")


if __name__ == "__main__":
    main()
