#!/bin/bash
# EC2 Bootstrap Script — Component 2: Amazon EC2 Deployment
# Run this as EC2 User Data (Amazon Linux 2023 / Ubuntu 22.04)
# The app will be accessible at http://<EC2-PUBLIC-IP>:8080

set -e

# 1. Update system packages
yum update -y 2>/dev/null || apt-get update -y

# 2. Install Python 3, pip, git
yum install -y python3 python3-pip git 2>/dev/null || apt-get install -y python3 python3-pip git

# 3. Clone or copy project (replace URL with your actual repo)
cd /home/ec2-user
git clone https://github.com/<YOUR_USERNAME>/cryptographic-arp.git app
# OR if uploading a zip: unzip cryptographic-arp.zip -d app

cd app

# 4. Install Python dependencies
pip3 install -r requirements.txt

# 5. Generate cryptographic keys
python3 keys/generate_keys.py

# 6. Open port 8080 in the instance (Security Group must also allow TCP 8080)
# This is configured in the EC2 Security Group inbound rules — not here.

# 7. Start the Flask web app as a background service
export FLASK_ENV=production
export PORT=8080
nohup python3 web_ui.py > /var/log/cryptoarp.log 2>&1 &

echo "App started. Access at http://$(curl -s http://169.254.169.254/latest/meta-data/public-ipv4):8080"
