#!/usr/bin/env python3
"""
AWS IMDS Mock Server - Para testing de SSRF
Emula Instance Metadata Service v1 (vulnerable)
"""

from http.server import BaseHTTPRequestHandler, HTTPServer
import json
from datetime import datetime, timedelta

class IMDSHandler(BaseHTTPRequestHandler):

    def log_message(self, format, *args):
        """Log requests con timestamp"""
        print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] {format % args}")

    def do_GET(self):
        """Handle GET requests - IMDSv1 (sin token, vulnerable)"""

        # Metadata endpoints realistas
        metadata_responses = {
            # Root endpoints
            '/': 'latest\n1.0\n2007-01-19\n2007-03-01\n2008-02-01\n2008-09-01\n2009-04-04\n2011-01-01\n2011-05-01\n2012-01-12\n',

            '/latest/': 'meta-data\nuser-data\ndynamic\n',

            '/latest/meta-data/': '''ami-id
ami-launch-index
ami-manifest-path
block-device-mapping/
events/
hostname
iam/
instance-action
instance-id
instance-life-cycle
instance-type
local-hostname
local-ipv4
mac
metrics/
network/
placement/
profile
public-hostname
public-ipv4
public-keys/
reservation-id
security-groups
services/''',

            # Instance info
            '/latest/meta-data/ami-id': 'ami-0abcdef1234567890',
            '/latest/meta-data/instance-id': 'i-1234567890abcdef0',
            '/latest/meta-data/instance-type': 't2.micro',
            '/latest/meta-data/local-ipv4': '172.31.45.123',
            '/latest/meta-data/public-ipv4': '54.123.45.67',
            '/latest/meta-data/hostname': 'ip-172-31-45-123.ec2.internal',
            '/latest/meta-data/public-hostname': 'ec2-54-123-45-67.compute-1.amazonaws.com',
            '/latest/meta-data/security-groups': 'web-server-sg\nssh-access-sg',

            # Placement info
            '/latest/meta-data/placement/': 'availability-zone\navailability-zone-id\nregion\n',
            '/latest/meta-data/placement/availability-zone': 'us-east-1a',
            '/latest/meta-data/placement/region': 'us-east-1',

            # IAM endpoints - AQUÍ ESTÁN LAS CREDENCIALES
            '/latest/meta-data/iam/': 'info\nsecurity-credentials/',
            '/latest/meta-data/iam/info': '''{
  "Code" : "Success",
  "LastUpdated" : "2024-02-26T10:30:45Z",
  "InstanceProfileArn" : "arn:aws:iam::123456789012:instance-profile/WebServerRole",
  "InstanceProfileId" : "AIPAI23HX7EXAMPLE"
}''',

            '/latest/meta-data/iam/security-credentials/': 'WebServerRole',

            # CREDENCIALES CRÍTICAS - El objetivo del ataque
            '/latest/meta-data/iam/security-credentials/WebServerRole': json.dumps({
                "Code": "Success",
                "LastUpdated": (datetime.now() - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "Type": "AWS-HMAC",
                "AccessKeyId": "ASIATESTAWSACCESSKEY123",
                "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                "Token": "FwoGZXIvYXdzEBQaDKr8nmS8j9bJKJH/KyLAAW+t8xvPmXH6v3TLvJEJZKZQOGXyuMvvZWy8YkP7TBGqv3aX5N4vwbqL+xJpL8aLVbRhW3nJYYtCv8PnH4mZnP5qJvZ8cL9WmP5yLxKpY8vJ9LmN5qYtPcZmY8pJqL9vZxJ5mPqYvL8pN9JqYvP5m8LxJpY9qLv...(truncated for brevity)...VeryLongTokenString",
                "Expiration": (datetime.now() + timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ")
            }, indent=2),

            # User data (scripts de inicio)
            '/latest/user-data': '''#!/bin/bash
# Instance initialization script
echo "Starting web server..."
systemctl start apache2
echo "DB_PASSWORD=MySecretDBPass2024!" > /etc/app/config.env
''',

            # Dynamic data
            '/latest/dynamic/': 'instance-identity/',
            '/latest/dynamic/instance-identity/': 'document\nsignature\npkcs7\nrsa2048',
            '/latest/dynamic/instance-identity/document': json.dumps({
                "accountId": "123456789012",
                "architecture": "x86_64",
                "availabilityZone": "us-east-1a",
                "imageId": "ami-0abcdef1234567890",
                "instanceId": "i-1234567890abcdef0",
                "instanceType": "t2.micro",
                "privateIp": "172.31.45.123",
                "region": "us-east-1",
                "version": "2017-09-30"
            }, indent=2),
        }

        # Servir respuesta
        response = metadata_responses.get(self.path, 'Not Found')

        if response == 'Not Found':
            self.send_response(404)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(b'404 - Not Found')
            print(f"⚠️  404: {self.path}")
        else:
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            self.wfile.write(response.encode())
            print(f"✅ 200: {self.path}")

    def do_PUT(self):
        """Handle PUT requests - IMDSv2 token generation (seguro)"""
        if self.path == '/latest/api/token':
            # Leer headers
            ttl = self.headers.get('X-aws-ec2-metadata-token-ttl-seconds', '21600')

            # Generar token simple
            token = "AQAAABpGz8dJAGEXAMPLETOKEN" + str(datetime.now().timestamp())

            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.send_header('X-aws-ec2-metadata-token-ttl-seconds', ttl)
            self.end_headers()
            self.wfile.write(token.encode())
            print(f"🔐 IMDSv2 Token generated (TTL: {ttl}s)")
        else:
            self.send_response(404)
            self.end_headers()

def run_server():
    """Iniciar servidor en 169.254.169.254:80"""
    server_address = ('169.254.169.254', 80)
    httpd = HTTPServer(server_address, IMDSHandler)

    print("=" * 60)
    print("🚀 AWS IMDS Mock Server Started")
    print("=" * 60)
    print(f"📍 Listening on: http://169.254.169.254")
    print(f"⚠️  IMDSv1 (vulnerable): ENABLED")
    print(f"🔐 IMDSv2 (secure): Available via PUT /latest/api/token")
    print(f"🎯 Target credentials at: /latest/meta-data/iam/security-credentials/WebServerRole")
    print("=" * 60)
    print("\n🔍 Waiting for requests...\n")

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n\n🛑 Server stopped by user")
        httpd.shutdown()

if __name__ == '__main__':
    run_server()
administrator@ubuntuserver:~$
