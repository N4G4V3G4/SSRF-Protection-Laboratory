<!-- This file should be in the Apache directory /var/www/html/ -->
<?php
error_reporting(E_ALL);
ini_set('display_errors', 1);
session_start();

// Toggle protection levels
if(isset($_GET['set_level'])) {
    $_SESSION['protection_level'] = $_GET['set_level'];
    $_SESSION['request_count'] = 0;
    header('Location: ssrf_multilevel.php');
    exit;
}

$protection_level = $_SESSION['protection_level'] ?? 'none';

/**
 * ==================================================================
 * FUNCIONES COMPARTIDAS
 * ==================================================================
 */

// Normalizar IP (decimal, hex, octal → dotted notation)
function normalize_ip($host) {
    // Decimal completo (2852039166)
    if(is_numeric($host) && !strpos($host, '.')) {
        $long = (int)$host;
        return long2ip($long);
    }

    // Hexadecimal (0xa9fea9fe)
    if(preg_match('/^0x[0-9a-f]+$/i', $host)) {
        $long = hexdec($host);
        return long2ip($long);
    }

    // Octal dotted (0251.0376.0251.0376)
    if(preg_match('/^0[0-7\.]+$/', $host)) {
        $parts = explode('.', $host);
        foreach($parts as $i => $part) {
            if(strpos($part, '0') === 0 && strlen($part) > 1) {
                $parts[$i] = octdec($part);
            }
        }
        return implode('.', $parts);
    }

    // Short form (127.1 → 127.0.0.1)
    if(preg_match('/^(\d+)\.(\d+)$/', $host) || preg_match('/^(\d+)\.(\d+)\.(\d+)$/', $host)) {
        $parts = explode('.', $host);
        while(count($parts) < 4) {
            array_splice($parts, -1, 0, '0');
        }
        return implode('.', $parts);
    }

    return $host;
}

// Verificar si es IP privada (IPv4)
function is_private_ip($ip) {
    $long = ip2long($ip);
    if($long === false) return false;

    $private_ranges = [
        ['10.0.0.0', '10.255.255.255'],           // 10.0.0.0/8
        ['172.16.0.0', '172.31.255.255'],         // 172.16.0.0/12
        ['192.168.0.0', '192.168.255.255'],       // 192.168.0.0/16
        ['127.0.0.0', '127.255.255.255'],         // 127.0.0.0/8 (Loopback)
        ['169.254.0.0', '169.254.255.255'],       // 169.254.0.0/16 (Link-local)
        ['0.0.0.0', '0.255.255.255'],             // 0.0.0.0/8
        ['224.0.0.0', '239.255.255.255'],         // Multicast
        ['240.0.0.0', '255.255.255.255'],         // Reserved
    ];

    foreach($private_ranges as $range) {
        $start = ip2long($range[0]);
        $end = ip2long($range[1]);
        if($long >= $start && $long <= $end) {
            return true;
        }
    }

    return false;
}

// Verificar si es IP privada (IPv6)
function is_private_ipv6($ip) {
    if($ip === '::1') return true;  // Localhost

    if(strpos($ip, 'fe80:') === 0) return true;  // Link-local
    if(strpos($ip, 'fc') === 0 || strpos($ip, 'fd') === 0) return true;  // Unique local

    // IPv4-mapped IPv6 (::ffff:192.168.1.1)
    if(preg_match('/::ffff:(\d+\.\d+\.\d+\.\d+)/', $ip, $matches)) {
        return is_private_ip($matches[1]);
    }

    return false;
}

/**
 * ==================================================================
 * NIVEL 1: SIN PROTECCIÓN
 * ==================================================================
 */
function validate_none($url) {
    return false; // Todo permitido
}

/**
 * ==================================================================
 * NIVEL 2: PROTECCIÓN MEDIA (Blacklist simple)
 * ==================================================================
 */
function validate_medium($url) {
    $blacklist = ['127.0.0.1', 'localhost', '0.0.0.0', '::1'];
    $keywords = ['localhost', 'metadata', '169.254', '169.169'];

    $parsed = parse_url($url);
    if(!$parsed || !isset($parsed['host'])) {
        return "Invalid URL format";
    }

    $host = strtolower($parsed['host']);

    // IP Blacklist
    if(in_array($host, $blacklist)) {
        return "Blocked: IP in blacklist";
    }

    // Keyword Blacklist
    $url_lower = strtolower($url);
    foreach($keywords as $keyword) {
        if(strpos($url_lower, $keyword) !== false) {
            return "Blocked: URL contains forbidden keyword '$keyword'";
        }
    }

    return false;
}

/**
 * ==================================================================
 * NIVEL 3: PROTECCIÓN ALTA (Normalización + Private IP ranges)
 * ==================================================================
 */
function validate_high($url) {
    $parsed = parse_url($url);
    if(!$parsed || !isset($parsed['host'])) {
        return "Invalid URL format";
    }

    // Protocol whitelist
    $scheme = strtolower($parsed['scheme'] ?? '');
    if(!in_array($scheme, ['http', 'https'])) {
        return "Blocked: Protocol '$scheme' not allowed (only http/https)";
    }

    $host = $parsed['host'];

    // Normalizar IP
    $normalized_host = normalize_ip($host);

    // Validar IPv4
    if(filter_var($normalized_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if(is_private_ip($normalized_host)) {
            return "Blocked: Private/Internal IP detected ($normalized_host)";
        }
    }

    // Validar IPv6
    if(filter_var($normalized_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if(is_private_ipv6($normalized_host)) {
            return "Blocked: Private IPv6 address detected";
        }
    }

    // Resolver DNS y validar
    $resolved_ip = gethostbyname($normalized_host);
    if($resolved_ip !== $normalized_host && filter_var($resolved_ip, FILTER_VALIDATE_IP)) {
        if(is_private_ip($resolved_ip)) {
            return "Blocked: Hostname resolves to private IP ($resolved_ip)";
        }
    }

    return false;
}

/**
 * ==================================================================
 * NIVEL 4: PROTECCIÓN IMPOSIBLE (Secure but Functional)
 * ==================================================================
 */
function validate_impossible($url) {
    // 1. Rate limiting
    $rate_check = check_rate_limit();
    if($rate_check) return $rate_check;

    // 2. Protocol validation
    $parsed = parse_url($url);
    if(!$parsed || !isset($parsed['host'])) {
        return "Invalid URL format";
    }

    $scheme = strtolower($parsed['scheme'] ?? '');
    if(!in_array($scheme, ['http', 'https'])) {
        return "Blocked: Protocol '$scheme' not allowed (only http/https)";
    }

    $host = $parsed['host'];

    // 3. Port restriction (only 80, 443)
    $port_check = check_network_egress($url);
    if($port_check) return $port_check;

    // 4. Normalize IP (decimal, hex, octal, short form)
    $normalized_host = normalize_ip($host);

    // 5. Block direct IP access to private ranges
    if(filter_var($normalized_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4)) {
        if(is_private_ip($normalized_host)) {
            return "Blocked: Private/Internal IP detected ($normalized_host)";
        }
    }

    // 6. Block IPv6 private addresses
    if(filter_var($normalized_host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
        if(is_private_ipv6($normalized_host)) {
            return "Blocked: Private IPv6 address detected";
        }
    }

    // 7. DNS resolution validation - CRITICAL
    // Resolve DNS BEFORE allowing request
    $resolved_ip = gethostbyname($normalized_host);
    if($resolved_ip !== $normalized_host) {
        // DNS resolved to an IP
        if(filter_var($resolved_ip, FILTER_VALIDATE_IP)) {
            if(is_private_ip($resolved_ip)) {
                return "Blocked: Hostname '$normalized_host' resolves to private IP ($resolved_ip)";
            }
        }
    }

    // 8. TOCTOU Protection (Time-of-Check-Time-of-Use)
    // Re-validate DNS after small delay to detect DNS rebinding
    usleep(100000); // 100ms delay
    $resolved_ip_2 = gethostbyname($normalized_host);
    if($resolved_ip !== $resolved_ip_2) {
        return "Blocked: DNS rebinding attack detected (IP changed during validation)";
    }

    // 9. Double-check the second resolution
    if(filter_var($resolved_ip_2, FILTER_VALIDATE_IP)) {
        if(is_private_ip($resolved_ip_2)) {
            return "Blocked: DNS rebinding to private IP detected";
        }
    }

    // All checks passed - allow request to public internet
    return false;
}

function check_rate_limit() {
    if(!isset($_SESSION['request_count'])) {
        $_SESSION['request_count'] = 0;
        $_SESSION['request_reset_time'] = time() + 60;
    }

    if(time() > $_SESSION['request_reset_time']) {
        $_SESSION['request_count'] = 0;
        $_SESSION['request_reset_time'] = time() + 60;
    }

    $_SESSION['request_count']++;

    if($_SESSION['request_count'] > 10) {
        return "Rate limit exceeded: Maximum 10 requests per minute";
    }

    return false;
}

function check_network_egress($url) {
    $parsed = parse_url($url);
    $port = $parsed['port'] ?? ($parsed['scheme'] === 'https' ? 443 : 80);

    $allowed_ports = [80, 443];

    if(!in_array($port, $allowed_ports)) {
        return "Blocked: Port $port not allowed (only 80, 443)";
    }

    return false;
}

function validate_response_content($content, $url) {
    // Detectar patrones sospechosos en respuesta
    $suspicious_patterns = [
        '/AKIA[0-9A-Z]{16}/',                    // AWS Access Key
        '/"AccessKeyId"\s*:\s*"/',               // JSON AWS creds
        '/"SecretAccessKey"\s*:\s*"/',
        '/aws_secret_access_key/',
        '/BEGIN RSA PRIVATE KEY/',               // Private keys
        '/ssh-rsa/',                             // SSH keys
    ];

    foreach($suspicious_patterns as $pattern) {
        if(preg_match($pattern, $content)) {
            error_log("SECURITY ALERT: Suspicious content detected from $url");
            return "Security Alert: Response contains sensitive data patterns";
        }
    }

    return false;
}

/**
 * ==================================================================
 * ROUTING DE VALIDACIÓN
 * ==================================================================
 */
function is_url_blocked($url) {
    global $protection_level;

    switch($protection_level) {
        case 'none':
            return validate_none($url);
        case 'medium':
            return validate_medium($url);
        case 'high':
            return validate_high($url);
        case 'impossible':
            return validate_impossible($url);
        default:
            return false;
    }
}

function log_attempt($url, $blocked, $reason = null) {
    $log_entry = sprintf(
        "[%s] Level: %s | URL: %s | Blocked: %s | Reason: %s\n",
        date('Y-m-d H:i:s'),
        strtoupper($_SESSION['protection_level'] ?? 'none'),
        $url,
        $blocked ? 'YES' : 'NO',
        $reason ?? 'N/A'
    );

    @file_put_contents('/tmp/ssrf_attempts.log', $log_entry, FILE_APPEND);
}

/**
 * ==================================================================
 * HANDLE REQUEST
 * ==================================================================
 */
$result = null;
$error = null;

if(isset($_GET['url']) && !empty($_GET['url'])) {
    $url = $_GET['url'];

    $block_reason = is_url_blocked($url);

    if($block_reason) {
        $error = $block_reason;
        log_attempt($url, true, $block_reason);
    } else {
        log_attempt($url, false);

        $opts = array(
            'http' => array(
                'method' => "GET",
                'timeout' => 5,
                'follow_location' => ($protection_level === 'high' || $protection_level === 'impossible') ? 0 : 1,
                'max_redirects' => 0,
                'header' => "User-Agent: SecureURLChecker/2.0\r\n"
            )
        );

        $context = stream_context_create($opts);
        $start_time = microtime(true);
        $content = @file_get_contents($url, false, $context);
        $end_time = microtime(true);

        if($content !== false) {
            // En nivel IMPOSIBLE, validar contenido de respuesta
            if($protection_level === 'impossible') {
                $content_check = validate_response_content($content, $url);
                if($content_check) {
                    $error = $content_check;
                    $content = null;
                }
            }

            if($content !== null) {
                $result = array(
                    'status' => 'success',
                    'response_time' => round(($end_time - $start_time) * 1000, 2),
                    'content_length' => strlen($content),
                    'content' => $content
                );
            }
        } else {
            $error = "Failed to fetch URL: Connection failed or timeout";
        }
    }
}
?>
<!DOCTYPE html>
<html>
<head>
    <title>SSRF Protection Lab - Multi-Level Security</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 40px 20px;
        }

        .container {
            max-width: 900px;
            margin: 0 auto;
            background: white;
            border-radius: 12px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 28px;
            margin-bottom: 10px;
        }

        .header p {
            opacity: 0.9;
            font-size: 14px;
        }

        .content {
            padding: 30px;
        }

        .level-selector {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 15px;
            margin-bottom: 25px;
        }

        .level-btn {
            padding: 20px 15px;
            border: 3px solid #ddd;
            border-radius: 10px;
            cursor: pointer;
            text-align: center;
            transition: all 0.3s;
            text-decoration: none;
            color: #333;
            display: block;
        }

        .level-btn:hover {
            transform: translateY(-3px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }

        .level-btn.active {
            transform: scale(1.05);
            box-shadow: 0 8px 20px rgba(0,0,0,0.3);
        }

        .level-none {
            border-color: #ff5252;
            background: linear-gradient(135deg, #ffebee, #fff);
        }
        .level-none.active {
            background: linear-gradient(135deg, #ff5252, #f44336);
            color: white;
            border-color: #d32f2f;
        }

        .level-medium {
            border-color: #ffa726;
            background: linear-gradient(135deg, #fff3e0, #fff);
        }
        .level-medium.active {
            background: linear-gradient(135deg, #ffa726, #ff9800);
            color: white;
            border-color: #f57c00;
        }

        .level-high {
            border-color: #66bb6a;
            background: linear-gradient(135deg, #e8f5e9, #fff);
        }
        .level-high.active {
            background: linear-gradient(135deg, #66bb6a, #4caf50);
            color: white;
            border-color: #388e3c;
        }

        .level-impossible {
            border-color: #7e57c2;
            background: linear-gradient(135deg, #ede7f6, #fff);
        }
        .level-impossible.active {
            background: linear-gradient(135deg, #7e57c2, #673ab7);
            color: white;
            border-color: #512da8;
        }

        .level-title {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 5px;
        }

        .level-desc {
            font-size: 12px;
            opacity: 0.8;
        }

        .current-level {
            background: #f5f5f5;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            text-align: center;
        }

        .form-group {
            margin-bottom: 20px;
        }

        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #333;
        }

        .url-input-wrapper {
            display: flex;
            gap: 10px;
        }

        .url-input {
            flex: 1;
            padding: 12px 15px;
            border: 2px solid #e0e0e0;
            border-radius: 6px;
            font-size: 14px;
            transition: border-color 0.3s;
        }

        .url-input:focus {
            outline: none;
            border-color: #667eea;
        }

        .btn {
            padding: 12px 25px;
            border: none;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s;
        }

        .btn-primary {
            background: #667eea;
            color: white;
        }

        .btn-primary:hover {
            background: #5568d3;
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }

        .result-box {
            margin-top: 25px;
            padding: 20px;
            border-radius: 8px;
            border-left: 4px solid;
        }

        .result-box.success {
            background: #e8f5e9;
            border-color: #4caf50;
        }

        .result-box.error {
            background: #ffebee;
            border-color: #f44336;
        }

        .result-box h3 {
            margin-bottom: 15px;
            color: #333;
        }

        .result-meta {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 15px;
        }

        .meta-item {
            background: white;
            padding: 12px;
            border-radius: 6px;
        }

        .meta-label {
            font-size: 12px;
            color: #666;
            text-transform: uppercase;
            margin-bottom: 5px;
        }

        .meta-value {
            font-size: 16px;
            font-weight: 600;
            color: #333;
        }

        .content-preview {
            background: #2d2d2d;
            color: #f8f8f8;
            padding: 15px;
            border-radius: 6px;
            overflow-x: auto;
            max-height: 400px;
            overflow-y: auto;
        }

        .content-preview pre {
            margin: 0;
            white-space: pre-wrap;
            word-wrap: break-word;
            font-family: 'Courier New', monospace;
            font-size: 13px;
            line-height: 1.5;
        }

        .error-message {
            color: #d32f2f;
            font-weight: 500;
        }

        .info-box {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            border-radius: 6px;
            margin-top: 20px;
        }

        .info-box h4 {
            margin-bottom: 10px;
            color: #1976d2;
        }

        .info-box ul {
            margin-left: 20px;
            color: #555;
        }

        .info-box li {
            margin-bottom: 5px;
        }

        .info-box p {
            margin-top: 8px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ SSRF Protection Laboratory</h1>
            <p>Multi-Level Security Testing Platform</p>
        </div>

        <div class="content">
            <!-- Level Selector -->
            <div class="level-selector">
                <a href="?set_level=none" class="level-btn level-none <?php echo $protection_level === 'none' ? 'active' : ''; ?>">
                    <div class="level-title">🔓 NONE</div>
                    <div class="level-desc">No Protection</div>
                </a>
                <a href="?set_level=medium" class="level-btn level-medium <?php echo $protection_level === 'medium' ? 'active' : ''; ?>">
                    <div class="level-title">⚠️ MEDIUM</div>
                    <div class="level-desc">Blacklist-based</div>
                </a>
                <a href="?set_level=high" class="level-btn level-high <?php echo $protection_level === 'high' ? 'active' : ''; ?>">
                    <div class="level-title">🔒 HIGH</div>
                    <div class="level-desc">Enterprise-grade</div>
                </a>
                <a href="?set_level=impossible" class="level-btn level-impossible <?php echo $protection_level === 'impossible' ? 'active' : ''; ?>">
                    <div class="level-title">🚫 IMPOSSIBLE</div>
                    <div class="level-desc">Multi-layer Defense</div>
                </a>
            </div>

            <div class="current-level">
                <strong>Current Protection Level:</strong>
                <span style="font-size: 20px; font-weight: 700; text-transform: uppercase; color: <?php
                    $colors = ['none' => '#f44336', 'medium' => '#ff9800', 'high' => '#4caf50', 'impossible' => '#673ab7'];
                    echo $colors[$protection_level] ?? '#333';
                ?>;">
                    <?php echo $protection_level; ?>
                </span>
                <?php if($protection_level === 'impossible'): ?>
                    <div style="margin-top: 10px; font-size: 13px; color: #666;">
                        Rate Limit: <?php echo $_SESSION['request_count'] ?? 0; ?>/10 requests this minute
                    </div>
                <?php endif; ?>
            </div>

            <!-- URL Form -->
            <form method="GET">
                <div class="form-group">
                    <label>Enter URL to test:</label>
                    <div class="url-input-wrapper">
                        <input type="text" name="url" class="url-input"
                               placeholder="https://httpbin.org/get"
                               value="<?php echo htmlspecialchars($_GET['url'] ?? ''); ?>">
                        <button type="submit" class="btn btn-primary">Test URL</button>
                    </div>
                </div>
            </form>

            <!-- Protection Info -->
            <?php if($protection_level === 'impossible'): ?>
            <div class="info-box">
                <h4>🔐 IMPOSSIBLE Level - Enterprise-Grade Protection</h4>
                <p><strong>Protection Mechanisms:</strong></p>
                <ul>
                    <li>✅ IP normalization (detects decimal, hex, octal, short form)</li>
                    <li>✅ Private IP range blocking (RFC 1918, link-local, localhost)</li>
                    <li>✅ DNS resolution validation (blocks domains resolving to private IPs)</li>
                    <li>✅ TOCTOU protection (detects DNS rebinding attacks)</li>
                    <li>✅ IPv6 validation (blocks private IPv6 ranges)</li>
                    <li>✅ Protocol whitelist (HTTP/HTTPS only)</li>
                    <li>✅ Port restriction (80, 443 only)</li>
                    <li>✅ Rate limiting (10 requests/minute)</li>
                    <li>✅ Response content scanning (detects leaked credentials)</li>
                </ul>
                <p style="color: #4caf50;"><strong>✅ Allows:</strong> Any public domain/IP on the internet (google.com, github.com, etc.)</p>
                <p style="color: #f44336;"><strong>❌ Blocks:</strong> Internal/private IPs, metadata services (169.254.169.254), localhost, private networks</p>
            </div>
            <?php endif; ?>

            <!-- Results -->
            <?php if($error): ?>
                <div class="result-box error">
                    <h3>⚠️ Request Blocked</h3>
                    <p class="error-message"><?php echo htmlspecialchars($error); ?></p>
                </div>
            <?php elseif($result): ?>
                <div class="result-box success">
                    <h3>✅ Response Received</h3>
                    <div class="result-meta">
                        <div class="meta-item">
                            <div class="meta-label">Response Time</div>
                            <div class="meta-value"><?php echo $result['response_time']; ?>ms</div>
                        </div>
                        <div class="meta-item">
                            <div class="meta-label">Content Size</div>
                            <div class="meta-value"><?php echo number_format($result['content_length']); ?> bytes</div>
                        </div>
                    </div>
                    <div class="meta-label" style="margin-bottom: 10px;">RESPONSE CONTENT:</div>
                    <div class="content-preview">
                        <pre><?php
                            $json = json_decode($result['content'], true);
                            if(json_last_error() === JSON_ERROR_NONE) {
                                echo htmlspecialchars(json_encode($json, JSON_PRETTY_PRINT));
                            } else {
                                echo htmlspecialchars(substr($result['content'], 0, 3000));
                                if(strlen($result['content']) > 3000) {
                                    echo "\n\n... (truncated)";
                                }
                            }
                        ?></pre>
                    </div>
                </div>
            <?php endif; ?>
        </div>
    </div>
</body>
</html>
