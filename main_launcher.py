# main_launcher.py

import os, csv, time, re, threading, platform, subprocess
from datetime import datetime
from collections import defaultdict
from urllib.parse import urljoin, urlparse

import requests
import pandas as pd
from bs4 import BeautifulSoup
from flask import Flask, render_template, request

from scapy.all import sniff, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ====================== CONFIG ======================
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
LOG_DIR = os.path.join(BASE_DIR, "Storage")
os.makedirs(LOG_DIR, exist_ok=True)

TRAFFIC_LOG = os.path.join(LOG_DIR, "traffic.csv")
ALERT_LOG = os.path.join(LOG_DIR, "ddos_alert.csv")
WEB_LOG = os.path.join(LOG_DIR, "web_alerts.csv")

THRESHOLD = 100
WEB_THRESHOLD = 100
CHECK_INTERVAL = 5
SEND_TEST_EMAIL = True

EMAIL_FROM = "cjagankumar2001@gmail.com"
EMAIL_PASSWORD = "bolnhamqbvrwsffs"
EMAIL_TO = "cjagankumar2001@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587
EMAIL_COOLDOWN = 300

WHITELIST_IPS = {"127.0.0.1", "192.168.1.114"}
traffic_counts = defaultdict(int)
web_counts = defaultdict(int)
emailed_ips = {}
blocked_ips = set()

conf.iface = "Wi-Fi"

app = Flask(__name__, template_folder=os.path.join(BASE_DIR, "template"))

# ====================== SQLi Scanner ======================
class SecureSQLiScanner:
    def __init__(self, target_url):
        self.target_url = self._validate_url(target_url)
        self.base_url = f"{urlparse(self.target_url).scheme}://{urlparse(self.target_url).netloc}"
        self.session = requests.Session()
        self.vulnerabilities = []
        self.headers = {
            'User-Agent': 'ShieldNetScanner/1.0',
            'Accept': 'text/html'
        }
        self.payloads = ["' OR '1'='1", "' UNION SELECT NULL, NULL--", "' AND SLEEP(3)--"]
        self.timeout = 20
        self.request_delay = 1.0
        self.start_time = time.time()

    def _validate_url(self, url):
        return url if url.startswith(('http://', 'https://')) else 'http://' + url

    def scan(self):
        try:
            res = self.session.get(self.target_url, headers=self.headers, timeout=self.timeout)
            forms = self._find_forms(res.text)
            self._test_forms(forms)
            if urlparse(self.target_url).query:
                self._test_url_parameters()
            return {
                'status': 'success',
                'vulnerabilities': self.vulnerabilities,
                'protections': self._generate_protection_advice(),
                'scan_time': round(time.time() - self.start_time, 2)
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _find_forms(self, html):
        return BeautifulSoup(html, 'html.parser').find_all('form')

    def _test_forms(self, forms):
        for form in forms:
            details = self._extract_form_details(form)
            for payload in self.payloads:
                time.sleep(self.request_delay)
                res = self._submit_form(details, payload)
                if payload.lower() in res.text.lower():
                    self.vulnerabilities.append({
                        'form_action': details['action'],
                        'payload': payload,
                        'method': details['method'],
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

    def _extract_form_details(self, form):
        return {
            'action': urljoin(self.base_url, form.get('action', '')),
            'method': form.get('method', 'get').lower(),
            'inputs': [tag.get('name') for tag in form.find_all(['input', 'textarea']) if tag.get('name')]
        }

    def _submit_form(self, form, payload):
        data = {name: payload for name in form['inputs']}
        if form['method'] == 'post':
            return self.session.post(form['action'], data=data, headers=self.headers)
        else:
            return self.session.get(form['action'], params=data, headers=self.headers)

    def _test_url_parameters(self):
        parsed = urlparse(self.target_url)
        base = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        params = dict(pair.split('=') for pair in parsed.query.split('&') if '=' in pair)
        for param in params:
            for payload in self.payloads:
                test_url = f"{base}?{param}={payload}"
                res = self.session.get(test_url, headers=self.headers)
                if payload.lower() in res.text.lower():
                    self.vulnerabilities.append({
                        'form_action': test_url,
                        'payload': payload,
                        'method': 'GET',
                        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })

    def _generate_protection_advice(self):
        return [
            "Use parameterized queries or ORM.",
            "Sanitize all user inputs.",
            "Avoid dynamic SQL queries.",
            "Apply WAF and input validation."
        ]

# ====================== Email Alert ======================
def send_email_alert(ip, count, test=False):
    subject = "✅ Test Email: DDoS Alert" if test else f"🚨 DDoS Alert for IP: {ip}"
    body = f"Time: {datetime.now()}\n\nSuspicious activity detected from IP: {ip}\nPacket Count: {count}"

    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.starttls()
            server.login(EMAIL_FROM, EMAIL_PASSWORD)
            server.send_message(msg)
    except Exception as e:
        print(f"[EMAIL ERROR] {e}")

def block_ip(ip):
    if ip in blocked_ips or ip in WHITELIST_IPS:
        return
    try:
        cmd = (
            ["netsh", "advfirewall", "firewall", "add", "rule", "name=BlockIP", "dir=in", "action=block", f"remoteip={ip}"]
            if platform.system() == "Windows" else
            ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        )
        subprocess.run(cmd, check=True)
        blocked_ips.add(ip)
    except Exception as e:
        print(f"[BLOCK ERROR] {e}")

# ====================== Packet Handler ======================
def packet_handler(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst

        if src_ip in WHITELIST_IPS:
            return

        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "OTHER"

        with open(TRAFFIC_LOG, 'a', newline='') as f:
            csv.writer(f).writerow([datetime.now(), src_ip, dst_ip, proto, len(packet)])

        traffic_counts[src_ip] += 1
        if proto in ["TCP", "UDP"] and packet.haslayer(TCP) and packet[TCP].dport in [80, 443]:
            web_counts[src_ip] += 1

# ====================== Detection Logic ======================
def detect_attacks():
    while True:
        time.sleep(CHECK_INTERVAL)
        now = datetime.now()
        for ip, count in list(traffic_counts.items()):
            if count > THRESHOLD:
                log_alert(ip, count, "DDoS")
                if ip not in emailed_ips or (now - emailed_ips[ip]).total_seconds() > EMAIL_COOLDOWN:
                    send_email_alert(ip, count)
                    emailed_ips[ip] = now
                    block_ip(ip)
        for ip, count in list(web_counts.items()):
            if count > WEB_THRESHOLD:
                log_alert(ip, count, "Web")
        traffic_counts.clear()
        web_counts.clear()

def log_alert(ip, count, alert_type):
    file = ALERT_LOG if alert_type == "DDoS" else WEB_LOG
    with open(file, 'a', newline='') as f:
        csv.writer(f).writerow([datetime.now(), ip, count, alert_type])

# ====================== Flask Routes ======================
@app.route('/')
def home():
    return render_template("home.html")

@app.route('/dashboard')
def dashboard():
    try:
        ddos_alerts = pd.read_csv(ALERT_LOG).tail(10).values.tolist()
        web_alerts = pd.read_csv(WEB_LOG).tail(10).values.tolist()
        total_packets = sum(1 for _ in open(TRAFFIC_LOG)) - 1 if os.path.exists(TRAFFIC_LOG) else 0
    except:
        ddos_alerts, web_alerts, total_packets = [], [], 0
    return render_template("dashboard.html",
                           recent_alerts=ddos_alerts + web_alerts,
                           total_packets=total_packets,
                           thresholds={"ddos": THRESHOLD, "web": WEB_THRESHOLD},
                           interface=conf.iface,
                           current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

@app.route('/sqlscanner', methods=['GET', 'POST'])
def sqlscanner():
    if request.method == 'POST':
        target_url = request.form['url']
        scanner = SecureSQLiScanner(target_url)
        result = scanner.scan()
        if result['status'] == 'success':
            return render_template("results.html",
                                   url=target_url,
                                   details=result['vulnerabilities'],
                                   scan_time=result['scan_time'],
                                   note="Be cautious with user inputs.")
        return render_template("error.html", error=result['message'])
    return render_template("index.html")

# ====================== Initialize ======================
def initialize_logs():
    for file, headers in [
        (TRAFFIC_LOG, ["timestamp", "src_ip", "dst_ip", "protocol", "length"]),
        (ALERT_LOG, ["timestamp", "ip", "count", "type"]),
        (WEB_LOG, ["timestamp", "ip", "count", "type"])
    ]:
        if not os.path.exists(file):
            with open(file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)

if __name__ == '__main__':
    initialize_logs()
    if SEND_TEST_EMAIL:
        send_email_alert("127.0.0.1", 0, test=True)
    threading.Thread(target=detect_attacks, daemon=True).start()
    threading.Thread(target=lambda: sniff(prn=packet_handler, store=False), daemon=True).start()
    app.run(debug=True, port=5000)