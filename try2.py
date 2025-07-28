#!/usr/bin/env python3
# ddos_detector.py - Real-time DDoS Detection System with Enhanced Dashboard, Email Alerts, and Auto-Firewall Blocking

import os
import csv
import time
import threading
import platform
import subprocess
from datetime import datetime
from collections import defaultdict
import pandas as pd
from scapy.all import sniff, conf, get_if_list
from scapy.layers.inet import IP, TCP, UDP
from flask import Flask, render_template
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

# ===== Configuration =====
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOG_DIR = os.path.join(BASE_DIR, "Storage")
os.makedirs(LOG_DIR, exist_ok=True)

TRAFFIC_LOG = os.path.join(LOG_DIR, "traffic.csv")
ALERT_LOG = os.path.join(LOG_DIR, "ddos_alert.csv")
WEB_LOG = os.path.join(LOG_DIR, "web_alerts.csv")

THRESHOLD = 500
WEB_THRESHOLD = 200
CHECK_INTERVAL = 5

EMAIL_FROM = "cjagankumar2001@gmail.com"
EMAIL_PASSWORD = "bolnhamqbvrwsffs"  # Gmail App Password
EMAIL_TO = "cjagankumar2001@gmail.com"
SMTP_SERVER = "smtp.gmail.com"
SMTP_PORT = 587

SEND_TEST_EMAIL = True
WHITELIST_IPS = {"127.0.0.1", "192.168.1.114"}  # Your own IPs to ignore

traffic_counts = defaultdict(int)
web_counts = defaultdict(int)
alerts = []
emailed_ips = {}
blocked_ips = set()
EMAIL_COOLDOWN = 300  # seconds

print("Available interfaces:", get_if_list())
conf.iface = "Wi-Fi"  # Change if needed


# ===== Email Notification =====
def send_email_alert(ip, count, test=False):
    subject = "✅ Test Email: DDoS Alert System" if test else f"CRITICAL DDoS Alert for IP: {ip}"
    body = f"""\n{"This is a test email to verify SMTP setup." if test else f'''
Critical DDoS attack detected!

IP Address: {ip}
Packet Count: {count} packets/sec
Time: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

Please take immediate action.
'''}"""

    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = EMAIL_TO
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        print(f"[DEBUG] Connecting to SMTP: {SMTP_SERVER}:{SMTP_PORT}")
        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        print("[DEBUG] Logging in...")
        server.login(EMAIL_FROM, EMAIL_PASSWORD)
        server.send_message(msg)
        server.quit()
        print("[+] Email alert sent." if not test else "[+] Test email sent.")
    except Exception as e:
        print(f"[!] Failed to send email alert: {e}")


# ===== Auto Firewall Blocking =====
def block_ip(ip):
    if ip in blocked_ips or ip in WHITELIST_IPS:
        return
    system = platform.system()
    try:
        if system == "Windows":
            cmd = ["netsh", "advfirewall", "firewall", "add", "rule",
                   "name=DDoSBlock", "dir=in", "action=block", f"remoteip={ip}", "enable=yes"]
        elif system == "Linux":
            cmd = ["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"]
        else:
            print(f"[!] Unsupported OS for firewall block: {system}")
            return

        subprocess.run(cmd, check=True)
        blocked_ips.add(ip)
        print(f"[FIREWALL] Blocked IP: {ip}")
    except Exception as e:
        print(f"[ERROR] Failed to block IP {ip}: {e}")


# ===== Packet Processing =====
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet.getlayer(IP)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        # Ignore local or whitelisted IPs
        if src_ip in WHITELIST_IPS:
            return

        if packet.haslayer(TCP):
            protocol = "TCP"
            dst_port = packet.getlayer(TCP).dport
        elif packet.haslayer(UDP):
            protocol = "UDP"
            dst_port = packet.getlayer(UDP).dport
        else:
            protocol = "OTHER"
            dst_port = None

        with open(TRAFFIC_LOG, 'a', newline='') as f:
            csv.writer(f).writerow([timestamp, src_ip, dst_ip, protocol, len(packet)])

        traffic_counts[src_ip] += 1
        if dst_port in [80, 443, 8080]:
            web_counts[src_ip] += 1


# ===== Detection Engine =====
def detect_attacks():
    while True:
        time.sleep(CHECK_INTERVAL)
        current_time = datetime.now().strftime("%H:%M:%S")

        for ip, count in list(traffic_counts.items()):
            if count > THRESHOLD:
                alert_msg = f"{current_time} - DDoS Alert: {ip} ({count} pps)"
                alerts.append(alert_msg)
                log_alert(ip, count, "DDoS")
                print(f"[!] {alert_msg}")

                if count > THRESHOLD * 1.5:
                    last_emailed = emailed_ips.get(ip)
                    now = datetime.now()
                    if not last_emailed or (now - last_emailed).total_seconds() > EMAIL_COOLDOWN:
                        send_email_alert(ip, count)
                        emailed_ips[ip] = now
                    block_ip(ip)

        for ip, count in list(web_counts.items()):
            if count > WEB_THRESHOLD:
                alert_msg = f"{current_time} - Web Attack: {ip} ({count} req/s)"
                alerts.append(alert_msg)
                log_alert(ip, count, "Web")
                print(f"[!] {alert_msg}")

        traffic_counts.clear()
        web_counts.clear()


# ===== Alert Logging =====
def log_alert(ip, count, alert_type):
    log_file = WEB_LOG if alert_type == "Web" else ALERT_LOG
    try:
        with open(log_file, 'a', newline='') as f:
            csv.writer(f).writerow([
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                ip,
                count,
                alert_type
            ])
    except Exception as e:
        print(f"[ERROR] Failed to log alert: {e}")


# ===== Flask Web Dashboard =====
app = Flask(__name__, template_folder="C://Users//cjaga//PycharmProjects//DDOS_Detection_System//template")


@app.route("/")
def dashboard():
    try:
        ddos_alerts = pd.read_csv(ALERT_LOG).tail(10).values.tolist() if os.path.exists(ALERT_LOG) else []
        web_alerts = pd.read_csv(WEB_LOG).tail(10).values.tolist() if os.path.exists(WEB_LOG) else []
        recent_alerts = sorted(ddos_alerts + web_alerts, key=lambda x: x[0], reverse=True)[:15]

        alert_counts = {
            "ddos": len(ddos_alerts),
            "web": len(web_alerts)
        }

        total_packets = 0
        if os.path.exists(TRAFFIC_LOG):
            with open(TRAFFIC_LOG, 'r') as f:
                total_packets = sum(1 for _ in f) - 1

    except Exception as e:
        print(f"[WEB ERROR] {e}")
        recent_alerts = []
        alert_counts = {"ddos": 0, "web": 0}
        total_packets = 0

    return render_template("dashboard.html",
                           recent_alerts=recent_alerts,
                           thresholds={"ddos": THRESHOLD, "web": WEB_THRESHOLD},
                           alert_counts=alert_counts,
                           total_packets=total_packets,
                           interface=conf.iface,
                           current_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

# ===== Init Log Files =====
def initialize_files():
    files = {
        TRAFFIC_LOG: ["timestamp", "src_ip", "dst_ip", "protocol", "length"],
        ALERT_LOG: ["timestamp", "ip", "count", "type"],
        WEB_LOG: ["timestamp", "ip", "count", "type"]
    }
    for file, headers in files.items():
        if not os.path.exists(file):
            with open(file, 'w', newline='') as f:
                csv.writer(f).writerow(headers)
            print(f"[+] Created {file}")

# ===== Main =====
if __name__ == "__main__":
    print("=== DDoS Detection System ===")
    print(f"Interface: {conf.iface}")
    print(f"DDoS Threshold: {THRESHOLD} packets/sec")
    print(f"Web Threshold: {WEB_THRESHOLD} requests/sec")

    initialize_files()

    if SEND_TEST_EMAIL:
        print("[*] Sending test email to verify SMTP configuration...")
        send_email_alert("127.0.0.1", 0, test=True)

    detection_thread = threading.Thread(target=detect_attacks, daemon=True)
    detection_thread.start()

    flask_thread = threading.Thread(
        target=lambda: app.run(host='0.0.0.0', port=5002, debug=False, use_reloader=False),
        daemon=True
    )
    flask_thread.start()

    try:
        print("\n[+] Starting packet capture... (Ctrl+C to stop)")
        sniff(prn=packet_handler, store=False)
    except KeyboardInterrupt:
        print("\n[!] Shutting down...")
    except Exception as e:
        print(f"[CRITICAL ERROR] {e}")
    finally:
        print("[+] Alert logs saved to:", LOG_DIR)