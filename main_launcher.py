import subprocess
import threading
import tkinter as tk
import webbrowser
import time
import sys
import os

def run_flask_app(script_name, port):
    def target():
        subprocess.run([sys.executable, script_name])
    threading.Thread(target=target, daemon=True).start()
    # Wait a bit for Flask to start, then open browser
    time.sleep(2.5)
    webbrowser.open(f"http://127.0.0.1:{port}")

def run_ddos_detector(script_name, dashboard_port):
    # Runs the DDoS detector script (which starts packet capture + dashboard)
    def start_and_open_dashboard():
        subprocess.Popen([sys.executable, script_name])
        time.sleep(3.0)
        webbrowser.open(f"http://127.0.0.1:{dashboard_port}")
    threading.Thread(target=start_and_open_dashboard, daemon=True).start()

root = tk.Tk()
root.title("Project Launcher")
root.geometry("350x210")

# Button 1: SQLi Scanner
btn1 = tk.Button(root, text="Run Web SQLi Scanner", font=("Arial", 12),
                 command=lambda: run_flask_app("web_ch1.py", 5001))
btn1.pack(pady=22)

# Button 2: DDoS Detection System
btn2 = tk.Button(root, text="Run DDoS Detection System", font=("Arial", 12),
                 command=lambda: run_ddos_detector("try2.py", 5002))
btn2.pack(pady=12)

label = tk.Label(root, text="Tip: Check console for live logs!", font=("Arial", 9))
label.pack(pady=12)

root.mainloop()