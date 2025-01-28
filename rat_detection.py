import scapy.all as scapy
import psutil
import hashlib
import os
import requests
import threading
import time
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from logging.handlers import RotatingFileHandler
import logging

# Configuration
rat_ips = ["192.168.1.10", "192.168.1.20"]  # Add more known RAT IPs if necessary
known_rats = ["rat.exe", "backdoor.exe", "trojan.exe", "evil.sh", "malicious.py"]
suspicious_ports = [4444, 5555, 8888]
critical_files = ["/bin/bash", "/etc/passwd", "/etc/shadow"]
virus_signatures = {
    # Trojan signatures
    "trojan_signature_1": "d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2d2",
    "trojan_signature_2": "a1b2c3d4e5f678901234567890abcdef",
    "trojan_signature_3": "f1e2d3c4b5a678901234567890abcdef",
    "trojan_signature_4": "1234567890abcdef1234567890abcdef",
    "trojan_signature_5": "abcdef1234567890abcdef1234567890",
    "trojan_signature_6": "4567890abcdef1234567890abcdef1234",
    "trojan_signature_7": "67890abcdef1234567890abcdef12345",
    "trojan_signature_8": "90abcdef1234567890abcdef12345678",
    "trojan_signature_9": "0abcdef1234567890abcdef123456789",
    "trojan_signature_10": "abcdef1234567890abcdef1234567890aa",

    # Malicious script signatures
    "malicious_signature_1": "e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2e2",
    "malicious_signature_2": "11223344556677889900aabbccddeeff",
    "malicious_signature_3": "ffeeddccbbaa99887766554433221100",
    "malicious_signature_4": "deadbeefcafebabe1122334455667788",
    "malicious_signature_5": "cafebabe11223344556677889900aabb",
    "malicious_signature_6": "33445566778899aabbccddeeff112233",
    "malicious_signature_7": "5566778899aabbccddeeff0011223344",
    "malicious_signature_8": "778899aabbccddeeff00112233445566",
    "malicious_signature_9": "99aabbccddeeff001122334455667788",
    "malicious_signature_10": "aabbccddeeff00112233445566778899",

    # Worm signatures
    "worm_signature_1": "a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2a2",
    "worm_signature_2": "bbccddeeff00112233445566778899aabb",
    "worm_signature_3": "00112233445566778899aabbccddeeff",
    "worm_signature_4": "ffeeddccbbaa99887766554433221100",
    "worm_signature_5": "deadbeefcafebabe33445566778899aa",
    "worm_signature_6": "11223344556677889900aabbccddeeff",
    "worm_signature_7": "cafebabe11223344556677889900aabb",
    "worm_signature_8": "5566778899aabbccddeeff0011223344",
    "worm_signature_9": "778899aabbccddeeff00112233445566",
    "worm_signature_10": "99aabbccddeeff001122334455667788",

    # Spyware signatures
    "spyware_signature_1": "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3",
    "spyware_signature_2": "11223344556677889900aabbccddeeff",
    "spyware_signature_3": "ffeeddccbbaa99887766554433221100",
    "spyware_signature_4": "deadbeefcafebabe1122334455667788",
    "spyware_signature_5": "cafebabe33445566778899aabbccddeeff",
    "spyware_signature_6": "5566778899aabbccddeeff0011223344",
    "spyware_signature_7": "778899aabbccddeeff00112233445566",
    "spyware_signature_8": "99aabbccddeeff001122334455667788",
    "spyware_signature_9": "aabbccddeeff00112233445566778899",
    "spyware_signature_10": "11223344556677889900aabbccddeeff",

    # Ransomware signatures
    "ransomware_signature_1": "f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4f4",
    "ransomware_signature_2": "33445566778899aabbccddeeff112233",
    "ransomware_signature_3": "deadbeefcafebabe33445566778899aa",
    "ransomware_signature_4": "cafebabe11223344556677889900aabb",
    "ransomware_signature_5": "5566778899aabbccddeeff0011223344",
    "ransomware_signature_6": "778899aabbccddeeff00112233445566",
    "ransomware_signature_7": "99aabbccddeeff001122334455667788",
    "ransomware_signature_8": "aabbccddeeff00112233445566778899",
    "ransomware_signature_9": "11223344556677889900aabbccddeeff",
    "ransomware_signature_10": "33445566778899aabbccddeeff112233",

    # Keylogger signatures
    "keylogger_signature_1": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
    "keylogger_signature_2": "33445566778899aabbccddeeff112233",
    "keylogger_signature_3": "cafebabe11223344556677889900aabb",
    "keylogger_signature_4": "5566778899aabbccddeeff0011223344",
    "keylogger_signature_5": "778899aabbccddeeff00112233445566",
    "keylogger_signature_6": "99aabbccddeeff001122334455667788",
    "keylogger_signature_7": "aabbccddeeff00112233445566778899",
    "keylogger_signature_8": "11223344556677889900aabbccddeeff",
    "keylogger_signature_9": "33445566778899aabbccddeeff112233",
    "keylogger_signature_10": "cafebabe33445566778899aabbccddeeff"
}
log_file = "rat_detection.log"

# Setup logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s",
                    handlers=[RotatingFileHandler(log_file, maxBytes=5 * 1024 * 1024, backupCount=2)])

def log_alert(message):
    logging.info(message)

def check_file_integrity(file_path):
    if os.path.exists(file_path):
        try:
            with open(file_path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        except Exception:
            return None
    return None

def get_ip_location(ip):
    try:
        url = f"http://ipinfo.io/{ip}/json"
        response = requests.get(url)
        data = response.json()
        return data.get("city", "Unknown") + ", " + data.get("region", "Unknown") + ", " + data.get("country", "Unknown")
    except requests.exceptions.RequestException:
        return "Location Unknown"

def monitor_traffic():
    def packet_callback(packet):
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            if ip_src in rat_ips:
                location = get_ip_location(ip_src)
                alert_message = f"RAT Detected! Source IP: {ip_src}, Location: {location}, Destination IP: {ip_dst}"
                log_alert(alert_message)
                display_alert_message(alert_message)
            elif packet.haslayer(scapy.TCP) and packet[scapy.TCP].sport in suspicious_ports:
                alert_message = f"Suspicious port detected! Source IP: {ip_src}, Port: {packet[scapy.TCP].sport}"
                log_alert(alert_message)
                display_alert_message(alert_message)
    scapy.sniff(prn=packet_callback, store=False, timeout=10)

def monitor_processes():
    for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
        try:
            if proc.info['name'].lower() in known_rats:
                alert_message = f"RAT process detected! Process: {proc.info['name']}, PID: {proc.info['pid']}"
                log_alert(alert_message)
                display_alert_message(alert_message)
            if proc.info['cpu_percent'] > 80:
                alert_message = f"High CPU usage detected! Process: {proc.info['name']}, PID: {proc.info['pid']}, CPU: {proc.info['cpu_percent']}%"
                log_alert(alert_message)
                display_alert_message(alert_message)
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

def check_malicious_files():
    suspicious_files = []
    for dirpath, dirnames, filenames in os.walk("/etc"):
        for filename in filenames:
            file_path = os.path.join(dirpath, filename)
            file_hash = check_file_integrity(file_path)
            if file_hash in virus_signatures.values():
                suspicious_files.append(file_path)
                alert_message = f"Malicious file detected! Path: {file_path}, Signature: {file_hash}"
                log_alert(alert_message)
                display_alert_message(alert_message)
    return suspicious_files

def delete_file(file_path):
    try:
        if check_file_integrity(file_path) in virus_signatures.values():
            os.remove(file_path)
            alert_message = f"File deleted: {file_path}"
            log_alert(alert_message)
            display_alert_message(alert_message)
    except Exception as e:
        alert_message = f"Failed to delete {file_path}: {str(e)}"
        log_alert(alert_message)
        display_alert_message(alert_message)

def monitor_file_integrity():
    for file_path in critical_files:
        file_hash = check_file_integrity(file_path)
        if file_hash:
            alert_message = f"File integrity checked: {file_path}, Hash: {file_hash}"
            log_alert(alert_message)
            display_alert_message(alert_message)

def display_alert_message(message):
    alert_text.insert(tk.END, f"{message}\n")
    alert_text.yview(tk.END)
    start_index = f"{alert_text.index(tk.END)}-1l"
    end_index = f"{alert_text.index(tk.END)}"
    if "RAT" in message or "Suspicious" in message:
        alert_text.tag_add("error", start_index, end_index)
        alert_text.tag_configure("error", foreground="red", font=("Arial", 10, "bold"))
    elif "High CPU" in message:
        alert_text.tag_add("warning", start_index, end_index)
        alert_text.tag_configure("warning", foreground="orange", font=("Arial", 10, "italic"))
    elif "Malicious" in message:
        alert_text.tag_add("danger", start_index, end_index)
        alert_text.tag_configure("danger", foreground="purple", font=("Arial", 10, "bold"))
    else:
        alert_text.tag_add("info", start_index, end_index)
        alert_text.tag_configure("info", foreground="green", font=("Arial", 10))

def periodic_monitoring():
    while True:
        monitor_traffic()
        monitor_processes()
        monitor_file_integrity()
        time.sleep(10)

def delete_malicious_files():
    suspicious_files = check_malicious_files()
    if suspicious_files:
        for file_path in suspicious_files:
            response = messagebox.askyesno("Delete Malicious File", f"Do you want to delete {file_path}?")
            if response:
                delete_file(file_path)
    else:
        messagebox.showinfo("No Malicious Files", "No malicious files found!")

# Create the main GUI window
root = tk.Tk()
root.title("RAT Detection & Malicious File Removal System")
root.geometry("600x500")
root.configure(bg="lightblue")

title_label = tk.Label(root, text="RAT & Malicious File Detection System", font=("Arial", 18), bg="lightblue", fg="black")
title_label.pack(pady=10)

alert_text = tk.Text(root, width=70, height=15, wrap=tk.WORD, font=("Arial", 12))
alert_text.pack(pady=20)

monitoring_text = tk.Text(root, width=70, height=10, wrap=tk.WORD, font=("Arial", 12))
monitoring_text.pack(pady=10)

start_button = tk.Button(root, text="Start Monitoring", font=("Arial", 12), command=lambda: [
    threading.Thread(target=periodic_monitoring, daemon=True).start()
])
start_button.pack(pady=10)

delete_button = tk.Button(root, text="Delete Malicious Files", font=("Arial", 12), command=lambda: threading.Thread(target=delete_malicious_files, daemon=True).start())
delete_button.pack(pady=10)

root.after(5000, lambda: display_alert_message("Monitoring started..."))
root.mainloop()
