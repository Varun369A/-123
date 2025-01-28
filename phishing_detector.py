import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import socket
import ssl
import whois
import requests
from urllib.parse import urlparse
from threading import Thread
import re

# VirusTotal API Key
VT_API_KEY = "2ec01ed009eab88bcbae17de4096ef9521864e72612a41aeb36550fc7f94cbee"

# Extract domain from URL
def extract_domain_from_url(url):
    parsed_url = urlparse(url)
    return parsed_url.netloc or ""

# Resolve domain to IP
def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

# Check SSL
def check_ssl(domain):
    try:
        context = ssl.create_default_context()
        with context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=domain) as s:
            s.settimeout(3)
            s.connect((domain, 443))
            cert = s.getpeercert()
            return True, cert.get('notAfter')
    except Exception:
        return False, None

# WHOIS Lookup
def get_whois_info(domain):
    try:
        w = whois.whois(domain)
        return w.text
    except Exception as e:
        return str(e)

# VirusTotal Reputation Check
def check_domain_reputation_api(domain):
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(f"https://www.virustotal.com/api/v3/domains/{domain}", headers=headers)
        if response.status_code == 200:
            data = response.json()
            malicious = data["data"]["attributes"]["last_analysis_stats"]["malicious"]
            return malicious > 0  # True if malicious activity is detected
        return None
    except Exception as e:
        return str(e)

# Detect phishing patterns
def detect_phishing_patterns(url, domain):
    patterns = []
    if re.search(r"[0-9]+|login|secure|verify|account|update", domain, re.IGNORECASE):
        patterns.append("Suspicious keywords or numbers in subdomains.")
    if domain.startswith("xn--"):
        patterns.append("Potential Unicode homograph attack (Punycode domain).")
    if url.startswith("http://"):
        patterns.append("Non-secure HTTP link.")
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain):
        patterns.append("IP-based domain detected.")
    if any(url.lower().endswith(ext) for ext in [".exe", ".scr", ".php", ".zip"]):
        patterns.append("Suspicious file extension detected.")
    if domain.split('.')[-1] in ["tk", "ml", "ga", "cf", "gq", "xyz", "top"]:
        patterns.append("Abnormal top-level domain detected.")
    return patterns

# Main function to scan links
def detect_malicious_link(url, results_text):
    results_text.delete(1.0, tk.END)
    domain = extract_domain_from_url(url)

    if not domain:
        results_text.insert(tk.END, "Invalid URL format. Please enter a valid link.\n")
        return

    results_text.insert(tk.END, f"Scanning domain: {domain}\n")
    malicious_reasons = []

    # DNS Resolution
    ip = resolve_domain(domain)
    if ip:
        results_text.insert(tk.END, f"Resolved to IP: {ip}\n")
    else:
        malicious_reasons.append("Domain failed to resolve.")
        results_text.insert(tk.END, "Domain failed to resolve.\n")

    # SSL Check
    ssl_status, expiry = check_ssl(domain)
    if ssl_status:
        results_text.insert(tk.END, f"SSL valid. Certificate expiry: {expiry}\n")
    else:
        malicious_reasons.append("SSL not valid or missing.")
        results_text.insert(tk.END, "SSL not valid or missing.\n")

    # WHOIS Lookup
    whois_info = get_whois_info(domain)
    if whois_info:
        results_text.insert(tk.END, f"WHOIS Data:\n{whois_info}\n")
    else:
        malicious_reasons.append("WHOIS data unavailable.")
        results_text.insert(tk.END, "WHOIS data unavailable.\n")

    # VirusTotal Reputation
    reputation = check_domain_reputation_api(domain)
    if isinstance(reputation, str):  # Error message
        results_text.insert(tk.END, f"VirusTotal reputation check error: {reputation}\n")
    elif reputation:
        malicious_reasons.append("Domain flagged as malicious by VirusTotal.")
        results_text.insert(tk.END, "Domain flagged as malicious by VirusTotal.\n")
    else:
        results_text.insert(tk.END, "Domain is not flagged as malicious by VirusTotal.\n")

    # Phishing Patterns
    phishing_reasons = detect_phishing_patterns(url, domain)
    malicious_reasons.extend(phishing_reasons)
    for reason in phishing_reasons:
        results_text.insert(tk.END, f"{reason}\n")

    # Display results
    if malicious_reasons:
        results_text.insert(tk.END, "\nMalicious link detected! Reason(s):\n")
        for reason in malicious_reasons:
            results_text.insert(tk.END, f"- {reason}\n")
    else:
        results_text.insert(tk.END, "\nLink is safe. No malicious activity detected.\n")

# Run detection in a thread
def perform_detection_threaded(url, results_text):
    thread = Thread(target=detect_malicious_link, args=(url, results_text))
    thread.start()

# Clear results and input field
def clear_fields(entry_target, results_text):
    entry_target.delete(0, tk.END)
    results_text.delete(1.0, tk.END)

# Save results to a file
def save_results(results_text):
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
    if file_path:
        try:
            with open(file_path, 'w') as file:
                file.write(results_text.get(1.0, tk.END))
            messagebox.showinfo("Success", "Results saved successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save the file: {str(e)}")

# GUI Setup
app = tk.Tk()
app.title("Phishing Link Detection Tool")
app.geometry("900x700")
app.config(bg="#f0f8ff")

header = tk.Label(app, text="Phishing Link Detection Tool", font=("Arial", 18, "bold"), bg="#4682b4", fg="white")
header.pack(fill=tk.X, pady=10)

frame_target = tk.Frame(app, bg="#f0f8ff")
frame_target.pack(pady=10)
tk.Label(frame_target, text="Enter Link to Scan:", font=("Arial", 14), bg="#f0f8ff").pack(side=tk.LEFT, padx=5)
entry_target = tk.Entry(frame_target, width=50, font=("Arial", 14))
entry_target.pack(side=tk.LEFT, padx=5)

btn_scan = tk.Button(app, text="Start Scan", command=lambda: perform_detection_threaded(entry_target.get(), result_text),
                     bg="#32cd32", fg="white", font=("Arial", 14))
btn_scan.pack(pady=5)

btn_clear = tk.Button(app, text="Clear", command=lambda: clear_fields(entry_target, result_text),
                      bg="#ff6347", fg="white", font=("Arial", 14))
btn_clear.pack(pady=5)

btn_save = tk.Button(app, text="Save Results", command=lambda: save_results(result_text),
                     bg="#4682b4", fg="white", font=("Arial", 14))
btn_save.pack(pady=5)

result_text = scrolledtext.ScrolledText(app, height=25, wrap=tk.WORD, font=("Arial", 12), bg="#ffffff")
result_text.pack(pady=10, padx=20, fill=tk.BOTH, expand=True)

footer = tk.Label(app, text="\u00a9 2025 Phishing Link Detection Tool | Designed by Your Name",
                  font=("Arial", 10), bg="#f0f8ff", fg="#808080")
footer.pack(side=tk.BOTTOM, pady=10)

app.mainloop()
