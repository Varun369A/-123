
Cyber Security Projects 
import tkinter as tk
from tkinter import scrolledtext, filedialog, messagebox
import scapy.all as scapy
import threading
import time
import dns.resolver
from collections import defaultdict

# GUI Setup
class DNSMonitorApp:
    def __init__(self, root):
        self.root = root
        self.root.title("DNS Attack Detection")
        self.root.geometry("700x600")
        
        # Colors
        self.bg_color = "#1E2A47"  # Deep blue background
        self.text_bg_color = "#ffffff"  # White background for text boxes
        self.alert_bg_color = "#F9C9D3"  # Light pinkish background for alerts
        self.button_color = "#4682b4"  # Steel blue buttons
        self.font_style = ("Arial", 12)  # Font for text

        # Setting up the GUI components
        self.root.config(bg=self.bg_color)
        
        # Normal Query Display Box
        self.query_label = tk.Label(self.root, text="DNS Queries", bg=self.bg_color, fg="white", font=("Arial", 14))
        self.query_label.pack(pady=5)
        self.output_area = scrolledtext.ScrolledText(self.root, width=70, height=10, bg=self.text_bg_color, font=self.font_style)
        self.output_area.pack(padx=10, pady=10)
        
        # Suspicious Activity Display Box
        self.suspicious_label = tk.Label(self.root, text="Suspicious Activity", bg=self.bg_color, fg="white", font=("Arial", 14))
        self.suspicious_label.pack(pady=5)
        self.suspicious_area = scrolledtext.ScrolledText(self.root, width=70, height=5, bg=self.alert_bg_color, font=self.font_style)
        self.suspicious_area.pack(padx=10, pady=10)
        
        # Control Buttons
        self.start_button = tk.Button(self.root, text="Start Monitoring", command=self.start_monitoring, bg=self.button_color, fg="white", font=self.font_style)
        self.start_button.pack(padx=10, pady=10)
        
        self.stop_button = tk.Button(self.root, text="Stop Monitoring", command=self.stop_monitoring, state=tk.DISABLED, bg=self.button_color, fg="white", font=self.font_style)
        self.stop_button.pack(padx=10, pady=10)
        
        self.save_button = tk.Button(self.root, text="Save Report", command=self.save_report, bg=self.button_color, fg="white", font=self.font_style)
        self.save_button.pack(padx=10, pady=10)
        
        self.monitoring_thread = None
        self.monitoring = False
        
        self.suspicious_ips = defaultdict(int)  # Tracks DNS queries per IP
        self.report_data = []  # Store log data to be saved

    def start_monitoring(self):
        self.output_area.delete(1.0, tk.END)
        self.suspicious_area.delete(1.0, tk.END)
        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.monitoring = True
        self.monitoring_thread = threading.Thread(target=self.monitor_dns_traffic)
        self.monitoring_thread.start()

    def stop_monitoring(self):
        self.monitoring = False
        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)

    def monitor_dns_traffic(self):
        scapy.sniff(prn=self.handle_packet, filter="udp port 53", store=0)

    def handle_packet(self, packet):
        if packet.haslayer(scapy.DNSQR):  # Check if it's a DNS query
            src_ip = packet[scapy.IP].src
            query_name = packet[scapy.DNSQR].qname.decode()
            
            # Monitor the number of queries from each IP
            self.suspicious_ips[src_ip] += 1
            
            # Detect unusual DNS query patterns (simple threshold)
            if self.suspicious_ips[src_ip] > 100:
                self.flag_suspicious_activity(src_ip, query_name)
            
            # DNS amplification detection
            if self.is_dns_amplification(packet):
                self.detect_amplification(packet, src_ip)
            
            # Display packet info in normal area
            self.display_packet_info(src_ip, query_name)
    
    def flag_suspicious_activity(self, ip, domain):
        alert_message = f"ALERT: Suspicious activity detected from {ip} on domain {domain}\n"
        self.suspicious_area.insert(tk.END, alert_message)
        self.report_data.append(alert_message)
        self.suspicious_area.yview(tk.END)
        self.suspicious_area.tag_add("alert", "1.0", "end")
        self.suspicious_area.tag_config("alert", foreground="#FF0000")  # Red for alerts

    def display_packet_info(self, src_ip, query_name):
        info_message = f"DNS Query from {src_ip}: {query_name}\n"
        self.output_area.insert(tk.END, info_message)
        self.report_data.append(info_message)
        self.output_area.yview(tk.END)

    def is_dns_amplification(self, packet):
        # Check if the DNS response size is unusually large for a small query
        if packet.haslayer(scapy.DNSRR):
            query_size = len(packet[scapy.DNSQR].qname)
            response_size = len(packet[scapy.DNSRR].rdata)
            amplification_ratio = response_size / query_size
            
            if amplification_ratio > 10:  # Threshold for amplification ratio (can be adjusted)
                return True
        return False

    def detect_amplification(self, packet, src_ip):
        alert_message = f"ALERT: Possible DNS Amplification Attack detected from {src_ip}\n"
        self.suspicious_area.insert(tk.END, alert_message)
        self.report_data.append(alert_message)
        self.suspicious_area.yview(tk.END)
        self.suspicious_area.tag_add("alert", "1.0", "end")
        self.suspicious_area.tag_config("alert", foreground="#FF0000")  # Red for alerts

    def save_report(self):
        # Save the log data to a user-defined location with a custom file name
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if file_path:
            try:
                with open(file_path, 'w') as file:
                    for line in self.report_data:
                        file.write(line)
                messagebox.showinfo("Success", f"Report saved successfully to {file_path}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to save report: {e}")

# DNS Query Analysis: Check if the DNS response is suspicious
def analyze_dns_response(domain):
    try:
        answers = dns.resolver.resolve(domain)
        for answer in answers:
            # Example of a suspicious check (IP resolution to an abnormal IP)
            if answer.address.startswith("192.168"):  # Detecting private IP address resolution
                return f"Suspicious IP {answer.address} resolved for {domain}"
    except dns.resolver.NoAnswer:
        return f"No answer for {domain}"
    except Exception as e:
        return f"Error resolving {domain}: {str(e)}"
    return None

# Main Application Loop
def main():
    root = tk.Tk()
    app = DNSMonitorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
