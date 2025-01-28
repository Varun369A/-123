import os
import platform
import subprocess
import shutil
import logging
import time
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog
from pathlib import Path

# Configuration Settings
LOG_DIRS = {
    "Event Logs": r"C:\\Windows\\System32\\winevt\\Logs",
    "System Logs": r"C:\\Windows\\System32\\LogFiles",
    "Application Logs": r"C:\\Program Files",
    "Windows Update Logs": r"C:\\Windows\\Logs\\WindowsUpdate",
}

# Set up logging
logging.basicConfig(
    filename="incident_response.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Function to collect logs from the system
def collect_logs():
    logs_collected = {"Event Logs": [], "System Logs": [], "Application Logs": [], "Windows Update Logs": []}

    try:
        for log_type, log_dir in LOG_DIRS.items():
            if os.path.exists(log_dir):
                logs_collected[log_type] = [
                    os.path.join(log_dir, file)
                    for file in os.listdir(log_dir)
                    if file.endswith(".log") or file.endswith(".evtx")
                ]
            else:
                logging.warning(f"Log directory {log_dir} not found.")
                logs_collected[log_type] = []

        logging.info("Logs collected successfully.")
    except Exception as e:
        logging.error(f"Error collecting logs: {e}")
    
    return logs_collected

# Function to collect event logs specifically
def collect_event_logs(log_directory, output_directory):
    """
    Collects Windows event logs from the specified directory.
    Parameters:
        log_directory (str): The path to the directory containing event logs.
        output_directory (str): The path to the directory where logs will be saved.
    """
    if not os.path.exists(output_directory):
        os.makedirs(output_directory)

    log_files = Path(log_directory).glob("*.evtx")

    for log_file in log_files:
        try:
            with open(log_file, "rb") as f:  # Binary mode for safe reading
                data = f.read()
            output_file = Path(output_directory) / log_file.name
            with open(output_file, "wb") as f:  # Save as binary to avoid encoding issues
                f.write(data)
            logging.info(f"Log {log_file} collected successfully.")
        except UnicodeDecodeError as e:
            logging.error(
                f"Error reading log {log_file}: {e}. "
                "Consider checking file encoding or corrupted files."
            )
        except Exception as e:
            logging.error(f"Unexpected error with file {log_file}: {e}")

# Function to analyze logs for suspicious activity
def analyze_logs(logs):
    suspicious_entries = {"Event Logs": [], "System Logs": [], "Application Logs": [], "Windows Update Logs": []}

    try:
        for log_type, log_files in logs.items():
            for log in log_files:
                try:
                    with open(log, 'r', encoding='utf-8', errors='ignore') as file:
                        content = file.read()
                        # Basic check for suspicious activity (e.g., "failed login", "error", etc.)
                        if "failed login" in content or "error" in content:
                            suspicious_entries[log_type].append(log)
                except Exception as e:
                    logging.error(f"Error reading log {log}: {e}")
    
    except Exception as e:
        logging.error(f"Error analyzing logs: {e}")

    return suspicious_entries

# Function to generate the report
def generate_report(suspicious_logs):
    report_file = filedialog.asksaveasfilename(
        title="Save Report As",
        defaultextension=".txt",
        filetypes=[("Text Files", "*.txt")]
    )
    
    if not report_file:
        logging.warning("Report save canceled by user.")
        return None
    
    try:
        with open(report_file, "w") as report:
            report.write("Incident Response Report\n")
            report.write(f"Timestamp: {time.ctime()}\n")
            report.write(f"System: {platform.system()} {platform.release()}\n")
            report.write("\nSuspicious Activity Logs:\n")
            
            for log_type, logs in suspicious_logs.items():
                report.write(f"\n{log_type}:\n")
                if logs:
                    for log in logs:
                        report.write(f"  - {log}\n")
                else:
                    report.write("  No suspicious activity detected.\n")
        
        logging.info(f"Report generated: {report_file}")
        return report_file
    except Exception as e:
        logging.error(f"Error generating report: {e}")
        return None

# GUI for Incident Response Tool
class IncidentResponseApp:
    def __init__(self, root):
        self.root = root
        self.suspicious_logs = None  # Initialize suspicious logs
        self.root.title("Incident Response Tool")
        self.root.geometry(f"{int(root.winfo_screenwidth() * 0.8)}x{int(root.winfo_screenheight() * 0.8)}")
        self.root.config(bg="#2e3b4e")

        self.log_area = tk.Text(root, height=15, width=100, bg="#f1f1f1", fg="#333333", font=("Arial", 12))
        self.log_area.pack(pady=10)

        self.suspicious_area = tk.Text(root, height=15, width=100, bg="#f1f1f1", fg="#333333", font=("Arial", 12))
        self.suspicious_area.pack(pady=10)

        self.start_button = tk.Button(root, text="Start Incident Response", command=self.start_incident_response, bg="#4CAF50", fg="white", font=("Arial", 12))
        self.start_button.pack(pady=5)

        self.clear_button = tk.Button(root, text="Clear Logs", command=self.clear_logs, bg="#f44336", fg="white", font=("Arial", 12))
        self.clear_button.pack(pady=5)

        self.download_button = tk.Button(root, text="Download Report", command=self.download_report, bg="#2196F3", fg="white", font=("Arial", 12))
        self.download_button.pack(pady=5)

    def start_incident_response(self):
        self.log_area.insert(tk.END, "Incident Response started...\n")
        logs = collect_logs()
        self.suspicious_logs = analyze_logs(logs)

        self.log_area.insert(tk.END, "Logs scanned...\n")
        for log_type, log_files in logs.items():
            self.log_area.insert(tk.END, f"\n{log_type}:\n")
            for log in log_files[:10]:  # Limit to first 10 logs
                self.log_area.insert(tk.END, f"  - {log}\n")
            if len(log_files) > 10:
                self.log_area.insert(tk.END, f"  ...and {len(log_files) - 10} more logs.\n")
        
        self.suspicious_area.insert(tk.END, "Suspicious Logs Found:\n")
        for log_type, logs in self.suspicious_logs.items():
            self.suspicious_area.insert(tk.END, f"\n{log_type}:\n")
            if logs:
                for log in logs:
                    self.suspicious_area.insert(tk.END, f"  - {log}\n")
            else:
                self.suspicious_area.insert(tk.END, "  No suspicious activity detected.\n")

    def clear_logs(self):
        self.log_area.delete(1.0, tk.END)
        self.suspicious_area.delete(1.0, tk.END)

    def download_report(self):
        if self.suspicious_logs:
            report = generate_report(self.suspicious_logs)
            if report:
                messagebox.showinfo("Success", f"Report saved as: {report}")
        else:
            messagebox.showwarning("Warning", "No suspicious logs to generate a report.")

# Main function to run the GUI application
def run_app():
    root = tk.Tk()
    app = IncidentResponseApp(root)
    root.mainloop()

if __name__ == "__main__":
    # Collect event logs and store them in a specific directory
    collect_event_logs(r"C:\\Windows\\System32\\winevt\\Logs", r"C:\\CollectedLogs")
    # Launch the GUI application
    run_app()
